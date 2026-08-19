package realtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"

	"zephyr.vox/server/ce/internal/snowflake"
)

const (
	// MaxSequencerQueueItems is the fixed ordinary-command admission limit.
	MaxSequencerQueueItems = 1024
	// MaxSequencerQueueBytes is the fixed ordinary-command admission byte limit.
	MaxSequencerQueueBytes = 4 << 20
)

var (
	// ErrInvalidSequencer is returned when construction or a submitted command
	// lacks the dependencies needed for ordered publication.
	ErrInvalidSequencer = errors.New("realtime: invalid post-commit sequencer")
	// ErrCommandQueueFull is returned before admission when either ordinary
	// command queue limit would be exceeded.
	ErrCommandQueueFull = errors.New("realtime: command queue full")
	// ErrSequencerClosed is returned after shutdown begins and no command may be
	// admitted to the ordinary command queue.
	ErrSequencerClosed = errors.New("realtime: post-commit sequencer closed")
	// ErrSequencerFailed is returned after a post-commit failure makes ordered
	// state publication unsafe to continue in this process.
	ErrSequencerFailed = errors.New("realtime: post-commit sequencer failed")
	// ErrCommandPanic reports a recovered command callback panic. A panic is
	// always fatal because it may have occurred after the database commit.
	ErrCommandPanic = errors.New("realtime: command callback panic")
	// ErrCommandNotCommitted is returned when a command returns without calling
	// Commit or MarkRuntimeCommitted for its reserved publication.
	ErrCommandNotCommitted = errors.New("realtime: command did not commit")
)

// PostCommitCommand is one state-changing operation accepted by the single
// writer. QueueBytes is its validated admission size. Execute receives the
// request context for rollbackable work and a CommandExecution for reserving
// final publication data before committing a persistent transaction.
type PostCommitCommand struct {
	QueueBytes int
	Execute    func(context.Context, int64, *CommandExecution) (CommandOutput, error)
}

// CommandOutput is command-owned result data for the HTTP or WS adapter and is
// never interpreted by the sequencer.
type CommandOutput struct {
	Value any
}

// CommandCompletion is delivered only after StatePublication has committed the
// command's candidate and events. CommandID is a positive snowflake ID and is
// stable data for later idempotency replay.
type CommandCompletion struct {
	CommandID   int64
	Publication PublicationResult
	Value       any
}

// CommandExecution coordinates one command's rollbackable and post-commit
// phases. Persistent commands reserve publication after building a candidate
// from their transaction-bound store, persist the resulting checkpoint/cursor
// in that same transaction, and then call Commit exactly once.
type CommandExecution struct {
	publication   *StatePublication
	commandID     int64
	completionCtx context.Context

	mu          sync.Mutex
	reservation *PublicationReservation
	committing  bool
	committed   bool
}

// Reserve assigns commandID to request events and reserves their final GEIDs,
// checkpoint, and visibility epochs without publishing them. It holds the
// publication boundary until the command later commits or aborts.
func (e *CommandExecution) Reserve(request PublicationRequest) (PublicationResult, error) {
	if e == nil || e.publication == nil {
		return PublicationResult{}, ErrInvalidSequencer
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reservation != nil || e.committed {
		return PublicationResult{}, ErrInvalidSequencer
	}
	request.Events = append([]StateEventTemplate(nil), request.Events...)
	for i := range request.Events {
		request.Events[i].CausationID = e.commandID
	}
	reservation, err := e.publication.Reserve(request)
	if err != nil {
		return PublicationResult{}, err
	}
	e.reservation = reservation
	return reservation.Result(), nil
}

// Commit commits tx and atomically enters the post-commit phase. tx must
// contain the domain mutation, the candidate used by Reserve, and its durable
// idempotency result. All work after this call must use its returned internal
// context; any later error or panic fails the sequencer instead of reporting an
// ordinary command failure.
func (e *CommandExecution) Commit(tx *sql.Tx) (context.Context, error) {
	if e == nil || tx == nil {
		return nil, ErrInvalidSequencer
	}
	e.mu.Lock()
	if e.reservation == nil || e.committing || e.committed {
		e.mu.Unlock()
		return nil, ErrCommandNotCommitted
	}
	e.committing = true
	e.mu.Unlock()
	if err := tx.Commit(); err != nil {
		e.mu.Lock()
		e.committing = false
		e.mu.Unlock()
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.committing = false
	e.committed = true
	return e.completionCtx, nil
}

// MarkRuntimeCommitted enters the post-commit phase for a runtime-only
// command. It must be called only after all reversible preparation has
// completed; StatePublication.Publish is that command's commit point.
func (e *CommandExecution) MarkRuntimeCommitted() (context.Context, error) {
	if e == nil {
		return nil, ErrInvalidSequencer
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reservation == nil || e.committing || e.committed {
		return nil, ErrCommandNotCommitted
	}
	e.committed = true
	return e.completionCtx, nil
}

// CompletionContext returns the internal context allowed after Commit or
// MarkRuntimeCommitted. It has the request's values but ignores request
// cancellation and deadlines.
func (e *CommandExecution) CompletionContext() (context.Context, error) {
	if e == nil {
		return nil, ErrInvalidSequencer
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.committed {
		return nil, ErrCommandNotCommitted
	}
	return e.completionCtx, nil
}

// committedReservation returns e's one committed reservation for publication.
func (e *CommandExecution) committedReservation() (*PublicationReservation, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reservation, e.committed
}

// abort releases an uncommitted publication reservation after an ordinary
// pre-commit command error. A committed reservation is deliberately retained
// for fail-fast recovery rather than silently discarding durable state.
func (e *CommandExecution) abort() {
	if e == nil {
		return
	}
	e.mu.Lock()
	reservation := e.reservation
	committed := e.committing || e.committed
	e.mu.Unlock()
	if reservation != nil && !committed {
		reservation.Abort()
	}
}

// PostCommitSequencer serializes all state-changing commands between their
// persistent commit and StatePublication commit. It owns one worker goroutine;
// Close drains admitted commands and waits for that worker to exit.
type PostCommitSequencer struct {
	publication *StatePublication
	idGen       *snowflake.IDGenerator
	onFatal     func(error)

	commands chan *queuedCommand
	done     chan struct{}

	mu          sync.Mutex
	accepting   bool
	closed      bool
	failure     error
	queuedBytes int
}

// queuedCommand holds one admitted command and its one buffered completion.
type queuedCommand struct {
	ctx        context.Context
	command    PostCommitCommand
	completion chan commandReply
}

// commandReply publishes a command outcome without blocking the worker when a
// disconnected caller no longer waits for it.
type commandReply struct {
	completion CommandCompletion
	err        error
}

// NewPostCommitSequencer creates an ordinary-command single writer with the v1
// fixed queue limits and starts its worker immediately. onFatal must cancel the
// process supervisor: a post-commit panic or publication failure cannot safely
// be isolated to one command.
func NewPostCommitSequencer(publication *StatePublication, idGen *snowflake.IDGenerator, onFatal func(error)) (*PostCommitSequencer, error) {
	if publication == nil || idGen == nil || onFatal == nil {
		return nil, ErrInvalidSequencer
	}
	sequencer := &PostCommitSequencer{
		publication: publication,
		idGen:       idGen,
		onFatal:     onFatal,
		commands:    make(chan *queuedCommand, MaxSequencerQueueItems),
		done:        make(chan struct{}),
		accepting:   true,
	}
	go sequencer.run()
	return sequencer, nil
}

// Submit admits command when both ordinary queue limits permit and waits for
// its ordered completion. A canceled context before dequeue prevents execution;
// callers must let a command that already committed finish its publication.
func (s *PostCommitSequencer) Submit(ctx context.Context, command PostCommitCommand) (CommandCompletion, error) {
	if ctx == nil || command.Execute == nil || command.QueueBytes <= 0 || command.QueueBytes > MaxSequencerQueueBytes {
		return CommandCompletion{}, ErrInvalidSequencer
	}
	pending := &queuedCommand{
		ctx:        ctx,
		command:    command,
		completion: make(chan commandReply, 1),
	}
	if err := s.enqueue(pending); err != nil {
		return CommandCompletion{}, err
	}
	select {
	case reply := <-pending.completion:
		return reply.completion, reply.err
	case <-ctx.Done():
		return CommandCompletion{}, ctx.Err()
	}
}

// Close stops ordinary admission, drains commands already accepted, and waits
// for the worker until ctx expires. It is safe to call more than once.
func (s *PostCommitSequencer) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidSequencer
	}
	s.mu.Lock()
	if s.accepting {
		s.accepting = false
	}
	if !s.closed {
		s.closed = true
		close(s.commands)
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// QueueDepth returns the admitted commands waiting behind the current worker.
func (s *PostCommitSequencer) QueueDepth() int {
	return len(s.commands)
}

// QueuedBytes returns the admitted byte count waiting behind the current worker.
func (s *PostCommitSequencer) QueuedBytes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queuedBytes
}

// enqueue reserves both limits before making pending visible to the worker.
// Holding mu through the non-blocking channel send keeps byte accounting and
// item admission linearized even when concurrent handlers submit commands.
func (s *PostCommitSequencer) enqueue(pending *queuedCommand) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.accepting {
		if s.failure != nil {
			return s.failure
		}
		return ErrSequencerClosed
	}
	if s.queuedBytes+pending.command.QueueBytes > MaxSequencerQueueBytes {
		return ErrCommandQueueFull
	}
	select {
	case s.commands <- pending:
		s.queuedBytes += pending.command.QueueBytes
		return nil
	default:
		return ErrCommandQueueFull
	}
}

// run processes one command at a time. Dequeue releases admission capacity
// before user code runs so a blocked database command cannot monopolize the
// bounded waiting queue.
func (s *PostCommitSequencer) run() {
	defer close(s.done)
	for pending := range s.commands {
		s.mu.Lock()
		s.queuedBytes -= pending.command.QueueBytes
		s.mu.Unlock()
		if failure := s.failed(); failure != nil {
			pending.completion <- commandReply{err: failure}
			continue
		}
		completion, err := s.execute(pending)
		pending.completion <- commandReply{completion: completion, err: err}
	}
}

// execute assigns the command ID only when execution begins. It recovers every
// callback panic but escalates it through onFatal because it cannot prove that
// a database transaction had not committed when the panic occurred.
func (s *PostCommitSequencer) execute(pending *queuedCommand) (completion CommandCompletion, err error) {
	execution := &CommandExecution{publication: s.publication, completionCtx: context.WithoutCancel(pending.ctx)}
	defer func() {
		if recovered := recover(); recovered != nil {
			execution.abort()
			err = fmt.Errorf("%w: %v", ErrCommandPanic, recovered)
			completion = CommandCompletion{}
			s.fail(err)
		}
	}()
	if err := pending.ctx.Err(); err != nil {
		return CommandCompletion{}, err
	}
	commandID, err := s.idGen.Next()
	if err != nil {
		return CommandCompletion{}, err
	}
	execution.commandID = commandID
	output, err := pending.command.Execute(pending.ctx, commandID, execution)
	if err != nil {
		if _, committed := execution.committedReservation(); committed {
			err = fmt.Errorf("%w: %v", ErrSequencerFailed, err)
			s.fail(err)
			return CommandCompletion{}, err
		}
		execution.abort()
		return CommandCompletion{}, err
	}
	reservation, committed := execution.committedReservation()
	if !committed || reservation == nil {
		execution.abort()
		return CommandCompletion{}, ErrCommandNotCommitted
	}
	publication, err := reservation.Publish()
	if err != nil {
		err = fmt.Errorf("%w: %v", ErrSequencerFailed, err)
		s.fail(err)
		return CommandCompletion{}, err
	}
	return CommandCompletion{CommandID: commandID, Publication: publication, Value: output.Value}, nil
}

// failed returns the process-fatal sequencer failure, if one has occurred.
func (s *PostCommitSequencer) failed() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

// fail atomically stops ordinary admission, wakes queued callers with the same
// fatal error, and notifies the process supervisor outside s.mu.
func (s *PostCommitSequencer) fail(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.failure != nil {
		s.mu.Unlock()
		return
	}
	s.failure = err
	s.accepting = false
	if !s.closed {
		s.closed = true
		close(s.commands)
	}
	s.mu.Unlock()
	s.onFatal(err)
}
