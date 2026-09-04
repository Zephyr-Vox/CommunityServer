package realtime

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"zephyr.vox/server/ce/internal/snowflake"
)

const (
	// MaxSequencerQueueItems is the fixed ordinary-command admission limit.
	MaxSequencerQueueItems = 1024
	// MaxSequencerQueueBytes is the fixed ordinary-command admission byte limit.
	MaxSequencerQueueBytes = 4 << 20
	// MaxControlTeardownQueueItems reserves lifecycle cleanup capacity that
	// ordinary client commands can never consume.
	MaxControlTeardownQueueItems = 1024
	MaxControlPlansPerItem       = 64
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
	// Commit or MarkRuntimeReady for its reserved publication.
	ErrCommandNotCommitted = errors.New("realtime: command did not commit")
)

// PostCommitCommand is one state-changing operation accepted by the single
// writer. QueueBytes is its validated admission size. Execute receives the
// request context for rollbackable work and a CommandExecution for reserving
// final publication data before committing a persistent transaction or marking
// a runtime-only candidate ready for its cancellable publication point.
type PostCommitCommand struct {
	QueueBytes int
	// CommandID supplies an already-durable command ID for the rare mutation
	// whose response result was persisted before its state publication. Zero
	// allocates the next process ID at dequeue as usual.
	CommandID int64
	// Acquire obtains command-scoped barriers at dequeue time and returns their
	// release function. The sequencer retains them through StatePublication so
	// auth and principal mutations cannot interleave after revalidation.
	Acquire func(context.Context) (release func(), err error)
	Execute func(context.Context, int64, *CommandExecution) (CommandOutput, error)
}

// CommandOutput is command-owned result data for the HTTP or WS adapter. Its
// optional post-publication callback runs before command admission barriers are
// released.
type CommandOutput struct {
	Value any
	// BeforePublish runs after a persistent transaction has committed and before
	// its reserved StatePublication becomes visible. It is for in-process
	// authority teardown that must be linearized with the candidate state.
	BeforePublish func(context.Context) error
	// AfterPublish runs after the publication commit and before Acquire's
	// release function runs. It is for in-process side effects that must share
	// the command's linearization barrier, such as closing revoked sockets.
	AfterPublish func(context.Context) error
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

	mu           sync.Mutex
	reservation  *PublicationReservation
	committing   bool
	persistent   bool
	runtimeReady bool
	noop         bool
	published    bool
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
	if e.reservation != nil || e.persistent || e.runtimeReady || e.published {
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

// ReservedResult returns the final unpublished publication result after Reserve
// succeeds. Persistent HTTP commands use its checkpoint and version to save a
// durable response before committing their transaction.
func (e *CommandExecution) ReservedResult() (PublicationResult, error) {
	if e == nil {
		return PublicationResult{}, ErrInvalidSequencer
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reservation == nil || e.committing || e.persistent || e.runtimeReady || e.published {
		return PublicationResult{}, ErrCommandNotCommitted
	}
	return e.reservation.Result(), nil
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
	if e.reservation == nil || e.committing || e.persistent || e.runtimeReady || e.published {
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
	e.persistent = true
	return e.completionCtx, nil
}

// CommitNoop commits a transaction that contains only a durable HTTP replay
// result for a successfully revalidated no-op. It retains the sequencer's
// no-publication semantics while making that completed response durable.
func (e *CommandExecution) CommitNoop(tx *sql.Tx) error {
	if e == nil || tx == nil {
		return ErrInvalidSequencer
	}
	e.mu.Lock()
	if e.reservation != nil || e.committing || e.persistent || e.runtimeReady || e.noop || e.published {
		e.mu.Unlock()
		return ErrCommandNotCommitted
	}
	e.committing = true
	e.mu.Unlock()
	if err := tx.Commit(); err != nil {
		e.mu.Lock()
		e.committing = false
		e.mu.Unlock()
		return err
	}
	e.mu.Lock()
	e.committing = false
	e.noop = true
	e.mu.Unlock()
	return nil
}

// MarkRuntimeReady marks a runtime-only command as fully prepared. It does not
// commit the command: PublicationReservation.PublishRuntime remains the runtime
// command's sole commit point, and cancellation before it mutates the ring
// aborts the reservation.
func (e *CommandExecution) MarkRuntimeReady() error {
	if e == nil {
		return ErrInvalidSequencer
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reservation == nil || e.committing || e.persistent || e.runtimeReady || e.published {
		return ErrCommandNotCommitted
	}
	e.runtimeReady = true
	return nil
}

// MarkNoop completes a successfully revalidated command that made no durable
// or runtime state change. It allocates a command ID but does not advance the
// StateStore version, ring, checkpoint, or visibility epoch.
func (e *CommandExecution) MarkNoop() error {
	if e == nil {
		return ErrInvalidSequencer
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.reservation != nil || e.committing || e.persistent || e.runtimeReady || e.noop || e.published {
		return ErrCommandNotCommitted
	}
	e.noop = true
	return nil
}

// CompletionContext returns the internal context allowed after a persistent
// Commit. It has the request's values but ignores request cancellation and
// deadlines; runtime commands remain cancellable until Publish succeeds.
func (e *CommandExecution) CompletionContext() (context.Context, error) {
	if e == nil {
		return nil, ErrInvalidSequencer
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.persistent {
		return nil, ErrCommandNotCommitted
	}
	return e.completionCtx, nil
}

// publicationState returns the reservation and terminal execution state.
func (e *CommandExecution) publicationState() (*PublicationReservation, bool, bool, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reservation, e.persistent, e.runtimeReady, e.noop
}

// abort releases an unpublished reservation after an ordinary pre-commit or
// runtime-ready error. A persistent reservation that has already published is
// left alone; a fatal error between database commit and publication may release
// only the publication lock because the process is already in fail-fast recovery.
func (e *CommandExecution) abort() {
	if e == nil {
		return
	}
	e.mu.Lock()
	reservation := e.reservation
	committed := e.committing || (e.persistent && e.published)
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
	controls chan *controlBatch
	done     chan struct{}
	progress chan struct{}

	mu           sync.Mutex
	accepting    bool
	closed       bool
	failure      error
	queuedBytes  int
	controlBytes int
}

// queuedCommand holds one admitted command and its one buffered completion.
type queuedCommand struct {
	ctx        context.Context
	command    PostCommitCommand
	completion chan commandReply
}

type controlBatch struct {
	commands []*queuedCommand
	bytes    int
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
		controls:    make(chan *controlBatch, MaxControlTeardownQueueItems),
		done:        make(chan struct{}),
		progress:    make(chan struct{}, 1),
		accepting:   true,
	}
	go sequencer.run()
	return sequencer, nil
}

// SubmitControl admits a lifecycle teardown command to the dedicated reserve.
// It has the same completion semantics as Submit but ordinary client work cannot
// consume its item or byte capacity.
func (s *PostCommitSequencer) SubmitControl(ctx context.Context, command PostCommitCommand) (CommandCompletion, error) {
	completions, err := s.SubmitControlBatch(ctx, []PostCommitCommand{command})
	if err != nil {
		return CommandCompletion{}, err
	}
	return completions[0], nil
}

// SubmitControlBatch admits up to MaxControlPlansPerItem lifecycle commands as
// one reserved control item. The commands still publish independently and
// therefore retain their own command IDs, candidates and completion results,
// while teardown admission remains bounded at the item level.
func (s *PostCommitSequencer) SubmitControlBatch(ctx context.Context, commands []PostCommitCommand) ([]CommandCompletion, error) {
	if ctx == nil || len(commands) == 0 || len(commands) > MaxControlPlansPerItem {
		return nil, ErrInvalidSequencer
	}
	pending := make([]*queuedCommand, len(commands))
	totalBytes := 0
	for index, command := range commands {
		if command.Execute == nil || command.QueueBytes <= 0 || command.QueueBytes > MaxSequencerQueueBytes || command.CommandID < 0 {
			return nil, ErrInvalidSequencer
		}
		pending[index] = &queuedCommand{ctx: ctx, command: command, completion: make(chan commandReply, 1)}
		totalBytes += command.QueueBytes
	}
	if err := s.enqueueControl(&controlBatch{commands: pending, bytes: totalBytes}); err != nil {
		return nil, err
	}
	completions := make([]CommandCompletion, len(pending))
	for index, command := range pending {
		reply := <-command.completion
		if reply.err != nil {
			return nil, reply.err
		}
		completions[index] = reply.completion
	}
	return completions, nil
}

// Submit admits command when both ordinary queue limits permit and waits for
// its ordered completion. Once admitted, only the worker decides whether
// cancellation happened before its commit point; callers always receive the
// terminal completion needed to reconcile a durable or runtime publication.
func (s *PostCommitSequencer) Submit(ctx context.Context, command PostCommitCommand) (CommandCompletion, error) {
	if ctx == nil || command.Execute == nil || command.QueueBytes <= 0 || command.QueueBytes > MaxSequencerQueueBytes || command.CommandID < 0 {
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
	reply := <-pending.completion
	return reply.completion, reply.err
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
		close(s.controls)
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Fail escalates an unrecoverable lifecycle-control failure through the same
// supervisor callback used for post-commit publication failures.
func (s *PostCommitSequencer) Fail(err error) { s.fail(err) }

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

// Done closes after the sequencer worker has drained or failed. Process
// supervision uses it to keep database teardown behind every command that can
// still access the persistent projection.
func (s *PostCommitSequencer) Done() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.done
}

// Failure returns the terminal sequencer failure, if any. A nil result after
// Done is only a normal shutdown when the owning supervisor is already
// stopping; an unexpected clean exit is handled by the supervisor wrapper.
func (s *PostCommitSequencer) Failure() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

// Progress emits coalesced idle/command-completion heartbeats. A silent
// channel while the worker is alive means execution has stalled inside a
// command or publication phase.
func (s *PostCommitSequencer) Progress() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.progress
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

// enqueueControl reserves the dedicated lifecycle queue before making work
// visible. Control bytes share the same fixed cap but never consume ordinary
// command capacity.
func (s *PostCommitSequencer) enqueueControl(batch *controlBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.accepting {
		if s.failure != nil {
			return s.failure
		}
		return ErrSequencerClosed
	}
	if s.controlBytes+batch.bytes > MaxSequencerQueueBytes {
		return ErrCommandQueueFull
	}
	select {
	case s.controls <- batch:
		s.controlBytes += batch.bytes
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
	defer close(s.progress)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	commands := s.commands
	controls := s.controls
	for commands != nil || controls != nil {
		var pending *queuedCommand
		var fromControl bool
		var batch *controlBatch
		select {
		case <-ticker.C:
			s.signalProgress()
			continue
		case batch = <-controls:
			fromControl = true
			if batch == nil {
				controls = nil
				continue
			}
		case pending = <-commands:
			if pending == nil {
				commands = nil
				continue
			}
		default:
			select {
			case <-ticker.C:
				s.signalProgress()
				continue
			case batch = <-controls:
				fromControl = true
				if batch == nil {
					controls = nil
					continue
				}
			case pending = <-commands:
				if pending == nil {
					commands = nil
					continue
				}
			}
		}
		if fromControl {
			s.mu.Lock()
			s.controlBytes -= batch.bytes
			s.mu.Unlock()
			for _, control := range batch.commands {
				s.executeAndReply(control)
			}
			continue
		}
		s.mu.Lock()
		if !fromControl {
			s.queuedBytes -= pending.command.QueueBytes
		}
		s.mu.Unlock()
		s.executeAndReply(pending)
	}
}

// executeAndReply runs one admitted command and never blocks the worker on an
// unbuffered caller response.
func (s *PostCommitSequencer) executeAndReply(pending *queuedCommand) {
	if failure := s.failed(); failure != nil {
		pending.completion <- commandReply{err: failure}
		return
	}
	completion, err := s.execute(pending)
	pending.completion <- commandReply{completion: completion, err: err}
	s.signalProgress()
}

func (s *PostCommitSequencer) signalProgress() {
	select {
	case s.progress <- struct{}{}:
	default:
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
	if pending.command.Acquire != nil {
		release, err := pending.command.Acquire(pending.ctx)
		if err != nil {
			return CommandCompletion{}, err
		}
		if release == nil {
			return CommandCompletion{}, ErrInvalidSequencer
		}
		defer release()
	}
	commandID := pending.command.CommandID
	if commandID == 0 {
		var err error
		commandID, err = s.idGen.Next()
		if err != nil {
			return CommandCompletion{}, err
		}
	}
	execution.commandID = commandID
	output, err := pending.command.Execute(pending.ctx, commandID, execution)
	if err != nil {
		if _, persistent, runtimeReady, _ := execution.publicationState(); persistent || runtimeReady {
			if runtimeReady && !persistent {
				execution.abort()
				return CommandCompletion{}, err
			}
			err = fmt.Errorf("%w: %v", ErrSequencerFailed, err)
			s.fail(err)
			return CommandCompletion{}, err
		}
		execution.abort()
		return CommandCompletion{}, err
	}
	reservation, persistent, runtimeReady, noop := execution.publicationState()
	if noop {
		if reservation != nil || persistent || runtimeReady {
			execution.abort()
			return CommandCompletion{}, ErrCommandNotCommitted
		}
		return CommandCompletion{CommandID: commandID, Value: output.Value}, nil
	}
	if (!persistent && !runtimeReady) || reservation == nil {
		execution.abort()
		return CommandCompletion{}, ErrCommandNotCommitted
	}
	if runtimeReady && !persistent {
		if err := pending.ctx.Err(); err != nil {
			execution.abort()
			return CommandCompletion{}, err
		}
	}
	if output.BeforePublish != nil {
		if !persistent {
			execution.abort()
			return CommandCompletion{}, ErrCommandNotCommitted
		}
		if err := output.BeforePublish(execution.completionCtx); err != nil {
			execution.abort()
			err = fmt.Errorf("%w: %v", ErrSequencerFailed, err)
			s.fail(err)
			return CommandCompletion{}, err
		}
	}
	var publication PublicationResult
	if runtimeReady && !persistent {
		publication, err = reservation.PublishRuntime(pending.ctx)
	} else {
		publication, err = reservation.Publish()
	}
	if err != nil {
		if runtimeReady && !persistent && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return CommandCompletion{}, err
		}
		err = fmt.Errorf("%w: %v", ErrSequencerFailed, err)
		s.fail(err)
		return CommandCompletion{}, err
	}
	execution.mu.Lock()
	execution.published = true
	execution.mu.Unlock()
	if output.AfterPublish != nil {
		if err := output.AfterPublish(execution.completionCtx); err != nil {
			err = fmt.Errorf("%w: %v", ErrSequencerFailed, err)
			s.fail(err)
			return CommandCompletion{}, err
		}
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
		close(s.controls)
	}
	s.mu.Unlock()
	s.onFatal(err)
}
