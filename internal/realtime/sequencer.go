package realtime

import (
	"context"
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
	// ErrCommandPanic reports a recovered command callback panic while keeping
	// the single publication worker alive for later commands.
	ErrCommandPanic = errors.New("realtime: command callback panic")
)

// PostCommitCommand is one state-changing operation accepted by the single
// writer. QueueBytes is its validated admission size; Execute must perform any
// persistent transaction before returning the unpublished candidate it built.
type PostCommitCommand struct {
	QueueBytes int
	Execute    func(context.Context, int64) (CommandOutput, error)
}

// CommandOutput is the unpublished work produced by one serialized command.
// Value is command-owned result data for the HTTP or WS adapter and is never
// interpreted by the sequencer.
type CommandOutput struct {
	Publication PublicationRequest
	Value       any
}

// CommandCompletion is delivered only after StatePublication has committed the
// command's candidate and events. CommandID is a positive snowflake ID and is
// stable data for later idempotency replay.
type CommandCompletion struct {
	CommandID   int64
	Publication PublicationResult
	Value       any
}

// PostCommitSequencer serializes all state-changing commands between their
// persistent commit and StatePublication commit. It owns one worker goroutine;
// Close drains admitted commands and waits for that worker to exit.
type PostCommitSequencer struct {
	publication *StatePublication
	idGen       *snowflake.IDGenerator

	commands chan *queuedCommand
	done     chan struct{}

	mu          sync.Mutex
	accepting   bool
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
// fixed queue limits and starts its worker immediately.
func NewPostCommitSequencer(publication *StatePublication, idGen *snowflake.IDGenerator) (*PostCommitSequencer, error) {
	if publication == nil || idGen == nil {
		return nil, ErrInvalidSequencer
	}
	sequencer := &PostCommitSequencer{
		publication: publication,
		idGen:       idGen,
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
		completion, err := s.execute(pending)
		pending.completion <- commandReply{completion: completion, err: err}
	}
}

// execute assigns the command ID only when execution begins, then ensures the
// publication gets that causation ID before completing the adapter result.
func (s *PostCommitSequencer) execute(pending *queuedCommand) (completion CommandCompletion, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: %v", ErrCommandPanic, recovered)
			completion = CommandCompletion{}
		}
	}()
	if err := pending.ctx.Err(); err != nil {
		return CommandCompletion{}, err
	}
	commandID, err := s.idGen.Next()
	if err != nil {
		return CommandCompletion{}, err
	}
	output, err := pending.command.Execute(pending.ctx, commandID)
	if err != nil {
		return CommandCompletion{}, err
	}
	for i := range output.Publication.Events {
		output.Publication.Events[i].CausationID = commandID
	}
	publication, err := s.publication.Commit(output.Publication)
	if err != nil {
		return CommandCompletion{}, err
	}
	return CommandCompletion{CommandID: commandID, Publication: publication, Value: output.Value}, nil
}
