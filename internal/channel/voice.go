package channel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"

	"zephyr.vox/server/ce/internal/api"
	"zephyr.vox/server/ce/internal/commandhttp"
	"zephyr.vox/server/ce/internal/protocol"
	"zephyr.vox/server/ce/internal/rbac"
	rbacecho "zephyr.vox/server/ce/internal/rbac/echo"
	"zephyr.vox/server/ce/internal/realtime"
	"zephyr.vox/server/ce/internal/store"
)

var (
	// ErrVoiceNotConnected is returned when the supplied control connection is
	// not an active, unexpired WS owned by the authenticated principal.
	ErrVoiceNotConnected = errors.New("channel: voice control connection not active")
	// ErrVoiceNotChannel is returned when a visible target is not a voice
	// channel.
	ErrVoiceNotChannel = errors.New("channel: target channel is not voice")
	// ErrVoiceFull is returned when projected target occupancy reaches capacity.
	ErrVoiceFull = errors.New("channel: voice channel is full")
	// ErrVoiceExpectedRequired is returned when an operation would replace or
	// move an existing voice authority without its exact expected session ID.
	ErrVoiceExpectedRequired = errors.New("channel: expected voice session is required")
	// ErrVoiceStale is returned when the expected session no longer matches the
	// current authority or the current session disappeared during validation.
	ErrVoiceStale = errors.New("channel: stale voice session")
	// ErrVoiceNotOwner is returned when another active control connection owns
	// the user's current voice authority.
	ErrVoiceNotOwner = errors.New("channel: control connection is not voice owner")
	// ErrVoiceCreateRateLimit is returned only when a new UDP session would be
	// allocated and the user/IP create budget is exhausted.
	ErrVoiceCreateRateLimit = errors.New("channel: voice session create rate limited")
)

const (
	voiceCreateWindow = time.Minute
	voiceCreateLimit  = 10
	voiceCreateKeyCap = 8192
)

// voiceCreateLimiter applies the v1 new-session budget independently for each
// user and source IP. It records only timestamps and never stores secrets.
type voiceCreateLimiter struct {
	mu      sync.Mutex
	entries map[voiceCreateKey][]time.Time
}

type voiceCreateKey struct {
	userID int64
	ip     string
}

// newVoiceCreateLimiter creates an empty fixed-window voice session limiter.
func newVoiceCreateLimiter() *voiceCreateLimiter {
	return &voiceCreateLimiter{entries: make(map[voiceCreateKey][]time.Time)}
}

// Allow consumes one new-session slot when the rolling one-minute window has
// fewer than ten prior allocations for the same user and source IP.
func (l *voiceCreateLimiter) Allow(userID int64, sourceIP string, now time.Time) bool {
	if l == nil || userID <= 0 || now.IsZero() {
		return false
	}
	key := voiceCreateKey{userID: userID, ip: sourceIP}
	cutoff := now.Add(-voiceCreateWindow)
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := l.entries[key]
	first := 0
	for first < len(entries) && !entries[first].After(cutoff) {
		first++
	}
	entries = entries[first:]
	if len(entries) == 0 {
		delete(l.entries, key)
	}
	if len(entries) == 0 && len(l.entries) >= voiceCreateKeyCap {
		l.pruneExpiredLocked(cutoff)
		if len(l.entries) >= voiceCreateKeyCap {
			return false
		}
	}
	if len(entries) >= voiceCreateLimit {
		l.entries[key] = entries
		return false
	}
	l.entries[key] = append(entries, now)
	return true
}

// pruneExpiredLocked removes keys whose entire create window has elapsed.
// Callers must hold l.mu; the sweep runs only when the bounded table is full.
func (l *voiceCreateLimiter) pruneExpiredLocked(cutoff time.Time) {
	for key, entries := range l.entries {
		if len(entries) == 0 || !entries[len(entries)-1].After(cutoff) {
			delete(l.entries, key)
		}
	}
}

// voiceJoinPlan is the sequencer-owned output before publication supplies the
// final state checkpoint. Version is retained only for the no-op branch.
type voiceJoinPlan struct {
	channel       realtime.SnapshotChannel
	channelID     int64
	info          protocol.SessionInfo
	created       bool
	version       *realtime.StateVersion
	schedules     []voiceTemporarySchedule
	cancellations []temporaryExpiryCancellation
}

type voiceTemporarySchedule struct {
	channelID int64
	schedule  realtime.ExpirySchedule
}

// voiceJoinResult is the HTTP result after StatePublication has committed.
// Replay is non-nil only for a completed in-memory idempotency replay.
type voiceJoinResult struct {
	response voiceJoinResponse
	state    StateCommand
	body     json.RawMessage
	replay   *realtime.RuntimeCommandResult
}

// voiceJoinPreparedResult carries the response bytes and state cursor that
// were derived from the reserved, still-unpublished version. Keeping these
// facts in the command output makes post-publication replay completion
// bookkeeping non-fallible.
type voiceJoinPreparedResult struct {
	plan   voiceJoinPlan
	result voiceJoinResult
}

// voiceLeavePlan retains the exact empty-channel timer selected by the
// sequenced leave command. The timer is armed only after publication.
type voiceLeavePlan struct {
	version   *realtime.StateVersion
	channelID int64
	schedule  *realtime.ExpirySchedule
}

// voiceLeaveResult is the cached 204 command result. Replay remains sensitive
// to the original checkpoint even though the response has no body.
type voiceLeaveResult struct {
	state  StateCommand
	replay *realtime.RuntimeCommandResult
}

// voiceLeavePreparedResult carries the exact checkpoint for a published
// runtime-only leave before the command crosses its publication boundary.
type voiceLeavePreparedResult struct {
	plan   voiceLeavePlan
	result voiceLeaveResult
}

// VoiceAuthorityProjection returns the channel-specific part of a coordinator
// teardown. The generic realtime publisher performs the authority clear; this
// hook adds the visible member tombstone and arms the temporary-channel grace
// timer after the same publication becomes visible.
func (s *Service) VoiceAuthorityProjection() realtime.VoiceAuthorityProjection {
	return func(candidate *realtime.StateCandidate, previous, current *realtime.VoiceAuthority, _ string) ([]realtime.StateEventTemplate, func(), error) {
		if s == nil || candidate == nil || previous == nil || current != nil {
			return nil, nil, nil
		}
		channel, exists := candidate.Version().Channel(previous.ChannelID)
		if !exists {
			return nil, nil, nil
		}
		before := candidate.Base()
		left, err := voiceMemberEvent(*previous, false, before, s.visibility)
		if err != nil {
			return nil, nil, err
		}
		oldSchedule, shouldCancel := candidate.ClearTemporaryExpiry(previous.ChannelID)
		var schedule *realtime.ExpirySchedule
		if channel.Temporary && activeChannelMembers(previous.ChannelID, candidate.Version()) == 0 {
			value, scheduleErr := candidate.ScheduleTemporaryExpiry(previous.ChannelID, s.voiceNowMillis()+30_000)
			if scheduleErr != nil {
				return nil, nil, scheduleErr
			}
			schedule = &value
		}
		if schedule == nil && !shouldCancel {
			return []realtime.StateEventTemplate{left}, nil, nil
		}
		return []realtime.StateEventTemplate{left}, func() {
			if shouldCancel {
				s.cancelTemporaryExpiry(temporaryExpiryCancellation{channelID: previous.ChannelID, generation: oldSchedule.Generation})
			}
			s.scheduleTemporary(previous.ChannelID, schedule)
		}, nil
	}
}

// PrepareVoiceAccessLoss removes every authority that is no longer visible in
// the candidate projection and returns one publication-time Manager/coordinator
// revoke. It is used by channel and RBAC mutations, so ACL, role, visibility,
// parent, and delete changes share identical access-loss cleanup.
func (s *Service) PrepareVoiceAccessLoss(candidate *realtime.StateCandidate) ([]realtime.StateEventTemplate, func() (func(), error), error) {
	if s == nil || candidate == nil || s.voiceManager == nil || s.connections == nil || s.visibility == nil {
		return nil, nil, nil
	}
	before := candidate.Base()
	after := candidate.Version()
	if before == nil || after == nil {
		return nil, nil, realtime.ErrInvalidProjection
	}
	type revokePlan struct {
		authority realtime.VoiceAuthority
		reason    string
	}
	plans := make([]revokePlan, 0)
	events := make([]realtime.StateEventTemplate, 0)
	schedules := make(map[int64]realtime.ExpirySchedule)
	cancellations := make(map[int64]uint64)
	clearedTemporary := make(map[int64]struct{})
	for _, authority := range before.VoiceAuthorities() {
		channel, exists := after.Channel(authority.ChannelID)
		lost := !exists || !s.visibility.CanAccessChannel(authority.UserID, authority.ChannelID, after)
		if !lost {
			continue
		}
		oldSchedule, hadSchedule := before.TemporaryExpiry(authority.ChannelID)
		if hadSchedule && oldSchedule.Generation > 0 && oldSchedule.Deadline > 0 {
			if previous, exists := cancellations[authority.ChannelID]; !exists || previous < oldSchedule.Generation {
				cancellations[authority.ChannelID] = oldSchedule.Generation
			}
		}
		if err := candidate.SetVoiceAuthority(authority.UserID, nil); err != nil {
			return nil, nil, err
		}
		reason := "channel_access_lost"
		if !exists {
			reason = "channel_deleted"
		} else {
			if channel.Temporary || hadSchedule {
				if _, cleared := clearedTemporary[channel.ID]; !cleared {
					candidate.ClearTemporaryExpiry(channel.ID)
					clearedTemporary[channel.ID] = struct{}{}
				}
			}
			if channel.Temporary {
				if activeChannelMembers(channel.ID, after) == 0 {
					schedule, scheduleErr := candidate.ScheduleTemporaryExpiry(channel.ID, s.voiceNowMillis()+30_000)
					if scheduleErr != nil {
						return nil, nil, scheduleErr
					}
					schedules[channel.ID] = schedule
				}
			}
		}
		authorityEvents, err := realtime.VoiceAuthorityEventTemplates(&authority, nil, reason)
		if err != nil {
			return nil, nil, err
		}
		events = append(events, authorityEvents...)
		if exists {
			left, err := voiceMemberEvent(authority, false, before, s.visibility)
			if err != nil {
				return nil, nil, err
			}
			events = append(events, left)
		}
		plans = append(plans, revokePlan{authority: authority, reason: reason})
	}
	if len(plans) == 0 {
		return nil, nil, nil
	}
	return events, func() (func(), error) {
		drains := make([]protocol.SessionSendDrain, 0, len(plans))
		cleanups := make([]protocol.RevocationCleanup, 0, len(plans))
		for _, plan := range plans {
			_, removed, drain, cleanup, err := s.connections.BeginVoiceRevokeForPublicationWithGate(plan.authority, s.voiceManager, plan.reason)
			if err != nil {
				for _, pending := range drains {
					pending()
				}
				return nil, err
			}
			if removed && drain != nil {
				drains = append(drains, drain)
			}
			if removed && cleanup != nil {
				cleanups = append(cleanups, cleanup)
			}
		}
		for _, drain := range drains {
			drain()
		}
		return func() {
			for channelID, generation := range cancellations {
				s.cancelTemporaryExpiry(temporaryExpiryCancellation{channelID: channelID, generation: generation})
			}
			for channelID, schedule := range schedules {
				s.scheduleTemporary(channelID, &schedule)
			}
			for _, cleanup := range cleanups {
				cleanup()
			}
		}, nil
	}, nil
}

// JoinVoice submits one authenticated channel join through the ordinary
// sequencer. It binds the request to an active WS generation, prepares any
// sensitive UDP session before publication, and caches the exact response for
// two-minute retries without persisting the session key.
func (s *Service) JoinVoice(ctx context.Context, actorID, channelID int64, controlConnectionID [16]byte, idempotencyKey string, input VoiceJoinInput, sourceIP string) (voiceJoinResult, error) {
	if ctx == nil || s == nil || s.stores == nil || s.principals == nil || s.gate == nil || s.state == nil || s.sequencer == nil || s.connections == nil || s.voiceManager == nil || s.voiceIdempotency == nil || s.requestSigner == nil || s.cursors == nil || actorID <= 0 || channelID <= 0 || controlConnectionID == [16]byte{} {
		return voiceJoinResult{}, ErrRealtimeUnavailable
	}
	if !realtime.IdempotencyKeyValid(idempotencyKey) || !validVoiceDeviceID(input.DeviceID) {
		return voiceJoinResult{}, realtime.ErrInvalidRequestIdentity
	}
	expectedID, err := parseVoiceSessionID(input.ExpectedVoiceSessionID)
	if err != nil {
		return voiceJoinResult{}, err
	}
	identity, err := realtime.NewHTTPCommandIdentity(actorID, http.MethodPost, "/api/v0/channels/:id/join", []realtime.CanonicalField{{Name: "id", Value: fmt.Sprint(channelID)}}, nil, input)
	if err != nil {
		return voiceJoinResult{}, err
	}
	identity.ControlConnectionID = fmt.Sprintf("%x", controlConnectionID)
	requestHMAC, err := s.requestSigner.Sum(identity)
	if err != nil {
		return voiceJoinResult{}, err
	}
	claim, err := s.voiceIdempotency.Claim(actorID, idempotencyKey, requestHMAC)
	if err != nil {
		return voiceJoinResult{}, err
	}
	if !claim.Owner() {
		cached, waitErr := claim.Wait(ctx)
		if waitErr != nil {
			return voiceJoinResult{}, waitErr
		}
		result, ok := cached.Value.(voiceJoinResult)
		if !ok {
			return voiceJoinResult{}, realtime.ErrInvalidCommandResult
		}
		result.replay = &cached
		return result, nil
	}
	completed := false
	defer func() {
		if !completed {
			_ = claim.Abort()
		}
	}()

	completion, err := s.sequencer.Submit(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Acquire: func(commandCtx context.Context) (func(), error) {
			unlock := s.principals.LockMutation(actorID)
			release, acquireErr := s.gate.Acquire(commandCtx)
			if acquireErr != nil {
				unlock()
				return nil, acquireErr
			}
			releaseRelay := s.connections.AcquireVoiceRelayGate(actorID)
			return func() {
				releaseRelay()
				release()
				unlock()
			}, nil
		},
		Execute: func(commandCtx context.Context, commandID int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			joinedAt := s.voiceNowMillis()
			version, err := s.currentVersion()
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			owner, ok := s.connections.ActiveConnection(actorID, controlConnectionID)
			if !ok || !s.connections.LeaseActive(owner, joinedAt) {
				return realtime.CommandOutput{}, ErrVoiceNotConnected
			}
			channel, exists := version.Channel(channelID)
			if !exists || !s.visibility.CanAccessChannel(actorID, channelID, version) {
				return realtime.CommandOutput{}, ErrTargetNotFound
			}
			if channel.Mode != "voice" {
				return realtime.CommandOutput{}, ErrVoiceNotChannel
			}

			current, hasCurrent := s.connections.VoiceAuthority(actorID)
			var previousProjected *realtime.VoiceAuthority
			if projected, projectedOK := version.VoiceAuthority(actorID); projectedOK {
				previousProjected = &projected
			}
			var pendingTeardown *realtime.VoiceAuthority
			pendingTeardownReason := "owner_ws_closed"
			if !hasCurrent && previousProjected != nil {
				if tombstone, reason, ok := s.connections.PendingVoiceAuthorityTombstone(actorID); ok && tombstone == *previousProjected {
					pending := tombstone
					pendingTeardown = &pending
					if reason == "" {
						reason = "owner_ws_closed"
					}
					pendingTeardownReason = reason
				}
			}
			if expectedID != ([16]byte{}) {
				matchesCurrent := hasCurrent && current.VoiceSessionID == expectedID
				matchesPendingTeardown := !hasCurrent && pendingTeardown != nil && pendingTeardown.VoiceSessionID == expectedID
				if !matchesCurrent && !matchesPendingTeardown {
					return realtime.CommandOutput{}, ErrVoiceStale
				}
			} else if hasCurrent && (current.ChannelID != channelID || input.ForceNew || current.ControlConnectionID != owner.ControlConnectionID || current.ConnectionGeneration != owner.Generation) {
				return realtime.CommandOutput{}, ErrVoiceExpectedRequired
			} else if pendingTeardown != nil {
				// The coordinator has already cleared the owner, but the matching
				// StateStore authority is still visible until its observer publishes.
				// Treat that tombstone as an existing binding so a rejoin cannot
				// silently overwrite the old authority and skip its clear events.
				return realtime.CommandOutput{}, ErrVoiceExpectedRequired
			}

			if hasCurrent && current.ChannelID == channelID && current.ControlConnectionID == owner.ControlConnectionID && current.ConnectionGeneration == owner.Generation && !input.ForceNew {
				snapshot, snapshotOK := s.voiceManager.Get(current.VoiceSessionID)
				if !snapshotOK || snapshot.UserID != actorID {
					return realtime.CommandOutput{}, ErrVoiceStale
				}
				if err := execution.MarkNoop(); err != nil {
					return realtime.CommandOutput{}, err
				}
				return realtime.CommandOutput{Value: voiceJoinPlan{
					channel:   snapshotChannel(channel),
					channelID: channel.ID,
					info: protocol.SessionInfo{
						ID:        snapshot.ID,
						UserID:    snapshot.UserID,
						Encrypted: snapshot.Encrypted,
						ExpiresAt: snapshot.ExpiresAt,
					},
					version: version,
				}}, nil
			}

			if activeChannelMembers(channelID, version) >= channel.Capacity && (previousProjected == nil || previousProjected.ChannelID != channelID) {
				return realtime.CommandOutput{}, ErrVoiceFull
			}

			var prepared *protocol.PreparedSession
			created := false
			var reusedInfo protocol.SessionInfo
			var naturalExpiryDrain protocol.SessionSendDrain
			if !hasCurrent || input.ForceNew || current.ControlConnectionID != owner.ControlConnectionID || current.ConnectionGeneration != owner.Generation {
				if !s.voiceCreateLimiter.Allow(actorID, sourceIP, time.UnixMilli(joinedAt)) {
					return realtime.CommandOutput{}, ErrVoiceCreateRateLimit
				}
				prepared, err = s.voiceManager.Prepare(actorID, input.DeviceID, s.voiceEncrypted)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				created = true
			}
			naturalExpiry := false
			if hasCurrent {
				snapshot, expiryDrain, snapshotOK := s.voiceManager.GetStaged(current.VoiceSessionID)
				if !snapshotOK || snapshot.UserID != actorID {
					if prepared == nil {
						// A reuse-move must never bind a channel to a Manager session
						// that has already expired or been removed. Replacements can
						// continue through the staged natural-expiry handoff below.
						return realtime.CommandOutput{}, ErrVoiceStale
					}
					naturalExpiry = true
					naturalExpiryDrain = expiryDrain
				} else {
					reusedInfo = protocol.SessionInfo{
						ID:        snapshot.ID,
						UserID:    snapshot.UserID,
						Encrypted: snapshot.Encrypted,
						ExpiresAt: snapshot.ExpiresAt,
					}
				}
			}

			var expected *realtime.VoiceAuthority
			if hasCurrent {
				expected = &current
			}
			stage, err := s.connections.StageVoiceReplacement(owner, expected, channelID, prepared, joinedAt)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			proposed, err := stage.ProposedAuthority()
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			candidate, err := s.state.BuildRuntimeCandidate()
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if err := candidate.SetVoiceAuthority(actorID, &proposed); err != nil {
				return realtime.CommandOutput{}, err
			}
			schedules := make([]voiceTemporarySchedule, 0, 1)
			cancellations := make([]temporaryExpiryCancellation, 0, 2)
			if channel.Temporary {
				if schedule, shouldCancel := candidate.ClearTemporaryExpiry(channel.ID); shouldCancel {
					cancellations = append(cancellations, temporaryExpiryCancellation{channelID: channel.ID, generation: schedule.Generation})
				}
			}
			if previousProjected != nil && previousProjected.ChannelID != proposed.ChannelID {
				if previousChannel, previousExists := version.Channel(previousProjected.ChannelID); previousExists && previousChannel.Temporary {
					if activeChannelMembers(previousChannel.ID, candidate.Version()) == 0 {
						schedule, scheduleErr := candidate.ScheduleTemporaryExpiry(previousChannel.ID, joinedAt+30_000)
						if scheduleErr != nil {
							return realtime.CommandOutput{}, scheduleErr
						}
						schedules = append(schedules, voiceTemporarySchedule{channelID: previousChannel.ID, schedule: schedule})
					} else {
						if oldSchedule, shouldCancel := candidate.ClearTemporaryExpiry(previousChannel.ID); shouldCancel {
							cancellations = append(cancellations, temporaryExpiryCancellation{channelID: previousChannel.ID, generation: oldSchedule.Generation})
						}
					}
				}
			}

			events := make([]realtime.StateEventTemplate, 0, 6)
			if pendingTeardown != nil {
				teardownEvents, teardownErr := realtime.VoiceAuthorityEventTemplates(pendingTeardown, nil, pendingTeardownReason)
				if teardownErr != nil {
					return realtime.CommandOutput{}, teardownErr
				}
				events = append(events, teardownEvents...)
				left, leftErr := voiceMemberEvent(*pendingTeardown, false, version, s.visibility)
				if leftErr != nil {
					return realtime.CommandOutput{}, leftErr
				}
				events = append(events, left)
			}
			memberLeft := pendingTeardown != nil
			if naturalExpiry && hasCurrent && !memberLeft {
				expiryEvents, expiryErr := realtime.VoiceAuthorityEventTemplates(expected, nil, "udp_timeout")
				if expiryErr != nil {
					return realtime.CommandOutput{}, expiryErr
				}
				events = append(events, expiryEvents...)
				left, leftErr := voiceMemberEvent(current, false, version, s.visibility)
				if leftErr != nil {
					return realtime.CommandOutput{}, leftErr
				}
				events = append(events, left)
				memberLeft = true
			}
			if previousProjected != nil && previousProjected.ChannelID != proposed.ChannelID && !memberLeft {
				left, err := voiceMemberEvent(*previousProjected, false, version, s.visibility)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				events = append(events, left)
				memberLeft = true
			}
			if previousProjected == nil || previousProjected.ChannelID != proposed.ChannelID || memberLeft {
				joined, err := voiceMemberEvent(proposed, true, version, s.visibility)
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				events = append(events, joined)
			}
			authorityReason := "joined"
			if hasCurrent {
				if current.VoiceSessionID != proposed.VoiceSessionID {
					authorityReason = "session_replaced"
				} else if current.ChannelID != proposed.ChannelID {
					authorityReason = "channel_moved"
				}
			}
			var authorityEvents []realtime.StateEventTemplate
			if naturalExpiry && hasCurrent {
				// Natural expiry is a terminal old-session transition followed by
				// a fresh join, so clients receive disconnected/clear before the
				// replacement authority rather than a misleading session_replaced.
				authorityEvents, err = realtime.VoiceAuthorityEventTemplates(nil, &proposed, "joined")
			} else {
				authorityEvents, err = realtime.VoiceAuthorityEventTemplates(expected, &proposed, authorityReason)
			}
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			events = append(events, authorityEvents...)
			info := protocol.SessionInfo{
				ID:        proposed.VoiceSessionID,
				UserID:    actorID,
				Encrypted: s.voiceEncrypted,
			}
			if prepared != nil {
				info = prepared.Info()
			} else if hasCurrent {
				// The session was already validated before the runtime commit. Do not
				// perform a second fallible Manager lookup here: natural expiry can
				// otherwise turn a successful coordinator move into an unpublished
				// runtime mutation after ApplyForPublication has completed.
				info = reusedInfo
			}
			plan := voiceJoinPlan{channel: snapshotChannel(channel), channelID: channel.ID, info: info, created: created, schedules: schedules, cancellations: cancellations}
			if _, err := execution.Reserve(realtime.PublicationRequest{
				Candidate: candidate,
				Events:    events,
				CommitRuntime: func() (func(), error) {
					if naturalExpiryDrain != nil {
						// Lazy expiry has already removed the old Manager index and
						// queued its control cleanup. Wait for old UDP sends here so
						// the replacement publication cannot overtake old audio.
						naturalExpiryDrain()
					}
					commit, commitErr := stage.ApplyForPublicationWithGate(s.voiceManager, naturalExpiry)
					if commitErr != nil {
						if errors.Is(commitErr, protocol.ErrSessionPrecondition) || errors.Is(commitErr, protocol.ErrSessionExpired) || errors.Is(commitErr, realtime.ErrVoiceAuthorityPrecondition) {
							// A runtime command has already reserved its publication. Mark
							// this exact-session race as a cancellable no-op so the
							// sequencer releases the reservation without declaring the
							// publication subsystem failed.
							return nil, fmt.Errorf("%w: %w", context.Canceled, ErrVoiceStale)
						}
						return nil, commitErr
					}
					if commit.Current != proposed {
						if commit.Drain != nil {
							commit.Drain()
						}
						if commit.Release != nil {
							commit.Release()
						}
						return nil, realtime.ErrVoiceAuthorityPrecondition
					}
					if commit.Drain != nil {
						commit.Drain()
					}
					cleanup := commit.Cleanup
					return func() {
						if commit.Release != nil {
							commit.Release()
						}
						if cleanup != nil {
							cleanup()
						}
					}, nil
				},
			}); err != nil {
				return realtime.CommandOutput{}, err
			}
			reserved, err := execution.ReservedResult()
			if err != nil || reserved.Version == nil {
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				return realtime.CommandOutput{}, ErrRealtimeUnavailable
			}
			state := StateCommand{CommandID: commandID, Checkpoint: reserved.Checkpoint}
			state.Cursor, err = s.cursors.IssueStateCursor(actorID, reserved.Version)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			response, err := s.voiceJoinResponse(actorID, plan, reserved.Version, state)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			body, err := realtime.CanonicalSuccessBody(response)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			body, err = realtime.CanonicalJSON(body)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			preparedResult := voiceJoinResult{response: response, state: state, body: body}
			if err := execution.MarkRuntimeReady(); err != nil {
				return realtime.CommandOutput{}, err
			}
			return realtime.CommandOutput{Value: voiceJoinPreparedResult{plan: plan, result: preparedResult}}, nil
		},
	})
	if err != nil {
		return voiceJoinResult{}, err
	}
	var plan voiceJoinPlan
	var result voiceJoinResult
	var prepared bool
	switch value := completion.Value.(type) {
	case voiceJoinPlan:
		plan = value
	case voiceJoinPreparedResult:
		plan = value.plan
		result = value.result
		prepared = true
	default:
		return voiceJoinResult{}, ErrRealtimeUnavailable
	}
	s.cancelTemporaryExpiries(plan.cancellations)
	for _, schedule := range plan.schedules {
		s.scheduleTemporary(schedule.channelID, &schedule.schedule)
	}
	if prepared {
		if err := claim.Complete(realtime.RuntimeCommandResult{
			CommandID:   result.state.CommandID,
			Status:      http.StatusOK,
			Body:        result.body,
			Headers:     store.IdempotencyHeaders{CacheControl: "no-store", Pragma: "no-cache"},
			Checkpoint:  result.state.Checkpoint,
			StateCursor: result.state.Cursor,
			Value:       result,
		}); err != nil {
			return voiceJoinResult{}, err
		}
		completed = true
		return result, nil
	}
	version := completion.Publication.Version
	state := StateCommand{CommandID: completion.CommandID}
	if version == nil {
		version = plan.version
	}
	if version == nil {
		return voiceJoinResult{}, ErrRealtimeUnavailable
	}
	if completion.Publication.Version != nil {
		state.Checkpoint = completion.Publication.Checkpoint
	} else {
		state.Checkpoint = version.Checkpoint()
	}
	state.Cursor, err = s.cursors.IssueStateCursor(actorID, version)
	if err != nil {
		return voiceJoinResult{}, err
	}
	response, err := s.voiceJoinResponse(actorID, plan, version, state)
	if err != nil {
		return voiceJoinResult{}, err
	}
	body, err := realtime.CanonicalSuccessBody(response)
	if err != nil {
		return voiceJoinResult{}, err
	}
	body, err = realtime.CanonicalJSON(body)
	if err != nil {
		return voiceJoinResult{}, err
	}
	result = voiceJoinResult{response: response, state: state, body: body}
	if err := claim.Complete(realtime.RuntimeCommandResult{
		CommandID:   state.CommandID,
		Status:      http.StatusOK,
		Body:        result.body,
		Headers:     store.IdempotencyHeaders{CacheControl: "no-store", Pragma: "no-cache"},
		Checkpoint:  state.Checkpoint,
		StateCursor: state.Cursor,
		Value:       result,
	}); err != nil {
		return voiceJoinResult{}, err
	}
	completed = true
	return result, nil
}

// LeaveVoice submits one exact-owner voice teardown through the sequencer. It
// removes the Manager session and coordinator authority at the same
// StatePublication boundary, but deliberately performs no UDP revocation.
func (s *Service) LeaveVoice(ctx context.Context, actorID int64, controlConnectionID [16]byte, idempotencyKey string, input VoiceLeaveInput) (voiceLeaveResult, error) {
	if ctx == nil || s == nil || s.stores == nil || s.principals == nil || s.gate == nil || s.state == nil || s.sequencer == nil || s.connections == nil || s.voiceManager == nil || s.voiceIdempotency == nil || s.requestSigner == nil || s.cursors == nil || actorID <= 0 || controlConnectionID == [16]byte{} {
		return voiceLeaveResult{}, ErrRealtimeUnavailable
	}
	expectedID, err := parseVoiceSessionID(input.VoiceSessionID)
	if err != nil || expectedID == ([16]byte{}) {
		return voiceLeaveResult{}, ErrVoiceStale
	}
	identity, err := realtime.NewHTTPCommandIdentity(actorID, http.MethodPost, "/api/v0/channels/current/leave", nil, nil, input)
	if err != nil {
		return voiceLeaveResult{}, err
	}
	identity.ControlConnectionID = fmt.Sprintf("%x", controlConnectionID)
	requestHMAC, err := s.requestSigner.Sum(identity)
	if err != nil {
		return voiceLeaveResult{}, err
	}
	claim, err := s.voiceIdempotency.Claim(actorID, idempotencyKey, requestHMAC)
	if err != nil {
		return voiceLeaveResult{}, err
	}
	if !claim.Owner() {
		cached, waitErr := claim.Wait(ctx)
		if waitErr != nil {
			return voiceLeaveResult{}, waitErr
		}
		result, ok := cached.Value.(voiceLeaveResult)
		if !ok {
			return voiceLeaveResult{}, realtime.ErrInvalidCommandResult
		}
		result.replay = &cached
		return result, nil
	}
	completed := false
	defer func() {
		if !completed {
			_ = claim.Abort()
		}
	}()

	completion, err := s.sequencer.Submit(ctx, realtime.PostCommitCommand{
		QueueBytes: 1,
		Acquire: func(commandCtx context.Context) (func(), error) {
			unlock := s.principals.LockMutation(actorID)
			release, acquireErr := s.gate.Acquire(commandCtx)
			if acquireErr != nil {
				unlock()
				return nil, acquireErr
			}
			releaseRelay := s.connections.AcquireVoiceRelayGate(actorID)
			return func() {
				releaseRelay()
				release()
				unlock()
			}, nil
		},
		Execute: func(commandCtx context.Context, commandID int64, execution *realtime.CommandExecution) (realtime.CommandOutput, error) {
			nowMillis := s.voiceNowMillis()
			version, err := s.currentVersion()
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			owner, ok := s.connections.ActiveConnection(actorID, controlConnectionID)
			if !ok || !s.connections.LeaseActive(owner, nowMillis) {
				return realtime.CommandOutput{}, ErrVoiceNotConnected
			}
			current, hasCurrent := s.connections.VoiceAuthority(actorID)
			if !hasCurrent {
				if err := execution.MarkNoop(); err != nil {
					return realtime.CommandOutput{}, err
				}
				return realtime.CommandOutput{Value: voiceLeavePlan{version: version}}, nil
			}
			if current.ControlConnectionID != owner.ControlConnectionID || current.ConnectionGeneration != owner.Generation {
				return realtime.CommandOutput{}, ErrVoiceNotOwner
			}
			if current.VoiceSessionID != expectedID {
				return realtime.CommandOutput{}, ErrVoiceStale
			}
			channel, exists := version.Channel(current.ChannelID)
			if !exists {
				return realtime.CommandOutput{}, ErrTargetNotFound
			}
			candidate, err := s.state.BuildRuntimeCandidate()
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			if err := candidate.SetVoiceAuthority(actorID, nil); err != nil {
				return realtime.CommandOutput{}, err
			}
			left, err := voiceMemberEvent(current, false, version, s.visibility)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			events, err := realtime.VoiceAuthorityEventTemplates(&current, nil, "left")
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			eventPlan := append(events, left)
			var schedule *realtime.ExpirySchedule
			if channel.Temporary && activeChannelMembers(channel.ID, version) <= 1 {
				value, scheduleErr := candidate.ScheduleTemporaryExpiry(channel.ID, nowMillis+30_000)
				if scheduleErr != nil {
					return realtime.CommandOutput{}, scheduleErr
				}
				schedule = &value
			}
			plan := voiceLeavePlan{version: version, channelID: channel.ID, schedule: schedule}
			if _, err := execution.Reserve(realtime.PublicationRequest{
				Candidate: candidate,
				Events:    eventPlan,
				CommitRuntime: func() (func(), error) {
					_, removed, drain, disconnectErr := s.connections.BeginVoiceDisconnectForPublicationWithGate(current, s.voiceManager, "left")
					if disconnectErr != nil {
						return nil, disconnectErr
					}
					if !removed {
						// A concurrent WS EOF or UDP expiry may have won the exact
						// coordinator CAS after this command built its candidate.
						// This is a normal stale request, not a publication failure.
						return nil, fmt.Errorf("%w: %w", context.Canceled, ErrVoiceStale)
					}
					if drain != nil {
						drain()
					}
					return nil, nil
				},
			}); err != nil {
				return realtime.CommandOutput{}, err
			}
			reserved, err := execution.ReservedResult()
			if err != nil || reserved.Version == nil {
				if err != nil {
					return realtime.CommandOutput{}, err
				}
				return realtime.CommandOutput{}, ErrRealtimeUnavailable
			}
			state := StateCommand{CommandID: commandID, Checkpoint: reserved.Checkpoint}
			state.Cursor, err = s.cursors.IssueStateCursor(actorID, reserved.Version)
			if err != nil {
				return realtime.CommandOutput{}, err
			}
			preparedResult := voiceLeaveResult{state: state}
			if err := execution.MarkRuntimeReady(); err != nil {
				return realtime.CommandOutput{}, err
			}
			return realtime.CommandOutput{Value: voiceLeavePreparedResult{plan: plan, result: preparedResult}}, nil
		},
	})
	if err != nil {
		return voiceLeaveResult{}, err
	}
	var plan voiceLeavePlan
	var result voiceLeaveResult
	var prepared bool
	switch value := completion.Value.(type) {
	case voiceLeavePlan:
		plan = value
	case voiceLeavePreparedResult:
		plan = value.plan
		result = value.result
		prepared = true
	default:
		return voiceLeaveResult{}, ErrRealtimeUnavailable
	}
	if plan.schedule != nil {
		s.scheduleTemporary(plan.channelID, plan.schedule)
	}
	if prepared {
		if err := claim.Complete(realtime.RuntimeCommandResult{
			CommandID:   result.state.CommandID,
			Status:      http.StatusNoContent,
			Headers:     store.IdempotencyHeaders{CacheControl: "no-store", Pragma: "no-cache"},
			Checkpoint:  result.state.Checkpoint,
			StateCursor: result.state.Cursor,
			Value:       result,
		}); err != nil {
			return voiceLeaveResult{}, err
		}
		completed = true
		return result, nil
	}
	version := completion.Publication.Version
	state := StateCommand{CommandID: completion.CommandID}
	if version == nil {
		version = plan.version
	}
	if version == nil {
		return voiceLeaveResult{}, ErrRealtimeUnavailable
	}
	if completion.Publication.Version != nil {
		state.Checkpoint = completion.Publication.Checkpoint
	} else {
		state.Checkpoint = version.Checkpoint()
	}
	state.Cursor, err = s.cursors.IssueStateCursor(actorID, version)
	if err != nil {
		return voiceLeaveResult{}, err
	}
	result = voiceLeaveResult{state: state}
	if err := claim.Complete(realtime.RuntimeCommandResult{
		CommandID:   state.CommandID,
		Status:      http.StatusNoContent,
		Headers:     store.IdempotencyHeaders{CacheControl: "no-store", Pragma: "no-cache"},
		Checkpoint:  state.Checkpoint,
		StateCursor: state.Cursor,
		Value:       result,
	}); err != nil {
		return voiceLeaveResult{}, err
	}
	completed = true
	return result, nil
}

// voiceJoinResponse materializes the response from the exact published
// version, never from a later mutable coordinator or Manager lookup.
func (s *Service) voiceJoinResponse(actorID int64, plan voiceJoinPlan, version *realtime.StateVersion, state StateCommand) (voiceJoinResponse, error) {
	if version == nil || plan.info.ID == ([16]byte{}) || plan.info.UserID != actorID {
		return voiceJoinResponse{}, ErrRealtimeUnavailable
	}
	members := make([]realtime.SnapshotVoiceMembership, 0)
	for _, authority := range version.VoiceAuthorities() {
		if authority.ChannelID != plan.channelID {
			continue
		}
		members = append(members, realtime.SnapshotVoiceMembership{UserID: fmt.Sprint(authority.UserID), ChannelID: fmt.Sprint(authority.ChannelID), JoinedAt: authority.JoinedAt})
	}
	checkpoint := stateCheckpointResponse{StreamEpoch: state.Checkpoint.StreamEpoch, GEID: fmt.Sprint(state.Checkpoint.GEID)}
	voice := voiceSessionResponse{
		Created:         plan.created,
		SessionID:       fmt.Sprintf("%x", plan.info.ID),
		Encrypted:       plan.info.Encrypted,
		MaxPayload:      protocol.MaxPayload(plan.info.Encrypted),
		ProtocolVersion: protocol.ProtocolVersion,
		ExpiresAt:       plan.info.ExpiresAt,
	}
	if !plan.info.Encrypted {
		voice.Warning = "plaintext_mode"
	}
	if plan.created && plan.info.Encrypted {
		voice.Key = base64.StdEncoding.EncodeToString(plan.info.MasterKey)
	}
	return voiceJoinResponse{
		Channel:         plan.channel,
		Members:         members,
		Voice:           voice,
		StateCursor:     state.Cursor,
		StateCheckpoint: checkpoint,
	}, nil
}

// voiceMemberEvent creates one channel-scoped membership upsert/delete. Left
// events carry the before-visible recipient set so losing access cannot expose
// a stale private-channel payload.
func voiceMemberEvent(authority realtime.VoiceAuthority, joined bool, before *realtime.StateVersion, visibility *realtime.VisibilityResolver) (realtime.StateEventTemplate, error) {
	if !authority.Valid() || before == nil || visibility == nil {
		return realtime.StateEventTemplate{}, realtime.ErrInvalidProjection
	}
	membership := realtime.SnapshotVoiceMembership{UserID: fmt.Sprint(authority.UserID), ChannelID: fmt.Sprint(authority.ChannelID), JoinedAt: authority.JoinedAt}
	data, err := json.Marshal(struct {
		Membership realtime.SnapshotVoiceMembership `json:"membership"`
	}{Membership: membership})
	if err != nil {
		return realtime.StateEventTemplate{}, err
	}
	event := realtime.StateEventTemplate{Scope: realtime.Scope{Type: "channel", ID: authority.ChannelID}, Data: data}
	if joined {
		event.EventType = "channel.member.joined"
		event.DeliveryPolicy = realtime.StateDeliveryVisibleAfter
		return event, nil
	}
	event.EventType = "channel.member.left"
	event.DeliveryPolicy = realtime.StateDeliveryVisibleBefore
	event.VisibleBeforeUserIDs = visibleChannelUsers(authority.ChannelID, before, visibility)
	data, err = json.Marshal(struct {
		UserID    string `json:"user_id"`
		ChannelID string `json:"channel_id"`
	}{UserID: fmt.Sprint(authority.UserID), ChannelID: fmt.Sprint(authority.ChannelID)})
	if err != nil {
		return realtime.StateEventTemplate{}, err
	}
	event.Data = data
	return event, nil
}

// VoiceJoinHandler handles POST /api/v0/channels/:id/join.
//
// Errors:
//   - 1 channel not found: the channel is absent or inaccessible
//   - 3 non-voice channel: the target channel cannot host voice membership
//   - 7 full: projected target occupancy reaches channel capacity
//   - 8 stale connection/session: the WS owner or expected session is stale
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: headers, path, or body fields are invalid
//   - 1001 malformed request: the JSON body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1008 rate limited: the bounded runtime replay cache cannot admit the request
//   - 1009 internal: sequenced voice preparation or publication failed
func VoiceJoinHandler(svc *Service) echo.HandlerFunc {
	const (
		codeNotFound    = 1
		codeNotVoice    = 3
		codeFull        = 7
		codeVoiceStale  = 8
		codeIdempotency = 9
	)
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		channelID, err := pathID(c.Param("id"))
		if err != nil {
			return api.InvalidField("path.id", "must be a positive decimal snowflake ID")
		}
		controlID, err := controlConnectionHeader(c)
		if err != nil {
			return err
		}
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		var req VoiceJoinInput
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		if !validVoiceDeviceID(req.DeviceID) {
			return api.InvalidField("body.device_id", "must be 1-64 characters using letters, digits, underscore, or hyphen")
		}
		if req.ExpectedVoiceSessionID != "" {
			if _, err := parseVoiceSessionID(req.ExpectedVoiceSessionID); err != nil {
				return api.InvalidField("body.expected_voice_session_id", "must be 32 lowercase hexadecimal characters")
			}
		}
		result, err := svc.JoinVoice(c.Request().Context(), principal.UserID, channelID, controlID, key, req, requestSourceIP(c))
		if result.replay != nil {
			return commandhttp.ReplayRuntime(c, *result.replay)
		}
		switch {
		case errors.Is(err, realtime.ErrIdempotencyMismatch):
			return api.NewError(codeIdempotency, http.StatusConflict, "idempotency key reused with different request")
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeNotFound, http.StatusNotFound, "channel not found")
		case errors.Is(err, ErrVoiceNotChannel):
			return api.NewError(codeNotVoice, http.StatusConflict, "channel is not a voice channel")
		case errors.Is(err, ErrVoiceFull):
			return api.NewError(codeFull, http.StatusConflict, "voice channel is full")
		case errors.Is(err, ErrVoiceNotConnected), errors.Is(err, ErrVoiceExpectedRequired), errors.Is(err, ErrVoiceStale), errors.Is(err, realtime.ErrVoiceAuthorityPrecondition):
			return api.NewError(codeVoiceStale, http.StatusConflict, "voice connection or session is stale")
		case errors.Is(err, ErrVoiceCreateRateLimit):
			return api.NewError(api.CodeRateLimited, http.StatusTooManyRequests, "voice session creation rate limited")
		case errors.Is(err, realtime.ErrRuntimeIdempotencyFull):
			return api.NewError(api.CodeRateLimited, http.StatusTooManyRequests, "voice retry cache is full")
		case err != nil:
			return err
		}
		c.Response().Header().Set("Cache-Control", "no-store")
		c.Response().Header().Set("Pragma", "no-cache")
		setStateHeaders(c, result.state)
		return commandhttp.OK(c, http.StatusOK, result.response)
	})
}

// VoiceLeaveHandler handles POST /api/v0/channels/current/leave.
//
// Errors:
//   - 8 stale connection/session: the caller is not the current voice owner
//   - 9 idempotency mismatch: the retry key belongs to another request
//   - 1000 invalid request parameters: headers or body fields are invalid
//   - 1001 malformed request: the JSON body could not be parsed
//   - 1002 unauthorized: missing or invalid access token
//   - 1008 rate limited: the bounded runtime replay cache cannot admit the request
//   - 1009 internal: sequenced voice teardown or publication failed
func VoiceLeaveHandler(svc *Service) echo.HandlerFunc {
	const codeVoiceStale = 8
	return rbacecho.WithPrincipal(func(c *echo.Context, principal *rbac.Principal) error {
		controlID, err := controlConnectionHeader(c)
		if err != nil {
			return err
		}
		key, err := idempotencyKey(c)
		if err != nil {
			return err
		}
		var req VoiceLeaveInput
		if err := api.Bind(c, &req); err != nil {
			return err
		}
		if _, err := parseVoiceSessionID(req.VoiceSessionID); err != nil {
			return api.InvalidField("body.voice_session_id", "must be 32 lowercase hexadecimal characters")
		}
		result, err := svc.LeaveVoice(c.Request().Context(), principal.UserID, controlID, key, req)
		if result.replay != nil {
			return commandhttp.ReplayRuntime(c, *result.replay)
		}
		switch {
		case errors.Is(err, realtime.ErrIdempotencyMismatch):
			return api.NewError(9, http.StatusConflict, "idempotency key reused with different request")
		case errors.Is(err, ErrVoiceNotConnected), errors.Is(err, ErrVoiceNotOwner), errors.Is(err, ErrVoiceStale), errors.Is(err, realtime.ErrVoiceAuthorityPrecondition):
			return api.NewError(codeVoiceStale, http.StatusConflict, "voice connection or session is stale")
		case errors.Is(err, ErrTargetNotFound):
			return api.NewError(codeVoiceStale, http.StatusConflict, "voice channel is no longer available")
		case errors.Is(err, realtime.ErrRuntimeIdempotencyFull):
			return api.NewError(api.CodeRateLimited, http.StatusTooManyRequests, "voice retry cache is full")
		case err != nil:
			return err
		}
		c.Response().Header().Set("Cache-Control", "no-store")
		c.Response().Header().Set("Pragma", "no-cache")
		setStateHeaders(c, result.state)
		return commandhttp.NoContent(c, http.StatusNoContent)
	})
}

// controlConnectionHeader parses the exact lowercase hexadecimal WS identity.
func controlConnectionHeader(c *echo.Context) ([16]byte, error) {
	values := c.Request().Header.Values("X-Zephyr-Control-Connection")
	if len(values) != 1 || len(values[0]) != 32 || strings.ToLower(values[0]) != values[0] {
		return [16]byte{}, api.InvalidField("header.X-Zephyr-Control-Connection", "must be one 32-character lowercase hexadecimal control connection ID")
	}
	var result [16]byte
	if _, err := hex.Decode(result[:], []byte(values[0])); err != nil || result == [16]byte{} {
		return [16]byte{}, api.InvalidField("header.X-Zephyr-Control-Connection", "must be one 32-character lowercase hexadecimal control connection ID")
	}
	return result, nil
}

// parseVoiceSessionID parses an optional exact session ID without accepting
// uppercase or all-zero values.
func parseVoiceSessionID(raw string) ([16]byte, error) {
	if raw == "" {
		return [16]byte{}, nil
	}
	if len(raw) != 32 || strings.ToLower(raw) != raw {
		return [16]byte{}, ErrVoiceStale
	}
	var result [16]byte
	if _, err := hex.Decode(result[:], []byte(raw)); err != nil || result == [16]byte{} {
		return [16]byte{}, ErrVoiceStale
	}
	return result, nil
}

// validVoiceDeviceID validates the diagnostic-only device identifier grammar.
func validVoiceDeviceID(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// requestSourceIP returns the normalized peer address used by the new-session
// limiter. Invalid or unavailable addresses collapse to a stable empty key.
func requestSourceIP(c *echo.Context) string {
	raw := strings.TrimSpace(c.RealIP())
	if raw == "" {
		raw = strings.TrimSpace(c.Request().RemoteAddr)
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	if addr, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return addr.Unmap().String()
	}
	return ""
}

// voiceNowMillis returns the service clock used for connection and membership
// validation. It is injectable only for deterministic tests.
func (s *Service) voiceNowMillis() int64 {
	if s != nil && s.voiceNow != nil {
		return s.voiceNow()
	}
	return time.Now().UnixMilli()
}
