package server

import (
	"time"

	"zephyr.vox/server/ce/internal/relay"
)

// newApplicationRelay adapts immutable realtime state and the process-owned
// UDP server to the transport-only relay package. Every resolver captures one
// StateVersion and returns copies, so relay workers never hold a publication
// or database lock while sending media.
func newApplicationRelay(app *App) (*relay.Relay, error) {
	if app == nil || app.voice == nil || app.voice.server == nil || app.voice.registry == nil || app.connections == nil || app.state == nil {
		return nil, relay.ErrInvalidRelay
	}
	return relay.New(relay.Config{
		Sender:               app.voice.server,
		Capabilities:         app.voice.registry,
		Gate:                 app.connections,
		GlobalPacketsPerSec:  app.voice.globalPacketsPerSec,
		SessionPacketsPerSec: app.voice.sessionPacketsPerSec,
		Now:                  time.Now,
		SourceResolver: func(userID int64) (relay.Source, bool) {
			authority, ok := app.connections.VoiceAuthority(userID)
			if !ok || !authority.Valid() {
				return relay.Source{}, false
			}
			return relay.Source{
				UserID:                   authority.UserID,
				SessionID:                authority.VoiceSessionID,
				ChannelID:                authority.ChannelID,
				ControlConnectionID:      authority.ControlConnectionID,
				ConnectionGeneration:     authority.ConnectionGeneration,
				VoiceAuthorityGeneration: authority.VoiceAuthorityGeneration,
			}, true
		},
		MembershipResolver: func(channelID int64) relay.MembershipSnapshot {
			version := app.state.Current()
			if version == nil {
				return relay.MembershipSnapshot{}
			}
			members := make([]relay.Recipient, 0)
			for _, authority := range version.VoiceAuthorities() {
				if authority.ChannelID != channelID || !authority.Valid() {
					continue
				}
				members = append(members, relay.Recipient{UserID: authority.UserID, SessionID: authority.VoiceSessionID})
			}
			return relay.MembershipSnapshot{ChannelID: channelID, Members: members}
		},
		MuteResolver: func(source relay.Source, channelType uint8) bool {
			version := app.state.Current()
			if version == nil {
				return false
			}
			caps, ok := app.voice.registry.Lookup(channelType)
			return ok && version.EffectiveMute(source.UserID, source.ChannelID, caps.MuteKind, time.Now().UnixMilli())
		},
	})
}
