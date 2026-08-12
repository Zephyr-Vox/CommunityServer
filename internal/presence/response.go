package presence

// Response payloads for the presence endpoints.

// onlineResponse is the data of GET /api/v0/presence: every online user keyed
// by user id. Absent ids mean offline.
type onlineResponse map[int64]State
