package image

// Response payloads for the image domain endpoints.

// uploadResponse is the body of a successful avatar upload: the raw object
// name, without any path prefix. Clients build the full URL by joining the
// name with the public prefix; today that prefix is the fixed route
// /avatar/ (e.g. "/avatar/" + name). A server metadata endpoint publishing
// a configurable prefix is future work.
type uploadResponse struct {
	Avatar string `json:"avatar"`
}
