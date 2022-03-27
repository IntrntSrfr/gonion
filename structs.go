package gonion

import (
	"net/http"
	"net/url"
)

var (
	EndpointDirectory = "http://localhost:9051"
	EndpointAPI       = EndpointDirectory + "/api"
	EndpointNodes     = EndpointAPI + "/nodes"
	EndpointHealth    = EndpointAPI + "/health"
)

// NodeInfo contains important Node information that can be sent through the network
type NodeInfo struct {
	IP        string `json:"ip"`
	Port      string `json:"port"`
	PublicKey []byte `json:"public_key"`
}

// HTTPRequest represents an HTTP request in its basic forms. Info such as what method, host, path, etc..
type HTTPRequest struct {
	Method  string              `json:"method"`
	Scheme  string              `json:"scheme"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Queries map[string][]string `json:"queries"`
	Headers map[string]string   `json:"headers"`
}

// ParseRequest takes in a string and attempts to parse it to an *HTTPRequest struct and returns it.
// It returns an error if the url could not be parsed.
func ParseRequest(inp string) (*HTTPRequest, error) {
	u, err := url.Parse(inp)
	if err != nil {
		return nil, err
	}
	return &HTTPRequest{
		Method:  "GET",
		Scheme:  u.Scheme,
		Host:    u.Host,
		Path:    u.Path,
		Queries: u.Query(),
	}, nil
}

// validHTTPMethod returns whether a string is a valid HTTP method
func validHTTPMethod(m string) bool {
	if m == http.MethodGet || m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch || m == http.MethodDelete || m == http.MethodHead {
		return true
	}
	return false
}
