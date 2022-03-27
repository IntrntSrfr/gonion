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

type NodeInfo struct {
	IP        string `json:"ip"`
	Port      string `json:"port"`
	PublicKey []byte `json:"public_key"`
}

type HTTPRequest struct {
	Method  string              `json:"method"`
	Scheme  string              `json:"scheme"`
	Host    string              `json:"host"`
	Path    string              `json:"path"`
	Queries map[string][]string `json:"queries"`
	Headers map[string]string   `json:"headers"`
}

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

func validHTTPMethod(m string) bool {
	if m == http.MethodGet || m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch || m == http.MethodDelete || m == http.MethodHead {
		return true
	}
	return false
}
