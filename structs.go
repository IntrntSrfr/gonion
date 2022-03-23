package gonion

import (
	"log"
	"net/url"
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

func ParseURL(inp string) *HTTPRequest {
	u, err := url.Parse(inp)
	if err != nil {
		log.Fatal(err)
	}
	return &HTTPRequest{
		Method:  "GET",
		Scheme:  u.Scheme,
		Host:    u.Host,
		Path:    u.Path,
		Queries: u.Query(),
	}
}
