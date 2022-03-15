package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// contains a directory of all nodes that are currently in the network, replies with all available nodes
// a node contains an ip and their public key

type Node struct {
	IP        string
	PublicKey string
}

var nodes = []*Node{
	{IP: "", PublicKey: ""},
	{IP: "", PublicKey: ""},
	{IP: "", PublicKey: ""},
}

func main() {
	r := gin.Default()

	r.GET("/api/nodes", func(c *gin.Context) {
		c.JSON(http.StatusOK, nodes)
	})

	http.ListenAndServe(":5555", r)
}
