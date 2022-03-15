package main

import (
	"bytes"
	"encoding/json"
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
	{IP: "127.0.0.1", PublicKey: "test1"},
	{IP: "127.0.0.1", PublicKey: "test2"},
	{IP: "127.0.0.1", PublicKey: "test3"},
}

func main() {
	r := gin.Default()

	r.GET("/api/nodes", func(c *gin.Context) {
		c.JSON(http.StatusOK, nodes)
	})

	http.ListenAndServe(":9002", r)
}

// test nodes every minute or so to keep them added to node list

// probably add a post request to let a node add itself to the directory 

func testNodes() {
	for _, node := range nodes {
		testNode(node.IP)
	}
}

func testNode(url string) {
	b := bytes.Buffer{}
	json.NewEncoder(&b).Encode("type:1")
	http.DefaultClient.Post(url, "application/json", &b)
}
