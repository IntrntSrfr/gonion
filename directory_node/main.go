package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// contains a directory of all nodes that are currently in the network, replies with all available nodes
// a node contains an ip and their public key

type SuccessResponse struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
}

// change handler to use a map of nodes instead, so that IPs can be used as key.
// it will make it easier to ping and remove them when that is needed.

type Handler struct {
	R     *gin.Engine
	Nodes []*Node
}

func main() {
	r := gin.Default()

	h := &Handler{R: r, Nodes: make([]*Node, 0)}
	h.RegisterControllers()

	h.Serve()
}

func (h *Handler) Serve() {
	http.ListenAndServe(":9051", h.R)
}

func NewHandler(r *gin.Engine) *Handler {

	return &Handler{
		R:     r,
		Nodes: make([]*Node, 0),
	}
}

func (h *Handler) RegisterControllers() {
	h.R.GET("/api/nodes", func(c *gin.Context) {
		c.JSON(http.StatusOK, h.Nodes)
	})
	h.R.POST("/api/nodes", h.addNode)
}

type Node struct {
	IP        string `json:"ip"`
	Port      string `json:"port"`
	PublicKey []byte `json:"public_key"`
}

func (h *Handler) addNode(c *gin.Context) {
	n := Node{}
	if err := c.BindJSON(&n); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.JSON(http.StatusOK, SuccessResponse{
		Code: 1,
		Data: "node added",
	})
	h.Nodes = append(h.Nodes, &n)
}

// test nodes every minute or so to keep them added to node list

// probably add a post request to let a node add itself to the directory
/*
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
*/
