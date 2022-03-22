package directory

import (
	"net/http"

	"github.com/intrntsrfr/gonion"

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

// Directory represents a Node directory that tracks active Nodes.
type Directory struct {
	R     *gin.Engine
	Nodes []*gonion.NodeInfo
}

func (d *Directory) Serve() {
	d.registerControllers()
	http.ListenAndServe(":9051", d.R)
}

func NewDirectory(r *gin.Engine) *Directory {
	return &Directory{
		R:     r,
		Nodes: []*gonion.NodeInfo{},
	}
}

func (d *Directory) registerControllers() {
	d.R.GET("/api/health", d.health)
	d.R.GET("/api/nodes", d.getNodes)
	d.R.POST("/api/nodes", d.addNode)
}

func (d *Directory) getNodes(c *gin.Context) {
	c.JSON(http.StatusOK, d.Nodes)
}

func (d *Directory) addNode(c *gin.Context) {
	n := gonion.NodeInfo{}
	if err := c.BindJSON(&n); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.JSON(http.StatusOK, SuccessResponse{
		Code: 1,
		Data: "node added",
	})
	d.Nodes = append(d.Nodes, &n)
}

func (d *Directory) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
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
