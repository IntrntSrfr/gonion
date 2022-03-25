package directory

import (
	"net/http"

	"github.com/intrntsrfr/gonion"

	"github.com/gin-gonic/gin"
)

// Directory represents a Node directory that tracks active Nodes.
type Directory struct {
	R     *gin.Engine
	Nodes []*gonion.NodeInfo
}

// Serve serves a directory node API at port 9051
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

// registerControllers registers all the necessary controllers to the server
func (d *Directory) registerControllers() {
	d.R.GET("/api/health", d.health)
	d.R.GET("/api/nodes", d.getNodes)
	d.R.POST("/api/nodes", d.addNode)
}

func (d *Directory) getNodes(c *gin.Context) {
	c.JSON(http.StatusOK, d.Nodes)
}

// addNode adds a node to the directory
func (d *Directory) addNode(c *gin.Context) {
	n := gonion.NodeInfo{}
	if err := c.BindJSON(&n); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.JSON(http.StatusOK, n)
	d.Nodes = append(d.Nodes, &n)
}

// health is a simple and small health check that returns {"status":"ok"}
func (d *Directory) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
