package main

import (
	"github.com/gin-gonic/gin"
	"github.com/intrntsrfr/gonion/directory"
)

func main() {
	r := gin.Default()
	h := directory.NewDirectory(r)
	h.Serve()
}
