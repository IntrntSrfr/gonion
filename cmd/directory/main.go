package main

import (
	"github.com/gin-gonic/gin"
	"github.com/intrntsrfr/gonion/directory"
	"log"
)

func main() {
	r := gin.Default()
	h := directory.NewDirectory(r)
	err := h.Serve()
	if err != nil {
		log.Fatal(err)
	}
}
