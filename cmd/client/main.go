package main

import (
	"flag"
	"io"
	"log"
	"os"

	"github.com/intrntsrfr/gonion"
	"github.com/intrntsrfr/gonion/client"
)

func main() {
	var err error

	/*
		var method string
		flag.StringVar(&method, "m", "GET", "HTTP method to use")
	*/

	flag.Parse()

	dst := flag.Arg(0)
	if dst == "" {
		log.Fatal("you need to specify a resource")
	}

	outStr := flag.Arg(1)
	out := os.Stdout
	if outStr != "" {
		out, err = os.Create(outStr)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer out.Close()

	req, err := gonion.ParseRequest(dst)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	_, err = io.Copy(out, resp)
	if err != nil {
		log.Fatal(err)
	}

}
