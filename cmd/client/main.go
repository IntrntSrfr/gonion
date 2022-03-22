package main

import (
	"flag"
	"github.com/intrntsrfr/gonion/client"
	"io"
	"log"
	"os"
)

func main() {

	var method string
	flag.StringVar(&method, "m", "GET", "HTTP method to use")
	flag.Parse()

	dst := flag.Arg(0)
	if dst == ""{
		log.Fatal("you need to specify a destination")
	}

	out := flag.Arg(1)
	if out == "" {
		log.Fatal("you need to specify a destination")
	}

	req := client.ParseURL(dst)
	resp := client.Do(req)

	f, err := os.Create(out)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	io.Copy(f, resp)
}
