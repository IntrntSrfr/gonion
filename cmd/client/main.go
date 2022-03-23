package main

import (
	"flag"
	"log"

	"github.com/intrntsrfr/gonion"
	"github.com/intrntsrfr/gonion/client"
)

func main() {

	var method string
	flag.StringVar(&method, "m", "GET", "HTTP method to use")
	flag.Parse()

	dst := flag.Arg(0)
	if dst == "" {
		log.Fatal("you need to specify a destination")
	}

	out := flag.Arg(1)
	if out == "" {
		log.Fatal("you need to specify a destination")
	}

	req := gonion.ParseURL(dst)
	client.Do(req)
	/*
		resp := client.Do(req)

		f, err := os.Create(out)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		io.Copy(f, resp)

	*/
}
