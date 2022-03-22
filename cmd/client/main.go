package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/intrntsrfr/gonion/client"
)

func main() {


	flag.Parse()

	fmt.Println(flag.Args())

	return
	file := flag.Arg(0)
	if file == "" {
		fmt.Println("please specify an output file")
		return
	}

	return

	a := "http://eu.httpbin.org/flasgger_static/swagger-ui-bundle.js"
	req := client.ParseURL(a)

	resp := client.Do(req)

	f, err := os.Create(file)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	io.Copy(f, resp)
}
