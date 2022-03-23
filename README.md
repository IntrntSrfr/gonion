# Gonion - An onion routing service

## Introduction

Gonion is an onion routing service that lets clients send HTTP requests through a network of
nodes. The most important factor is the privacy and security of the data that is sent. 
The data is sent through secure and encrypted tunnels, and the data itself is encrypted 
on top of that as well. The client can be sure that their privacy and their security is 
maintained by using Gonion. (This is obviously a bit of an over-exaggeration, as having a 
small amount of users basically makes it insecure.)

Gonion consists of 3 components. A client, nodes, and a directory. The client is what the 
user will use to send requests to the Node network. The network consists of nodes. A Node
is a small server that either relays data, or fires a request on the behalf of a client. 
The directory is a server that keeps data of all active nodes. The client needs to be able 
to connect to the directory to be able to get access to Node data, otherwise the client 
will be unable to send data anywhere.

## Implemented functionality 

* Sending GET requests and saving data to file
* Encryption back and forth using AES-256-CFB and RSA.

## Future work

* Capability to add files to request data
* Making packets more safe to use, and more efficient

## Dependencies

Currently, Gonion has very few dependencies, and they are for convenience.

* [github.com/gin-gonic/gin](https://github.com/gin-gonic/gin)
  * HTTP framework used by the Directory Node, simply for convenience.
* [github.com/tidwall/secret](https://github.com/tidwall/secret)
  * Small AES-256-CFB library that makes it very simple to work with encryption. This is also just
    convenience.

Everything else is written using the built-in libraries that Go provides.

## Installation

As there are 3 components, there are 3 things you can install.

### Client

### Node

### Directory

## Usage

## Testing

Testing the package can be done by running `go test ./...`

## API Documentation

Only the directory has an API, and its use is very simple.

### Get nodes

Returns a list of all currently active nodes.
* URL
  * `/api/nodes`
* Method
  * `GET`
* URL Params
  * None
* Data Params
  * None
* Success response
  * 200 OK
    * `[{"ip": "127.0.0.1", "port":"1234", "public_key":"123abc..."}, ...]`


### Post Node

Adds a node to the directory.
* URL
    * `/api/nodes`
* Method
    * `POST`
* URL Params
    * None
* Data Params
    * None
* Success response
  * 200 OK
    * `{"ip": "127.0.0.1", "port":"1234", "public_key":"123abc..."}`
* Error response
  * 400 Bad Request
    
### Health check

A simple health check that simply returns `{"status": "ok"}` if the server is running.
* URL
    * `/api/nodes`
* Method
    * `GET`
* Success response
    * 200 OK
        * `{"status":"ok"}`
