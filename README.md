# Gonion - An onion routing service

This is an onion routing service that consists of a client, any amount of available nodes,
and a directory node.

## Client

The client is the end-user interface for interacting with the node network.

## Node

A node is a part of the node network that clients can use for transporting encrypted messages.

## Directory node

The directory node is an API service that provides clients with an up-to-date collection of
available nodes. The directory node requires individual nodes to send keep-alive messages
to the directory node to stay added to the available nodes. The API will provide clients with
node IPs and their public keys.
