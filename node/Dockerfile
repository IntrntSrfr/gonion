FROM golang:alpine

WORKDIR /node

COPY . .

RUN go mod download

RUN go build -o node

EXPOSE 9050

CMD [ "./node" ]