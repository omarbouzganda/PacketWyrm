FROM golang:1.21-alpine

RUN apk add --no-cache libpcap-dev linux-headers git gcc musl-dev

WORKDIR /app
COPY go.mod main.go ./
RUN go mod tidy && CGO_ENABLED=1 go build -o packetwyrm .

EXPOSE 8080
CMD ["./packetwyrm"]
