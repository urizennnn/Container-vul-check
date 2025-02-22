FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod  ./
RUN sed -i 's/^go 1\.23\.0/go 1.23/' go.mod
RUN go mod download
COPY . .
RUN go build -o myapp .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/myapp .
EXPOSE 8080
ENTRYPOINT ["./myapp"]

