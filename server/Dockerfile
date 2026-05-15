FROM golang:1.22-bookworm
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o robot-server main.go
EXPOSE 8443
ENV GODEBUG=rsa1024min=0,tlsrsakex=1
CMD ["./robot-server"]
