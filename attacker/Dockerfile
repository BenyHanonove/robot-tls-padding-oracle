FROM golang:1.22-bookworm
WORKDIR /app
COPY . .
RUN go mod tidy
RUN go build -o robot-attacker main.go
ENV GODEBUG=rsa1024min=0,tlsrsakex=1
CMD ["sh", "-c", "sleep 5 && ./robot-attacker"]
