FROM golang:1.22-bookworm
WORKDIR /app
COPY . .
RUN if [ ! -f go.mod ]; then go mod init victim-app; fi
RUN go mod tidy
RUN go build -o victim-app main.go
ENV GODEBUG=rsa1024min=0,tlsrsakex=1
CMD ["sh", "-c", "sleep 10 && ./victim-app"]
