FROM golang:1.24-alpine

# Install git
RUN apk --update add \
        git openssl \
        && rm /var/cache/apk/*

# Define current working directory
WORKDIR /01-Quickstart-Go-API

# Download modules to local cache so we can skip re-
# downloading on consecutive docker build commands
COPY go.mod .
COPY go.sum .
RUN go mod download

# Add sources
COPY . .

# Expose port 8080 for our api binary
EXPOSE 8080

CMD ["go", "run", "cmd/server/main.go"]
