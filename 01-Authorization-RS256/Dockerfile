FROM golang:1.17-alpine3.14

# Install git
RUN apk --update add \
	git openssl \
	&& rm /var/cache/apk/*

# Define current working directory
WORKDIR /01-Authorization-RS256

# Download modules to local cache so we can skip re-
# downloading on consecutive docker build commands
COPY go.mod .
COPY go.sum .
RUN go mod download

# Add sources
COPY . .

# Expose port 3010 for our api binary
EXPOSE 3010

CMD ["go", "run", "main.go"]
