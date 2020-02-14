##########################
# Create a build image
FROM golang:1.12

# Set work dir
RUN mkdir -p /go/src/github.com/infinitbyte/framework
WORKDIR /go/src/github.com/infinitbyte/framework

COPY . .

CMD ./docker/start.sh