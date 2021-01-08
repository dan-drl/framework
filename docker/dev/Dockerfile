##########################
# Create a build image
FROM golang:1.12

# Set work dir
RUN mkdir -p /go/src/github.com/dan-drl/framework
WORKDIR /go/src/github.com/dan-drl/framework

COPY . .

CMD ./docker/start.sh