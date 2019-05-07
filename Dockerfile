FROM golang:1-alpine3.9

ADD server.go /go/src/loeessh/
WORKDIR /go/src/loeessh

RUN apk update && apk add git && go get && go build -o app

CMD ["/bin/sh"]
FROM alpine:3.9
COPY --from=0 /go/src/loeessh/app /app
CMD ["/app"]
