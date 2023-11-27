FROM golang:1.21 AS build
WORKDIR /build
COPY ./ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o ./goxdp ./server/

FROM alpine:latest AS Production
COPY --from=build /build/goxdp /usr/sbin/goxdp
ENTRYPOINT [ "/usr/sbin/goxdp" ]
