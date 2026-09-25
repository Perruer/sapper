# Sapper: find where vulnerable packages sit across all of your products.
#   docker build -t sapper .
#   docker run -p 8089:8089 -v sapper-data:/data sapper
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/Perruer/sapper/cmd/root.Version=${VERSION}" \
      -o /out/sapper . \
    && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sapper /usr/local/bin/sapper
COPY --from=build --chown=65532:65532 /out/data /data
ENV SAPPER_DATA_DIR=/data
VOLUME /data
EXPOSE 8089
USER nonroot
ENTRYPOINT ["sapper"]
CMD ["server", "--addr", "0.0.0.0:8089"]
