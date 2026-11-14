FROM golang:1.26-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -o /out/mcp ./cmd/mcp

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=backend /out/mcp /usr/local/bin/mcp
WORKDIR /app
ENV CONNKIT_DB_PATH=/data/connkit.db CONNKIT_MCP_ADDR=:8081
EXPOSE 8081 8082
ENTRYPOINT ["/usr/local/bin/mcp"]
