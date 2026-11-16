FROM golang:1.26-bookworm AS backend
RUN apt-get update && apt-get install -y --no-install-recommends freerdp2-dev libpng-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /out && cc -O2 -Wall -Wextra -Wl,--export-dynamic-symbol=connect internal/rdpbackend/worker.c -o /out/connkit-rdp $(pkg-config --cflags --libs freerdp2 freerdp-client2 winpr2 libpng openssl)
RUN CGO_ENABLED=1 go build -trimpath -o /out/mcp ./cmd/mcp

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libfreerdp2-2 libfreerdp-client2-2 libwinpr2-2 libpng16-16 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=backend /out/mcp /usr/local/bin/mcp
COPY --from=backend /out/connkit-rdp /usr/local/bin/connkit-rdp
WORKDIR /app
ENV CONNKIT_DB_PATH=/data/connkit.db CONNKIT_MCP_ADDR=:8081
EXPOSE 8081 8082
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s CMD ["/usr/local/bin/mcp", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/mcp"]
