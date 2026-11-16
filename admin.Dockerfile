FROM node:22-alpine AS web
WORKDIR /web
COPY admin-web/package.json admin-web/package-lock.json ./
RUN npm ci
COPY admin-web/ ./
RUN npm run build

FROM golang:1.26-bookworm AS backend
RUN apt-get update && apt-get install -y --no-install-recommends freerdp2-dev libpng-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -p /out && cc -O2 -Wall -Wextra -Wl,--export-dynamic-symbol=connect internal/rdpbackend/worker.c -o /out/connkit-rdp $(pkg-config --cflags --libs freerdp2 freerdp-client2 winpr2 libpng openssl)
RUN CGO_ENABLED=1 go build -trimpath -o /out/admin ./cmd/admin

FROM nginx:stable-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libfreerdp2-2 libfreerdp-client2-2 libwinpr2-2 libpng16-16 ca-certificates curl tini && rm -rf /var/lib/apt/lists/*
COPY --from=web /web/dist /usr/share/nginx/html
COPY --from=backend /out/admin /usr/local/bin/admin
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY deploy/admin-entrypoint.sh /usr/local/bin/admin-entrypoint
RUN chmod +x /usr/local/bin/admin-entrypoint
COPY --from=backend /out/connkit-rdp /usr/local/bin/connkit-rdp
WORKDIR /app
ENV CONNKIT_DB_PATH=/data/connkit.db CONNKIT_ADMIN_ADDR=127.0.0.1:8080
EXPOSE 80
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s CMD curl -fsS http://127.0.0.1/healthz || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/admin-entrypoint"]
