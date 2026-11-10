# Penteos team server (experimental): the same core the desktop app runs, served to a team.
# It refuses to start on the network without TLS (or --allow-plaintext, behind a VPN or SSH tunnel).
#
#   docker build -t penteos-server .
#   docker run --rm -v penteos:/data penteos-server operator add alice lead   # first lead (token shown once)
#   docker run -d --name penteos -p 8443:8443 -v penteos:/data -v $PWD/tls:/tls:ro penteos-server \
#     --host 0.0.0.0 --port 8443 --tls-cert /tls/cert.pem --tls-key /tls/key.pem

FROM node:24-bookworm AS build
WORKDIR /src
ENV ELECTRON_SKIP_BINARY_DOWNLOAD=1
RUN corepack enable
COPY . .
RUN pnpm install --frozen-lockfile \
 && node scripts/bundle-core.mjs /out \
 && cd /out && npm install --omit=dev --no-audit --no-fund --no-package-lock

FROM node:24-bookworm-slim
# The usual tools, so the team server can run scans out of the box (more can be installed later).
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap curl dnsutils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out /opt/penteos
WORKDIR /opt/penteos
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["node", "/opt/penteos/core.mjs", "--data-dir", "/data"]
CMD ["--host", "0.0.0.0", "--port", "8443", "--tls-cert", "/tls/cert.pem", "--tls-key", "/tls/key.pem"]
