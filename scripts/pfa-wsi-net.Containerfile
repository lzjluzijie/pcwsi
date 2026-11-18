# The PFA-WSI artifact image plus iproute2 and ping, so that a container can shape its own loopback with tc and check it.
# Build the artifact image first from its repository (~/dev/pfa-wsi): podman build -t localhost/pfa-wsi .
# Then: podman build -t localhost/pfa-wsi-net -f scripts/pfa-wsi-net.Containerfile scripts
FROM localhost/pfa-wsi
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iputils-ping && rm -rf /var/lib/apt/lists/*
