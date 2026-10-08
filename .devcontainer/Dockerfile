FROM mcr.microsoft.com/vscode/devcontainers/base:ubuntu-22.04

RUN apt-get update \
 && apt-get install -y build-essential

RUN apt-get install -y python3 python3-pip python3-dev python-is-python3

# uv static binary, pinned by digest; Renovate updates the tag and the digest together. Installs the Python workspace (install.dependencies.sh)
COPY --from=ghcr.io/astral-sh/uv:0.12.9@sha256:8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff /uv /usr/local/bin/uv

RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - \
 && apt-get install -y nodejs \
 && corepack enable

RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null \
 && apt-get update \
 && apt-get install -y docker-ce

RUN curl -SL https://github.com/docker/compose/releases/download/v2.5.1/docker-compose-linux-x86_64 -o /usr/bin/docker-compose \
 && chmod +x /usr/bin/docker-compose \
 && usermod -aG docker vscode

RUN apt-get install -y git dnsutils net-tools iputils-ping netcat