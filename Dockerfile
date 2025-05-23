# Use Ubuntu 22.04 as the base image
FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update package list and install required packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssh-server \
    openssh-client \
    curl \
    gnupg \
    && mkdir /run/sshd

# Install Teleport
RUN curl https://goteleport.com/static/install.sh | bash -s 17.4.10
RUN rm -rf /var/lib/apt/lists/*

COPY files/openssh/* /etc/ssh/sshd_config.d/
COPY files/entrypoint.sh /entrypoint.sh

# Expose SSH port
# EXPOSE 22

# Set default command
ENTRYPOINT ["/bin/bash","/entrypoint.sh"]
