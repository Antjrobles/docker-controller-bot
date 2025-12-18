#!/bin/sh

# Setup SSH directory
mkdir -p /root/.ssh
chmod 700 /root/.ssh

# Copy keys and config from mounted volume if available
# We use a different mount point in docker-compose to avoid permission issues directly on /root/.ssh
if [ -d "/ssh-keys" ]; then
    echo "Setting up SSH keys from volume..."
    cp -R /ssh-keys/* /root/.ssh/
    
    # Fix permissions and ownership for SSH to be happy
    chown -R root:root /root/.ssh
    chmod 600 /root/.ssh/*
    chmod 644 /root/.ssh/*.pub 2>/dev/null || true
    chmod 700 /root/.ssh
    
    # Disable StrictHostKeyChecking to allow non-interactive connections to new hosts
    echo "StrictHostKeyChecking no" >> /root/.ssh/config
    echo "UserKnownHostsFile /dev/null" >> /root/.ssh/config
    
    echo "SSH keys setup complete."
fi

# Execute the main command
exec "$@"