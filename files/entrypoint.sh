#!/bin/bash

echo "Starting SSHD..."
/usr/sbin/sshd

rm -f /var/lib/teleport/debug.sock

echo "Starting Teleport..."
/usr/local/bin/teleport start -c /etc/teleport/teleport.yaml &

echo "Waiting for Teleport to start..."
while ! tctl status; do
  echo "Teleport is not ready yet..."
  sleep 5
done

echo "Exporting Teleport CA key..."
tctl auth export --type user | sed 's/cert-authority //' > /etc/ssh/teleport.ca.key

echo "sleep infinity..."
sleep infinity