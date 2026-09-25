#!/bin/bash
set -e

mkdir -p /var/run/openvswitch /etc/openvswitch

# Initialize the OVS database only if it doesn't already exist
if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

# Start ovsdb-server directly (bypasses ovs-ctl's dbus-touching steps)
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --private-key=db:Open_vSwitch,SSL,private_key \
    --certificate=db:Open_vSwitch,SSL,certificate \
    --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert \
    --pidfile --detach --log-file

ovs-vsctl --no-wait init
ovs-vsctl --no-wait set Open_vSwitch . external-ids:system-id=random

# Load kernel module if available on host (harmless if it fails — e.g. already built-in)
modprobe openvswitch 2>/dev/null || true

ovs-vswitchd --pidfile --detach --log-file

exec "$@"
