#!/usr/bin/env python3
"""
Topología mínima: h1 --- r1, con r1 corriendo FRR (RIPv2 + auth MD5).
Banco de pruebas local para validar inject_rip.py antes del objetivo real.

"""

from mininet.net import Mininet
from mininet.node import Node
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info

RIP_KEY_ID = 1
RIP_KEY = "abc123"

R1_H1_IP = "10.0.1.1/24"
H1_IP = "10.0.1.10/24"

FRR_BIN_DIR = "/usr/lib/frr"  # ajustar según instalación


class LinuxRouter(Node):
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0")
        super(LinuxRouter, self).terminate()


def build_topo():
    net = Mininet(controller=None, link=TCLink)

    r1 = net.addHost("r1", cls=LinuxRouter, ip=None)
    h1 = net.addHost("h1", ip=H1_IP)
    net.addLink(h1, r1, intfName2="r1-eth0", params2={"ip": R1_H1_IP})

    net.build()
    configure_frr(r1)

    return net, r1, h1


def configure_frr(r1):
    frr_dir = f"/tmp/frr-{r1.name}"
    r1.cmd(f"mkdir -p {frr_dir}")

    zebra_conf = f"""hostname {r1.name}
log file {frr_dir}/zebra.log
!
interface r1-eth0
 ip address {R1_H1_IP}
!
"""

    ripd_conf = f"""hostname {r1.name}
log file {frr_dir}/ripd.log
!
key chain RIP_KEYS
 key {RIP_KEY_ID}
  key-string {RIP_KEY}
!
interface r1-eth0
 ip rip authentication mode md5
 ip rip authentication key-chain RIP_KEYS
!
router rip
 version 2
 network r1-eth0
 redistribute connected
!
"""

    with open(f"{frr_dir}/zebra.conf", "w") as f:
        f.write(zebra_conf)
    with open(f"{frr_dir}/ripd.conf", "w") as f:
        f.write(ripd_conf)

    r1.cmd(f"{FRR_BIN_DIR}/zebra -d -f {frr_dir}/zebra.conf "
           f"-z {frr_dir}/zebra.sock -i {frr_dir}/zebra.pid")
    r1.cmd(f"{FRR_BIN_DIR}/ripd -d -f {frr_dir}/ripd.conf "
           f"-z {frr_dir}/zebra.sock -i {frr_dir}/ripd.pid")


def main():
    setLogLevel("info")
    net, r1, h1 = build_topo()

    info(f"\n*** RIPv2 + auth MD5 corriendo en r1-eth0. Key: '{RIP_KEY}' (id {RIP_KEY_ID})\n")
    info("*** Captura de referencia: r1 tcpdump -i r1-eth0 -w /tmp/rip_ref.pcap udp port 520 &\n\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()