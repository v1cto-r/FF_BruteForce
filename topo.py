import argparse
import time

from mininet.net import Mininet
from mininet.node import Node, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI

# editar aquí para la prueba
RIP_KEY = "xy548"
RIP_KEY_ID = 1

SPOOFER_PATH = "/data/FF_BruteForce/spoofer.py"
OUT_DIR = "/data/FF_BruteForce"

class Router(Node):
    def config(self, **params):
        super(Router, self).config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')
        self.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0')
        self.cmd('sysctl -w net.ipv4.conf.default.rp_filter=0')
        self.cmd(f'install -d -m 0777 /tmp/{self.name}')

        self.cmd(f'/usr/lib/frr/mgmtd -d --vty_socket /tmp/{self.name} '
                  f'-i /tmp/{self.name}.mgmtd.pid')
        self.cmd(f'/usr/lib/frr/zebra -d --vty_socket /tmp/{self.name} '
                  f'-i /tmp/{self.name}.zebra.pid')
        self.cmd(f'/usr/lib/frr/ripd -d --vty_socket /tmp/{self.name} '
                  f'-i /tmp/{self.name}.ripd.pid')
        self.cmd(f'chmod 777 /tmp/{self.name}* /tmp/{self.name}*.pid 2>/dev/null')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        self.cmd("pkill -9 -f 'mgmtd|zebra|ripd'")
        self.cmd(f'rm -f /tmp/{self.name} /tmp/{self.name}.*.pid')
        super(Router, self).terminate()

    def vtysh(self, *cmds):
        args = " ".join(f'-c "{c}"' for c in cmds)
        return self.cmd(f'vtysh --vty_socket /tmp/{self.name} {args}')

    def applyRoutingRIP(self, networks):
        self.vtysh("configure terminal", "router rip", "version 2", "end")
        for network in networks:
            self.vtysh("configure terminal", "router rip", f"network {network}", "end")

    def applyAuthRIP(self, key, key_id=RIP_KEY_ID):
        self.vtysh(
            "configure terminal",
            "key chain RIP_KEYS",
            f"key {key_id}",
            f"key-string {key}",
            "end",
        )
        for intf in self.intfNames():
            if intf == "lo":
                continue
            self.vtysh(
                "configure terminal",
                f"interface {intf}",
                "ip rip authentication mode md5",
                "ip rip authentication key-chain RIP_KEYS",
                "end",
            )


def build_topo():
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)

    routers = [net.addHost(f'r{i}', ip=None, cls=Router) for i in range(3)]
    h1 = net.addHost('h1', ip='10.0.1.10/24', defaultRoute='via 10.0.1.254')
    h2 = net.addHost('h2', ip='10.0.2.10/24', defaultRoute='via 10.0.2.254')

    net.addLink(routers[0], routers[1])
    net.addLink(routers[1], routers[2])
    net.addLink(h1, routers[0])
    net.addLink(h2, routers[2])

    net.start()

    routers[0].setIP('172.16.50.1/30', intf='r0-eth0')
    routers[0].setIP('10.0.1.254/24', intf='r0-eth1')
    routers[0].applyRoutingRIP(['172.16.50.0/30', '10.0.1.0/24'])
    routers[0].applyAuthRIP(RIP_KEY)

    routers[1].setIP('172.16.50.2/30', intf='r1-eth0')
    routers[1].setIP('172.16.50.5/30', intf='r1-eth1')
    routers[1].applyRoutingRIP(['172.16.50.0/30', '172.16.50.4/30'])
    routers[1].applyAuthRIP(RIP_KEY)

    routers[2].setIP('172.16.50.6/30', intf='r2-eth0')
    routers[2].setIP('10.0.2.254/24', intf='r2-eth1')
    routers[2].applyRoutingRIP(['172.16.50.4/30', '10.0.2.0/24'])
    routers[2].applyAuthRIP(RIP_KEY)

    return net, routers, h1, h2

def start_capture(node, iface, pcap_path):
    node.cmd(f'mkdir -p {OUT_DIR}')
    node.cmd(f'tcpdump -i {iface} -w {pcap_path} udp port 520 '
              f'> /dev/null 2>&1 & echo $! > /tmp/tcpdump_{node.name}.pid')


def stop_capture(node):
    node.cmd(f'kill $(cat /tmp/tcpdump_{node.name}.pid) 2>/dev/null')


def dump_routes(routers, out_path):
    with open(out_path, 'w') as f:
        for r in routers:
            f.write(f'{r.name}:\n')
            f.write(r.vtysh('show ip route'))
            f.write('\n')
    print(open(out_path).read())


def run_auto_injection(routers, h1, key):
    print('Esperando convergencia inicial de RIP')
    time.sleep(5)

    dump_routes(routers, f'{OUT_DIR}/routes_before.txt')

    start_capture(routers[0], 'r0-eth1', f'{OUT_DIR}/inject_capture.pcap')

    print(f'Inyectando con spoofer.py en h1 (key={key})')
    print(h1.cmd(f'python3 {SPOOFER_PATH} {key}'))

    print('Esperando a que FRR procese la ruta envenenada')
    time.sleep(5)

    stop_capture(routers[0])
    dump_routes(routers, f'{OUT_DIR}/routes_after.txt')

    print(f'Listo. Resultados en {OUT_DIR}/ '
          f'(inject_capture.pcap, routes_before.txt, routes_after.txt)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key",
    )
    args = parser.parse_args()

    net, routers, h1, h2 = build_topo()

    if args.key:
        run_auto_injection(routers, h1, args.key)
        net.stop()
    else:
        routers[0].cmd(f'mkdir -p {OUT_DIR}')
        start_capture(routers[0], 'r0-eth0', f'{OUT_DIR}/capture.pcap')
        print(f"\nRIPv2 + auth MD5 corriendo. Key: '{RIP_KEY}' (id {RIP_KEY_ID})")
        print(f"Capturando tráfico RIP en {OUT_DIR}/capture.pcap "
              "escribe 'exit' para detener (Espera unos segundos).\n")
        CLI(net)
        stop_capture(routers[0])
        net.stop()


if __name__ == "__main__":
    main()
