#!/usr/bin/env python3

import bisect
import ipaddress

views = {
    '192.0.2.0/24': 1,
    '10.0.0.0/8': 2,
    '10.0.4.0/24': 3,
    '2001:db8::/32': 4,
}

ips = {
    '192.0.2.5': 1,
    '10.0.0.1': 2,
    '10.0.4.1': 3,
    '10.0.4.255': 3,
    '10.8.5.2': 2,
    '192.168.0.1': None,
    '2001:db8::1234': 4,
}

methods = []


def registerMethod(cls):
    methods.append(cls)


class ViewLookupResult:
    def __init__(self, ip, net, view, ops):
        self.ip = ip
        self.net = net
        self.view = view
        self.ops = ops


class MethodBase:
    def __str__(self):
        return f"{str(self.__class__).split('.')[-1][:-2]} " \
                "with {len(self.views)} entries"


@registerMethod
class MethodScan(MethodBase):
    def __init__(self, views):
        self.views = dict()
        for k, v in views.items():
            self.views[ipaddress.ip_network(k)] = v

    def lookup(self, ip):
        prefix = 0
        ip = ipaddress.ip_address(ip)
        net = None
        view = None
        ops = 0
        for k, v in self.views.items():
            ops += 1
            if ip in k and k.prefixlen > prefix:
                net = k
                view = v
                prefix = k.prefixlen
        return ViewLookupResult(ip, net, view, ops)


if __name__ == '__main__':
    for method in methods:
        db = method(views)
        print(f"testing {db}")
        ops = 0
        for ip, view in ips.items():
            res = db.lookup(ip)
            print(f"{res.ip} in {res.net} with view {res.view}, {res.ops} ops")
            assert res.view == view
            ops += res.ops
        print(f"total {ops} ops")
