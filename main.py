#!/usr/bin/env python3

import bisect
import collections
import ipaddress

from prettytable import PrettyTable

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
               f"with {len(self.views)} entries"

    def methodname(self):
        return f"{str(self.__class__).split('.')[-1][:-2]}"

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


@registerMethod
class MethodBisectSortedNoScan(MethodBase):
    def __init__(self, views):
        self.views = []
        for k,v in views.items():
            self.views.append(ipaddress.get_mixed_type_key(ipaddress.ip_network(k).broadcast_address) + (ipaddress.ip_network(k), v))
        self.views.sort()
        # print(self.views)

    def lookup(self, ip):
        i = bisect.bisect(self.views, ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)))
        res = self.views[i]
        print(res)
        if ipaddress.ip_address(ip) in res[2]:
            return ViewLookupResult(ip, res[1], res[3], 0)
        else:
            return ViewLookupResult(ip, None, None, 0)

@registerMethod
class MethodBisectSortedScan(MethodBase):
    def __init__(self, views):
        self.views = []
        for k,v in views.items():
            self.views.append((ipaddress.get_mixed_type_key(ipaddress.ip_network(k).broadcast_address), (ipaddress.ip_network(k), v)))
        self.views.sort()
        print(self.views)

    def lookup(self, ip):
        ops = 0
        i = bisect.bisect(self.views, (ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)),))
        res = None
        prefixlen = -1
        for idx in range(i, len(views)):
            tmp = self.views[i]
            print(tmp)
            print(ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)))
            print(ipaddress.ip_address(ip),"in",tmp[1][0], ipaddress.ip_address(ip) in tmp[1][0])
            if ipaddress.ip_address(ip) in tmp[1][0] and tmp[1][0].prefixlen > prefixlen:
                print("got prefixlen", tmp[1][0].prefixlen)
                res = tmp
                prefixlen = tmp[1][0].prefixlen
            else:
                print

            if tmp[0] < ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)):
                print("breaking")
                print(tmp[0], ">", ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)))
                break
        if res:
            print(res)
            return ViewLookupResult(ip, res[1][0], res[1][1], ops)
        else:
            return ViewLookupResult(ip, None, None, 0)


if __name__ == '__main__':
    table = PrettyTable()
    table.add_column("IP", list(ips.keys()) + ["Total"])
    for method in methods:
        methodresults = []
        db = method(views)
        # table.field_names.append(db.methodname()[6:])
        print(f"testing {db}")
        ops = 0
        for ip, view in ips.items():
            res = db.lookup(ip)
            print(f"{res.ip} in {res.net} with view {res.view}, {res.ops} ops")
            # assert res.view == view
            ops += res.ops
            methodresults.append((res.view, res.ops if res.view == view else -1))
            # ipresults[ip] =
        methodresults.append(ops)
        print(f"total {ops} ops")
        table.add_column(db.methodname()[6:], methodresults)
    print(table.field_names)
    print(table)
