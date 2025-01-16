#!/usr/bin/env python3

import bisect
import ipaddress
import psycopg

from collections import namedtuple
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


ViewLookupResult = namedtuple('ViewLookupResult', ('ip', 'net', 'view'))


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
        return ViewLookupResult(ip, net, view)


@registerMethod
class MethodBisectSortedNoScan(MethodBase):
    def __init__(self, views):
        self.views = []
        for k, v in views.items():
            self.views.append(ipaddress.get_mixed_type_key(ipaddress.ip_network(k).broadcast_address) + (ipaddress.ip_network(k), v))
        self.views.sort()
        # print(self.views)

    def lookup(self, ip):
        i = bisect.bisect(self.views, ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)))
        res = self.views[i]
        print(res)
        if ipaddress.ip_address(ip) in res[2]:
            return ViewLookupResult(ip, res[1], res[3])
        else:
            return ViewLookupResult(ip, None, None)


@registerMethod
class MethodBisectSortedScan(MethodBase):
    def __init__(self, views):
        self.views = []
        for k, v in views.items():
            self.views.append((ipaddress.get_mixed_type_key(ipaddress.ip_network(k).broadcast_address), (ipaddress.ip_network(k), v)))
        self.views.sort()
        print(self.views)

    def lookup(self, ip):
        ops = 0
        i = bisect.bisect(self.views, (ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)),))
        print(i)
        res = None
        prefixlen = -1
        for idx in range(i, len(views)):
            tmp = self.views[idx]
            print(tmp)
            print(ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)))
            print(ipaddress.ip_address(ip), "in", tmp[1][0], ipaddress.ip_address(ip) in tmp[1][0])
            if ipaddress.ip_address(ip) in tmp[1][0] and tmp[1][0].prefixlen > prefixlen:
                print("got prefixlen", tmp[1][0].prefixlen)
                res = tmp
                prefixlen = tmp[1][0].prefixlen

            if tmp[0] < ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)):
                print("breaking")
                print(tmp[0], ">", ipaddress.get_mixed_type_key(ipaddress.ip_address(ip)))
                break

            ops += 1
        if res:
            print(res)
            return ViewLookupResult(ip, res[1][0], res[1][1])
        else:
            return ViewLookupResult(ip, None, None)

@registerMethod
class MethodPostgresSimple(MethodBase):
    def __init__(self, views):
        self.views = views
        with psycopg.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS views;")
                cur.execute("CREATE TABLE views (net cidr, tag int);")
                for k,v in views.items():
                    cur.execute(f"insert into views values('{k}', {v});")

    def lookup(self, ip):
        with psycopg.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"select net, tag from views where inet('{ip}') <<= net order by masklen(net) desc limit 1;")
                res = cur.fetchone()
                if res:
                    return ViewLookupResult(ip, res[0], res[1])
                else:
                    return ViewLookupResult(ip, None, None)


# this *has* to run after PostgresSimple
@registerMethod
class MethodPostgresDouble(MethodBase):
    def __init__(self, views):
        self.views = views
        with psycopg.connect() as conn:
            with conn.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS viewmap;")
                cur.execute("CREATE TABLE viewmap (net cidr, netmin inet, netmax inet, tag int);")
                cur.execute("insert into viewmap select net, host(net)::inet, host(broadcast(net))::inet, tag from views;")

    def lookup(self, ip):
        with psycopg.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"select net, tag from viewmap where inet('{ip}') >= netmin order by netmin desc limit 1;")
                res1 = cur.fetchone()
                cur.execute(f"select net, tag from viewmap where inet('{ip}') <= netmax order by netmax asc limit 1;")
                res2 = cur.fetchone()

                res = None

                print(ip, end=" ")
                for res_ in (res1, res2):
                    net, tag = res_
                    b = ipaddress.ip_address(ip) in ipaddress.ip_network(net)
                    if b:
                        print("in", net, end="; ")
                        res = res_
                    else:
                        print("NOT in", net, end="; ")

                if res:
                    return ViewLookupResult(ip, res[0], res[1])
                else:
                    return ViewLookupResult(ip, None, None)



if __name__ == '__main__':
    table = PrettyTable()
    table.add_column("IP", list(ips.keys()))
    for method in methods:
        methodresults = []
        db = method(views)
        # table.field_names.append(db.methodname()[6:])
        print(f"testing {db}")
        ops = 0
        for ip, view in ips.items():
            res = db.lookup(ip)
            print(f"{res.ip} in {res.net} with view {res.view}")
            # assert res.view == view
            if res.view == view:
                methodresults.append(res.view)
            else:
                methodresults.append('XXX')
            # ipresults[ip] =
        table.add_column(db.methodname()[6:], methodresults)
    print(table.field_names)
    print(table)
