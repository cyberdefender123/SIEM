import Parser
import datetime
import time

def Specific_Port(c):
    'Alerts if specific ports - 444 or 4445 were contacted'
    query = "SELECT SRC_IP FROM fwlogs WHERE PORT=444 OR PORT=4445"
    c.execute(query)
    list_of_ips = set(c)
    if len(list_of_ips) >= 1:
        return "{} {} {}".format('Alert!', list_of_ips, 'has tried to connect to port 444 and/or 4445')


def PortScan(c):
    'Alerts if more than 10 ports were contacted by the same ip address'
    query = "SELECT SRC_IP, DST_IP, PORT FROM fwlogs"
    c.execute(query)
    ip_dict = dict()

    for ip in c:
        src_dst = ip[0] + ' ' + ip[1]
        port = ip[2]
        if src_dst in ip_dict:
            ip_dict[src_dst].add(port)
        else:
            ip_dict[src_dst] = set([port])

    alerts = ""
    for ip in ip_dict:
        if len(ip_dict[ip]) >= 10:
            alerts += "{} {} {} {} {}\n".format('Alert!', ip.split()[0], 'has scanned', len(ip_dict[ip]), 'different ports of mine')
    return alerts


def PingSweep(c):
    'Alerts if a ping sweep was done - source ip contacted more than 10 destination ips'
    query = "SELECT SRC_IP, DST_IP FROM fwlogs WHERE PORT=0"
    c.execute(query)
    src_ip_dict = dict()

    for ip in c:
        src_ip = ip[0]
        dst_ip = ip[1]
        if src_ip in src_ip_dict:
            src_ip_dict[src_ip].add(dst_ip)
        else:
            src_ip_dict[src_ip] = set([dst_ip])

    alerts = ""
    for ip in src_ip_dict:
        if len(src_ip_dict[ip]) >= 10:
            alerts += "{} {} {} {} {}".format('Alert!', src_ip, 'has scanned', len(src_ip_dict[ip]), 'different destination IPs')
    return alerts


def PingSweepWithTime(c):
    'Alerts if more than 10 destination ips were contacted in less than 10 seconds'
    query = "SELECT SRC_IP, DST_IP, DATE FROM fwlogs WHERE PORT=0"
    c.execute(query)
    src_ip_date_dict = dict()

    for ip in c:
        src_ip = ip[0]
        dateandtime = ip[2]
        if src_ip in src_ip_date_dict:
            src_ip_date_dict[src_ip].append(dateandtime)
        else:
            src_ip_date_dict[src_ip] = [dateandtime]

    alerts = ""
    for ip in src_ip_date_dict:
        if len(src_ip_date_dict[ip]) >= 10:
            difference_in_time = GetTimeDifferences(src_ip_date_dict[ip][0], src_ip_date_dict[ip][-1])
            if difference_in_time >= 10:
                alerts += "{} {} {} {} {} {} {}".format('Alert!', src_ip, 'has scanned', len(src_ip_date_dict[ip]), 'different destination IPs in', difference_in_time[1], 'seconds')
    return alerts


def GetTimeDifferences(start, end):
    'Calculates difference in time between 2 logs'
    c = end - start
    return divmod(c.days * 86400 + c.seconds, 60)


def main():
    'set the Analyser to run every 5 seconds. The sets of old alerts and new alerts is to counteract problem of the analyser returning the same alerts repeatedly each time it is run'
    old_alerts = set()
    cnx, cursor = Parser.ConnectToDB()
    while True:
        new_alerts = set()
        new_alerts.add(Specific_Port(cursor))
        new_alerts.add(PortScan(cursor))
        new_alerts.add(PingSweep(cursor))
        new_alerts.add(PingSweepWithTime(cursor))
        for alert in new_alerts.difference(old_alerts):
            print alert
        old_alerts = old_alerts.union(new_alerts)
        time.sleep(5)

if __name__ == "__main__":
    main()