#!/usr/bin/python

import re

# server_cnt = 1
# while server_cnt <= 3:
#         with open('h%s.txt' % server_cnt) as f:
#             for line in f:
#                 if "MBytes" in line and "SUM" not in line:
#                     content = re.findall(r'(?:"[^"]*"|[^\s"])+', line)
#                     print(content[5])
#                     print(content[7])
#                     print(content[9])
#                     print(content[11][:-1])
#                     print(content[12])
                    
#         server_cnt += 1

def main():
    is_udp = False
    is_tcp = False
    server_cnt = 1
    ttots = []
    tputs = []
    jitts = []
    losts_dgrams = []
    tot_dgrams = []

    while server_cnt <= 3:
        with open('h%s.txt' % server_cnt) as f:
            for line in f:
                if not is_udp and not is_tcp:
                    if "UDP" in line:
                        is_udp = True
                    elif "TCP" in line:
                        is_tcp = True
                if is_tcp:
                    if "MBytes" in line and "SUM" not in line:
                        content = re.findall(r'(?:"[^"]*"|[^\s"])+', line)
                        bwidth = float(content[len(content)-2])
                        if "Kbits" in line:
                            bwidth = bwidth / float(1024)
                        tputs.append(bwidth)
                elif is_udp:
                    if "MBytes" in line and "SUM" not in line:
                        content = re.findall(r'(?:"[^"]*"|[^\s"])+', line)
                        ttots.append(float(content[len(content)-9]))
                        bwidth = float(content[len(content)-7])
                        if "Kbits" in line:
                            bwidth = bwidth / float(1024)
                        tputs.append(bwidth)
                        jitts.append(float(content[len(content)-5]))
                        losts_dgrams.append(float(content[len(content)-3][:-1]))
                        tot_dgrams.append(float(content[len(content)-2]))

        server_cnt += 1

    if is_tcp:
        print('Servers')
        print('Mean ' + str(mean(tputs)))
        print('SDev ' + str(stddev(tputs)))
        print('Min  ' + str(min(tputs)))
        print('Max  ' + str(max(tputs)))
    elif is_udp:
        print('Servers')
        print('TTot   ' + str(sum(ttots)))
        print('MTput  ' + str(mean(tputs)))
        print('MJitts ' + str(mean(jitts)))
        print('Lost   ' + str(sum(losts_dgrams)))
        print('Total  ' + str(sum(tot_dgrams)))
        print('%      ' + str(sum(losts_dgrams) / sum(tot_dgrams)))


    client_cnt = 4
    ttots = []
    tputs = []
    jitts = []
    losts_dgrams = []
    tot_dgrams = []
    try:
        while client_cnt <= 6:
            with open('h%s.txt' % client_cnt) as f:
                dont_read_next = False
                for line in f:
                    if not is_udp and not is_tcp:
                        if "UDP" in line:
                            is_udp = True
                        elif "TCP" in line:
                            is_tcp = True
                    if is_tcp:
                        if "MBytes" in line and "SUM" not in line:
                            content = re.findall(r'(?:"[^"]*"|[^\s"])+', line)
                            bwidth = float(content[len(content)-2])
                            if "Kbits" in line:
                                bwidth = bwidth / float(1024)
                            tputs.append(bwidth)
                    elif is_udp:
                        if "Server" in line:
                            dont_read_next = True

                        if "MBytes" in line and "SUM" not in line:
                            if dont_read_next:
                                dont_read_next = False
                            else:
                                content = re.findall(r'(?:"[^"]*"|[^\s"])+', line)
                                ttots.append(float(content[len(content)-4]))
                                bwidth = float(content[len(content)-2])
                                if "Kbits" in line:
                                    bwidth = bwidth / float(1024)
                                tputs.append(bwidth)
            client_cnt += 1
    except IOError:
        pass
    print '' 
    if is_tcp:
        print('Clients')
        print('Mean ' + str(mean(tputs)))
        print('SDev ' + str(stddev(tputs)))
        print('Min  ' + str(min(tputs)))
        print('Max  ' + str(max(tputs)))
    elif is_udp:
        print('Clients')
        print('TTot   ' + str(sum(ttots)))
        print('MTput  ' + str(mean(tputs)))

    client_cnt = 4
    timeputs = []
    try:
        while client_cnt <= 6:
            with open('h%sT.txt' % client_cnt) as f:
                for line in f:
                   content = line.split(" ")
                   timeputs.append(int(content[0]))
            client_cnt += 1
    except IOError:
        pass

    min_time = min(timeputs)
    max_time = max(timeputs)
    interval_time = max_time - min_time
    interval_time_secs = interval_time / float(1000000000)

    print ('')
    print('Time')
    print('From     ' + str(min_time))
    print('To       ' + str(max_time))
    print('Interval ' + str(interval_time))
    print('Intrvl s ' + str(interval_time_secs))
    
def mean(data):
    """Return the sample arithmetic mean of data."""
    n = len(data)
    if n < 1:
        raise ValueError('mean requires at least one data point')
    return sum(data)/float(n) # in Python 2 use sum(data)/float(n)

def _ss(data):
    """Return sum of square deviations of sequence data."""
    c = mean(data)
    ss = sum((x-c)**2 for x in data)
    return ss

def stddev(data, ddof=0):
    """Calculates the population standard deviation
    by default; specify ddof=1 to compute the sample
    standard deviation."""
    n = len(data)
    if n < 2:
        raise ValueError('variance requires at least two data points')
    ss = _ss(data)
    pvar = ss/(n-ddof)
    return pvar**0.5

if __name__ == "__main__":
    main()