#!/usr/bin/python

import re

def main():

    is_tcp = False
    is_udp = False

    port_to_client_times = {}
    conn_est_interval = []
    client_bandwidths = []
    reads = []
    total_times = []
    total_transfers = []
    server_bandwidths = []
    retries = []
    rtts = []

    transfers = []
    ppss = []
    jitters = []
    lost_pkts = []
    total_pkts = []
    latencies = []


    server_cnt = 1
    client_cnt = 4

    while client_cnt <= 6:
        with open('h%s.txt' % client_cnt) as f:
            for line in f:
                if not is_udp and not is_tcp:
                    if "UDP" in line:
                        is_udp = True
                    elif "TCP" in line:
                        is_tcp = True
                    continue
                content = re.findall(r'(?:"[^"]*"|[^\s"])+', line)
                if "connected" in line:
                    client_time = float(content[len(content) - 1][:-1])
                    conn_port = content[len(content) - 8]
                    port_to_client_times[conn_port] = client_time
                    continue

                if "Bandwidth" in line:

                    bandwidth = float(content[1])
                    if "Kbits" in line:
                        bandwidth /= float(1000)
                    client_bandwidths.append(bandwidth)
                    continue

                if is_tcp:
                    if "RetryO" in line:
                        retries.append(float(content[1]))
                    elif "RTTO" in line:
                        rtts.append(float(content[1]))
        client_cnt += 1
    while server_cnt <= 3:
        with open('h%s.txt' % server_cnt) as f:
            for line in f:
                content = re.findall(r'(?:"[^"]*"|[^\s"])+', line)
                
                if "connected" in line:
                    conn_port = content[len(content) - 3]
                    if conn_port in port_to_client_times:
                        server_time = float(content[len(content) - 1][:-1])
                        conn_est_interval.append((server_time - port_to_client_times[conn_port]) / float(1000000))
                    continue

                if "Bandwidth" in line:
                    bandwidth = float(content[1])
                    if "Kbits" in line:
                        bandwidth /= float(1000)
                    server_bandwidths.append(bandwidth)
                    continue

                if is_tcp:                    
                    if "Reads" in line:
                        reads.append(float(content[1]))                    
                elif is_udp:
                    if "Jitter" in line:
                        jitters.append(float(content[1]))
                    elif "LostO" in line:
                        lost_pkts.append(float(content[1]))
                    elif "TotalO" in line:
                        total_pkts.append(float(content[1]))
                    elif "LatencyAvg" in line:
                        latencies.append(float(content[1]))
                    elif "PPSO" in line:
                        ppss.append(float(content[1]))

                if "TotalTime" in line:
                    total_times.append(float(content[1]))
                        
                if "Transfer" in line:
                    transfersize = float(content[1])
                    if "KBytes" in line:
                        transfersize /= float(1000)
                    total_transfers.append(transfersize)
                    
                    
        server_cnt += 1

    # Print Results
    if is_tcp:
        print("Ave.Delay(Ryu):\t" + str(mean(conn_est_interval)) + " ms")
        print("Transfer Time:\t" + str(max(total_times)) + " secs")
        print("Total Transfer:\t" + str(sum(total_transfers)) + " MBytes")
        print(total_transfers);
        print("Ave.Server TP:\t" + str(mean(server_bandwidths)) + " Mbits/sec")        
        print("Tot.Reads:\t" + str(sum(reads)))
        print("Ave.Client TP:\t" + str(mean(client_bandwidths)) + " Mbits/sec")
        print("Ave.Retries:\t" + str(mean(retries)))
        print("Ave.RTT:\t" + str(mean(rtts)))
        print("\nCopy Below!")
        print(str(mean(conn_est_interval)) + "," + \
            str(max(total_times)) + "," + \
            str(sum(total_transfers)) + "," + \
            str(mean(server_bandwidths)) + "," + \
            str(sum(reads)) + ",,,,,,,,,,," + \
            str(mean(client_bandwidths)) + "," + \
            str(sum(retries)) + "," + \
            str(mean(rtts))
        ) 
    elif is_udp:
        print("Ave.Delay(Ryu):\t" + str(mean(conn_est_interval)) + " ms")
        print("Transfer Time:\t" + str(max(total_times)) + " secs")
        print("Total Transfer:\t" + str(sum(total_transfers)) + "Mbytes")
        print("Ave.Server TP:\t" + str(mean(server_bandwidths)) + " Mbits/sec")
        print("Ave.Jitter:\t" + str(mean(jitters)) + " ms")
        print("Tot.Loss:\t" + str(sum(lost_pkts)))
        print("Tot.Total:\t" + str(sum(total_pkts)))
        print("Ratio Loss:\t" + str(sum(lost_pkts) / sum(total_pkts)))
        print("Avg.Latency:\t" + str(mean(latencies)) + " ms")
        print("Avg.PPS:\t" + str(mean(ppss)))
        print("Ave.Client TP:\t" + str(mean(client_bandwidths)) + " Mbits/sec")
        print("\nCopy Below!")
        print(str(mean(conn_est_interval)) + "," + \
            str(max(total_times)) + "," + \
            str(sum(total_transfers)) + "," + \
            str(mean(server_bandwidths)) + ",," + \
            str(mean(jitters)) + ",," + \
            str(sum(lost_pkts)) + "," + \
            str(sum(total_pkts)) + "," + \
            str(sum(lost_pkts) / sum(total_pkts)) + ",," + \
            str(mean(latencies)) + ",," + \
            str(mean(ppss)) + ",," + \
            str(mean(client_bandwidths))
        )
        

def mean(data):
    """Return the sample arithmetic mean of data."""
    n = len(data)
    if n < 1:
        raise ValueError('mean requires at least one data point')
    return sum(data)/float(n) # in Python 2 use sum(data)/float(n)

if __name__ == "__main__":
    main()
