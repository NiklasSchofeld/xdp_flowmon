import os
import subprocess
import time
import argparse
from argparse import ArgumentParser

#get cli arguments
parser = ArgumentParser(description='run performance tests')
parser.add_argument('--sender',required=True, type=str, dest='sender', help="sending interface")
parser.add_argument('--receiver',required=True, type=str, dest='receiver', help="receiving interface")
parser.add_argument('--dut-interface',required=True, type=str, dest='dut_interface', help="receiving interface of the dut")
parser.add_argument('--dut-ip',required=True, type=str, dest='dut_ip', help="ip of the dut")
parser.add_argument('--pcap-dir',required=True, type=str, dest='pcap_dir', help="directory where all pcaps are saved")
parser.add_argument('--dest-mac',required=True, type=str, dest='dest_mac', help="Destination MAC of the traffic generator")
parser.add_argument('--search-duration',required=False, default=10,type=int, dest='search_duration', help="time in seconds each run during a search should last")
parser.add_argument('--test-duration',required=False, default=90,type=int, dest='test_duration', help="time in seconds each run during a test should last")
parser.add_argument('--test-replays',required=False, default=3,type=int, dest='test_replays', help="number of repetitions of a test")
parser.add_argument('--max-retries',required=False, default=3,type=int, dest='max_retries', help="number of retries when a test fails")
parser.add_argument('--max-packetloss',required=False, type=float, dest='max_packetloss', help="packetloss in % that will be searched")

args = parser.parse_args()
#TODO handle and log errors
#TODO save all raw data (tcpreplay output, ethtool -S output)

#set sending and receiving interfaces
sender = args.sender
receiver = args.receiver
dut_ip = args.dut_ip
dut_interface = args.dut_interface
pcap_path = args.pcap_dir
dest_mac = args.dest_mac
if args.max_packetloss:
    max_packetloss = args.max_packetloss
else:
    max_packetloss = 0.001

if args.max_retries:
    max_retries = args.max_retries
else:
    max_retries = 5

#id: int = 0
id = 0

#get transmitted and received packets before starting the traffic generator #TODO cleanup and make correct sender/receiver stats
##########
#functions
def log(text, file):
    with open(file, 'a') as f:
        f.write(text+'\n')
    return
def log_search_stats(stats: dict):
    #id pcap_file duration packet_size flow_count pps mbps sent received loss
    log_text = str(stats['id'])+' '+str(stats['pcap_file'])+' '+str(stats['duration'])+' '+str(stats['packet_size'])+' '+str(stats['flow_count'])+' '+str(stats['pps'])+' '+str(stats['mbps'])+' '+str(stats['sent_packets'])+' '+str(stats['received_packets'])+' '+str(stats['packet_loss'])
    log(log_text, 'log/search_stats')
    return
def log_test_stats(stats: dict):
    #id pcap_file duration packet_size flow_count pps mbps sent received loss
    log_text = str(stats['id'])+' '+str(stats['pcap_file'])+' '+str(stats['duration'])+' '+str(stats['packet_size'])+' '+str(stats['flow_count'])+' '+str(stats['pps'])+' '+str(stats['mbps'])+' '+str(stats['sent_packets'])+' '+str(stats['received_packets'])+' '+str(stats['packet_loss'])
    log(log_text, 'result_stats')
    return
def log_test_stats_userspace(stats: dict):
    #id pcap_file duration packet_size flow_count pps mbps sent received loss
    log_text = str(stats['id'])+' '+str(stats['pcap_file'])+' '+str(stats['duration'])+' '+str(stats['packet_size'])+' '+str(stats['flow_count'])+' '+str(stats['pps'])+' '+str(stats['mbps'])+' '+str(stats['sent_packets'])+' '+str(stats['received_packets'])+' '+str(stats['packet_loss'])
    log(log_text, 'result_stats_userspace')
    return
def log_test_raw_data(id: int, log_text: str):
    log('ID: '+str(id)+'\n'+log_text+'\n- - - - - - - - - - - - - - - - - - - -\n\n', 'log/raw_data_log')
    return
def log_error(id: int, log_text: str):
    log('ID: '+str(id)+'\n'+log_text+'\n- - - - - - - - - - - - - - - - - - - -\n\n', 'log/error_log')
    return

def get_tx_packets(interface):
    # tx_subp = subprocess.Popen('ethtool -S '+interface+' | grep tx_packets: | awk -F \' \' \'{print $2}\'', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    # return float(tx_subp.communicate()[0].removesuffix('\n'))
    ethtool_stats = subprocess.Popen('ethtool -S '+interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True).communicate()[0]
    log_test_raw_data(id,'ethtool -S '+interface+':\n'+ethtool_stats)
    stats_list = ethtool_stats.split(' ')
    for word in stats_list:
        if word == 'tx_packets:':
            tx = float(stats_list[stats_list.index(word)+1].removesuffix('\n'))
    return float(tx)
def get_rx_packets(interface):
    ethtool_stats = subprocess.Popen('ethtool -S '+interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True).communicate()[0]
    log_test_raw_data(id,'ethtool -S '+interface+':\n'+ethtool_stats)
    stats_list = ethtool_stats.split(' ')
    for word in stats_list:
        if word == 'rx_packets:':
            rx = float(stats_list[stats_list.index(word)+1].removesuffix('\n'))
        if word == 'rx_dropped:':
            missed = float(stats_list[stats_list.index(word)+1].removesuffix('\n'))
    rx_total = rx + missed
    return float(rx_total)

def parse_tcpreplay_output(out_text: str) -> dict:
    out_list = out_text.split()
    i = 0
    pps= -1
    mbps=-1
    flow_count=-1
    sent=-1
    failed=-1
    enobufs=-1
    eagain=-1

    for word in out_list:
        if word == 'pps':
            pps = out_list[i-1].removesuffix('\n')
        elif word == 'Mbps,':
            mbps = out_list[i-1].removesuffix('\n')
        elif word == 'flows,':
            flow_count = out_list[i-1].removesuffix('\n')
        elif word == 'Successful' and out_list[i+1] == 'packets:':
            sent = out_list[i+2].removesuffix('\n')
        elif word == 'Failed' and out_list[i+1] == 'packets:':
            failed = out_list[i+2].removesuffix('\n')
        elif word == 'Retried' and out_list[i+1] == 'packets' and out_list[i+2] == '(ENOBUFS):':
            enobufs = out_list[i+3].removesuffix('\n')
        elif word == 'Retried' and out_list[i+1] == 'packets' and out_list[i+2] == '(EAGAIN):':
            eagain = out_list[i+3].removesuffix('\n')
        i += 1
    
    return {"pps": float(pps),
            "mbps": float(mbps),
            "flow_count": int(flow_count),
            "sent_packets": int(sent),
            "failed": int(failed),
            "eagain": int(eagain),
            "enobufs": int(enobufs)}


def test_pps(flow_count: int, packets_per_second: int, duration: int, pcap_path: str, user_space: str, bpf_opts: str) -> dict:
    print("pcap_path: "+pcap_path)
    global id
    id += 1
    if bpf_opts == '':
        bpf_opts_arg = ''
    else:
        bpf_opts_arg = ' --bpf-opts '+bpf_opts

    dut_duration = duration + 22

    #get stats before traffic generation
    tx_before = get_tx_packets(sender)
    rx_before = get_rx_packets(receiver)
    # dropped_before = get_dropped_packets(receiver)

    #start script on DUT
    try:
        dut_script_subp = subprocess.Popen('ssh -i ~/equinix_key root@'+str(dut_ip)+' "python3 /root/dut_script.py --receiver '+str(dut_interface)+' --duration '+str(dut_duration)+' --dest-mac '+str(dest_mac)+' --id '+str(id)+' --user-space '+user_space+bpf_opts_arg+'"', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    except:
        print("ERROR - ssh dut-script")

    if flow_count == 1:
        change_ip_loops = 999999999999
    elif packets_per_second > 0:
        change_ip_loops = int((packets_per_second * duration) / flow_count +10) #ip will change after every change_ip_loops loops
    elif packets_per_second <= 0:
        print("can\'t perform test run with pps: "+str(packets_per_second)+" and flow count: not 1 (flow count is: "+str(flow_count)+")")
        exit(1)
    
    if packets_per_second <= 0: #send with topspeed
        traffic_generator_subp = subprocess.Popen('tcpreplay -K -t -i '+sender+' --duration='+str(duration)+' --unique-ip-loops='+str(change_ip_loops)+' --unique-ip --loop 999999999999999 --netmap '+pcap_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    else:
        traffic_generator_subp = subprocess.Popen('tcpreplay -K -i '+sender+' --duration='+str(duration)+' --pps '+str(packets_per_second)+' --unique-ip-loops='+str(change_ip_loops)+' --unique-ip --loop 999999999999999 --netmap '+pcap_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    
    #start traffic generator and wait until it ends
    traffic_generator_output = traffic_generator_subp.communicate() #waits until tcpreplay has finished
    #check error
    if traffic_generator_subp.returncode != 0:
        print("ERROR - tcpreplay: "+traffic_generator_output[1])
        log_error(id, 'ERROR - tcpreplay:\n'+traffic_generator_output[1])
        return {"error": -1}
    else:
        print(traffic_generator_output[0]+'\n')
    
    log_test_raw_data(id, 'tcpreplay:\n'+traffic_generator_output[0])
    tcpreplay_stats = parse_tcpreplay_output(traffic_generator_output[0])


    #count sent, received and dropped packets after traffic generator ran
    tx_after = get_tx_packets(sender)
    rx_after = get_rx_packets(receiver)
    #calculate tx and rx
    #tx = tx_after - tx_before
    tx = float(tcpreplay_stats['sent_packets'])
    # rx = rx_after - rx_before


    #check if xdp prog has stopped
    dut_script_output = dut_script_subp.communicate()   #waits for script to return
    #check error #TODO ssh will likely throw an error, because the connection will be lost
    if dut_script_subp.returncode != 0:
        print("ERROR - dut-script: "+dut_script_output[1])
        log_error(id, 'ERROR - dut_script:\n'+dut_script_output[1])
        return {'error': -1}

    rx = float(dut_script_output[0])

    #calculate packetloss
    if rx > tx:
        rx = tx
    packet_loss = (tx-rx)/tx
    print('packet loss: '+str(packet_loss))

    #prepare return stats
    pcap_file = pcap_path.split('/')[-1]
    try:
        packet_size = pcap_file.split('.')[0].split('_')[1]
    except:
        packet_size = 0    #when the name has not the format: [type]_[size].pcap

    test_run_stats = {'error': 0,
                      'id': id,
                      'pcap_file': pcap_file,
                      'duration': duration,
                      'packet_size': packet_size,
                      'received_packets': rx,
                      'packet_loss': packet_loss}
    test_run_stats.update(tcpreplay_stats)

    return test_run_stats



def test_run_management(pcap_dir: str, max_packet_loss: float):
    search_duration = args.search_duration
    test_duration = args.test_duration
    test_replays = args.test_replays
    flow_cnt_list = [1,2,10,100,1000,10000,100000,1000000,10000000]
    found = False
    global max_retries
    print(max_retries)

    testdir = './test_run__'+str(time.time())+'/'
    os.mkdir(testdir)
    os.chdir(testdir)
    os.mkdir('./log/')

    # os.chdir(pcap_dir)

    for pcap in os.listdir(pcap_dir):   #for all pcap files
        print("pcap_dir "+pcap_dir)
        if not pcap.endswith('.pcap'):
            continue         #skip non pcap files
        pps = 0 #indicates that max pps is used
        pps_before = -1

        for flow_cnt in flow_cnt_list:  #for all flow counts
            found = False
            retry_counter = 0
            
            while not found:            #search packet rate
                test_stats = test_pps(flow_count=flow_cnt, packets_per_second=pps, duration=search_duration, pcap_path=pcap_dir+pcap,user_space='False',bpf_opts='')
                if test_stats["error"] == -1:
                    retry_counter += 1
                    if retry_counter < max_retries+1:
                        continue
                    else:
                        log_error(id,"ERROR - too many SEARCH retries")
                        print("ERROR: exit, too many SEARCH retries with errors")
                        exit(1)
                packet_loss = test_stats['packet_loss']
                log_search_stats(test_stats)

                if pps_before == 0 and pps ==0:
                    pps = 1

                pps_before = pps
                if packet_loss > max_packet_loss and pps > 0:
                    pps = test_stats['pps'] / 2.0 #50% less pps
                    if int(pps/1000000) == int(pps_before/1000000):
                        pps = pps + 0.25*pps
                        print('+0.25')

                elif packet_loss <= 0 and pps > 0:
                    pps = test_stats['pps'] + test_stats['pps'] * 0.5 #50% more pps
                    if int(pps/1000000) == int(pps_before/1000000):
                        pps = pps - 0.25*pps
                        print('-0.25')

                elif packet_loss <= max_packet_loss and packet_loss >= 0:
                    found = True #found
                    
                    #perform test
                    i=0
                    retry_counter = 0
                    while i < test_replays:
                        test_stats = test_pps(flow_count=flow_cnt,packets_per_second=pps,duration=test_duration,pcap_path=pcap_dir+pcap,user_space='False',bpf_opts='')
                        if test_stats["error"] == -1:
                            retry_counter += 1
                            if retry_counter < max_retries+1:
                                continue
                            else:
                                log_error(id,"ERROR - too many TEST retries")
                                print("ERROR: exit, too many TEST retries with errors")
                                exit(1)
                        else:
                            log_test_stats(test_stats)
                            i += 1

                    #perform test with user space app
                    i=0
                    retry_counter = 0
                    while i < test_replays:
                        test_stats = test_pps(flow_count=flow_cnt,packets_per_second=pps,duration=test_duration,pcap_path=pcap_dir+pcap,user_space='True',bpf_opts='')
                        if test_stats["error"] == -1:
                            retry_counter += 1
                            if retry_counter < max_retries+1:
                                continue
                            else:
                                log_error(id,"ERROR - too many TEST (userspace) retries")
                                print("ERROR: exit, too many TEST (userspace) retries with errors")
                                exit(1)
                        else:
                            log_test_stats_userspace(test_stats)
                            i += 1
                    
                    pps = test_stats['pps']

            #end while not found
        #end for flow_cnt
        
        #backup:
        try:
            rsync_subp = subprocess.Popen('rsync -a -i ~/equinix_key ./ root@10.10.10.10:/root/', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
        except:
            print("ERROR - backup failed:\n")  
            log_error(id, 'ERROR - rsync failed:\n'+rsync_subp.communicate()[0])     
    #end for pcap_file



test_run_management(pcap_path, max_packetloss)
            
        
        # test_pps(flow_count=10, packets_per_second=1000, duration=10, pcap_path='/home/niklas/Documents/abschlussarbeit/performance/all_you_need/pcaps/TCP_67.pcap')


#for file in pcapfolder
    #for flow_cnt in flow_cnts:
        #test_max_speed
        #check packetloss
        #test half_max_speed
        #check packetloss
        #test 50%+half_max_speed
