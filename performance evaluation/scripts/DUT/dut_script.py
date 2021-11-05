
from re import I
import subprocess
import time
import argparse
from argparse import ArgumentParser
import re
import os
from shutil import copyfile
import stat

#cli arguments
parser = ArgumentParser(description='run xdp program and get performance infos')
parser.add_argument('--id',required=True, type=int, dest='id', help="id of current test")
parser.add_argument('--duration',required=True, type=int, dest='duration', help="duration of current test")
parser.add_argument('--receiver',required=True, type=str, dest='receiver', help="receiving interface")
parser.add_argument('--dest-mac',required=True, type=str, dest='dest_mac', help="Destination MAC of the traffic generator")
parser.add_argument('--user-space',required=True, type=str, dest='user_space', help="swith to run with or without user space flow management")
parser.add_argument('--sender',required=False, type=str, dest='sender', help="sending interface")
parser.add_argument('--bpf-opts',required=False, type=str, dest='bpf_opts', help="variable options for the BPF program")


args = parser.parse_args()

id: int = args.id

def log(text, file):
    with open(file, 'a') as f:
        f.write(text+'\n')
    return
def log_error(id: int, log_text: str):
    log('ID: '+str(id)+'\n'+log_text+'\n- - - - - - - - - - - - - - - - - - - -\n\n', 'log/error_log')
    return

def log_meminfo_before(id: int, meminfo: str):
    log(meminfo, 'performance_data/meminfo/meminfo_before_'+str(id))
def log_slabinfo_before(id: int, slabinfo: str):
    log(slabinfo, 'performance_data/slabinfo/slabinfo_before_'+str(id))
def log_meminfo_during(id: int, meminfo: str):
    log(meminfo, 'performance_data/meminfo/meminfo_during_'+str(id))
def log_slabinfo_during(id: int, slabinfo: str):
    log(slabinfo, 'performance_data/slabinfo/slabinfo_during_'+str(id))
def log_cpu_stat_before(id: int, cpu_stat: str):
    log(cpu_stat, 'performance_data/cpu/cpu_stat_before_'+str(id))
def log_cpu_stat_during(id: int, cpu_stat: str):
    log(cpu_stat, 'performance_data/cpu/cpu_stat_during'+str(id))

def get_dropped_packets(interface) -> int:
    ethtool_stats = subprocess.Popen('ethtool -S '+interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True).communicate()[0]
    log('ID: '+str(id)+'\n'+'ethtool -S'+interface+':\n'+ethtool_stats+'\n- - - - - - - - - - - - - - - - - - - -\n\n', 'log/raw_data_log')
    stats_list = ethtool_stats.split(' ')
    for word in stats_list:
        if word == 'rx_dropped:':
            dropped = int(stats_list[stats_list.index(word)+1].removesuffix('\n'))
    return dropped
def get_rx_packets(interface):
    ethtool_stats = subprocess.Popen('ethtool -S '+interface, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True).communicate()[0]
    log('ID: '+str(id)+'\n'+'ethtool -S '+interface+':\n'+ethtool_stats+'\n- - - - - - - - - - - - - - - - - - - -\n\n', 'log/raw_data_log')
    stats_list = ethtool_stats.split(' ')
    for word in stats_list:
        if word == 'rx_packets:':
            rx = float(stats_list[stats_list.index(word)+1].removesuffix('\n'))
    return float(rx)

def get_meminfo():
    meminfo = subprocess.Popen('cat /proc/meminfo', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True).communicate()[0]
    return meminfo
def get_slabinfo():
    slabinfo = subprocess.Popen('cat /proc/slabinfo', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True).communicate()[0]
    return slabinfo
def get_cpu_stat():
    cpu_stat = subprocess.Popen('cat /proc/stat', stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True).communicate()[0]
    return cpu_stat

def get_free_mem(meminfo: str) -> int:
    meminfo_list = meminfo.split(' ')
    for i in range(len(meminfo_list)):
        try:
            meminfo_list.remove('')
        except:
            break
    for word in meminfo_list:
        if word == 'MemFree:' or word.__contains__('\nMemFree:'):
            mem_free = int(meminfo_list[meminfo_list.index(word)+1].removesuffix('\n'))
            break
    return mem_free


def perform_test_run():
    duration = args.duration
    receiver = args.receiver
    if args.bpf_opts:
        bpf_opts = args.bpf_opts
    else:
        bpf_opts = ''
    
    if args.user_space == 'True' or args.user_space == str(1):
        user_space: bool = True
        bpf_opts = bpf_opts+' -u'
    else:
        user_space: bool = False

    # make directory for test files / go into testdir when the already exist
    testdir = './test_run/'
    try:
        os.mkdir(testdir)
        os.chdir(testdir)
        copyfile('../bpflowmon', './bpflowmon')
        os.chmod('./bpflowmon', stat.S_IEXEC)
        os.mkdir('./log/')
        os.mkdir('./performance_data/')
        os.mkdir('./performance_data/meminfo/')
        os.mkdir('./performance_data/slabinfo/')
        os.mkdir('./performance_data/cpu/')
    except:
        os.chdir(testdir)

    #log performance stats before
    meminfo = get_meminfo()
    slabinfo = get_slabinfo()
    cpu_stat = get_cpu_stat()
    log_meminfo_before(id, meminfo)
    log_slabinfo_before(id, slabinfo)
    log_cpu_stat_before(id, cpu_stat)
    mem_free_before = get_free_mem(meminfo)

    rx_before = get_rx_packets(receiver)
    dropped_before = get_dropped_packets(receiver)

    bpflowmon_subp = subprocess.Popen('./bpflowmon -i '+receiver+',enp65s0f1 -t '+str(duration)+' -d '+str(args.dest_mac)+' -m driver,driver '+bpf_opts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True)
    
    #wait 2/3 of total duration
    wait_duration = (float(duration) / 3) * 2
    time.sleep(wait_duration)

    #wait the rest of the time and keep one second to get the rx packet before the are resetted
    wait_duration = (float(duration) / 3) -1
    time.sleep(wait_duration)
    # rx = float(get_rx_packets(receiver))
    rx_after = get_rx_packets(receiver)

    #log performance stats while test runs
    meminfo = get_meminfo()
    slabinfo = get_slabinfo()
    cpu_stat = get_cpu_stat()
    log_meminfo_during(id, meminfo)
    log_slabinfo_during(id, slabinfo)
    log_cpu_stat_during(id, cpu_stat)
    mem_free_during = get_free_mem(meminfo)

    #wait until xdp prog finished, check errs and log
    bpflowmon_out = bpflowmon_subp.communicate()
    if bpflowmon_subp.returncode != 0:
        log_error(id, bpflowmon_out[1])
        print(bpflowmon_out[1])
        exit(bpflowmon_out[1])
    
    # print(bpflowmon_out[0])

    #calc dropped packets
    dropped_after = get_dropped_packets(receiver)
    dropped = dropped_after - dropped_before

    #calc rx_packets
    #rx_after = get_rx_packets(receiver)
    rx = rx_after - rx_before
    # rx = float(get_rx_packets(receiver))

    #calc mem usage
    mem_usage = mem_free_before - mem_free_during

    #log id dropped_packets rx mem_usage
    if user_space:
        log(str(id)+' '+str(dropped)+' '+str(rx)+' '+str(mem_usage), 'test_stats_userspace')
    else:
        log(str(id)+' '+str(dropped)+' '+str(rx)+' '+str(mem_usage), 'test_stats')

    print(str(rx))


perform_test_run()

    
