# xdp_flowmon
XDP BPF programs to monitor network flows. There are three implementations that leverage the tail call mechanism to understand how and to what extend, bpf can be used to monitor network flows. The implementations differ in the way information is shared between tail called programs. Parts of this program are based on or copied from <A href="https://github.com/mattereppe/bpf_flowmon/blob/main/flow_mgmt.c">bpf_flowmon</A>.

## Supported protocols:
### layer 2
- ethernet
### layer 3
- IP
- IPv6
### layer 4
- TCP
- UDP
- ICMP
- ICMPv6

## Scope
The goal of this work is to investigate how and to what extent bpf can be used to monitor network flows and how this affects performance. For this purpose the headers of layer 2 - 4 are parsed and certain information is stored in maps. Since the maximum number of instructions per program is reached fast, the parsing process is divided into different programs, which call each other with the `bpf_tail_call()` helper function. Three different ways of passing information between tail calls have been implemented to better assess the performance impact.

## Architecture
In general, the parsing process is divided into a start program, a program for each of the layers 2,3,4 and an end program. Optionally, after the end program, a start program for deep packet inspection can be started, which detects the l5 protocol based on the ports used and calls an associated program to inspect.<br>

The start program is attached to the appropriate hook point and is called on arrival of each packet. It stores the timestamp of the call, adjusts the meta data pointer of the packet and then calls the parser for layer 2. For layer 2 the parsing of ethernet headers is implemented, for layer 3 IP and IPv6 and for layer 4 TCP, UDP, ICMP and ICMPv6. The parsers of the particular headers store the headers in a specific data structure for later processing.<br>
The end program handles the calculation of certain statistics of the flow associated with the packet and stores them under the flow id consisting of src ip, dest ip, src port, dest port and proto in a map from which they can be read by a user space application. The management of the flows is done by a user space application, which is copied from <A href="https://github.com/mattereppe/bpf_flowmon/blob/main/flow_mgmt.c">bpf_flowmon</A>.<br>

To process the packets, each parser must know the starting position of the header it is processing. To share this between the programs the offset (=header_position-data_start) is written into the `data_meta` field of the `struct xdp_md ctx`, since it is expected that accessing this area is much faster than accessing bpf maps.<br>

To be able to call the programs, each program has a number assigned to it, under which it can be accessed in an extra bpf map (`jmp_table`). This is used by the helper function `bpf_tail_call()`. This allows the user space application, which initializes this map, to make only parsers for certain protocols accessible via this `jmp_table` if this is desired.

## user space application
```
$ ./bpflowmon --help
```
```
Required options:
        -d      --dev                 <interface>: network devices/interfaces where the XDP BPF program is to be attached. Comma separated values

Optional options:
        -v      --verbose             get information about flow counts [default: verbose]
        -q      --quiet               get no intormation [default: verbose]
        -h      --help                print help
        -p      --protocols           <proto>: protocols to be parsed. Comma separated values
        -m      --mode                <xdp-flag>: mode for each interface. Comma separated values in same order as devices [default=skb/generic]
        -D      --DPI                 decide if deep packet inspection should be performed
        -O      --Output              <dir>: directory where to save dumped flows. [default to current dir]
        -L      --Log                 <file>: log messages to file [default: stdout]
        -M      --Map                 <file>: map for flow_stats that is to be reused (full path) [default: /sys/fs/bpf/xdp/globals/flow_stats
        -F      --Folder              <dir>: Folder where the maps are to be saved (full path) [default: /sys/fs/bpf/xdp/globals/
        -i      --interval            <interval>: reporting period in sec [default=1s; 0=print once and exit]
        -j      --json                encode flow info as json
```
### examples:
attach to eth0 and parse all packets:
```
./bpflowmon -d eth0
```
<br>

attach to eth0, parse only eth, ipv6 and tcp headers and perform deep packet inspection:
```
./bpflowmon -d eth0 -p eth,ipv6,tcp -D
```
<br>


attach to eth0 in driver mode and wlan0 in generic mode, reuse the flow_stats map at the given path and get no informations to the console:
```
./bpflowmon -d eth0,wlan0 -m driver,generic -M /sys/fs/bpf/xdp/globals/flow_stats -q
```

## Installation
To use one of the programs in the `src` directory, clone this repository and run make in the directory of the program.
# --------------------------------------------------------------------------------







## Scope
Das ziel dieser Arbeit ist zu untersuchen, wie und in welchem umfang bpf genutzt werden kann um network flows zu monitoren und welche auswirkungen das auf die Performance hat. Dafür werden die header der layer 2 - 4 untersucht und bestimmte informationen in maps gespeichert. Da die maximale Anzahl an instruktionen pro Programm schnell erreicht ist, wird der parsing Prozess auf verschiedene programme aufgeteilt, welche sich mithilfe der helferfunktion bpf_tail_call() aufrufen. Es wurden drei verschiedene Arten der Informationsweitergabe zwischen tail calls implementiert um die Performanceauswirkungen besser einschätzen zu können.<br>

## Architektur
Im allgemeinen teilt sich der parsing prozess auf ein start programm, je ein Programm für die schichten 2,3,4 und einem end Programm auf. Optional kann nach dem end Programm ein start programm für deep packet inspection gestartet werden, welches basierend auf den verwendeten ports das l5 protokoll ermittelt und ein entsprechendes programm zum inspizieren aufruft.<br>
Das start programm wird am entsprechenden hook point attached und bei Ankunft jedes Pakets aufgerufen. Dieses speichert den Zeittstempel des aufrufs und ruft als nächstes den parser für layer 2 auf. Für layer 2 wurde das parsing von ethernet headern implementiert, für layer 3 IP und IPv6 und für layer 4 TCP, UDP, ICMP und ICMPv6. Die parser der einzelnen header speichern die header in einer bestimmten datenstruktur für die spätere bearbeitung.<br>
Das end programm übernimmt die berechnung von bestimmten Statistiken des zu dem paket gehörigen flows und speichert diese unter der flow id bestehend aus src ip, dest ip, src port, dest port und proto in map, aus der sie von einer user space application gelesen werden können. Das manegemnt der Flows geschieht durch eine user space applikation (von LINK bpf_flowmon).<br>

Für die bearbeitung der Pakete muss jeder parser die Startposition des headers kennen den er bearbeitet. Um diese zwischen den Programmen zu teilen wird der offset (=header_position-data_start) in das meta daten feld des struct xdp_md ctx geschrieben, da zu erwarten ist dass der zugriff auf diesen bereich wesentlich schneller ist als der zugriff auf bpf maps.<br>

Um die Programme aufrufen zu können, wird jedem Programm eine nummer zugewiesen, unter welcher es in einer extra bpf map (jmp_table) erreichbar ist. Diese wird von der helferfunktion bpf_tail_call() genutzt. Das ermöglicht der user space applikation welche diese map initialisiert, nur parser für bestimmte protokolle über diese jmp_table erreichbar zu machen falls dies gewünscht ist.<br>

## user space application
```
$ ./bpflowmon --help
```
```
Required options:
        -d      --dev                 <interface>: network devices/interfaces where the XDP BPF program is to be attached. Comma separated values

Optional options:
        -v      --verbose             get information about flow counts [default: verbose]
        -q      --quiet               get no intormation [default: verbose]
        -h      --help                print help
        -p      --protocols           <proto>: protocols to be parsed. Comma separated values
        -m      --mode                <xdp-flag>: mode for each interface. Comma separated values in same order as devices [default=skb/generic]
        -D      --DPI                 decide if deep packet inspection should be performed
        -O      --Output              <dir>: directory where to save dumped flows. [default to current dir]
        -L      --Log                 <file>: log messages to file [default: stdout]
        -M      --Map                 <file>: map for flow_stats that is to be reused (full path) [default: /sys/fs/bpf/xdp/globals/flow_stats
        -F      --Folder              <dir>: Folder where the maps are to be saved (full path) [default: /sys/fs/bpf/xdp/globals/
        -i      --interval            <interval>: reporting period in sec [default=1s; 0=print once and exit]
        -j      --json                encode flow info as json
```
### examples:
attach to eth0 and parse all packets:
```
./bpflowmon -d eth0
```
<br>

attach to eth0, parse only eth, ip, ipv6 and tcp headers and perform deep packet inspection:
```
./bpflowmon -d eth0 -p eth,ip,ip6,tcp -D
```
<br>


attach to eth0, reuse the flow_stats map at the given path and get no informations on the console:
```
./bpflowmon -d eth0 -M /sys/fs/bpf/xdp/globals/flow_stats -q
```