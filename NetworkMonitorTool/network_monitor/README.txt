{\rtf1\ansi\ansicpg1252\cocoartf1348\cocoasubrtf170
{\fonttbl\f0\fswiss\fcharset0 Helvetica;\f1\fnil\fcharset0 LucidaGrande;\f2\ftech\fcharset0 Wingdings-Regular;
\f3\fmodern\fcharset0 CourierNewPSMT;\f4\fnil\fcharset0 PTMono-Regular;}
{\colortbl;\red255\green255\blue255;}
{\*\listtable{\list\listtemplateid1\listhybrid{\listlevel\levelnfc0\levelnfcn0\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{decimal\}.}{\leveltext\leveltemplateid1\'02\'00.;}{\levelnumbers\'01;}\fi-360\li720\lin720 }{\listname ;}\listid1}
{\list\listtemplateid2\listhybrid{\listlevel\levelnfc23\levelnfcn23\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{disc\}}{\leveltext\leveltemplateid101\'01\uc0\u8226 ;}{\levelnumbers;}\fi-360\li720\lin720 }{\listname ;}\listid2}
{\list\listtemplateid3\listhybrid{\listlevel\levelnfc23\levelnfcn23\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{disc\}}{\leveltext\leveltemplateid201\'01\uc0\u8226 ;}{\levelnumbers;}\fi-360\li720\lin720 }{\listname ;}\listid3}
{\list\listtemplateid4\listhybrid{\listlevel\levelnfc23\levelnfcn23\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{disc\}}{\leveltext\leveltemplateid301\'01\uc0\u8226 ;}{\levelnumbers;}\fi-360\li720\lin720 }{\listname ;}\listid4}
{\list\listtemplateid5\listhybrid{\listlevel\levelnfc23\levelnfcn23\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{disc\}}{\leveltext\leveltemplateid401\'01\uc0\u8226 ;}{\levelnumbers;}\fi-360\li720\lin720 }{\listlevel\levelnfc23\levelnfcn23\leveljc0\leveljcn0\levelfollow0\levelstartat1\levelspace360\levelindent0{\*\levelmarker \{disc\}}{\leveltext\leveltemplateid402\'01\uc0\u8226 ;}{\levelnumbers;}\fi-360\li1440\lin1440 }{\listname ;}\listid5}}
{\*\listoverridetable{\listoverride\listid1\listoverridecount0\ls1}{\listoverride\listid2\listoverridecount0\ls2}{\listoverride\listid3\listoverridecount0\ls3}{\listoverride\listid4\listoverridecount0\ls4}{\listoverride\listid5\listoverridecount0\ls5}}
\margl1440\margr1440\vieww27300\viewh16500\viewkind0
\deftab720
\pard\pardeftab720\ri0

\f0\fs28 \cf0 The network-monitor folder contains 3 files.\
\pard\pardeftab720\li1080\fi-360\ri0
\ls1\ilvl0\cf0 1)	Makefile\
2)	mydump.c\
3)	commons.h\
\pard\pardeftab720\ri0
\cf0 \
\pard\pardeftab720\li360\fi-360\ri0
\ls2\ilvl0
\f1 \cf0 \'ac
\f2 	
\f0 Makefile is used for compiling the mydump program using pcap library. \
\pard\pardeftab720\ri0
\cf0 \
\pard\pardeftab720\li360\fi-360\ri0
\ls3\ilvl0
\f1 \cf0 \'ac
\f2 	
\f0 commons.h contains different packet headers structs like sniff_ip, sniff_tcp, sniff_udp, sniff_arp, sniff_icmp and other Macros.\
\pard\pardeftab720\ri0
\cf0 \
\pard\pardeftab720\li360\fi-360\ri0
\ls4\ilvl0
\f1 \cf0 \'ac
\f2 	
\f0 mydump code takes 3 values as inputs \'96 all are optional. \
\pard\pardeftab720\ri0
\cf0 \
\pard\pardeftab720\li1080\fi-360\ri0
\ls5\ilvl1
\f3 \cf0 o	
\f0 \'96i for giving an interface like en0 or en1\
\ls5\ilvl1
\f3 o	
\f0 \'96r for giving a pcap file \
\ls5\ilvl1
\f3 o	
\f0 \'96s for pattern matching\
\ls5\ilvl1
\f3 o	
\f0 \'96h screen for showing all the possible options\
\pard\pardeftab720\li720\ri0
\cf0 \
Without any of the input arguments, the program runs on a default interface and captures live packets in promiscuous mode. \
\
The program handles 2 types of network protocols: IP and ARP.\
In IP - TCP, UDP, ICMP and Other are handled separately and in ARP, Request and Reply are handled.\
\
I am also attaching a dump(hw1pcapoutput.txt) of the hw1.pcap file along with the above 3 files.\
\
\

\i\b Code Details:\

\i0\b0 \
The main function uses the getopt method to parse the command line arguments. If there are no devices, error messages are printed respectively like \'93Couldn\'92t find a default device\'94 or \'93Couldn\'92t get a net mask for device\'94 or \'93Couldn\'92t open device\'94 etc.\
\
 The program runs in an infinite loop until a user terminates using Ctrl-C. This is done using the pcap_loop() method.\
\
If any expression is given using -s option, it is stored in the global variable called 
\b pattern
\b0 . \
\
Then there is a callback function called 
\b got_packet
\b0  whenever a packet is captured. The timestamp of the packet is extracted from the header and printed. \
\
Since we are capturing packets only from devices which can provide Ethernet headers, we are directly using sniff_ethernet header for the packet. We check the ether type and call the corresponding handlers - ip_handler() or arp_handler().\
\
In ip_handler(), we check for the protocol and call the respective handlers - tcp_handler(), udp_handler(), icmp_handler() or unknown_handler().\
\
For each packet, we are printing Source and Destination MAC addresses, source and destination IP addresses and ports, type, length of packet, protocol , payload and payload-length.\
\
If an expression is given, then strstr() method is used to check if payload contains this expression. If yes, then only print the values else continue.\
\
For ICMP packets, different ICMP messages are printed using the code and type fields of the icmp_header().\
\
\
\

\i\b Sample Outputs:\
\

\i0\b0 \
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\ri0

\f4 \cf0 sh-3.2# ./mydump -h\
Use the following command line inputs:\
-i  Listen on network device <interface> (e.g., en0).\
-r  Read packets from <file>.\
-s  Keep only packets that contain <string> in their payload.\
\pard\pardeftab720\ri0

\f0\fs24 \cf0 \

\f4\fs28 \ul 1) With all default values\

\f0\fs24 \ulnone \
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\ri0

\f4\fs28 \cf0 sh-3.2# ./mydump\
\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \CocoaLigature0 2016-03-11 21:38:23.813082 34:36:3b:85:49:32 -> b8:af:67:63:a3:28 type 0x800  len 113\
172.24.23.48:53989 -> 173.194.123.67:443 TCP  payload-length = 47\
2b 61 f7 17 df 8f 14 6e  12 25 11 6b 7d c8 1d c2    +a.....n.%.k\}...\
77 3b 90 cf 19 ff ee 31  7f 09 11 74 7e ad 57 6f    w;.....1...t~.Wo\
be 9e fa e4 95 3e 14 1f  67 82 05 3c 31 4c 9f       .....>..g..<1L.\
\
2016-03-11 21:38:23.813421 b8:af:67:63:a3:28 -> 34:36:3b:85:49:32 type 0x800  len 112\
173.194.123.67:443 -> 172.24.23.48:53989 TCP  payload-length = 46\
17 03 03 00 29 00 00 00  00 00 00 00 35 ed c8 99    ....).......5...\
8a a3 5d 75 8d 4f 8a 6c  62 69 0a 10 8a 8d e5 b0    ..]u.O.lbi......\
73 2d 86 a3 31 29 a3 6a  5d fe f7 75 70 15          s-..1).j]..up.\
\
2016-03-11 21:38:23.813494 34:36:3b:85:49:32 -> b8:af:67:63:a3:28 type 0x800  len 66\
172.24.23.48:53989 -> 173.194.123.67:443 TCP  payload-length = 0\
\
2016-03-11 21:38:23.813871 b8:af:67:63:a3:28 -> 34:36:3b:85:49:32 type 0x800  len 66\
173.194.123.67:443 -> 172.24.23.48:53989 TCP  payload-length = 0\
^C\
\
\
\ul 2) Get only tcp packets from hw1.pcap file\
\ulnone \
sh-3.2# ./mydump -r hw1.pcap tcp | head -10\
\
2013-01-12 14:35:49.329823 c4:3d:c7:17:6f:9b -> 0:c:29:e9:94:8e type 0x800  len 74\
122.154.101.54:39437 -> 192.168.0.200:443 TCP  payload-length = 0\
\
2013-01-12 14:35:49.350673 0:c:29:e9:94:8e -> c4:3d:c7:17:6f:9b type 0x800  len 74\
192.168.0.200:443 -> 122.154.101.54:39437 TCP  payload-length = 0\
\
2013-01-12 14:35:49.679245 c4:3d:c7:17:6f:9b -> 0:c:29:e9:94:8e type 0x800  len 66\
122.154.101.54:39437 -> 192.168.0.200:443 TCP  payload-length = 0\
\
\
\
\
\ul 3) Get only UDP packets from hw1.pcap file\
\ulnone \
sh-3.2# ./mydump -r hw1.pcap udp | head -50\
\
2013-01-12 11:38:02.227995 c4:3d:c7:17:6f:9b -> 1:0:5e:7f:ff:fa type 0x800  len 342\
192.168.0.1:1901 -> 239.255.255.250:1900 UDP  payload-length = 300\
4e 4f 54 49 46 59 20 2a  20 48 54 54 50 2f 31 2e    NOTIFY * HTTP/1.\
31 0d 0a 48 4f 53 54 3a  20 32 33 39 2e 32 35 35    1..HOST: 239.255\
2e 32 35 35 2e 32 35 30  3a 31 39 30 30 0d 0a 43    .255.250:1900..C\
61 63 68 65 2d 43 6f 6e  74 72 6f 6c 3a 20 6d 61    ache-Control: ma\
78 2d 61 67 65 3d 33 36  30 30 0d 0a 4c 6f 63 61    x-age=3600..Loca\
74 69 6f 6e 3a 20 68 74  74 70 3a 2f 2f 31 39 32    tion: http://192\
2e 31 36 38 2e 30 2e 31  3a 38 30 2f 52 6f 6f 74    .168.0.1:80/Root\
44 65 76 69 63 65 2e 78  6d 6c 0d 0a 4e 54 3a 20    Device.xml..NT: \
75 75 69 64 3a 75 70 6e  70 2d 49 6e 74 65 72 6e    uuid:upnp-Intern\
65 74 47 61 74 65 77 61  79 44 65 76 69 63 65 2d    etGatewayDevice-\
31 5f 30 2d 63 34 33 64  63 37 31 37 36 66 39 62    1_0-c43dc7176f9b\
0d 0a 55 53 4e 3a 20 75  75 69 64 3a 75 70 6e 70    ..USN: uuid:upnp\
2d 49 6e 74 65 72 6e 65  74 47 61 74 65 77 61 79    -InternetGateway\
44 65 76 69 63 65 2d 31  5f 30 2d 63 34 33 64 63    Device-1_0-c43dc\
37 31 37 36 66 39 62 0d  0a 4e 54 53 3a 20 73 73    7176f9b..NTS: ss\
64 70 3a 61 6c 69 76 65  0d 0a 53 65 72 76 65 72    dp:alive..Server\
3a 20 55 50 6e 50 2f 31  2e 30 20 55 50 6e 50 2f    : UPnP/1.0 UPnP/\
31 2e 30 20 55 50 6e 50  2d 44 65 76 69 63 65 2d    1.0 UPnP-Device-\
48 6f 73 74 2f 31 2e 30  0d 0a 0d 0a                Host/1.0....\
\
2013-01-12 11:38:02.231699 c4:3d:c7:17:6f:9b -> 1:0:5e:7f:ff:fa type 0x800  len 398\
192.168.0.1:1901 -> 239.255.255.250:1900 UDP  payload-length = 356\
4e 4f 54 49 46 59 20 2a  20 48 54 54 50 2f 31 2e    NOTIFY * HTTP/1.\
31 0d 0a 48 4f 53 54 3a  20 32 33 39 2e 32 35 35    1..HOST: 239.255\
2e 32 35 35 2e 32 35 30  3a 31 39 30 30 0d 0a 43    .255.250:1900..C\
61 63 68 65 2d 43 6f 6e  74 72 6f 6c 3a 20 6d 61    ache-Control: ma\
78 2d 61 67 65 3d 33 36  30 30 0d 0a 4c 6f 63 61    x-age=3600..Loca\
74 69 6f 6e 3a 20 68 74  74 70 3a 2f 2f 31 39 32    tion: http://192\
2e 31 36 38 2e 30 2e 31  3a 38 30 2f 52 6f 6f 74    .168.0.1:80/Root\
44 65 76 69 63 65 2e 78  6d 6c 0d 0a 4e 54 3a 20    Device.xml..NT: \
75 72 6e 3a 73 63 68 65  6d 61 73 2d 75 70 6e 70    urn:schemas-upnp\
2d 6f 72 67 3a 64 65 76  69 63 65 3a 49 6e 74 65    -org:device:Inte\
72 6e 65 74 47 61 74 65  77 61 79 44 65 76 69 63    rnetGatewayDevic\
65 3a 31 0d 0a 55 53 4e  3a 20 75 75 69 64 3a 75    e:1..USN: uuid:u\
70 6e 70 2d 49 6e 74 65  72 6e 65 74 47 61 74 65    pnp-InternetGate\
77 61 79 44 65 76 69 63  65 2d 31 5f 30 2d 63 34    wayDevice-1_0-c4\
33 64 63 37 31 37 36 66  39 62 3a 3a 75 72 6e 3a    3dc7176f9b::urn:\
73 63 68 65 6d 61 73 2d  75 70 6e 70 2d 6f 72 67    schemas-upnp-org\
3a 64 65 76 69 63 65 3a  49 6e 74 65 72 6e 65 74    :device:Internet\
47 61 74 65 77 61 79 44  65 76 69 63 65 3a 31 0d    GatewayDevice:1.\
0a 4e 54 53 3a 20 73 73  64 70 3a 61 6c 69 76 65    .NTS: ssdp:alive\
0d 0a 53 65 72 76 65 72  3a 20 55 50 6e 50 2f 31    ..Server: UPnP/1\
2e 30 20 55 50 6e 50 2f  31 2e 30 20 55 50 6e 50    .0 UPnP/1.0 UPnP\
2d 44 65 76 69 63 65 2d  48 6f 73 74 2f 31 2e 30    -Device-Host/1.0\
0d 0a 0d 0a                                         ....\
\
\
\ul 4) Get only ARP packets from hw1.pcap file\
\ulnone \
sh-3.2# ./mydump -r hw1.pcap arp | head -50\
2013-01-12 11:37:42.871346  c4:3d:c7:17:6f:9b > ff:ff:ff:ff:ff:ff   ethertype ARP (0x806), length 60: Request who-has 192.168.0.12 tell 192.168.0.1, length 46\
2013-01-12 11:38:13.796474  c4:3d:c7:17:6f:9b > ff:ff:ff:ff:ff:ff   ethertype ARP (0x806), length 60: Request who-has 192.168.0.12 tell 192.168.0.1, length 46\
2013-01-12 11:38:44.821049  c4:3d:c7:17:6f:9b > ff:ff:ff:ff:ff:ff   ethertype ARP (0x806), length 60: Request who-has 192.168.0.12 tell 192.168.0.1, length 46\
2013-01-12 11:39:15.847663  c4:3d:c7:17:6f:9b > ff:ff:ff:ff:ff:ff   ethertype ARP (0x806), length 60: Request who-has 192.168.0.12 tell 192.168.0.1, length 46\
2013-01-12 11:39:16.974524  c4:3d:c7:17:6f:9b > ff:ff:ff:ff:ff:ff   ethertype ARP (0x806), length 60: Request who-has 192.168.0.2 tell 192.168.0.1, length 46\
2013-01-14 13:05:19.480519  0:c:29:e9:94:8e > c4:3d:c7:17:6f:9b   ethertype ARP (0x806), length 42: Reply 192.168.0.1 is-at c4:3d:c7:17:6f:9b, length 28\
\
\
\
\ul 5) Get only ICMP packets from hw1.pcap file\
\
\ulnone sh-3.2# ./mydump -r hw1.pcap icmp | head -30\
\
2013-01-14 12:42:31.752299 c4:3d:c7:17:6f:9b -> 0:c:29:e9:94:8e type 0x800  len 90\
1.234.31.20 192.168.0.200 ICMP  payload-length = 56\
Destination Unreachable - Host Prohibited \
45 00 00 30 00 00 40 00  2e 06 6a 5a c0 a8 00 c8    E..0..@...jZ....\
01 ea 1f 14 00 50 7b 81  bd cd 09 c6 3a 35 22 b0    .....P\{.....:5".\
70 12 39 08 11 ab 00 00  02 04 05 b4 01 01 04 02    p.9.............\
61 63 68 65 2d 43 6f 6e                             ache-Con\
\
\
\
\ul 6) Get only TCP packets from hw1.pcap file with grep \'93GET\'94\
\ulnone \
sh-3.2# ./mydump -r hw1.pcap -s GET tcp | head -50\
\
2013-01-12 22:30:48.908526 c4:3d:c7:17:6f:9b -> 0:c:29:e9:94:8e type 0x800  len 177\
92.240.68.152:9485 -> 192.168.0.200:80 TCP  payload-length = 111\
47 45 54 20 68 74 74 70  3a 2f 2f 70 69 63 2e 6c    GET http://pic.l\
65 65 63 68 2e 69 74 2f  69 2f 66 31 36 36 63 2f    eech.it/i/f166c/\
34 37 39 32 34 36 62 30  61 73 74 74 61 73 2e 6a    479246b0asttas.j\
70 67 20 48 54 54 50 2f  31 2e 31 0a 55 73 65 72    pg HTTP/1.1.User\
2d 41 67 65 6e 74 3a 20  77 65 62 63 6f 6c 6c 61    -Agent: webcolla\
67 65 2f 31 2e 31 33 35  61 0a 48 6f 73 74 3a 20    ge/1.135a.Host: \
70 69 63 2e 6c 65 65 63  68 2e 69 74 0a 0a 00       pic.leech.it...\
\
2013-01-12 22:30:49.32953 0:c:29:e9:94:8e -> c4:3d:c7:17:6f:9b type 0x800  len 229\
192.168.0.200:40341 -> 87.98.246.8:80 TCP  payload-length = 163\
47 45 54 20 2f 69 2f 66  31 36 36 63 2f 34 37 39    GET /i/f166c/479\
32 34 36 62 30 61 73 74  74 61 73 2e 6a 70 67 20    246b0asttas.jpg \
48 54 54 50 2f 31 2e 30  0d 0a 55 73 65 72 2d 41    HTTP/1.0..User-A\
67 65 6e 74 3a 20 4d 6f  7a 69 6c 6c 61 2f 34 2e    gent: Mozilla/4.\
30 20 28 63 6f 6d 70 61  74 69 62 6c 65 3b 20 4d    0 (compatible; M\
53 49 45 20 36 2e 30 3b  20 57 69 6e 64 6f 77 73    SIE 6.0; Windows\
20 4e 54 20 35 2e 31 29  0d 0a 41 63 63 65 70 74     NT 5.1)..Accept\
3a 20 2a 2f 2a 0d 0a 48  6f 73 74 3a 20 70 69 63    : */*..Host: pic\
2e 6c 65 65 63 68 2e 69  74 3a 38 30 0d 0a 43 6f    .leech.it:80..Co\
6e 6e 65 63 74 69 6f 6e  3a 20 63 6c 6f 73 65 0d    nnection: close.\
0a 0d 0a                                            ...\
\
2013-01-12 22:31:19.154432 c4:3d:c7:17:6f:9b -> 0:c:29:e9:94:8e type 0x800  len 207\
92.240.68.152:17260 -> 192.168.0.200:80 TCP  payload-length = 141\
47 45 54 20 68 74 74 70  3a 2f 2f 65 63 78 2e 69    GET http://ecx.i\
6d 61 67 65 73 2d 61 6d  61 7a 6f 6e 2e 63 6f 6d    mages-amazon.com\
2f 69 6d 61 67 65 73 2f  49 2f 34 31 6f 5a 31 58    /images/I/41oZ1X\
73 69 4f 41 4c 2e 5f 53  4c 35 30 30 5f 41 41 33    siOAL._SL500_AA3\
30 30 5f 2e 6a 70 67 20  48 54 54 50 2f 31 2e 31    00_.jpg HTTP/1.1\
0a 55 73 65 72 2d 41 67  65 6e 74 3a 20 77 65 62    .User-Agent: web\
63 6f 6c 6c 61 67 65 2f  31 2e 31 33 35 61 0a 48    collage/1.135a.H\
6f 73 74 3a 20 65 63 78  2e 69 6d 61 67 65 73 2d    ost: ecx.images-\
61 6d 61 7a 6f 6e 2e 63  6f 6d 0a 0a 00             amazon.com...\
\
\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ul \ulc0 7) Get only UDP packets from hw1.pcap file with grep \'93HTTP\'94\
\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ulnone sh-3.2# ./mydump -r hw1.pcap -s HTTP udp | head -50\
\
2013-01-12 11:38:02.227995 c4:3d:c7:17:6f:9b -> 1:0:5e:7f:ff:fa type 0x800  len 342\
192.168.0.1:1901 -> 239.255.255.250:1900 UDP  payload-length = 300\
4e 4f 54 49 46 59 20 2a  20 48 54 54 50 2f 31 2e    NOTIFY * HTTP/1.\
31 0d 0a 48 4f 53 54 3a  20 32 33 39 2e 32 35 35    1..HOST: 239.255\
2e 32 35 35 2e 32 35 30  3a 31 39 30 30 0d 0a 43    .255.250:1900..C\
61 63 68 65 2d 43 6f 6e  74 72 6f 6c 3a 20 6d 61    ache-Control: ma\
78 2d 61 67 65 3d 33 36  30 30 0d 0a 4c 6f 63 61    x-age=3600..Loca\
74 69 6f 6e 3a 20 68 74  74 70 3a 2f 2f 31 39 32    tion: http://192\
2e 31 36 38 2e 30 2e 31  3a 38 30 2f 52 6f 6f 74    .168.0.1:80/Root\
44 65 76 69 63 65 2e 78  6d 6c 0d 0a 4e 54 3a 20    Device.xml..NT: \
75 75 69 64 3a 75 70 6e  70 2d 49 6e 74 65 72 6e    uuid:upnp-Intern\
65 74 47 61 74 65 77 61  79 44 65 76 69 63 65 2d    etGatewayDevice-\
31 5f 30 2d 63 34 33 64  63 37 31 37 36 66 39 62    1_0-c43dc7176f9b\
0d 0a 55 53 4e 3a 20 75  75 69 64 3a 75 70 6e 70    ..USN: uuid:upnp\
2d 49 6e 74 65 72 6e 65  74 47 61 74 65 77 61 79    -InternetGateway\
44 65 76 69 63 65 2d 31  5f 30 2d 63 34 33 64 63    Device-1_0-c43dc\
37 31 37 36 66 39 62 0d  0a 4e 54 53 3a 20 73 73    7176f9b..NTS: ss\
64 70 3a 61 6c 69 76 65  0d 0a 53 65 72 76 65 72    dp:alive..Server\
3a 20 55 50 6e 50 2f 31  2e 30 20 55 50 6e 50 2f    : UPnP/1.0 UPnP/\
31 2e 30 20 55 50 6e 50  2d 44 65 76 69 63 65 2d    1.0 UPnP-Device-\
48 6f 73 74 2f 31 2e 30  0d 0a 0d 0a                Host/1.0....\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ul \
\
8) Get all TCP packets from live capturing\
\
\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ulnone sh-3.2# ./mydump tcp\
\
2016-03-11 22:50:27.317186 34:36:3b:85:49:32 -> b8:af:67:63:a3:28 type 0x800  len 54\
172.24.23.48:54381 -> 216.58.219.206:443 TCP  payload-length = 0\
\
2016-03-11 22:50:27.317186 34:36:3b:85:49:32 -> b8:af:67:63:a3:28 type 0x800  len 54\
172.24.23.48:54380 -> 216.58.219.206:443 TCP  payload-length = 0\
\
2016-03-11 22:50:27.323571 b8:af:67:63:a3:28 -> 34:36:3b:85:49:32 type 0x800  len 66\
216.58.219.206:443 -> 172.24.23.48:54381 TCP  payload-length = 0\
\
2016-03-11 22:50:27.323575 b8:af:67:63:a3:28 -> 34:36:3b:85:49:32 type 0x800  len 66\
216.58.219.206:443 -> 172.24.23.48:54380 TCP  payload-length = 0\
\
2016-03-11 22:50:27.891140 34:36:3b:85:49:32 -> b8:af:67:63:a3:28 type 0x800  len 104\
172.24.23.48:53785 -> 169.55.74.45:443 TCP  payload-length = 38\
17 03 03 00 21 00 00 00  00 00 00 01 fc b3 52 7a    ....!.........Rz\
14 9b 37 c3 3d e3 8a 33  15 11 61 5f 48 7b 72 fb    ..7.=..3..a_H\{r.\
7a 58 7c db de 66                                   zX|..f\
\
2016-03-11 22:50:27.913913 b8:af:67:63:a3:28 -> 34:36:3b:85:49:32 type 0x800  len 111\
169.55.74.45:443 -> 172.24.23.48:53785 TCP  payload-length = 45\
17 03 03 00 28 1c ce 5a  cd 48 30 6f 0d ac 5c a7    ....(..Z.H0o..\\.\
ea 76 0e 70 0d d4 09 1a  36 25 9f 88 b4 00 02 77    .v.p....6%.....w\
37 08 cc 37 66 e0 e3 65  41 c1 72 50 75             7..7f..eA.rPu\
\
\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ul 9) Get all UDP packets from live capturing\
\
\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ulnone sh-3.2# ./mydump udp\
\
2016-03-11 22:51:46.52937 b8:af:67:63:a3:28 -> 34:36:3b:85:49:32 type 0x800  len 85\
173.194.68.189:443 -> 172.24.23.48:51034 UDP  payload-length = 43\
00 03 e9 4b f7 5b de 11  8e 24 f2 a9 6b 15 f3 d9    ...K.[...$..k...\
33 51 1b 2f 2f 49 a1 ad  31 cd 82 42 59 8b c1 47    3Q.//I..1..BY..G\
aa 35 9a d7 0f 2e fb f6  41 aa 38                   .5......A.8\
\
2016-03-11 22:51:48.593717 b8:af:67:63:a3:28 -> 34:36:3b:85:49:32 type 0x800  len 107\
130.245.255.4:53 -> 172.24.23.48:36281 UDP  payload-length = 65\
37 f0 81 80 00 01 00 02  00 00 00 00 03 77 77 77    7............www\
07 74 63 70 64 75 6d 70  03 6f 72 67 00 00 01 00    .tcpdump.org....\
01 c0 0c 00 01 00 01 00  00 00 3c 00 04 c0 8b 2e    ..........<.....\
42 c0 0c 00 01 00 01 00  00 00 3c 00 04 84 d5 ee    B.........<.....\
06                                                  .\
\
2016-03-11 22:51:49.931522 34:36:3b:85:49:32 -> b8:af:67:63:a3:28 type 0x800  len 77\
172.24.23.48:2199 -> 130.245.255.4:53 UDP  payload-length = 35\
42 62 01 00 00 01 00 00  00 00 00 00 03 77 77 77    Bb...........www\
09 67 6c 61 73 73 64 6f  6f 72 03 63 6f 6d 00 00    .glassdoor.com..\
01 00 01                                            ...\
\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ul \
\
10) Get all ICMP packets from live capturing\
\
\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ulnone sh-3.2# ./mydump icmp\
\
2016-03-11 22:54:23.854132 34:36:3b:85:49:32 -> b8:af:67:63:a3:28 type 0x800  len 70\
172.24.23.48 130.245.255.4 ICMP  payload-length = 36\
Destination Unreachable - Port Unreachable \
45 00 00 4c d3 e9 00 00  3f 11 62 75 82 f5 ff 04    E..L....?.bu....\
ac 18 17 30 00 35 1d 71  00 38 00 00 ef 92 e3 56    ...0.5.q.8.....V\
75 08 0d 00                                         u...\
\
2016-03-11 22:54:23.854133 34:36:3b:85:49:32 -> b8:af:67:63:a3:28 type 0x800  len 70\
172.24.23.48 130.245.255.4 ICMP  payload-length = 36\
Destination Unreachable - Port Unreachable \
45 00 00 4c d3 ea 00 00  3f 11 62 74 82 f5 ff 04    E..L....?.bt....\
ac 18 17 30 00 35 a3 13  00 38 00 00 00 00 00 00    ...0.5...8......\
00 00 00 00                                         ....\
\
\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ul 11) Get other packets from file\
\cb1 \
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardirnatural
\cf0 \ulnone sh-3.2# ./mydump -r hw1.pcap igmp | head -10\
\
2013-01-12 11:39:26.113670 44:6d:57:f6:7e:0 -> 1:0:5e:0:0:16 type 0x800  len 60\
192.168.0.11 -> 224.0.0.22 OTHER\
\
2013-01-12 11:39:26.127793 44:6d:57:f6:7e:0 -> 1:0:5e:0:0:16 type 0x800  len 60\
192.168.0.11 -> 224.0.0.22 OTHER\
\
2013-01-12 11:39:26.130006 44:6d:57:f6:7e:0 -> 1:0:5e:0:0:16 type 0x800  len 60\
192.168.0.11 -> 224.0.0.22 OTHER\
\pard\tx560\tx1120\tx1680\tx2240\tx2800\tx3360\tx3920\tx4480\tx5040\tx5600\tx6160\tx6720\pardeftab720\pardirnatural
\cf0 \ul \ulc0 \
\
}