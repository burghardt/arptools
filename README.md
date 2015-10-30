ARP Tools
---------

Collection of ARP utilities.

Currently it contains:

  * arpdiscover (ARP Discover) - Ethernet scanner based on ARP protocol
  * arpflood (ARP Flood) - Ethernet flooder based on ARP protocol
  * arppoison (ARP Poison) - Poison switches MAC address tables

How to build it?
----------------

To compile it you will need:

  * [libpcap](http://sourceforge.net/projects/libpcap/)
  * [libnet](http://libnet.sourceforge.net/)

Install `libpcap-dev` and `libnet-dev` (Debian/Ubuntu) or equivalent:
```
# apt-get update -qq
# apt-get install libpcap-dev libnet-dev
```

Compile `arptools` with:
```
# sh autogen.sh
# sh configure
make
```

Enjoy!
