ARP Tools
---------

Collection of ARP utilities.

[![Travis-CI](https://travis-ci.org/burghardt/arptools.svg?branch=master)](https://travis-ci.org/burghardt/arptools/)
[![CircleCI](https://circleci.com/gh/burghardt/arptools/tree/master.svg?style=svg)](https://circleci.com/gh/burghardt/arptools)
[![Drone.IO](https://drone.io/github.com/burghardt/arptools/status.png)](https://drone.io/github.com/burghardt/arptools)
[![Coverity](https://scan.coverity.com/projects/6834/badge.svg)](https://scan.coverity.com/projects/6834)
[![CodeCov](http://codecov.io/github/burghardt/arptools/coverage.svg?branch=master)](http://codecov.io/github/burghardt/arptools/)

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
