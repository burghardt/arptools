/*
   ARP Tools Common Functions
   Copyright (C) 2006, 2015 Krzysztof Burghardt.

   $Id: arppoison.c,v 1.1 2006-03-08 00:10:42 kb Exp $

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#define _GNU_SOURCE
/* standard headers */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
/* extern int errno */
#include <errno.h>
/* strerror() */
#include <string.h>
/* libpcap */
#include <pcap.h>
/* libnet */
#include <libnet.h>

void pcap_die (pcap_t *pcap_handle, char *message) {
    fprintf(stderr, "%s: %s\n", message, pcap_geterr(pcap_handle));
    pcap_close(pcap_handle);
    exit(EXIT_FAILURE);
}

void libnet_die (libnet_t *libnet_handle) {
    fprintf(stderr, "%s", libnet_geterror(libnet_handle));
    libnet_destroy(libnet_handle);
    exit(EXIT_FAILURE);
}

char *hw_ntoa(struct libnet_ether_addr *hw) {
    static int i;
    char *str;

    if ((str = malloc(6*2+5+1)) == NULL) {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    str[0] = '\0';

    for (i = 0; i < 6; ++i) {
        sprintf(str, "%s%2.2X%s", str, hw->ether_addr_octet[i], i<5 ? ":" : "");
    }
    str[6*2+5] = '\0';

    return str;
}

char *pcap_get_first_interface(char *pcap_error_buffer) {
    pcap_if_t *pcap_alldevs;

    if(pcap_findalldevs(&pcap_alldevs, pcap_error_buffer)) {
        fprintf(stderr, "pcap_findalldevs: %s\n", pcap_error_buffer);
        exit(EXIT_FAILURE);
    }
    if(pcap_alldevs == NULL) {
        fprintf(stderr, "pcap_findalldevs: no devices found\n");
        exit(EXIT_FAILURE);
    }

    const size_t len = strlen(pcap_alldevs[0].name);
    char *result = malloc(len+1);
    if(result == NULL) {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    memcpy(result, pcap_alldevs[0].name, len+1);

    pcap_freealldevs(pcap_alldevs);
    return result;
}
