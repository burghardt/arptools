/*
   ARP Discover - Ethernet scanner based on ARP protocol
   Copyright (C) 2006 Krzysztof Burghardt.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
/* commcon functions */
#include "common.h"

int main (int argc, char **argv) {
    char *interface = NULL;
    pcap_if_t *pcap_alldevs = NULL;
    pcap_t *pcap_handle = NULL;
    libnet_t *libnet_handle = NULL;
    char pcap_error_buffer[PCAP_ERRBUF_SIZE];
    char libnet_error_buffer[LIBNET_ERRBUF_SIZE];
    struct libnet_ether_addr *hw_src = NULL;
    struct libnet_ether_addr *hw_dst = NULL;
    struct in_addr ip_src, ip_dst;
    struct bpf_program socket_filter;
    struct pcap_pkthdr packet_header;
    char filter[1024];
    u_int8_t *packet = NULL;
    u_int32_t packet_size;
    const unsigned char *pcap_packet = NULL;
    pid_t pid;
    int i, status, amount;
    int timeout = 10;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s 1st_dst_ip amount [interface]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if ((amount = atoi(argv[2])) < 1) {
        fprintf(stderr, "amount have to be positive integer\n");
        exit(EXIT_FAILURE);
    }

    if (argc > 3)
        interface = argv[3];

    if (interface == NULL)
        interface = pcap_get_first_interface(&pcap_alldevs, pcap_error_buffer);

    printf ("using interface %s\n", interface);

    if ((pcap_handle = pcap_open_live(interface, BUFSIZ, amount, timeout, pcap_error_buffer)) == NULL) {
        fprintf(stderr, "pcap_open_live: %s\n", pcap_error_buffer);
        exit(EXIT_FAILURE);
    }

    if ((libnet_handle = libnet_init(LIBNET_LINK_ADV, interface, libnet_error_buffer)) == NULL) {
        fprintf(stderr, "%s", libnet_error_buffer);
        exit(EXIT_FAILURE);
    }

    if ((hw_src = libnet_get_hwaddr(libnet_handle)) == NULL)
        libnet_die(libnet_handle);

    printf("our hw address is %s\n", hw_ntoa(hw_src));

    ip_src.s_addr = libnet_get_ipaddr4(libnet_handle);
    printf("our ip address is %s\n", inet_ntoa(ip_src));

    if ((hw_dst = malloc(sizeof(struct libnet_ether_addr))) == NULL) {
        fprintf(stderr, "%s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    hw_dst->ether_addr_octet[0] = hw_dst->ether_addr_octet[1] =
        hw_dst->ether_addr_octet[2] = hw_dst->ether_addr_octet[3] =
        hw_dst->ether_addr_octet[4] = hw_dst->ether_addr_octet[5] = 0xff;

    sprintf(filter, "ether dst %s && arp", hw_ntoa(hw_src));
    printf("bpf filter is '%s'\n", filter);

    if (pcap_compile(pcap_handle, &socket_filter, filter, 0, 0) == -1)
        pcap_die(pcap_handle, "pcap_compile");

    if (pcap_setfilter(pcap_handle, &socket_filter) == -1)
        pcap_die(pcap_handle, "pcap_setfilter");

    switch (pid = fork ()) {
        case -1:
            fprintf(stderr, "%s\n", strerror(errno));
            exit(EXIT_FAILURE);
        case 0:
            alarm(timeout); /* timeout if no packet arrives */
            for (i = 0; ; ++i) {
                pcap_packet = pcap_next(pcap_handle, &packet_header);

                printf("received arp packet %i bytes, ", packet_header.len);

                if (pcap_packet[20] == 0 && pcap_packet[21] == 2) {
                    memcpy(hw_src->ether_addr_octet, &pcap_packet[22], 6);
                    printf("hw address is %s, ", hw_ntoa(hw_src));
                    memcpy(&ip_src.s_addr, &pcap_packet[28], 4);
                    printf("ip address is %s\n", inet_ntoa(ip_src));
                    fflush(stdout);
                } else
                    printf("not an arp reply packet\n");
            }
            break;
        default:
            printf("sniffer fork()ed into background with pid = %i\n", pid);

            sleep(1); /* give child time to born */

            if (inet_aton(argv[1], &ip_dst) == 0) {
                fprintf(stderr, "inet_aton: invalid address\n");
                exit(EXIT_FAILURE);
            }

            for (i = 1; i <= amount; ++i) {

                printf("request for hw address of ip address %s, ", inet_ntoa (ip_dst));

                if (libnet_build_arp(
                        ARPHRD_ETHER,                   /* hardware addr */
                        ETHERTYPE_IP,                   /* protocol addr */
                        ETHER_ADDR_LEN,                 /* hardware addr size */
                        4,                              /* protocol addr size */
                        ARPOP_REQUEST,                  /* operation type */
                        hw_src->ether_addr_octet,       /* sender hardware addr */
                        (u_int8_t *)&ip_src.s_addr,     /* sender protocol addr */
                        hw_dst->ether_addr_octet,       /* target hardware addr */
                        (u_int8_t *)&ip_dst.s_addr,     /* target protocol addr */
                        NULL,                           /* payload */
                        0,                              /* payload size */
                        libnet_handle,                  /* libnet context */
                        0) == -1)                       /* libnet id */
                    libnet_die(libnet_handle);

                if (libnet_build_ethernet(
                        hw_dst->ether_addr_octet,       /* dest eth addr */
                        hw_src->ether_addr_octet,       /* src eth addr */
                        ETHERTYPE_ARP,                  /* protocol type */
                        NULL,                           /* payload */
                        0,                              /* payload size */
                        libnet_handle,                  /* libnet context */
                        0) == -1)                       /* libnet id */
                    libnet_die(libnet_handle);

                if (libnet_adv_cull_packet(libnet_handle, &packet, &packet_size) == -1)
                    libnet_die(libnet_handle);

                printf("%i bytes to send, ", packet_size);
                libnet_adv_free_packet(libnet_handle, packet);

                usleep(100); /* prevents flooding */
                if ((status = libnet_write(libnet_handle)) == -1)
                    libnet_die(libnet_handle);

                printf("%d bytes sent\n", status);
                fflush(stdout);
                libnet_clear_packet(libnet_handle);

                /* address increments needs double conversion */
                ip_dst.s_addr = ntohl(htonl(ip_dst.s_addr) + 1);

            }

            printf("waiting for sniffer terminate\n");

            if (wait(&status) == pid)
                printf("sniffer terminated, exiting\n");
    }

    libnet_destroy(libnet_handle);
    pcap_close(pcap_handle);

    if(pcap_alldevs != NULL)
        pcap_freealldevs(pcap_alldevs);

    printf("scanner terminated\n");

    return EXIT_SUCCESS;
}

// EoF
