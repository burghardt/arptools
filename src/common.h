/*
   ARP Tools Common Functions
   Copyright (C) 2006, 2015 Krzysztof Burghardt.

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

void pcap_die (pcap_t *pcap_handle, char *message);
void libnet_die (libnet_t *libnet_handle);
char *hw_ntoa(struct libnet_ether_addr *hw);
char *pcap_get_first_interface(pcap_if_t **pcap_alldevs, char *pcap_error_buffer);
