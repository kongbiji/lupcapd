#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

bool lupcap_open(pcap_t * handle, char * dev);
bool lupcap_close(pcap_t * handle);
bool lupcap_findalldevs();
bool lupcap_read(pcap_t * handle, struct pcap_pkthdr * header, unsigned int &data_length, uint8_t * data);
bool lupcap_write(pcap_t * handle, unsigned int * data_length, uint8_t * data);