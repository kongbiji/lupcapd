#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

typedef struct{
    uint16_t data_length;
    lupcap_data data;
}socket_data;

typedef struct{
    uint16_t type;
    uint8_t ret;
    uint16_t data_length;
}lupcap_header;

typedef struct{
    lupcap_header header;
    uint8_t body[1460]; 
}lupcap_data;

bool lupcap_close(pcap_t * handle);
bool lupcap_findalldevs(uint16_t *data_length, uint8_t * data);
bool lupcap_read(pcap_t * handle, uint16_t * data_length, uint8_t * data);
bool lupcap_write(pcap_t * handle, uint8_t * data);