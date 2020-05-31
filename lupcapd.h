#include <stdio.h>
#include <stdbool.h>
#include <pcap.h>
#include <string.h>
#include <stdlib.h>

#pragma pack(push, 1)
typedef struct{
    uint16_t type;
    uint8_t ret = 0x00;
    uint16_t data_length = 0x0000;
}lupcap_header;

typedef struct{
    lupcap_header header;
    uint8_t body[1514] = {0,};
}lupcap_data;
#pragma pack(pop)

void lupcap_close(pcap_t * handle);
void lupcap_findalldevs(lupcap_data * data);
void lupcap_read(pcap_t * handle, lupcap_data * data);
void lupcap_write(pcap_t * handle, lupcap_data * data);