#include "lupcapd.h"

#define OPEN 0x1111
#define CLOSE 0x1112
#define FIND 0x1113
#define READ 0x1114
#define WRITE 0x1115

void lupcap_close(pcap_t * handle){
    if(handle == NULL){
    }else{
        pcap_close(handle);
        printf("[+] pcap close success\n");
    }
}

void lupcap_findalldevs(lupcap_data * data){
    pcap_if_t * alldevs;
    pcap_if_t * temp;
    char errbuf[PCAP_ERRBUF_SIZE];

    data->header.type = htons(FIND);
    
    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        data->header.ret = 0x00;
        printf("[-] pcap_findalldevs failed\n");
        return;
    }
    data->header.ret = 0x01;
    for(temp = alldevs; temp; temp=temp->next){
        strcat((char *)data->body, temp->name);
        strcat((char *)data->body, "+");
    }
    data->header.data_length = htons(strlen((char *)data->body));
    printf("[+] pcap_findalldevs success\n");
}

void lupcap_read(pcap_t * handle, lupcap_data * data){
    data->header.type = htons(READ);
    struct pcap_pkthdr * header;
    const u_char * temp;
    int res = pcap_next_ex(handle, &header, &temp);
    if(res == -1 || res == -2){
        data->header.ret = 0x00;
        printf("[-] pcap next_ex failed\n");
        return;
    }
    memcpy(data->body, temp, header->caplen);
    
    data->header.ret = 0x01;
    data->header.data_length = strlen((char *)data->body);
    printf("[+] pcap next_ex success\n");
}

void lupcap_write(pcap_t * handle, lupcap_data * data){
    if(pcap_sendpacket(handle, data->body, data->header.data_length) != 0){
        printf("[-] pcap_sendpacket failed\n");
    }
    printf("[+] pcap_sendpacket success\n");
}
