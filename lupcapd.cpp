#include "lupcapd.h"

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
    
    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        printf("[-] pcap_findalldevs failed\n");
    }
    int i = 0;
    for(temp = alldevs; temp; temp=temp->next){
        strcat((char *)data, temp->name);
        strcat((char *)data, "+");
    }
    printf("[+] pcap_findalldevs success\n");
    data->header.data_length = strlen((char *)data->body);
}

void lupcap_read(pcap_t * handle, lupcap_data * data){
    bool ret = 1;
    struct pcap_pkthdr * header;
    const u_char * temp;
    int res = pcap_next_ex(handle, &header, &temp);
    if(res == -1 || res == -2){
        printf("[-] pcap next_ex failed\n");
    }
    memcpy(data->body, temp, sizeof(temp));
    data->header.data_length = strlen((char *)data->body);
    printf("[+] pcap next_ex success\n");
}

void lupcap_write(pcap_t * handle, lupcap_data * data){
    if(pcap_sendpacket(handle, data->body, data->header.data_length) != 0){
        printf("[-] pcap_sendpacket failed\n");
    }
    printf("[+] pcap_sendpacket success\n");
}
