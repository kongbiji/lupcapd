#include "lupcapd.h"

bool lupcap_close(pcap_t * handle){
    if(handle == NULL){
        return 0;
    }else{
        pcap_close(handle);
        printf("[+] pcap close success\n");
        return 1;
    }
}

bool lupcap_findalldevs(uint16_t *data_length, uint8_t * data){
    pcap_if_t * alldevs;
    pcap_if_t * temp;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        printf("[-] pcap_findalldevs failed\n");
        return false;
    }
    int i = 0;
    for(temp = alldevs; temp; temp=temp->next){
        strcat((char *)data, temp->name);
        strcat((char *)data, "+");
    }
    printf("[+] pcap_findalldevs success\n");
    *data_length = sizeof(*data);
    return true;
}

bool lupcap_read(pcap_t * handle, uint16_t *data_length, uint8_t * data){
    bool ret = 1;
    struct pcap_pkthdr * header;
    const u_char * temp;
    int res = pcap_next_ex(handle, &header, &temp);
    if(res == -1 || res == -2){
        printf("[-] pcap next_ex failed\n");
        return 0;
    }
    memcpy(data, temp, header->caplen);
    *data_length = header->caplen;
    printf("[+] pcap next_ex success\n");
    
    return ret;
}

bool lupcap_write(pcap_t * handle, uint8_t * data){
    uint16_t send_len = *data;
    if(pcap_sendpacket(handle, data, send_len) != 0){
        printf("[-] pcap_sendpacket failed\n");
        return false;
    }
    printf("[+] pcap_sendpacket success\n");
    return true;
}
