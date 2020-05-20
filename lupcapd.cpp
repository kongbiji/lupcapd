#include "lupcapd.h"

bool lupcap_open(pcap_t * handle, char * dev){
    char errbuf[PCAP_ERRBUF_SIZE];
    bool ret = 1;
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    printf("handle 1 >> %s\n", handle);
    if(handle == NULL){
        ret = 0;
    }else{
        printf("[+] pcap handle success\n");
    }
    
    return ret;
}

bool lupcap_close(pcap_t * handle){
    if(handle == NULL){
        return 0;
    }else{
        pcap_close(handle);
        printf("[+] pcap close success\n");
        return 1;
    }
}

// bool lupcap_findalldevs(){

// }

bool lupcap_read(pcap_t * handle, struct pcap_pkthdr * header, unsigned int &data_length, uint8_t * data){
    bool ret = 1;
    struct pcap_pkthdr * header_;
    const u_char * temp;
    printf("111111111111\n");
    while(1){
        printf("22222222222\n");
        int res = pcap_next_ex(handle, &header_, &temp);
        printf("33333333333\n");
        if(res == -1 || res == -2){
            ret = 0;
            break;
        }
        if(res == 0){
            continue;
        }
    }
    printf("im hear~~~\n");
    memcpy(data, temp, sizeof(temp));
    data_length = header_->caplen;
    printf("data >> %s\n", data);
    printf("[+] pcap next_ex success\n");
    return ret;
}

bool lupcap_write(pcap_t * handle, unsigned int * data_length, uint8_t * data){
    if(pcap_sendpacket(handle, data, *data_length) != 0){
        return false;
    }
    return true;
}
