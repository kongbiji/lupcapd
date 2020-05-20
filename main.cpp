#include <stdio.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "lupcapd.h"

#define SEND_SIZE 1460

int main(){
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int client_fd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int len;
    char type[2];
    unsigned int data_length;
    uint8_t data[SEND_SIZE];
    uint8_t save_data[SEND_SIZE];
    uint8_t recv_data[SEND_SIZE] ={0,};
    char dev[10] = {0,};

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(2020);


    if(server_fd == -1){
        printf("[-] socket creation failed\n");
        return 0;
    }
    if(bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        printf("[-] bind failed\n");
        return 0;
    }
    if(listen(server_fd, 5) < 0){
        printf("[-] listen failed\n");
        return 0;
    }
    len = sizeof(client_addr);
    
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&len);
    if(client_fd < 0){
        close(server_fd);
        exit(1);
    }

    printf("[*] connection success\n");

    pcap_t * handle;
    bool ret_check;
    pcap_pkthdr * header;
    const unsigned char * rep;
    
    while(1){
        printf("[+] waiting...\n");
        memset(recv_data, 0, sizeof(recv_data));
        memset(data, 0, sizeof(data));
        if(recv(client_fd, recv_data, sizeof(recv_data), 0) == -1){
            printf("[-] recv failed\n");
            continue;
        }
        printf("recv data >> %x\n",recv_data);
        memcpy(type, recv_data, sizeof(type));
        
        printf("type >> %X%X\n",type[0],type[1]);
        if(memcmp(type, "\x11\x11", sizeof(type)) == 0){
            strcpy(dev, "wlan0");
            // ret_check = lupcap_open(handle, dev);
            char errbuf[PCAP_ERRBUF_SIZE];
            handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
            if(handle == NULL){
                ret_check = 0;
                printf("[-] pcap handle failed\n");
            }else{
                ret_check = 1;
                printf("[+] pcap handle success\n");
            }
        }
        if(memcmp(type, "\x11\x12", sizeof(type)) == 0){
            ret_check = lupcap_close(handle);
            break;
        }
        if(memcmp(type, "\x11\x13", sizeof(type)) == 0){
            //ret_check = lupcap_findalldevs();
        }
        if(memcmp(type, "\x11\x14", sizeof(type)) == 0){
            ret_check = lupcap_read(handle, header, data_length, save_data);
            
        }
        if(memcmp(type, "\x11\x15", sizeof(type)) == 0){
            //ret_check = lupcap_write(handle, data_length, save_data);
        }
        // TODO: send data to client
        memcpy(data, type, sizeof(type));
        if(ret_check == 0){
            data[sizeof(type)] = '\x00';
        }else{
            data[sizeof(type)] = '\x01';
            printf("check check\n");
            if(memcmp(type, "\x11\x14", sizeof(type)) == 0 || memcmp(type, "\x11\x13", sizeof(type)) == 0){
                memcpy(data+sizeof(type)+1, save_data, sizeof(save_data));
                printf("success >> %X\n", data[2]);
                printf("data >> %X:%X:%X:%X:%X:%X\n", data[3],data[4],data[5],data[6],data[7],data[8]);
            }
        }
        send(client_fd, data, SEND_SIZE, 0);
   }
   close(client_fd);
   close(server_fd);
}