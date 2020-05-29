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
#include <signal.h>
#include <thread>
#include "lupcapd.h"

using namespace std;

#define SEND_SIZE 1460
int server_fd = socket(AF_INET, SOCK_STREAM, 0);

void sig_handler(int signo){
    close(server_fd);
    exit(1);
}

void client_thread(int client_fd){
    pcap_t * handle;
    bool ret_check;
    pcap_pkthdr * header;
    const unsigned char * rep;

    char type[2];
    uint16_t data_length;
    uint8_t data[SEND_SIZE];
    uint8_t save_data[SEND_SIZE];
    uint8_t recv_data[SEND_SIZE] ={0,};
    char dev[10] = {0,};
    
    while(1){
        printf("[+] waiting...\n");
        memset(recv_data, 0, sizeof(recv_data));
        memset(data, 0, sizeof(data));
        memset(save_data, 0, sizeof(save_data));

        if(recv(client_fd, recv_data, sizeof(recv_data), 0) == -1){
            printf("[-] recv failed\n");
            continue;
        }
        memcpy(type, recv_data, sizeof(type));
        
        if(memcmp(type, "\x11\x11", sizeof(type)) == 0){
            uint16_t recv_len = *(recv_data + 2);
            memcpy(dev, recv_data+4, recv_len);
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
            ret_check = lupcap_findalldevs(&data_length, save_data);
        }
        if(memcmp(type, "\x11\x14", sizeof(type)) == 0){
            ret_check = lupcap_read(handle, &data_length, save_data);
        }
        if(memcmp(type, "\x11\x15", sizeof(type)) == 0){
            ret_check = lupcap_write(handle, recv_data+2);
        }

        memcpy(data, type, sizeof(type));
        if(ret_check == 0){
            data[sizeof(type)] = '\x00';
        }else{
            data[sizeof(type)] = '\x01';
            if(memcmp(type, "\x11\x14", sizeof(type)) == 0 || memcmp(type, "\x11\x13", sizeof(type)) == 0){
                memcpy(data+sizeof(type)+1, &data_length, 2);
                memcpy(data+sizeof(type)+3, save_data, sizeof(save_data));
            }
        }
        send(client_fd, data, SEND_SIZE, 0);
        if(memcmp(type, "\x11\x12", sizeof(type)) == 0){
            break;
        }
   }
   close(client_fd);
}

int main(){
    signal(SIGINT, sig_handler);

    int client_fd;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int len;

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
    

    while(1){
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&len);
        if(client_fd < 0){
            close(server_fd);
            exit(1);
        }
        printf("[*] connection success\n");
        thread c_th(client_thread, client_fd);
        c_th.detach();
    }
}