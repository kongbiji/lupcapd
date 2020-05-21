#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

bool lupcap_connect(struct sockaddr_in *server_addr, int *server_fd){
    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr->sin_port = htons(2020);

    *server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(*server_fd == -1){
        return false;
    }   
    if(connect(*server_fd, (struct sockaddr*)server_addr, sizeof(*server_addr)) < 0){
        return false;
    }

    return true;
}

bool lupcap_open(int *server_fd, uint8_t * buf, char * dev){
    char temp[1460] = {0,};
    uint16_t * dev_len;
    *dev_len = strlen(dev);

    uint8_t send_data[20] = {0,};
    memcpy(send_data, "\x11\x11", 2);
    memcpy(send_data+2, dev_len, sizeof(*dev_len));
    memcpy(send_data+4, dev, sizeof(dev));

    if(send(*server_fd, send_data, sizeof(send_data), 0) < 0){
        return false;
    }
    memset(temp, 0, sizeof(temp));
    if(recv(*server_fd, temp, sizeof(temp), 0) < 0){
        return false;
    }
    if(temp[2] == '\x01'){
        memcpy(buf, temp+4, sizeof(temp)-4);
    }
    return true;
}

bool lupcap_close(int *server_fd, uint8_t * buf){
    char temp[1460] = {0,};
    uint8_t type[2];
    memcpy(type, "\x11\x12", sizeof(type));

    if(send(*server_fd, type, sizeof(type), 0) < 0){
        return false;
    }
    if(recv(*server_fd, temp, sizeof(temp), 0) < 0){
        return false;
    }
    if(temp[2] == '\x01'){
        memcpy(buf, temp+4, sizeof(temp)-4);
    }
    
    return true;
}

bool lupcap_findalldevs(int *server_fd, uint8_t * buf){
    char temp[1460] = {0,};
    uint8_t type[2];
    memcpy(type, "\x11\x13", sizeof(type));

    if(send(*server_fd, type, sizeof(type), 0) < 0){
        return false;
    }
    if(recv(*server_fd, temp, sizeof(temp), 0) < 0){
        return false;
    }
    if(temp[2] == '\x01'){
        memcpy(buf, temp+5, sizeof(temp)-5);
        printf("check >> %s\n", buf);
        char *ptr = strtok((char *)buf, "+");
        while (ptr != NULL){
            ptr = strtok(NULL, "+");
        }
    }
    return true;
}

int lupcap_read(int *server_fd, uint8_t * buf){
    uint8_t temp[1460] = {0,};
    uint8_t type[2];
    memcpy(type, "\x11\x14", sizeof(type));

    if(send(*server_fd, type, sizeof(type), 0) < 0){
        return false;
    }
    if(recv(*server_fd, temp, sizeof(temp), 0) < 0){
        return false;
    }
    if(temp[2] == '\x01'){
        memcpy(buf, temp+5, sizeof(temp)-5);
        return true;
    }else{
        return false;
    }
    
}

int lupcap_write(int *server_fd, uint8_t * buf){
    char temp[1460] = {0,};
    uint8_t type[2];
    memcpy(type, "\x11\x15", sizeof(type));
    if(send(*server_fd, type, sizeof(type), 0) < 0){
        return false;
    }
    if(recv(*server_fd, temp, sizeof(temp), 0) < 0){
        return false;
    }
    if(temp[2] == '\x01'){
        memcpy(buf, temp+3, sizeof(temp)-3);
    }
    return true;    
}