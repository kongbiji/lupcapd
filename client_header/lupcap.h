#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define OPEN 0x1111
#define CLOSE 0x1112
#define FIND 0x1113
#define READ 0x1114
#define WRITE 0x1115

#pragma pack(push, 1)
typedef struct{
    uint16_t type;
    uint8_t ret = 0x00;
    uint16_t data_length = 0x0000;
}lupcap_header;

typedef struct{
    lupcap_header header;
    uint8_t body[1460] = {0,};
}lupcap_data;
#pragma pack(pop)

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
    lupcap_data *l_data = (lupcap_data *)malloc(sizeof(lupcap_data));

    l_data->header.type = OPEN;
    l_data->header.ret = 0x01;
    l_data->header.data_length = strlen(dev);
    printf("len >> %d %d\n", l_data->header.data_length, strlen(dev));
    memcpy(l_data->body, dev, strlen(dev));
    printf("dev >> %s %s\n", l_data->body, dev);

    if(send(*server_fd, l_data, sizeof(*l_data), 0) < 0){
        return false;
    }
    memset(l_data, 0, sizeof(l_data));
    if(recv(*server_fd, l_data, sizeof(l_data), 0) < 0){
        return false;
    }
    if(l_data->header.ret == 0x00){
        return false;
        //memcpy(buf, temp+4, sizeof(temp)-4);
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