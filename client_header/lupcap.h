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

bool lupcap_open(int *server_fd, uint8_t *datalink_type, char * dev){
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
    }
    *datalink_type = *l_data->body; // 1==eth, 127==802.11

    return true;
}

bool lupcap_close(int *server_fd{
    lupcap_data *l_data = (lupcap_data *)malloc(sizeof(lupcap_data));

    l_data->header.type = 0x1112;
    l_data->header.ret = 0x01;
    l_data->header.data_length = 0x0000;

    if(send(*server_fd, l_data, sizeof(lupcap_data), 0) < 0){
        return false;
    }
    memset(l_data, 0, sizeof(l_data));
    if(recv(*server_fd, l_data, sizeof(lupcap_data), 0) < 0){
        return false;
    }
    if(l_data->header.ret == 0x00){
        return false;
    }
    return true;
}

bool lupcap_findalldevs(int *server_fd, lupcap_data *l_data){
    //lupcap_data *l_data = (lupcap_data *)malloc(sizeof(lupcap_data));
    char temp[1460] = {0,};
    l_data->header.type = 0x1113;
    l_data->header.ret = 0x01;
    l_data->header.data_length = 0;

    if(send(*server_fd, l_data, sizeof(lupcap_data), 0) < 0){
        return false;
    }
    memset(l_data, 0, sizeof(l_data));
    if(recv(*server_fd, l_data, sizeof(lupcap_data), 0) < 0){
        return false;
    }
    if(l_data->header.ret == 0x01){
        printf("check >> %s\n", l_data->body);
        char *ptr = strtok((char *)l_data->body, "+");
        int i = 1;
        while (ptr != NULL){
            printf("%d: %s\n", ptr);
            ptr = strtok(NULL, "+");
            i++;
        }
    }
    return true;
}

int lupcap_read(int *server_fd, lupcap_data *l_data){
    //lupcap_data *l_data = (lupcap_data *)malloc(sizeof(lupcap_data));

    l_data->header.type = 0x1114;
    l_data->header.ret = 0x01;
    l_data->header.data_length = 0x0000;

    if(send(*server_fd, l_data, sizeof(lupcap_data), 0) < 0){
        return false;
    }
    memset(l_data, 0, sizeof(l_data));
    if(recv(*server_fd, l_data, sizeof(lupcap_data), 0) < 0){
        return false;
    }
    if(l_data->header.ret == 0x01){
        return true;
    }else{
        return false;
    }
    
}

int lupcap_write(int *server_fd, lupcap_data *l_data){

    l_data->header.type = 0x1114;
    l_data->header.ret = 0x01;

    if(send(*server_fd, l_data, sizeof(lupcap_data), 0) < 0){
        return false;
    }
    memset(l_data, 0, sizeof(l_data));
    if(recv(*server_fd, l_data, sizeof(lupcap_data), 0) < 0){
        return false;
    }
    if(l_data->header.ret == 0x00){
        return false;
    }
    return true;    
}