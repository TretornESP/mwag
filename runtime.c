#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <errno.h>
#include <string.h>

void * handle;
char inhibit = 0;

struct jmptable {
    void * addr;
    struct jmptable * next;
};
short lastjumps = -1;

void decrypt_page_and_restore() {

    short jumps = *(short*)(dlsym(handle, "jumps"));
    printf("Jumps: %d Lastjumps: %d\n", jumps, lastjumps);
    if (jumps == lastjumps) {
        printf("Real crash detected, exiting\n");
        exit(1);
    }
    lastjumps = jumps;

    struct jmptable* table = (struct jmptable*)(dlsym(handle, "jmphead"));
    long long last_addr = *((long long*)table->addr);
    unsigned long page_start = last_addr & ~(0xfff);
    if (last_addr != page_start) {
        printf("Error: last jump %llx is not page aligned\n", last_addr);
        exit(1);
    }

    if (mprotect((void *)page_start, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        printf("Error: %s\n", strerror(errno));
        exit(1);
    }

    //Decrypt the entire page
    for (int i = 0; i < 0x1000; i++)
        *(char *)(page_start + i) ^= 0x55;

    void* function_end = (void*)last_addr;
    long long max_function_size = 0x1000;
    // Find the end of the function marked by \xcc\x5d\xc3
    while ((*(unsigned char*)function_end != 0x90 || *(unsigned char*)(function_end + 1) != 0x90 || *(unsigned char*)(function_end + 2) != 0xcc) && max_function_size > 0) {
        function_end++;
        max_function_size--;
    }

    printf("Function start: %llx end: %p\n", last_addr, function_end);

    //Ecrypt again the entire page
    for (int i = 0; i < 0x1000; i++)
        *(char *)(page_start + i) ^= 0x55;

    if (max_function_size == 0) {
        printf("Error: function too large\n");
        exit(1);
    }

    function_end += 3;

    // Restore the function
    for (int i = 0; i < (function_end - (void*)last_addr); i++)
        *(char *)(page_start + i) ^= 0x55;

    if (mprotect((void *)page_start, 0x1000, PROT_READ | PROT_EXEC) == -1) {
        printf("Error: %s\n", strerror(errno));
        exit(1);
    }
}

void encrypt() {
   
    long long last_addr = *(long long*)(dlsym(handle, "retaddr"));
    unsigned long page_start = last_addr & ~(0xfff);
    if (last_addr != page_start) {
        printf("Error: last jump %llx is not page aligned\n", last_addr);
        exit(1);
    }

    if (mprotect((void *)page_start, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        printf("Error: %s\n", strerror(errno));
        exit(1);
    }

    void* function_end = (void*)last_addr;
    long long max_function_size = 0x1000;
    // Find the end of the function marked by \xcc\x5d\xc3
    while ((*(unsigned char*)function_end != 0x90 || *(unsigned char*)(function_end + 1) != 0x90 || *(unsigned char*)(function_end + 2) != 0xcc) && max_function_size > 0) {
        function_end++;
        max_function_size--;
    }

    function_end--;
    printf("Encrypting from %p to %p\n", (void*)last_addr, function_end);

    if (max_function_size == 0) {
        printf("Error: function too large\n");
        exit(1);
    }

    // Encrypt the function
    for (int i = 0; i < (function_end - (void*)last_addr); i++)
        *(char *)(page_start + i) ^= 0x55;

    if (mprotect((void *)page_start, 0x1000, PROT_READ | PROT_EXEC) == -1) {
        printf("Error: %s\n", strerror(errno));
        exit(1);
    }

    inhibit = 0;
}

void handler(int sig, siginfo_t *info, void *ucontext) {
    switch (sig) {
        case SIGSEGV:
            printf("Segmentation fault, decrypting\n");
            decrypt_page_and_restore();
            break;
        case SIGILL:
            printf("Illegal instruction, decrypting\n");
            decrypt_page_and_restore();
            break;
        case SIGTRAP:
            printf("Trap detected, encrypting\n");
            encrypt();
            break;
        default:
            printf("Unknown signal\n");
            break;
    }
}

int main(int argc, char* argv[]) {
    struct sigaction act;
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGILL, &act, NULL);
    sigaction(SIGTRAP, &act, NULL);

    handle = dlopen(argv[1], RTLD_LAZY);
    if (handle == NULL) {
        printf("Error: %s\n", dlerror());
        return 1;
    }

    int (*func)(int, char*[]) = dlsym(handle, "main");

    if (func == NULL) {
        printf("Error: %s\n", dlerror());
        return 1;
    }
    func(argc, argv);
    dlclose(handle);
    return 0;
}