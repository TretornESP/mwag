#ifndef _VMAL_H
#define _VMAL_H
struct jmptable {
    void * addr;
    struct jmptable * next;
};

struct jmptable * jmphead = NULL;
void * retaddr = NULL;
short jumps = 0;

void jump(void * addr) {
    struct jmptable * jmp = valloc(sizeof(struct jmptable));
    jmp->addr = addr;
    jmp->next = jmphead;
    jmphead = jmp;
    jumps++;
}

void ret() {
    struct jmptable * jmp = jmphead;
    jmphead = jmp->next;
    retaddr = jmp->addr;
    free(jmp);
}

#define ENC __attribute__((__section__(".encrypted"), __aligned__(0x1000)))
#define JMP(x) jump(x); x();
#define JMPI(x) asm("nop"); asm("nop"); asm("int3"); JMP(x);
#define RET ret(); asm("nop"); asm("nop"); asm("int3"); return;

#endif