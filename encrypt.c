#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>

#define PASSWORD 0x55

int main(int argc, char* argv[]) {
    FILE *fp = fopen(argv[1], "rb");
    fseek(fp, 0, SEEK_END);
    size_t size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buf = malloc(size);
    fread(buf, 1, size, fp);
    fclose(fp);

    //Encrypt all .text section
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buf;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(buf + ehdr->e_shoff);
    Elf64_Shdr *sh_strtab = &shdr[ehdr->e_shstrndx];
    const char *const sh_strtab_p = buf + sh_strtab->sh_offset;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *const name = sh_strtab_p + shdr[i].sh_name;
        if (shdr[i].sh_type == SHT_PROGBITS && strcmp(name, ".encrypted") == 0) {
            //Make section not executable
            printf("Encrypting section %s\n", name);
            for (int j = 0; j < shdr[i].sh_size; j++) {
                buf[shdr[i].sh_offset + j] ^= PASSWORD;
            }
        }
    }
    
    //Write to file, create if not exist
    fp = fopen(argv[2], "wb");
    fwrite(buf, 1, size, fp);
    fclose(fp);
}