#ifndef __CREOLE_LOAD_ELF_H__
#define __CREOLE_LOAD_ELF_H__

#include <stdlib.h>
#include <stdint.h>
#include <elf.h>

#define ELF_MAGIC 0x464c457f    // 0x7f + "ELF"
#define ELF_PHOFF_32 0x34
#define ELF_PHOFF_64 0x40
#define INT3 ((uint8_t)0xcc)

struct elf
{
    size_t map_length;
    void *map;
    void *base;
    void *vaddr_start;
    size_t file_length;
    union
    {   
        void *file;
        Elf32_Ehdr *e_hdr32;
        Elf64_Ehdr *e_hdr64;
    };
    size_t phnum;
    union
    {   
        void *e_pht;
        Elf32_Phdr *e_pht32;
        Elf64_Phdr *e_pht64;
    };
    size_t shnum;
    union
    {   
        void *e_sht;
        Elf32_Shdr *e_sht32;
        Elf64_Shdr *e_sht64;
    };
    uint8_t class;
};

struct elf load_elf(char *pathname);

#endif

