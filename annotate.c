#include <stdlib.h>
#include <stdint.h>
#include <elf.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include <stdio.h>

#include "load_elf.h"
#include "xed/xed-interface.h"

// struct impurity_table
// {
//     size_t aaa;
// };

struct branch_table
{
};

struct text_table
{
    size_t size;
    struct text_table_entry
    {
        size_t length;
        void *start;
    } entries[];
};

struct annotated_elf
{
    struct elf elf;
    char *string_table;
    struct text_table *text_table;
};

void find_text_segments(
    struct elf elf, 
    char *string_table,
    struct text_table **text_table)
{
    assert(!*text_table);
    *text_table = calloc(1, sizeof(struct text_table));
    assert(*text_table);

    for (size_t i = 0; i < elf.shnum; ++i)
    {
        uint64_t type = 0;
        uint64_t flags = 0;
        size_t size = 0;
        void *addr = NULL;
        char *name = NULL;
        switch (elf.class)
        {
            case ELFCLASS32:
                type = elf.e_sht32[i].sh_type;
                flags = elf.e_sht32[i].sh_flags;
                size = elf.e_sht32[i].sh_size;
                addr = (void *)(uint64_t)elf.e_sht32[i].sh_addr;
                name = string_table + elf.e_sht32[i].sh_name;
                break;
            case ELFCLASS64:
                type = elf.e_sht64[i].sh_type;
                flags = elf.e_sht64[i].sh_flags;
                size = elf.e_sht64[i].sh_size;
                addr = (void *)(uint64_t)elf.e_sht64[i].sh_addr;
                name = string_table + elf.e_sht64[i].sh_name;
                break;
            default:
                assert(false);
        }
        if (type != SHT_PROGBITS || flags != (SHF_ALLOC | SHF_EXECINSTR))
        {
            continue;
        }
        assert(name);
        if (strncmp(".text", name, 32))
        {
            continue;
        }
        assert(type && flags && size && addr);
        ++(*text_table)->size;
        *text_table = realloc(*text_table,
            sizeof(struct text_table) 
            + (*text_table)->size * sizeof(struct text_table_entry));
        assert(*text_table);
        (*text_table)->entries[(*text_table)->size - 1] = 
            (struct text_table_entry)
        {
            .length = size,
            .start = addr,
        };
    }
}

void load_string_table(struct elf elf, char **string_table)
{
    assert(!*string_table);
    size_t shstrndx = elf.class == ELFCLASS32
        ? elf.e_hdr32->e_shstrndx
        : elf.e_hdr64->e_shstrndx;
    size_t offset = 0;
    size_t length = 0;
    // Elf64_Shdr shte = elf.e_sht64[shstrndx];
    switch (elf.class)
    {
        case ELFCLASS32:
            assert(elf.e_sht32[shstrndx].sh_type == SHT_STRTAB);
            assert(elf.e_sht32[shstrndx].sh_flags == 0);
            assert(elf.e_sht32[shstrndx].sh_entsize == 0);
            offset = elf.e_sht32[shstrndx].sh_offset;
            length = elf.e_sht32[shstrndx].sh_size;
            break;
        case ELFCLASS64:
            assert(elf.e_sht64[shstrndx].sh_type == SHT_STRTAB);
            assert(elf.e_sht64[shstrndx].sh_flags == 0);
            assert(elf.e_sht64[shstrndx].sh_entsize == 0);
            offset = elf.e_sht64[shstrndx].sh_offset;
            length = elf.e_sht64[shstrndx].sh_size;
            break;
        default:
            assert(false);
    }
    assert(offset && length && offset + length > offset);
    assert(offset + length <= elf.file_length);
    *string_table = calloc(length, sizeof(char));
    assert(*string_table);
    memcpy(*string_table, elf.file + offset, length);
    //assert(false);
}

struct annotated_elf annotate_elf(struct elf elf)
{
    struct annotated_elf anno_elf;
    memset(&anno_elf, 0, sizeof(struct annotated_elf));
    anno_elf.elf = elf;
    load_string_table(elf, &anno_elf.string_table);
    find_text_segments(
        anno_elf.elf, 
        anno_elf.string_table, 
        &anno_elf.text_table);
    return anno_elf;
}

int main(int argc, char** argv)
{
    struct elf elf = load_elf("hw");
    struct annotated_elf anno_elf = annotate_elf(elf);
    printf("%p\n", anno_elf.text_table->entries[0].start);

    xed_tables_init();
    xed_machine_mode_enum_t mmode = XED_MACHINE_MODE_LONG_64;
    xed_address_width_enum_t stack_addr_width = XED_ADDRESS_WIDTH_64b;
    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero(&xedd);
    xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
    xed_error_enum_t xed_error = xed_decode(
        &xedd,
        (const uint8_t *)"\xcc\x00\x00\xcc" + 1,
        3);
        
    return 0;
}

