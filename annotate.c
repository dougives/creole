#include <stdlib.h>
#include <stdint.h>
#include <elf.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>

#include <stdio.h>

#include "load_elf.h"
#include "annotate.h"
#include "decoder.h"
#include "xed/xed-interface.h"

static void enumerate_insts(
    void (*fn)(struct decoder *decoder, struct annotated_elf *anno_elf),
    struct annotated_elf *anno_elf)
{
    struct decoder *decoder = anno_elf->elf.class == ELFCLASS32
    ? create_decoder(
        XED_MACHINE_MODE_LONG_COMPAT_32, 
        XED_ADDRESS_WIDTH_32b)
    : create_decoder(
        XED_MACHINE_MODE_LONG_64,
        XED_ADDRESS_WIDTH_64b);
    struct text_table *text_table = anno_elf->text_table;
    for (size_t i = 0; i < text_table->size; ++i)
    {
        struct text_table_entry text_table_entry = text_table->entries[i];
        for (activate_decoder(decoder, text_table_entry.start);
            decoder->inst_ptr + decoder->inst_length 
                < text_table_entry.start + text_table_entry.length;
            decode_next(decoder))
        {
            fn(decoder, anno_elf);
        }
        reset_decoder(decoder);
    }
    free_decoder(decoder);
    return;
}

static void find_inst_bounds_fn(
    struct decoder *decoder,
    struct annotated_elf *anno_elf)
{
    struct inst_bounds **inst_bounds = &anno_elf->inst_bounds;
    ++(*inst_bounds)->size;
    *inst_bounds = realloc(
        *inst_bounds,
        sizeof(struct inst_bounds)
            + sizeof(void *) * (*inst_bounds)->size);
    assert(*inst_bounds);
    (*inst_bounds)->entries[(*inst_bounds)->size - 1] = decoder->inst_ptr;
    print_current_inst(decoder);
    return;
}

static void find_inst_bounds(struct annotated_elf *anno_elf)
{
    struct inst_bounds **inst_bounds = &anno_elf->inst_bounds;
    assert(!*inst_bounds);
    *inst_bounds = calloc(1, sizeof(struct inst_bounds));
    assert(*inst_bounds);
    enumerate_insts(find_inst_bounds_fn, anno_elf);
    return;
}

static void load_control_table_fn(
    struct decoder *decoder,
    struct annotated_elf *anno_elf)
{
    struct control_table **control_table = &anno_elf->control_table;
    switch (decoder->inst_class)
    {
        // case XED_ICLASS_BOUND:
        // case XED_ICLASS_INTO:
        //     assert(elf.class == ELFCLASS32);
        case XED_ICLASS_JB:
        case XED_ICLASS_JBE:
        case XED_ICLASS_JCXZ:
        case XED_ICLASS_JECXZ:
        case XED_ICLASS_JL:
        case XED_ICLASS_JLE:
        case XED_ICLASS_JMP:
        case XED_ICLASS_JMP_FAR:
        case XED_ICLASS_JNB:
        case XED_ICLASS_JNBE:
        case XED_ICLASS_JNL:
        case XED_ICLASS_JNLE:
        case XED_ICLASS_JNO:
        case XED_ICLASS_JNP:
        case XED_ICLASS_JNS:
        case XED_ICLASS_JNZ:
        case XED_ICLASS_JO:
        case XED_ICLASS_JP:
        case XED_ICLASS_JRCXZ:
        case XED_ICLASS_JS:
        case XED_ICLASS_JZ:
        case XED_ICLASS_LOOP:
        case XED_ICLASS_LOOPE:
        case XED_ICLASS_LOOPNE:
        case XED_ICLASS_CALL_FAR:
        case XED_ICLASS_CALL_NEAR:
        case XED_ICLASS_RET_FAR:
        case XED_ICLASS_RET_NEAR:
            ++(*control_table)->size;
            *control_table = realloc(
                *control_table,
                sizeof(struct control_table)
                    + sizeof(struct control_table_entry)
                        * (*control_table)->size);
            assert(*control_table);
            (*control_table)->entries[(*control_table)->size - 1] =
                (struct control_table_entry)
            {
                .inst_ptr = decoder->inst_ptr,
                .inst_class = decoder->inst_class,
                .inst = decoder->xedd,
            };
            // print_current_inst(decoder);
            return;
        default:
            return;
    }
}

static void load_control_table(struct annotated_elf *anno_elf)
{
    struct control_table **control_table = &anno_elf->control_table;
    assert(!*control_table);
    *control_table = calloc(1, sizeof(struct control_table));
    assert(*control_table);
    enumerate_insts(load_control_table_fn, anno_elf);
    return;
}

static void find_text_segments(
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
        uint64_t addr = 0;
        char *name = NULL;
        switch (elf.class)
        {
            case ELFCLASS32:
                type = elf.e_sht32[i].sh_type;
                flags = elf.e_sht32[i].sh_flags;
                size = elf.e_sht32[i].sh_size;
                addr = elf.e_sht32[i].sh_addr;
                name = string_table + elf.e_sht32[i].sh_name;
                break;
            case ELFCLASS64:
                type = elf.e_sht64[i].sh_type;
                flags = elf.e_sht64[i].sh_flags;
                size = elf.e_sht64[i].sh_size;
                addr = elf.e_sht64[i].sh_addr;
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
            .start = elf.map + addr,
        };
    }
}

static void load_string_table(struct elf elf, char **string_table)
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
    find_inst_bounds(&anno_elf);
    load_control_table(&anno_elf);
    return anno_elf;
}

int main(int argc, char** argv)
{
    struct elf elf = load_elf("hw");
    struct annotated_elf anno_elf = annotate_elf(elf);
    // printf("%p\n", anno_elf.text_table->entries[0].start);
        
    return 0;
}

