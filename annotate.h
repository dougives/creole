#ifndef __CREOLE_ANNOTATE_H__
#define __CREOLE_ANNOTATE_H__

#include <stdlib.h>

#include "load_elf.h"

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

struct annotated_elf annotate_elf(struct elf elf);

#endif
