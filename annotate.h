#ifndef __CREOLE_ANNOTATE_H__
#define __CREOLE_ANNOTATE_H__

#include <stdlib.h>

#include "xed/xed-interface.h"
#include "load_elf.h"

// struct impurity_table
// {
//     size_t aaa;
// };

struct inst_bounds
{
    size_t size;
    void *entries[];
};

struct control_table
{
    size_t size;
    struct control_table_entry
    {
        void *inst_ptr;
        xed_iclass_enum_t inst_class;
        xed_decoded_inst_t inst;
    } entries[];
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
    struct control_table *control_table;
    struct inst_bounds *inst_bounds;
};

struct annotated_elf annotate_elf(struct elf elf);

#endif
