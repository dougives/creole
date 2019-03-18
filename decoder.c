#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include <stdio.h>

#include "xed/xed-interface.h"
#include "load_elf.h"
#include "annotate.h"
#include "decoder.h"


void reset_decoder(struct decoder *decoder)
{
    decoder->inst_ptr = NULL;
    decoder->inst_class = XED_ICLASS_INVALID;
    decoder->xed_error = XED_ERROR_NONE;
    decoder->_inst_previous_length = 0;
    xed_decoded_inst_zero(&decoder->xedd);
    xed_decoded_inst_set_mode(
        &decoder->xedd, 
        decoder->mmode, 
        decoder->stack_addr_width);
    return;
}

struct decoder *create_decoder(
    xed_machine_mode_enum_t mmode,
    xed_address_width_enum_t stack_addr_width)
{
    xed_tables_init();
    struct decoder *decoder = calloc(1, sizeof(struct decoder));
    assert(decoder);
    decoder->mmode = mmode;
    decoder->stack_addr_width = stack_addr_width;
    reset_decoder(decoder);
    return decoder;
}

void free_decoder(struct decoder *decoder)
{
    free(decoder);
    return;
}

bool decoder_is_active(struct decoder *decoder)
{
    return (bool)decoder->inst_ptr;
}

static void update_decoder(struct decoder *decoder)
{
    decoder->inst_class = xed_decoded_inst_get_iclass(&decoder->xedd);
    decoder->_inst_previous_length = decoder->inst_length;
    decoder->inst_length = xed_decoded_inst_get_length(&decoder->xedd);
    return;
}

void activate_decoder(struct decoder *decoder, void *inst_ptr)
{
    // reset_decoder(decoder);
    assert(!decoder_is_active(decoder));
    decoder->inst_ptr = inst_ptr;
    decoder->xed_error = xed_decode(
        &decoder->xedd, 
        (const uint8_t *)decoder->inst_ptr, 
        15);
    assert(decoder->xed_error == XED_ERROR_NONE);
    update_decoder(decoder);
    return;
}

static void decode_current(struct decoder *decoder)
{
    xed_decoded_inst_zero_keep_mode(&decoder->xedd);
    decoder->xed_error = xed_decode(
        &decoder->xedd, 
        (const uint8_t *)decoder->inst_ptr, 
        15);
    assert(decoder->xed_error == XED_ERROR_NONE);
    update_decoder(decoder);
    return;
}

void decode_next(struct decoder *decoder)
{
    decoder->inst_ptr += decoder->inst_length;
    decode_current(decoder);
    return;
}

void print_current_inst(struct decoder *decoder)
{
    char buffer[0x100];
    xed_format_context(
        XED_SYNTAX_INTEL, 
        &decoder->xedd, 
        buffer, 0x100, 
        0, 0, 0);
    printf("%p[%d]: \t%s\n", 
        decoder->inst_ptr, 
        decoder->inst_length, 
        buffer);
    return;
}

// int main(int argc, char **argv)
// {
//     struct elf elf = load_elf("hw");
//     // struct annotated_elf anno_elf = annotate_elf(elf);
//     struct decoder *decoder = create_decoder(
//         XED_MACHINE_MODE_LONG_64,
//         XED_ADDRESS_WIDTH_64b);
//     activate_decoder(decoder, elf.map + elf.e_hdr64->e_entry);
//     print_current_inst(decoder);
//     decode_next(decoder);
//     print_current_inst(decoder);
//     decode_next(decoder);
//     print_current_inst(decoder);
//     free_decoder(decoder);
//     return 0;
// }
