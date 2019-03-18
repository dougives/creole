#ifndef __CREOLE_DECODER_H__
#define __CREOLE_DECODER_H__

#include <stdbool.h>

#include "xed/xed-interface.h"


struct decoder
{
    void *inst_ptr;
    xed_iclass_enum_t inst_class;
    xed_uint_t inst_length;
    xed_machine_mode_enum_t mmode;
    xed_address_width_enum_t stack_addr_width;
    xed_error_enum_t xed_error;
    xed_decoded_inst_t xedd;

    xed_uint_t _inst_previous_length;
};

void reset_decoder(struct decoder *decoder);
struct decoder *create_decoder(
    xed_machine_mode_enum_t mmode,
    xed_address_width_enum_t stack_addr_width);
void free_decoder(struct decoder *decoder);
bool decoder_is_active(struct decoder *decoder);
void activate_decoder(struct decoder *decoder, void *inst_ptr);
void decode_next(struct decoder *decoder);
void print_current_inst(struct decoder *decoder);

#endif
