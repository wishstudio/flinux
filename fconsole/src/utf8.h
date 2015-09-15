#pragma once

#include <stdint.h>

int utf8_get_sequence_len(char ch);
uint32_t utf8_decode(const char *data);
int utf8_to_utf16(const char *data, int srclen, uint16_t *outdata, int dstlen);
