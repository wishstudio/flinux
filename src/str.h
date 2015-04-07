/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdint.h>

int kprintf(const char *format, ...);
int ksprintf(char *buffer, const char *format, ...);

int utf8_get_sequence_len(char ch);
uint32_t utf8_decode(const char *data);
int utf8_to_utf16(const char *data, int srclen, uint16_t *outdata, int dstlen);
int utf8_to_utf16_filename(const char *data, int srclen, uint16_t *outdata, int dstlen);
int utf16_to_utf8(const uint16_t *data, int srclen, char *outdata, int dstlen);
int utf16_to_utf8_filename(const uint16_t *data, int srclen, char *outdata, int dstlen);
int wcwidth(uint32_t ucs); /* Defined in wcwidth.c */
