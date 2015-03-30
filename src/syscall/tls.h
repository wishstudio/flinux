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

#define TLS_KERNEL_ENTRY_COUNT	4
/* Used by dbt */
#define TLS_ENTRY_SCRATCH		0
#define TLS_ENTRY_GS			1
#define TLS_ENTRY_GS_ADDR		2
#define TLS_ENTRY_RETURN_ADDR	3

void tls_init();
void tls_reset();
void tls_shutdown();
void tls_beforefork();
void tls_afterfork();

int tls_kernel_entry_to_offset(int entry);
int tls_user_entry_to_offset(int entry);
