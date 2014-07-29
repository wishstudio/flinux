#pragma once

#include <common/ldt.h>
#include <Windows.h>
#include <stdint.h>

void tls_init();
void tls_shutdown();

int set_thread_area(struct user_desc *u_info);
int tls_gs_emulation(PCONTEXT context, uint8_t *code);
