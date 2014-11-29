#pragma once

#include <common/ldt.h>
#include <Windows.h>
#include <stdint.h>

void tls_init();
void tls_reset();
void tls_shutdown();
void tls_beforefork();
void tls_afterfork();

int sys_set_thread_area(struct user_desc *u_info);
int tls_gs_emulation(PCONTEXT context, uint8_t *code);
