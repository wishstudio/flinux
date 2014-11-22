#pragma once

#include <common/ldt.h>
#include <Windows.h>
#include <stdint.h>

void tls_init();
void tls_reset();
void tls_shutdown();
void tls_beforefork();
void tls_afterfork();

int tls_gs_emulation(PCONTEXT context, uint8_t *code);
