#pragma once

#include <Windows.h>
#include <stdint.h>

void tls_init();
void tls_reset();
void tls_shutdown();
void tls_beforefork();
void tls_afterfork();

int tls_emulation(PCONTEXT context, uint8_t *code);
