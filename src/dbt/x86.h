#pragma once

void dbt_init();
void dbt_reset();
void dbt_shutdown();

void __declspec(noreturn) dbt_run(size_t pc, size_t sp);
