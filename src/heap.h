#pragma once

void heap_init();
void heap_shutdown();

void *kmalloc(int size);
void kfree(void *mem, int size);
