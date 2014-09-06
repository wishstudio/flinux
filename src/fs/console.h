#pragma once

#include <fs/file.h>

int console_is_ready(struct file *f);
int console_alloc(struct file **in_file, struct file **out_file);
int console_is_console_file(struct file *f);
