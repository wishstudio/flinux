#pragma once

#include <fs/file.h>

int pipe_alloc(struct file **fread, struct file **fwrite, int flags);
