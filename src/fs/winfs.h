#pragma once

#include <fs/file.h>

struct file_system *winfs_alloc();
int winfs_is_winfile(struct file *f);
