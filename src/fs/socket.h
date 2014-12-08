#pragma once

#include <fs/file.h>

struct file *socket_socket(int domain, int type, int protocol);
