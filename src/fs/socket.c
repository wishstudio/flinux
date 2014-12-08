#include <fs/socket.h>
#include <heap.h>

struct socket_file
{
	struct file base_file;
};

struct file *socket_socket(int domain, int type, int protocol)
{
	return NULL;
}
