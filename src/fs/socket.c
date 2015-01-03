#include <common/fcntl.h>
#include <common/net.h>
#include <common/socket.h>
#include <fs/file.h>
#include <fs/socket.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/vfs.h>
#include <errno.h>
#include <heap.h>
#include <log.h>

#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")

static int socket_inited;

static void socket_ensure_initialized()
{
	if (!socket_inited)
	{
		WSADATA wsa_data;
		int r = WSAStartup(MAKEWORD(2, 2), &wsa_data);
		if (r != 0)
		{
			log_error("WSAStartup() failed, error code: %d\n", r);
			ExitProcess(1);
		}
		else
		{
			socket_inited = 1;
			log_info("WinSock2 initialized, version: %d.%d\n", LOBYTE(wsa_data.wVersion), HIBYTE(wsa_data.wVersion));
		}
	}
}

void socket_init()
{
	socket_inited = 0;
}

void socket_shutdown()
{
	if (socket_inited)
		WSACleanup();
}

struct socket_file
{
	SOCKET socket;
	struct file base_file;
};

static int socket_close(struct file *f)
{
	kfree(f, sizeof(struct socket_file));
	return 0;
}

struct file_ops socket_ops =
{
	.close = socket_close,
};

static int translate_socket_error(int error)
{
	switch (error)
	{
	case WSA_NOT_ENOUGH_MEMORY: return -ENOMEM;
	case WSAEINTR: return -EINTR;
	case WSAEBADF: return -EBADF;
	case WSAEACCES: return -EACCES;
	case WSAEFAULT: return -EFAULT;
	case WSAEINVAL: return -EINVAL;
	case WSAEMFILE: return -EMFILE;
	case WSAEWOULDBLOCK: return -EWOULDBLOCK;
	case WSAEINPROGRESS: return -EINPROGRESS;
	case WSAEALREADY: return -EALREADY;
	case WSAENOTSOCK: return -ENOTSOCK;
	case WSAEDESTADDRREQ: return -EDESTADDRREQ;
	case WSAEMSGSIZE: return -EMSGSIZE;
	case WSAEPROTOTYPE: return -EPROTOTYPE;
	case WSAENOPROTOOPT: return -ENOPROTOOPT;
	case WSAEPROTONOSUPPORT: return -EPROTONOSUPPORT;
	case WSAESOCKTNOSUPPORT: return -EPROTONOSUPPORT;
	case WSAEOPNOTSUPP: return -EOPNOTSUPP;
	case WSAEPFNOSUPPORT: return -EAFNOSUPPORT;
	case WSAEAFNOSUPPORT: return -EAFNOSUPPORT;
	case WSAEADDRINUSE: return -EADDRINUSE;
	case WSAEADDRNOTAVAIL: return -EADDRNOTAVAIL;
	case WSAENETDOWN: return -ENETDOWN;
	case WSAENETUNREACH: return -ENETUNREACH;
	case WSAENETRESET: return -ENETRESET;
	case WSAECONNABORTED: return -ECONNABORTED;
	case WSAECONNRESET: return -ECONNRESET;
	case WSAENOBUFS: return -ENOBUFS;
	case WSAEISCONN: return -EISCONN;
	case WSAENOTCONN: return -ENOTCONN;
	case WSAETIMEDOUT: return -ETIMEDOUT;
	case WSAECONNREFUSED: return -ECONNREFUSED;
	case WSAELOOP: return -ELOOP;
	case WSAENAMETOOLONG: return -ENAMETOOLONG;
	case WSAEHOSTDOWN: return -ETIMEDOUT;
	case WSAEHOSTUNREACH: return -EHOSTUNREACH;
	case WSAENOTEMPTY: return -ENOTEMPTY;
	case WSAECANCELLED: return -ECANCELED;
	default:
		log_error("Unhandled WSA error code: %d\n", error);
		return -EIO;
	}
}

DEFINE_SYSCALL(socket, int, domain, int, type, int, protocol)
{
	log_info("socket(domain=%d, type=%d, protocol=%d)\n", domain, type, protocol);
	socket_ensure_initialized();

	/* Translation constants to their Windows counterparts */
	int win32_af;
	switch (domain)
	{
	case LINUX_AF_UNSPEC: win32_af = AF_UNSPEC; break;
	case LINUX_AF_UNIX: win32_af = AF_UNIX; break;
	case LINUX_AF_INET: win32_af = AF_INET; break;
	case LINUX_AF_INET6: win32_af = AF_INET6; break;
	default:
		return -EAFNOSUPPORT;
	}

	int win32_type;
	switch (type & LINUX_SOCK_TYPE_MASK)
	{
	case LINUX_SOCK_DGRAM: win32_type = SOCK_DGRAM; break;
	case LINUX_SOCK_STREAM: win32_type = SOCK_STREAM; break;
	case LINUX_SOCK_RAW: win32_type = SOCK_RAW; break;
	case LINUX_SOCK_RDM: win32_type = SOCK_RDM; break;
	case LINUX_SOCK_SEQPACKET: win32_type = SOCK_SEQPACKET; break;
	default:
		return -EPROTONOSUPPORT;
	}

	int win32_protocol = protocol;
	if (protocol != 0)
	{
		log_error("protocol(%d) != 0\n", protocol);
		return -EPROTONOSUPPORT;
	}
	SOCKET sock = socket(win32_af, win32_type, win32_protocol);
	if (sock == INVALID_SOCKET)
	{
		log_warning("socket() failed, error code: %d\n", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	if (type & O_NONBLOCK)
	{
		int mode = 1;
		log_info("Set socket to non blocking mode.\n");
		int r = ioctlsocket(sock, FIONBIO, &mode);
		if (r)
		{
			log_warning("ioctlsocket() failed, error code: %d\n", WSAGetLastError());
			closesocket(sock);
			return translate_socket_error(WSAGetLastError());
		}
	}

	struct socket_file *f = (struct file *) kmalloc(sizeof(struct socket_file));
	f->base_file.op_vtable = &socket_ops;
	f->base_file.ref = 1;
	f->socket = sock;
	
	int fd = vfs_store_file(f, (type & O_CLOEXEC) > 0);
	if (fd < 0)
		vfs_release(f);
	return fd;
}

/* Argument list sizes for sys_socketcall */
#define AL(x) ((x) * sizeof(uintptr_t))
static const unsigned char nargs[21] = {
	AL(0), AL(3), AL(3), AL(3), AL(2), AL(3),
	AL(3), AL(3), AL(4), AL(4), AL(4), AL(6),
	AL(6), AL(2), AL(5), AL(5), AL(3), AL(3),
	AL(4), AL(5), AL(4)
};

DEFINE_SYSCALL(socketcall, int, call, uintptr_t *, args)
{
	if (call < 1 || call > SYS_SENDMMSG)
		return -EINVAL;
	if (!mm_check_read(args, nargs[call]))
		return -EFAULT;
	switch (call)
	{
	case SYS_SOCKET:
		return sys_socket(args[0], args[1], args[2]);

	default:
	{
		log_error("Unimplemented socketcall: %d\n", call);
		return -ENOSYS;
	}
	}
}
