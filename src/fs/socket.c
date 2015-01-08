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

#include <malloc.h>
#include <WinSock2.h>

#pragma comment(lib, "ws2_32.lib")

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
	struct file base_file;
	SOCKET socket;
	HANDLE event_handle;
	int flags;
};

static HANDLE socket_get_poll_handle(struct file *f, int *poll_events)
{
	struct socket_file *socket_file = (struct socket_file *) f;
	WSANETWORKEVENTS events;
	WSAEnumNetworkEvents(socket_file->socket, NULL, &events);
	*poll_events = 0;
	if ((events.lNetworkEvents & FD_READ) > 0)
	{
		if (events.iErrorCode[FD_READ_BIT])
		{
			*poll_events = LINUX_POLLERR;
			return NULL;
		}
		*poll_events |= LINUX_POLLIN;
	}
	if ((events.lNetworkEvents & FD_ACCEPT) > 0)
	{
		if (events.iErrorCode[FD_ACCEPT_BIT])
		{
			*poll_events = LINUX_POLLERR;
			return NULL;
		}
		*poll_events |= LINUX_POLLIN;
	}
	if ((events.lNetworkEvents & FD_WRITE) > 0)
	{
		if (events.iErrorCode[FD_WRITE_BIT])
		{
			*poll_events = LINUX_POLLERR;
			return NULL;
		}
		*poll_events |= LINUX_POLLOUT;
	}
	if ((events.lNetworkEvents & FD_CONNECT) > 0)
	{
		if (events.iErrorCode[FD_CONNECT_BIT])
		{
			*poll_events = LINUX_POLLERR;
			return NULL;
		}
		*poll_events |= LINUX_POLLOUT;
	}
	if ((events.lNetworkEvents & FD_CLOSE) > 0)
	{
		if (events.iErrorCode[FD_CLOSE_BIT])
		{
			*poll_events = LINUX_POLLERR;
			return NULL;
		}
		*poll_events |= LINUX_POLLIN | LINUX_POLLOUT;
	}
	if (*poll_events)
		return NULL;

	*poll_events = LINUX_POLLIN | LINUX_POLLOUT | LINUX_POLLERR;
	return socket_file->event_handle;
}

static int socket_blocking_wait(struct socket_file *f, int event_bit)
{
	do
	{
		WaitForSingleObject(f->event_handle, INFINITE);
		WSANETWORKEVENTS events;
		WSAEnumNetworkEvents(f->socket, f->event_handle, &events);
		if ((events.lNetworkEvents & (1 << event_bit)) > 0)
			return events.iErrorCode[event_bit];
	} while (1);
}

static int socket_sendmsg(struct socket_file *f, const struct msghdr *msg, int flags)
{
	if (flags)
		log_error("socket_sendmsg(): flags (0x%x) ignored.\n", flags);
	if ((f->flags & O_NONBLOCK))
	{
		WSABUF *buffers = (WSABUF *)alloca(sizeof(struct iovec) * msg->msg_iovlen);
		for (int i = 0; i < msg->msg_iovlen; i++)
		{
			buffers[i].len = msg->msg_iov[i].iov_len;
			buffers[i].buf = msg->msg_iov[i].iov_base;
		}
		WSAMSG wsamsg;
		wsamsg.name = msg->msg_name;
		wsamsg.namelen = msg->msg_namelen;
		wsamsg.lpBuffers = buffers;
		wsamsg.dwBufferCount = msg->msg_iovlen;
		wsamsg.Control.buf = msg->msg_control;
		wsamsg.Control.len = msg->msg_controllen;
		wsamsg.dwFlags = 0;
		
		DWORD sent;
		if (WSASendMsg(f->socket, &wsamsg, 0, &sent, NULL, NULL) == SOCKET_ERROR)
		{
			log_warning("WSASendMsg() failed, error code: %d\n", WSAGetLastError());
			return translate_socket_error(WSAGetLastError());
		}
		return sent;
	}
	else
	{
		/* TODO */
		__debugbreak();
	}
}

static int socket_close(struct file *f)
{
	struct socket_file *socket_file = (struct socket_file *) f;
	closesocket(socket_file->socket);
	CloseHandle(socket_file->event_handle);
	kfree(socket_file, sizeof(struct socket_file));
	return 0;
}

struct file_ops socket_ops =
{
	.get_poll_handle = socket_get_poll_handle,
	.close = socket_close,
};

static HANDLE init_socket_event(int sock)
{
	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.lpSecurityDescriptor = NULL;
	attr.bInheritHandle = TRUE;
	HANDLE handle = CreateEventW(&attr, FALSE, FALSE, NULL);
	if (handle == NULL)
	{
		log_error("CreateEventW() failed, error code: %d\n", GetLastError());
		return NULL;
	}
	if (WSAEventSelect(sock, handle, FD_READ | FD_WRITE | FD_ACCEPT | FD_CONNECT) == SOCKET_ERROR)
	{
		log_error("WSAEventSelect() failed, error code: %d\n", WSAGetLastError());
		CloseHandle(handle);
		return NULL;
	}
	return handle;
}

static int get_sockfd(int fd, struct socket_file **sock)
{
	struct file *f = vfs_get(fd);
	if (!f)
		return -EBADF;
	if (f->op_vtable != &socket_ops)
		return -ENOTSOCK;
	*sock = (struct socket_file *)f;
	return 0;
}

static int mm_check_read_msghdr(const struct msghdr *msg)
{
	if (!mm_check_read(msg, sizeof(struct msghdr)))
		return 0;
	if (msg->msg_iovlen && !mm_check_read(msg->msg_iov, sizeof(struct iovec) * msg->msg_iovlen))
		return 0;
	if (msg->msg_controllen && !mm_check_read(msg->msg_control, msg->msg_controllen))
		return 0;
	for (int i = 0; i < msg->msg_iovlen; i++)
	{
		log_info("iov %d: [%p, %p)\n", i, msg->msg_iov[i].iov_base, (uintptr_t)msg->msg_iov[i].iov_base + msg->msg_iov[i].iov_len);
		if (!mm_check_read(msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len))
			return 0;
	}
	return 1;
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
	HANDLE event_handle = init_socket_event(sock);
	if (!event_handle)
	{
		closesocket(sock);
		log_error("init_socket_event() failed.\n");
		return -ENFILE;
	}

	struct socket_file *f = (struct socket_file *) kmalloc(sizeof(struct socket_file));
	f->base_file.op_vtable = &socket_ops;
	f->base_file.ref = 1;
	f->socket = sock;
	f->event_handle = event_handle;
	f->flags = 0;
	if ((type & O_NONBLOCK))
		f->flags |= O_NONBLOCK;
	
	int fd = vfs_store_file((struct file *)f, (type & O_CLOEXEC) > 0);
	if (fd < 0)
		vfs_release((struct file *)f);
	log_info("socket fd: %d\n", fd);
	return fd;
}

DEFINE_SYSCALL(connect, int, sockfd, const struct sockaddr *, addr, size_t, addrlen)
{
	log_info("connect(%d, %p, %d)\n", sockfd, addr, addrlen);
	if (!mm_check_read(addr, sizeof(struct sockaddr)))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	/* WinSock2 sockaddr struct is compatible with the Linux one */
	if (connect(f->socket, addr, addrlen) == SOCKET_ERROR)
	{
		int e = WSAGetLastError();
		if (e == WSAEWOULDBLOCK)
		{
			if ((f->flags & O_NONBLOCK) > 0)
			{
				log_info("connect() returned EINPROGRESS.\n");
				return -EINPROGRESS;
			}
			else
				return socket_blocking_wait(f, FD_CONNECT_BIT);
		}
		log_warning("connect() failed, error code: %d\n", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	return 0;
}

DEFINE_SYSCALL(getsockname, int, sockfd, struct sockaddr *, addr, int *, addrlen)
{
	log_info("getsockname(%d, %p, %p)\n", sockfd, addr, addrlen);
	if (!mm_check_write(addrlen, sizeof(*addrlen)))
		return -EFAULT;
	if (!mm_check_write(addr, *addrlen))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	if (getsockname(f->socket, addr, addrlen) == SOCKET_ERROR)
	{
		log_warning("getsockname() failed, error code: %d\n", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	return 0;
}

DEFINE_SYSCALL(getpeername, int, sockfd, struct sockaddr *, addr, int *, addrlen)
{
	log_info("getpeername(%d, %p, %p)\n", sockfd, addr, addrlen);
	if (!mm_check_write(addrlen, sizeof(*addrlen)))
		return -EFAULT;
	if (!mm_check_write(addr, *addrlen))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	if (getpeername(f->socket, addr, addrlen) == SOCKET_ERROR)
	{
		log_warning("getsockname() failed, error code: %d\n", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	return 0;
}

DEFINE_SYSCALL(send, int, sockfd, const void *, buf, size_t, len, int, flags)
{
	log_info("send(%d, %p, %d, %x)\n", sockfd, buf, len, flags);
	if (!mm_check_read(buf, len))
		return -EFAULT;
	if (flags)
		log_error("flags (0x%x) ignored.\n", flags);
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	if ((f->flags & O_NONBLOCK) == 0)
	{
		/* TODO */
		__debugbreak();
	}
	r = send(f->socket, buf, len, 0);
	if (r == SOCKET_ERROR)
	{
		log_warning("send() failed, error code: %d\n", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	return r;
}

DEFINE_SYSCALL(recv, int, sockfd, void *, buf, size_t, len, int, flags)
{
	log_info("recv(%d, %p, %d, %x)\n", sockfd, buf, len, flags);
	if (!mm_check_write(buf, len))
		return -EFAULT;
	if (flags)
		log_error("flags (0x%x) ignored.\n", flags);
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	if ((f->flags & O_NONBLOCK) == 0)
	{
		/* TODO */
		__debugbreak();
	}
	r = recv(f->socket, buf, len, 0);
	if (r == SOCKET_ERROR)
	{
		log_warning("recv() faield, error code: %d\n", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	return r;
}

DEFINE_SYSCALL(sendto, int, sockfd, const void *, buf, size_t, len, int, flags, const struct sockaddr *, dest_addr, int, addrlen)
{
	log_info("sendto(%d, %p, %d, %x, %p, %d)\n", sockfd, buf, len, flags, dest_addr, addrlen);
	if (!mm_check_read(buf, len))
		return -EFAULT;
	if (dest_addr && !mm_check_read(dest_addr, addrlen))
		return -EFAULT;
	if (flags)
		log_error("flags (0x%x) ignored.\n", flags);
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	if ((f->flags & O_NONBLOCK) == 0)
	{
		/* TODO */
		__debugbreak();
	}
	r = sendto(f->socket, buf, len, 0, dest_addr, addrlen);
	if (r == SOCKET_ERROR)
	{
		log_warning("sendto() failed, error code: %d\n", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	return r;
}

DEFINE_SYSCALL(recvfrom, int, sockfd, void *, buf, size_t, len, int, flags, struct sockaddr *, src_addr, int *, addrlen)
{
	log_info("recvfrom(%d, %p, %d, %x, %p, %p)\n", sockfd, buf, len, flags, src_addr, addrlen);
	if (!mm_check_write(buf, len))
		return -EFAULT;
	if (src_addr)
	{
		if (!mm_check_write(addrlen, sizeof(*addrlen)))
			return -EFAULT;
		if (!mm_check_write(src_addr, *addrlen))
			return -EFAULT;
	}
	if (flags)
		log_error("flags (0x%x) ignored.\n", flags);
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	if ((f->flags & O_NONBLOCK) == 0)
	{
		/* TODO */
		__debugbreak();
	}
	r = recvfrom(f->socket, buf, len, 0, src_addr, addrlen);
	if (r == SOCKET_ERROR)
	{
		log_warning("recvfrom() faield, error code: %d\n", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	return r;
}

DEFINE_SYSCALL(sendmsg, int, sockfd, const struct msghdr *, msg, int, flags)
{
	log_info("sendmsg(%d, %p)\n", sockfd, msg);
	if (!mm_check_read_msghdr(msg))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	return socket_sendmsg(f, msg, flags);
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

	case SYS_CONNECT:
		return sys_connect(args[0], (const struct sockaddr *)args[1], args[2]);

	case SYS_GETSOCKNAME:
		return sys_getsockname(args[0], (struct sockaddr *)args[1], (int *)args[2]);

	case SYS_GETPEERNAME:
		return sys_getpeername(args[0], (struct sockaddr *)args[1], (int *)args[2]);

	case SYS_SEND:
		return sys_send(args[0], (const void *)args[1], args[2], args[3]);

	case SYS_RECV:
		return sys_recv(args[0], (void *)args[1], args[2], args[3]);

	case SYS_SENDTO:
		return sys_sendto(args[0], (const void *)args[1], args[2], args[3], (const struct sockaddr *)args[4], args[5]);
		
	case SYS_RECVFROM:
		return sys_recvfrom(args[0], (void *)args[1], args[2], args[3], (struct sockaddr *)args[4], (int *)args[5]);

	case SYS_SENDMSG:
		return sys_sendmsg(args[0], (const struct msghdr *)args[1], args[2]);

	default:
	{
		log_error("Unimplemented socketcall: %d\n", call);
		return -EINVAL;
	}
	}
}

DEFINE_SYSCALL(sendmmsg, int, sockfd, struct mmsghdr *, msgvec, unsigned int, vlen, unsigned int, flags)
{
	log_info("sendmmsg(sockfd=%d, msgvec=%p, vlen=%d, flags=%d)\n", sockfd, msgvec, vlen, flags);
	if (!mm_check_write(msgvec, sizeof(struct mmsghdr) * vlen))
		return -EFAULT;
	for (int i = 0; i < vlen; i++)
	{
		log_info("msgvec %d:\n", i);
		if (!mm_check_read_msghdr(&msgvec[i].msg_hdr))
			return -EFAULT;
	}
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	/* Windows have no native sendmmsg(), we emulate it by sending msgvec one by one */
	for (int i = 0; i < vlen; i++)
	{
		int len = socket_sendmsg(f, &msgvec[i].msg_hdr, flags);
		if (i == 0 && len < 0)
			return len;
		if (i == 0 && len == 0)
			return -EWOULDBLOCK;
		if (len <= 0)
			return i;
		msgvec[i].msg_len = len;
		int total = 0;
		for (int j = 0; j < msgvec[i].msg_hdr.msg_iovlen; j++)
			total += msgvec[i].msg_hdr.msg_iov[j].iov_len;
		if (len < total)
			return i + 1;
	}
	return vlen;
}
