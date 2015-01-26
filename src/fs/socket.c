/*
 * This file is part of Foreign Linux.
 *
 * Copyright (C) 2014, 2015 Xiangyan Sun <wishstudio@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <common/errno.h>
#include <common/fcntl.h>
#include <common/in.h>
#include <common/net.h>
#include <common/socket.h>
#include <common/tcp.h>
#include <fs/file.h>
#include <fs/socket.h>
#include <syscall/mm.h>
#include <syscall/syscall.h>
#include <syscall/vfs.h>
#include <heap.h>
#include <log.h>

#include <malloc.h>
#include <WinSock2.h>
#include <mstcpip.h>
#include <MSWSock.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

static int translate_address_family(int af)
{
	switch (af)
	{
	case LINUX_AF_UNSPEC: return AF_UNSPEC;
	case LINUX_AF_UNIX: return AF_UNIX;
	case LINUX_AF_INET: return AF_INET;
	case LINUX_AF_INET6: return AF_INET6;
	default:
		log_error("Unknown af: %d\n", af);
		return -EAFNOSUPPORT;
	}
}

static int translate_socket_error(int error)
{
	switch (error)
	{
	case 0: return 0;
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
		socket_inited = 1;
		log_info("WinSock2 initialized, version: %d.%d\n", LOBYTE(wsa_data.wVersion), HIBYTE(wsa_data.wVersion));
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
	int af, type;
	int events, connect_error;
};

/* Reports current ready state
 * If one event in error_report_events has potential error code, the last WSA error code is set to that
 */
static int socket_update_events(struct socket_file *f, int error_report_events)
{
	/* CAUTION:
	 * When we finally get to add multi-process(thread) shared socket support,
	 * We have to do proper synchronization to ensure even if a process die halfway
	 * the other processes won't lose the ready notification.
	 * This is very complicated and I don't want to touch too far for now
	 */
	WSANETWORKEVENTS events;
	WSAEnumNetworkEvents(f->socket, f->event_handle, &events);
	if (events.lNetworkEvents & FD_READ)
		f->events |= FD_READ;
	if (events.lNetworkEvents & FD_WRITE)
		f->events |= FD_WRITE;
	if (events.lNetworkEvents & FD_ACCEPT)
		f->events |= FD_ACCEPT;
	if (events.lNetworkEvents & FD_CONNECT)
	{
		f->events |= FD_CONNECT;
		f->connect_error = events.iErrorCode[FD_CONNECT_BIT];
	}
	if (events.lNetworkEvents & FD_CLOSE)
		f->events |= FD_CLOSE;
	int e = f->events;
	if (error_report_events & f->events & FD_CONNECT)
	{
		WSASetLastError(f->connect_error);
		f->events &= ~FD_CONNECT;
		f->connect_error = 0;
	}
	return e;
}

static int socket_get_poll_status(struct file *f)
{
	struct socket_file *socket_file = (struct socket_file *) f;
	int e = socket_update_events(socket_file, 0);
	int ret = 0;
	if (e & FD_READ)
		ret |= LINUX_POLLIN;
	if (e & FD_WRITE)
		ret |= LINUX_POLLOUT;
	return ret;
}

static HANDLE socket_get_poll_handle(struct file *f, int *poll_events)
{
	struct socket_file *socket_file = (struct socket_file *) f;
	*poll_events = LINUX_POLLIN | LINUX_POLLOUT;
	return socket_file->event_handle;
}

static int socket_wait_event(struct socket_file *f, int event, int flags)
{
	do
	{
		int e = socket_update_events(f, event);
		if (e & event)
			return 0;
		if ((f->base_file.flags & O_NONBLOCK) || (flags & LINUX_MSG_DONTWAIT))
			return -EWOULDBLOCK;
		WaitForSingleObject(f->event_handle, INFINITE);
	} while (1);
}

static int socket_sendto(struct socket_file *f, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, int addrlen)
{
	if (flags & ~LINUX_MSG_DONTWAIT)
		log_error("flags (0x%x) contains unsupported bits.\n", flags);
	int r;
	while ((r = socket_wait_event(f, FD_WRITE, flags)) == 0)
	{
		r = sendto(f->socket, buf, len, 0, dest_addr, addrlen);
		if (r != SOCKET_ERROR)
			break;
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("sendto() failed, error code: %d\n", err);
			return translate_socket_error(err);
		}
		f->events &= ~FD_WRITE;
	}
	return r;
}

static int socket_sendmsg(struct socket_file *f, const struct msghdr *msg, int flags)
{
	if (flags & ~LINUX_MSG_DONTWAIT)
		log_error("socket_sendmsg(): flags (0x%x) contains unsupported bits.\n", flags);
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
	
	int r;
	while ((r = socket_wait_event(f, FD_WRITE, flags)) == 0)
	{
		if (WSASendMsg(f->socket, &wsamsg, 0, &r, NULL, NULL) != SOCKET_ERROR)
			break;
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("WSASendMsg() failed, error code: %d\n", err);
			return translate_socket_error(err);
		}
		f->events &= ~FD_WRITE;
	}
	return r;
}

static int socket_recvfrom(struct socket_file *f, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen)
{
	if (flags & ~(LINUX_MSG_PEEK | LINUX_MSG_DONTWAIT))
		log_error("flags (0x%x) contains unsupported bits.\n", flags);
	int r;
	while ((r = socket_wait_event(f, FD_READ, flags)) == 0)
	{
		if (!(flags & LINUX_MSG_PEEK))
			f->events &= ~FD_READ;
		r = recvfrom(f->socket, buf, len, flags, src_addr, addrlen);
		if (r != SOCKET_ERROR)
			break;
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("recvfrom() failed, error code: %d\n", err);
			return translate_socket_error(err);
		}
	}
	return r;
}

static int socket_recvmsg(struct socket_file *f, struct msghdr *msg, int flags)
{
	if (flags & ~LINUX_MSG_DONTWAIT)
		log_error("socket_sendmsg(): flags (0x%x) contains unsupported bits.\n", flags);

	if (f->type != LINUX_SOCK_DGRAM && f->type != LINUX_SOCK_RAW)
	{
		/* WSARecvMsg() only supports datagram and raw sockets
		 * For other types we emulate using recvfrom()
		 */
		/* TODO: MSG_WAITALL
		 * Per documentation, MSG_WAITALL should only return one type of message, i.e. only from one addr
		 * But in this case (TCP) this should be true
		 */
		msg->msg_controllen = 0;
		msg->msg_flags = 0; /* TODO */
		return socket_recvfrom(f, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, flags, msg->msg_name, &msg->msg_namelen);
	}

	typedef int(*PFNWSARECVMSG)(
		_In_		SOCKET s,
		_Inout_		LPWSAMSG lpMsg,
		_Out_		LPDWORD lpdwNumberOfBytesRecvd,
		_In_		LPWSAOVERLAPPED lpOverlapped,
		_In_		LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
		);
	static PFNWSARECVMSG WSARecvMsg;
	if (!WSARecvMsg)
	{
		GUID guid = WSAID_WSARECVMSG;
		DWORD bytes;
		if (WSAIoctl(f->socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &WSARecvMsg, sizeof(WSARecvMsg), &bytes, NULL, NULL) == SOCKET_ERROR)
		{
			log_error("WSAIoctl(WSARecvMsg) failed, error code: %d\n", WSAGetLastError());
			return -EIO;
		}
	}

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

	int r;
	while ((r = socket_wait_event(f, FD_READ, flags)) == 0)
	{
		if (WSARecvMsg(f->socket, &wsamsg, &r, NULL, NULL) != SOCKET_ERROR)
			break;
		f->events &= ~FD_READ;
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("WSARecvMsg() failed, error code: %d\n", err);
			return translate_socket_error(err);
		}
	}
	/* TODO: Translate WSAMSG output to msghdr */
	return r;
}

static int socket_close(struct file *f)
{
	struct socket_file *socket_file = (struct socket_file *) f;
	closesocket(socket_file->socket);
	CloseHandle(socket_file->event_handle);
	kfree(socket_file, sizeof(struct socket_file));
	return 0;
}

static size_t socket_read(struct file *f, char *buf, size_t count)
{
	struct socket_file *socket_file = (struct socket_file *) f;
	return socket_recvfrom(socket_file, buf, count, 0, NULL, 0);
}

static size_t socket_write(struct file *f, const char *buf, size_t count)
{
	struct socket_file *socket_file = (struct socket_file *) f;
	return socket_sendto(socket_file, buf, count, 0, NULL, 0);
}

struct file_ops socket_ops =
{
	.get_poll_status = socket_get_poll_status,
	.get_poll_handle = socket_get_poll_handle,
	.close = socket_close,
	.read = socket_read,
	.write = socket_write,
};

static HANDLE init_socket_event(int sock)
{
	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.lpSecurityDescriptor = NULL;
	attr.bInheritHandle = TRUE;
	HANDLE handle = CreateEventW(&attr, TRUE, FALSE, NULL);
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
	if (msg->msg_namelen && !mm_check_read(msg->msg_name, msg->msg_namelen))
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

static int mm_check_write_msghdr(struct msghdr *msg)
{
	if (!mm_check_write(msg, sizeof(struct msghdr)))
		return 0;
	if (msg->msg_namelen && !mm_check_write(msg->msg_name, msg->msg_namelen))
		return 0;
	if (msg->msg_iovlen && !mm_check_write(msg->msg_iov, sizeof(struct iovec) * msg->msg_iovlen))
		return 0;
	if (msg->msg_controllen & !mm_check_write(msg->msg_control, msg->msg_controllen))
		return 0;
	for (int i = 0; i < msg->msg_iovlen; i++)
	{
		log_info("iov %d: [%p, %p)\n", i, msg->msg_iov[i].iov_base, (uintptr_t)msg->msg_iov[i].iov_base + msg->msg_iov[i].iov_len);
		if (!mm_check_write(msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len))
			return 0;
	}
	return 1;
}

DEFINE_SYSCALL(socket, int, domain, int, type, int, protocol)
{
	log_info("socket(domain=%d, type=0%o, protocol=%d)\n", domain, type, protocol);
	socket_ensure_initialized();

	/* Translation constants to their Windows counterparts */
	int win32_af = translate_address_family(domain);
	if (win32_af < 0)
		return win32_af;

	int win32_type;
	switch (type & LINUX_SOCK_TYPE_MASK)
	{
	case LINUX_SOCK_DGRAM: win32_type = SOCK_DGRAM; break;
	case LINUX_SOCK_STREAM: win32_type = SOCK_STREAM; break;
	case LINUX_SOCK_RAW: win32_type = SOCK_RAW; break;
	case LINUX_SOCK_RDM: win32_type = SOCK_RDM; break;
	case LINUX_SOCK_SEQPACKET: win32_type = SOCK_SEQPACKET; break;
	default:
		log_error("Unknown type: %d\n", type & LINUX_SOCK_TYPE_MASK);
		return -EPROTONOSUPPORT;
	}

	SOCKET sock = socket(win32_af, win32_type, protocol);
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
	f->af = domain;
	f->type = (type & LINUX_SOCK_TYPE_MASK);
	f->events = 0;
	f->connect_error = 0;
	f->base_file.flags = O_RDWR;
	if ((type & O_NONBLOCK))
		f->base_file.flags |= O_NONBLOCK;
	
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
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("connect() failed, error code: %d\n", err);
			return translate_socket_error(err);
		}
		if ((f->base_file.flags & O_NONBLOCK) > 0)
		{
			log_info("connect() returned EINPROGRESS.\n");
			return -EINPROGRESS;
		}
		else
		{
			socket_wait_event(f, FD_CONNECT, 0);
			return translate_socket_error(WSAGetLastError());
		}
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
		if (GetLastError() == WSAEINVAL)
		{
			/* Winsock returns WSAEINVAL if the socket is unbound, but in Linux this is okay.
			 * We fake a result and return
			 */
			switch (f->af)
			{
			case AF_INET:
				addr->sa_family = AF_INET;
				memset(addr->sa_data, 0, sizeof(addr->sa_data));
				*addrlen = sizeof(struct sockaddr_in);
				break;

			case AF_INET6:
				addr->sa_family = AF_INET6;
				memset(addr->sa_data, 0, sizeof(addr->sa_data));
				*addrlen = sizeof(struct sockaddr_in6);
				break;
			}
		}
		else
		{
			log_warning("getsockname() failed, error code: %d\n", WSAGetLastError());
			return translate_socket_error(WSAGetLastError());
		}
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
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	return socket_sendto(f, buf, len, flags, NULL, 0);
}

DEFINE_SYSCALL(recv, int, sockfd, void *, buf, size_t, len, int, flags)
{
	log_info("recv(%d, %p, %d, %x)\n", sockfd, buf, len, flags);
	if (!mm_check_write(buf, len))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	return socket_recvfrom(f, buf, len, flags, NULL, 0);
}

DEFINE_SYSCALL(sendto, int, sockfd, const void *, buf, size_t, len, int, flags, const struct sockaddr *, dest_addr, int, addrlen)
{
	log_info("sendto(%d, %p, %d, %x, %p, %d)\n", sockfd, buf, len, flags, dest_addr, addrlen);
	if (!mm_check_read(buf, len))
		return -EFAULT;
	if (dest_addr && !mm_check_read(dest_addr, addrlen))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	return socket_sendto(f, buf, len, flags, dest_addr, addrlen);
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
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	return socket_recvfrom(f, buf, len, flags, src_addr, addrlen);
}

DEFINE_SYSCALL(shutdown, int, sockfd, int, how)
{
	log_info("shutdown(%d, %d)\n", sockfd, how);
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r < 0)
		return r;
	int win32_how;
	if (how == SHUT_RD)
		win32_how = SD_RECEIVE;
	else if (how == SHUT_WR)
		win32_how = SD_SEND;
	else if (how == SHUT_RDWR)
		win32_how = SD_BOTH;
	else
		return -EINVAL;
	if (shutdown(f->socket, win32_how) == SOCKET_ERROR)
	{
		log_warning("shutdown() failed, error code: %d\n", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	return 0;
}

static int socket_get_set_sockopt(int call, struct socket_file *f, int level, int optname, const void *set_optval, int set_optlen, void *get_optval, int *get_optlen)
{
	int in_level = level, in_optname = optname;
	switch (level)
	{
	case LINUX_SOL_IP:
	{
		level = IPPROTO_IP;
		switch (optname)
		{
		case LINUX_IP_HDRINCL: optname = IP_HDRINCL; goto get_set_sockopt;
		}
	}
	case LINUX_SOL_SOCKET:
	{
		level = SOL_SOCKET;
		switch (optname)
		{
		case LINUX_SO_ERROR: optname = SO_ERROR; goto get_set_sockopt;
		case LINUX_SO_BROADCAST: optname = SO_BROADCAST; goto get_set_sockopt;
		case LINUX_SO_KEEPALIVE: optname = SO_KEEPALIVE; goto get_set_sockopt;
		}
	}
	case LINUX_SOL_TCP:
	{
		level = IPPROTO_TCP;
		switch (optname)
		{
		case LINUX_TCP_NODELAY: optname = TCP_NODELAY; goto get_set_sockopt;
		}
	}
	}
	log_error("Unhandled sockopt level %d, optname %d\n", in_level, in_optname);
	return -EINVAL;

get_set_sockopt:
	/* The default case */
	if (call == SYS_SETSOCKOPT)
	{
		if (setsockopt(f->socket, level, optname, set_optval, set_optlen) == SOCKET_ERROR)
		{
			log_warning("setsockopt() failed, error code: %d\n", WSAGetLastError());
			return translate_socket_error(WSAGetLastError());
		}
		return 0;
	}
	else
	{
		if (getsockopt(f->socket, level, optname, get_optval, get_optlen) == SOCKET_ERROR)
		{
			log_warning("getsockopt() failed, error code: %d\n", WSAGetLastError());
			return translate_socket_error(WSAGetLastError());
		}
		return 0;
	}
}

DEFINE_SYSCALL(setsockopt, int, sockfd, int, level, int, optname, const void *, optval, int, optlen)
{
	log_info("setsockopt(%d, %d, %d, %p, %d)\n", sockfd, level, optname, optval, optlen);
	if (optval && !mm_check_read(optval, optlen))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	return socket_get_set_sockopt(SYS_SETSOCKOPT, f, level, optname, optval, optlen, NULL, NULL);
}

DEFINE_SYSCALL(getsockopt, int, sockfd, int, level, int, optname, void *, optval, int *, optlen)
{
	log_info("getsockopt(%d, %d, %d, %p, %p)\n", sockfd, level, optname, optval, optlen);
	if (optlen && !mm_check_write(optlen, sizeof(*optlen)))
		return -EFAULT;
	if (optlen && !mm_check_write(optval, *optlen))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	return socket_get_set_sockopt(SYS_GETSOCKOPT, f, level, optname, NULL, NULL, optval, optlen);
}

DEFINE_SYSCALL(sendmsg, int, sockfd, const struct msghdr *, msg, int, flags)
{
	log_info("sendmsg(%d, %p, %x)\n", sockfd, msg, flags);
	if (!mm_check_read_msghdr(msg))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r)
		return r;
	return socket_sendmsg(f, msg, flags);
}

DEFINE_SYSCALL(recvmsg, int, sockfd, struct msghdr *, msg, int, flags)
{
	log_info("recvmsg(%d, %p, %x)\n", sockfd, msg, flags);
	if (!mm_check_write_msghdr(msg))
		return -EFAULT;
	struct socket_file *f;
	int r = get_sockfd(sockfd, &f);
	if (r < 0)
		return r;
	return socket_recvmsg(f, msg, flags);
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

	case SYS_SHUTDOWN:
		return sys_shutdown(args[0], args[1]);

	case SYS_SETSOCKOPT:
		return sys_setsockopt(args[0], args[1], args[2], (const void *)args[3], args[4]);

	case SYS_GETSOCKOPT:
		return sys_getsockopt(args[0], args[1], args[2], (void *)args[3], (int *)args[4]);

	case SYS_SENDMSG:
		return sys_sendmsg(args[0], (const struct msghdr *)args[1], args[2]);

	case SYS_RECVMSG:
		return sys_recvmsg(args[0], (struct msghdr *)args[1], args[2]);

	case SYS_SENDMMSG:
		return sys_sendmmsg(args[0], (struct mmsghdr *)args[1], args[2], args[3]);

	default:
	{
		log_error("Unimplemented socketcall: %d\n", call);
		return -EINVAL;
	}
	}
}
