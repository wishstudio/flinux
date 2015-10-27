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
#include <syscall/process.h>
#include <syscall/sig.h>
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
		log_error("Unknown af: %d", af);
		return -L_EAFNOSUPPORT;
	}
}

static int translate_socket_error(int error)
{
	switch (error)
	{
	case 0: return 0;
	case WSA_NOT_ENOUGH_MEMORY: return -L_ENOMEM;
	case WSAEINTR: return -L_EINTR;
	case WSAEBADF: return -L_EBADF;
	case WSAEACCES: return -L_EACCES;
	case WSAEFAULT: return -L_EFAULT;
	case WSAEINVAL: return -L_EINVAL;
	case WSAEMFILE: return -L_EMFILE;
	case WSAEWOULDBLOCK: return -L_EWOULDBLOCK;
	case WSAEALREADY: return -L_EALREADY;
	case WSAENOTSOCK: return -L_ENOTSOCK;
	case WSAEDESTADDRREQ: return -L_EDESTADDRREQ;
	case WSAEMSGSIZE: return -L_EMSGSIZE;
	case WSAEPROTOTYPE: return -L_EPROTOTYPE;
	case WSAENOPROTOOPT: return -L_ENOPROTOOPT;
	case WSAEPROTONOSUPPORT: return -L_EPROTONOSUPPORT;
	case WSAESOCKTNOSUPPORT: return -L_EPROTONOSUPPORT;
	case WSAEOPNOTSUPP: return -L_EOPNOTSUPP;
	case WSAEPFNOSUPPORT: return -L_EPFNOSUPPORT;
	case WSAEAFNOSUPPORT: return -L_EAFNOSUPPORT;
	case WSAEADDRINUSE: return -L_EADDRINUSE;
	case WSAEADDRNOTAVAIL: return -L_EADDRNOTAVAIL;
	case WSAENETDOWN: return -L_ENETDOWN;
	case WSAENETUNREACH: return -L_ENETUNREACH;
	case WSAENETRESET: return -L_ENETRESET;
	case WSAECONNABORTED: return -L_ECONNABORTED;
	case WSAECONNRESET: return -L_ECONNRESET;
	case WSAENOBUFS: return -L_ENOBUFS;
	case WSAEISCONN: return -L_EISCONN;
	case WSAENOTCONN: return -L_ENOTCONN;
	case WSAETIMEDOUT: return -L_ETIMEDOUT;
	case WSAECONNREFUSED: return -L_ECONNREFUSED;
	case WSAELOOP: return -L_ELOOP;
	case WSAENAMETOOLONG: return -L_ENAMETOOLONG;
	case WSAEHOSTDOWN: return -L_ETIMEDOUT;
	case WSAEHOSTUNREACH: return -L_EHOSTUNREACH;
	case WSAENOTEMPTY: return -L_ENOTEMPTY;
	case WSAECANCELLED: return -L_ECANCELED;
	default:
		log_error("Unhandled WSA error code: %d", error);
		return -L_EIO;
	}
}

static int translate_socket_addr_to_winsock(const struct sockaddr_storage *from, struct sockaddr_storage *to, int addrlen)
{
	if (addrlen < sizeof(from->ss_family))
		return SOCKET_ERROR;
	switch (from->ss_family)
	{
	case LINUX_AF_UNSPEC:
		memset(to, 0, addrlen);
		return addrlen;

	case LINUX_AF_INET:
		if (addrlen < sizeof(struct sockaddr_in))
			return SOCKET_ERROR;
		memcpy(to, from, addrlen);
		return addrlen;

	case LINUX_AF_INET6:
		if (addrlen < sizeof(struct sockaddr_in6))
			return SOCKET_ERROR;
		memcpy(to, from, addrlen);
		to->ss_family = AF_INET6;
		return addrlen;
		
	default:
		log_error("Unknown address family: %d", from->ss_family);
		return SOCKET_ERROR;
	}
}

/* Caller ensures the input is correct */
static int translate_socket_addr_to_linux(struct sockaddr_storage *addr, int addrlen)
{
	switch (addr->ss_family)
	{
	case AF_INET6:
		addr->ss_family = LINUX_AF_INET6;
		break;
	}
	return addrlen;
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
			log_error("WSAStartup() failed, error code: %d", r);
			process_exit(1, 0);
		}
		socket_inited = 1;
		log_info("WinSock2 initialized, version: %d.%d", LOBYTE(wsa_data.wVersion), HIBYTE(wsa_data.wVersion));
	}
}

void socket_init()
{
	socket_inited = 0;
}

struct socket_file
{
	struct file base_file;
	SOCKET socket;
	HANDLE event_handle;
	int af, type;
	int events, connect_error, accept_error;
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
	if (events.lNetworkEvents & FD_CONNECT)
	{
		f->events |= FD_CONNECT;
		f->connect_error = events.iErrorCode[FD_CONNECT_BIT];
	}
	if (events.lNetworkEvents & FD_ACCEPT)
	{
		f->events |= FD_ACCEPT;
		f->accept_error = events.iErrorCode[FD_ACCEPT_BIT];
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
	if (error_report_events & f->events & FD_ACCEPT)
	{
		WSASetLastError(f->accept_error);
		f->events &= ~FD_ACCEPT;
		f->accept_error = 0;
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
	if (e & FD_CLOSE)
		ret |= LINUX_POLLIN | LINUX_POLLHUP;
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
			return -L_EWOULDBLOCK;
		if (signal_wait(1, &f->event_handle, INFINITE) == WAIT_INTERRUPTED)
			return -L_EINTR;
	} while (1);
}

static int socket_sendto_unsafe(struct socket_file *f, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, int addrlen)
{
	if (flags & ~LINUX_MSG_DONTWAIT)
		log_error("flags (0x%x) contains unsupported bits.", flags);
	struct sockaddr_storage addr_storage;
	if (addrlen)
	{
		if ((addrlen = translate_socket_addr_to_winsock((const struct sockaddr_storage *)dest_addr, &addr_storage, addrlen)) == SOCKET_ERROR)
			return -L_EINVAL;
		dest_addr = (const struct sockaddr *)&addr_storage;
	}
	else
		dest_addr = NULL;
	int r;
	while ((r = socket_wait_event(f, FD_WRITE, flags)) == 0)
	{
		r = sendto(f->socket, buf, len, 0, dest_addr, addrlen);
		if (r != SOCKET_ERROR)
			break;
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("sendto() failed, error code: %d", err);
			return translate_socket_error(err);
		}
		f->events &= ~FD_WRITE;
	}
	return r;
}

static int socket_sendmsg_unsafe(struct socket_file *f, const struct msghdr *msg, int flags)
{
	if (flags & ~LINUX_MSG_DONTWAIT)
		log_error("socket_sendmsg(): flags (0x%x) contains unsupported bits.", flags);
	WSABUF *buffers = (WSABUF *)alloca(sizeof(struct iovec) * msg->msg_iovlen);
	for (int i = 0; i < msg->msg_iovlen; i++)
	{
		buffers[i].len = msg->msg_iov[i].iov_len;
		buffers[i].buf = msg->msg_iov[i].iov_base;
	}
	struct sockaddr_storage addr_storage;
	WSAMSG wsamsg;
	if (msg->msg_namelen)
	{
		if ((wsamsg.namelen = translate_socket_addr_to_winsock(msg->msg_name, &addr_storage, msg->msg_namelen)) == SOCKET_ERROR)
			return -L_EINVAL;
		wsamsg.name = (LPSOCKADDR)&addr_storage;
	}
	else
	{
		wsamsg.name = NULL;
		wsamsg.namelen = 0;
	}
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
			log_warning("WSASendMsg() failed, error code: %d", err);
			return translate_socket_error(err);
		}
		f->events &= ~FD_WRITE;
	}
	return r;
}

static int socket_recvfrom_unsafe(struct socket_file *f, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen)
{
	if (flags & ~(LINUX_MSG_PEEK | LINUX_MSG_DONTWAIT))
		log_error("flags (0x%x) contains unsupported bits.", flags);
	struct sockaddr_storage addr_storage;
	int addr_storage_len = sizeof(struct sockaddr_storage);
	int r;
	while ((r = socket_wait_event(f, FD_READ | FD_CLOSE, flags)) == 0)
	{
		if (!(flags & LINUX_MSG_PEEK))
			f->events &= ~FD_READ;
		r = recvfrom(f->socket, buf, len, flags, (struct sockaddr *)&addr_storage, &addr_storage_len);
		if (r != SOCKET_ERROR)
			break;
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("recvfrom() failed, error code: %d", err);
			return translate_socket_error(err);
		}
	}
	if (addrlen)
	{
		addr_storage_len = translate_socket_addr_to_linux(&addr_storage, addr_storage_len);
		int copylen = min(*addrlen, addr_storage_len);
		memcpy(src_addr, &addr_storage, copylen);
		*addrlen = addr_storage_len;
	}
	return r;
}

static int socket_recvmsg_unsafe(struct socket_file *f, struct msghdr *msg, int flags)
{
	if (flags & ~LINUX_MSG_DONTWAIT)
		log_error("socket_sendmsg(): flags (0x%x) contains unsupported bits.", flags);

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
		return socket_recvfrom_unsafe(f, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, flags, msg->msg_name, &msg->msg_namelen);
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
			log_error("WSAIoctl(WSARecvMsg) failed, error code: %d", WSAGetLastError());
			return -L_EIO;
		}
	}

	WSABUF *buffers = (WSABUF *)alloca(sizeof(struct iovec) * msg->msg_iovlen);
	for (int i = 0; i < msg->msg_iovlen; i++)
	{
		buffers[i].len = msg->msg_iov[i].iov_len;
		buffers[i].buf = msg->msg_iov[i].iov_base;
	}
	struct sockaddr_storage addr_storage;
	int addr_storage_len = sizeof(struct sockaddr_storage);
	WSAMSG wsamsg;
	wsamsg.name = (LPSOCKADDR)&addr_storage;
	wsamsg.namelen = addr_storage_len;
	wsamsg.lpBuffers = buffers;
	wsamsg.dwBufferCount = msg->msg_iovlen;
	wsamsg.Control.buf = msg->msg_control;
	wsamsg.Control.len = msg->msg_controllen;
	wsamsg.dwFlags = 0;

	int r;
	while ((r = socket_wait_event(f, FD_READ | FD_CLOSE, flags)) == 0)
	{
		if (WSARecvMsg(f->socket, &wsamsg, &r, NULL, NULL) != SOCKET_ERROR)
			break;
		f->events &= ~FD_READ;
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("WSARecvMsg() failed, error code: %d", err);
			return translate_socket_error(err);
		}
	}
	/* Translate WSAMSG back to msghdr */
	addr_storage_len = translate_socket_addr_to_linux(&addr_storage, wsamsg.namelen);
	int copylen = min(msg->msg_namelen, addr_storage_len);
	memcpy(msg->msg_name, &addr_storage, copylen);
	msg->msg_namelen = addr_storage_len;
	msg->msg_controllen = wsamsg.Control.len;
	msg->msg_flags = 0;
	if (wsamsg.dwFlags & MSG_TRUNC)
		msg->msg_flags |= LINUX_MSG_TRUNC;
	if (wsamsg.dwFlags & MSG_CTRUNC)
		msg->msg_flags |= LINUX_MSG_CTRUNC;
	/* TODO: MSG_EOR, MSG_OOB, and MSG_ERRQUEUE */
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
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = socket_recvfrom_unsafe(socket_file, buf, count, 0, NULL, 0);
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static size_t socket_write(struct file *f, const char *buf, size_t count)
{
	struct socket_file *socket_file = (struct socket_file *) f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = socket_sendto_unsafe(socket_file, buf, count, 0, NULL, 0);
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_stat(struct file *f, struct newstat *buf)
{
	INIT_STRUCT_NEWSTAT_PADDING(buf);
	buf->st_dev = 0;
	buf->st_ino = 0;
	buf->st_mode = S_IFSOCK + 0644;
	buf->st_nlink = 1;
	buf->st_uid = 0;
	buf->st_gid = 0;
	buf->st_rdev = 0;
	buf->st_size = 0;
	buf->st_blksize = PAGE_SIZE;
	buf->st_blocks = 0;
	buf->st_atime = 0;
	buf->st_atime_nsec = 0;
	buf->st_mtime = 0;
	buf->st_mtime_nsec = 0;
	buf->st_ctime = 0;
	buf->st_ctime_nsec = 0;
	return 0;
}


static HANDLE init_socket_event(int sock)
{
	SECURITY_ATTRIBUTES attr;
	attr.nLength = sizeof(SECURITY_ATTRIBUTES);
	attr.lpSecurityDescriptor = NULL;
	attr.bInheritHandle = TRUE;
	HANDLE handle = CreateEventW(&attr, TRUE, FALSE, NULL);
	if (handle == NULL)
	{
		log_error("CreateEventW() failed, error code: %d", GetLastError());
		return NULL;
	}
	if (WSAEventSelect(sock, handle, FD_READ | FD_WRITE | FD_ACCEPT | FD_CONNECT | FD_CLOSE) == SOCKET_ERROR)
	{
		log_error("WSAEventSelect() failed, error code: %d", WSAGetLastError());
		CloseHandle(handle);
		return NULL;
	}
	return handle;
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
		log_info("iov %d: [%p, %p)", i, msg->msg_iov[i].iov_base, (uintptr_t)msg->msg_iov[i].iov_base + msg->msg_iov[i].iov_len);
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
		log_info("iov %d: [%p, %p)", i, msg->msg_iov[i].iov_base, (uintptr_t)msg->msg_iov[i].iov_base + msg->msg_iov[i].iov_len);
		if (!mm_check_write(msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len))
			return 0;
	}
	return 1;
}

static const struct file_ops socket_ops;
static int socket_open(int domain, int type, int protocol)
{
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
		log_error("Unknown type: %d", type & LINUX_SOCK_TYPE_MASK);
		return -L_EPROTONOSUPPORT;
	}

	socket_ensure_initialized();
	SOCKET sock = socket(win32_af, win32_type, protocol);
	if (sock == INVALID_SOCKET)
	{
		log_warning("socket() failed, error code: %d", WSAGetLastError());
		return translate_socket_error(WSAGetLastError());
	}
	HANDLE event_handle = init_socket_event(sock);
	if (!event_handle)
	{
		closesocket(sock);
		log_error("init_socket_event() failed.");
		return -L_ENFILE;
	}

	struct socket_file *f = (struct socket_file *) kmalloc(sizeof(struct socket_file));
	file_init(&f->base_file, &socket_ops, O_RDWR);
	f->socket = sock;
	f->event_handle = event_handle;
	f->af = domain;
	f->type = (type & LINUX_SOCK_TYPE_MASK);
	f->events = 0;
	f->connect_error = 0;
	if ((type & O_NONBLOCK))
		f->base_file.flags |= O_NONBLOCK;

	int fd = vfs_store_file((struct file *)f, (type & O_CLOEXEC) > 0);
	if (fd < 0)
		vfs_release((struct file *)f);
	return fd;
}

static int socket_bind(struct file *f, const struct sockaddr *addr, int addrlen)
{
	struct socket_file *socket = (struct socket_file *)f;
	struct sockaddr_storage addr_storage;
	int addr_storage_len;
	if ((addr_storage_len = translate_socket_addr_to_winsock((const struct sockaddr_storage *)addr, &addr_storage, addrlen)) == SOCKET_ERROR)
		return -L_EINVAL;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = 0;
	if (bind(socket->socket, (struct sockaddr *)&addr_storage, addr_storage_len) == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		log_warning("bind() failed, error code: %d", err);
		r = translate_socket_error(err);
	}
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_connect(struct file *f, const struct sockaddr *addr, size_t addrlen)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	struct sockaddr_storage addr_storage;
	int r = 0;
	int addr_storage_len;
	if ((addr_storage_len = translate_socket_addr_to_winsock((const struct sockaddr_storage *)addr, &addr_storage, addrlen)) == SOCKET_ERROR)
		r = -L_EINVAL;
	else if (connect(socket->socket, (struct sockaddr *)&addr_storage, addr_storage_len) == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("connect() failed, error code: %d", err);
			r = translate_socket_error(err);
		}
		else if ((f->flags & O_NONBLOCK) > 0)
		{
			log_info("connect() returned EINPROGRESS.");
			r = -L_EINPROGRESS;
		}
		else
		{
			socket_wait_event(socket, FD_CONNECT, 0);
			r = translate_socket_error(WSAGetLastError());
		}
	}
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_listen(struct file *f, int backlog)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = 0;
	if (listen(socket->socket, backlog) == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		log_warning("listen() failed, error code: %d", err);
		r = translate_socket_error(err);
	}
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_accept(struct file *f, struct sockaddr *addr, int *addrlen)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = 0;
	if (accept(socket->socket, addr, addrlen) == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK)
		{
			log_warning("accept() failed, error code: %d", err);
			r = translate_socket_error(err);
		}
		else if ((f->flags & O_NONBLOCK) > 0)
		{
			log_info("No connecting clients, return EAGAIN.");
			r = -L_EAGAIN;
		}
		else
		{
			socket_wait_event(socket, FD_ACCEPT, 0);
			r = translate_socket_error(WSAGetLastError());
		}
	}
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_getsockname(struct file *f, struct sockaddr *addr, int *addrlen)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = 0;
	struct sockaddr_storage addr_storage;
	int addr_storage_len = sizeof(struct sockaddr_storage);
	if (getsockname(socket->socket, (struct sockaddr *)&addr_storage, &addr_storage_len) != SOCKET_ERROR)
		addr_storage_len = translate_socket_addr_to_linux(&addr_storage, addr_storage_len);
	else
	{
		if (GetLastError() == WSAEINVAL)
		{
			/* Winsock returns WSAEINVAL if the socket is unbound, but in Linux this is okay.
			* We fake a result and return
			*/
			switch (socket->af)
			{
			case LINUX_AF_INET:
			{
				struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr_storage;
				memset(addr_in, 0, sizeof(struct sockaddr_in));
				addr_storage_len = sizeof(struct sockaddr_in);
				break;
			}

			case LINUX_AF_INET6:
			{
				struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr_storage;
				memset(addr_in6, 0, sizeof(struct sockaddr_in6));
				addr_storage_len = sizeof(struct sockaddr_in6);
				break;
			}

			default:
				r = -L_EOPNOTSUPP;
				goto out;
			}
		}
		else
		{
			log_warning("getsockname() failed, error code: %d", WSAGetLastError());
			r = translate_socket_error(WSAGetLastError());
			goto out;
		}
	}
	int copylen = min(*addrlen, addr_storage_len);
	memcpy(addr, &addr_storage, copylen);
	*addrlen = addr_storage_len;
out:
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_getpeername(struct file *f, struct sockaddr *addr, int *addrlen)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	struct sockaddr_storage addr_storage;
	int addr_storage_len = sizeof(struct sockaddr_storage);
	int r = 0;
	if (getpeername(socket->socket, (struct sockaddr *)&addr_storage, &addr_storage_len) == SOCKET_ERROR)
	{
		log_warning("getsockname() failed, error code: %d", WSAGetLastError());
		r = translate_socket_error(WSAGetLastError());
		goto out;
	}
	addr_storage_len = translate_socket_addr_to_linux(&addr_storage, addr_storage_len);
	int copylen = min(*addrlen, addr_storage_len);
	memcpy(addr, &addr_storage, copylen);
	*addrlen = addr_storage_len;
out:
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static size_t socket_sendto(struct file *f, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, int addrlen)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = socket_sendto_unsafe(socket, buf, len, flags, dest_addr, addrlen);
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static size_t socket_recvfrom(struct file *f, void *buf, size_t len, int flags, struct sockaddr *src_addr, int *addrlen)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = socket_recvfrom_unsafe(socket, buf, len, flags, src_addr, addrlen);
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_shutdown(struct file *f, int how)
{
	struct socket_file *socket = (struct socket_file *)f;
	int win32_how;
	if (how == SHUT_RD)
		win32_how = SD_RECEIVE;
	else if (how == SHUT_WR)
		win32_how = SD_SEND;
	else if (how == SHUT_RDWR)
		win32_how = SD_BOTH;
	else
		return -L_EINVAL;
	int r = 0;
	AcquireSRWLockExclusive(&f->rw_lock);
	if (shutdown(socket->socket, win32_how) == SOCKET_ERROR)
	{
		log_warning("shutdown() failed, error code: %d", WSAGetLastError());
		r = translate_socket_error(WSAGetLastError());
	}
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
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
		case LINUX_SO_REUSEADDR: optname = SO_REUSEADDR;
			log_warning("SO_REUSEADDR: Current semantic is not exactly correct.");
			goto get_set_sockopt;
		case LINUX_SO_ERROR: optname = SO_ERROR; goto get_set_sockopt;
		case LINUX_SO_BROADCAST: optname = SO_BROADCAST; goto get_set_sockopt;
		case LINUX_SO_SNDBUF: optname = SO_SNDBUF; goto get_set_sockopt;
		case LINUX_SO_RCVBUF: optname = SO_RCVBUF; goto get_set_sockopt;
		case LINUX_SO_KEEPALIVE: optname = SO_KEEPALIVE; goto get_set_sockopt;
		case LINUX_SO_LINGER: {
			/* TODO: Handle integer overflow, buffer overflow etc */
			struct linger win32_linger;
			if (call == SYS_SETSOCKOPT)
			{
				const struct linux_linger *linger = (const struct linux_linger *)set_optval;
				win32_linger.l_onoff = linger->l_onoff;
				win32_linger.l_linger = linger->l_linger;
				if (setsockopt(f->socket, SOL_SOCKET, SO_LINGER, (const char *)&win32_linger, sizeof(win32_linger)) == SOCKET_ERROR)
				{
					log_warning("setsockopt() failed, error code: %d", WSAGetLastError());
					return translate_socket_error(WSAGetLastError());
				}
			}
			else
			{
				int optlen;
				if (getsockopt(f->socket, SOL_SOCKET, SO_LINGER, (char *)&win32_linger, &optlen) == SOCKET_ERROR)
				{
					log_warning("getsockopt() failed, error code: %d", WSAGetLastError());
					return translate_socket_error(WSAGetLastError());
				}
				struct linux_linger *linger = (struct linux_linger *)get_optval;
				linger->l_onoff = win32_linger.l_onoff;
				linger->l_linger = win32_linger.l_linger;
				*get_optlen = sizeof(struct linux_linger);
			}
			return 0;
		}
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
	log_error("Unhandled sockopt level %d, optname %d", in_level, in_optname);
	return -L_EINVAL;

get_set_sockopt:
	/* The default case */
	if (call == SYS_SETSOCKOPT)
	{
		if (setsockopt(f->socket, level, optname, set_optval, set_optlen) == SOCKET_ERROR)
		{
			log_warning("setsockopt() failed, error code: %d", WSAGetLastError());
			return translate_socket_error(WSAGetLastError());
		}
		return 0;
	}
	else
	{
		if (getsockopt(f->socket, level, optname, get_optval, get_optlen) == SOCKET_ERROR)
		{
			log_warning("getsockopt() failed, error code: %d", WSAGetLastError());
			return translate_socket_error(WSAGetLastError());
		}
		return 0;
	}
}

static int socket_setsockopt(struct file *f, int level, int optname, const void *optval, int optlen)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = socket_get_set_sockopt(SYS_SETSOCKOPT, socket, level, optname, optval, optlen, NULL, NULL);
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_getsockopt(struct file *f, int level, int optname, void *optval, int *optlen)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = socket_get_set_sockopt(SYS_GETSOCKOPT, socket, level, optname, NULL, 0, optval, optlen);
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_sendmsg(struct file *f, const struct msghdr *msg, int flags)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = socket_sendmsg_unsafe(socket, msg, flags);
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_recvmsg(struct file *f, struct msghdr *msg, int flags)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = socket_recvmsg_unsafe(socket, msg, flags);
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static int socket_sendmmsg(struct file *f, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags)
{
	struct socket_file *socket = (struct socket_file *)f;
	AcquireSRWLockExclusive(&f->rw_lock);
	int r = 0;
	/* Windows have no native sendmmsg(), we emulate it by sending msgvec one by one */
	for (int i = 0; i < vlen; i++)
	{
		int len = socket_sendmsg_unsafe(socket, &msgvec[i].msg_hdr, flags);
		if (i == 0 && len < 0)
		{
			r = len;
			goto out;
		}
		if (i == 0 && len == 0)
		{
			r = -L_EWOULDBLOCK;
			goto out;
		}
		if (len <= 0)
		{
			r = i;
			goto out;
		}
		msgvec[i].msg_len = len;
		int total = 0;
		for (int j = 0; j < msgvec[i].msg_hdr.msg_iovlen; j++)
			total += msgvec[i].msg_hdr.msg_iov[j].iov_len;
		if (len < total)
		{
			r = i + 1;
			goto out;
		}
	}
	r = vlen;
out:
	ReleaseSRWLockExclusive(&f->rw_lock);
	return r;
}

static const struct file_ops socket_ops = 
{
	.get_poll_status = socket_get_poll_status,
	.get_poll_handle = socket_get_poll_handle,
	.close = socket_close,
	.read = socket_read,
	.write = socket_write,
	.stat = socket_stat,
	.bind = socket_bind,
	.connect = socket_connect,
	.listen = socket_listen,
	.getsockname = socket_getsockname,
	.getpeername = socket_getpeername,
	.sendto = socket_sendto,
	.recvfrom = socket_recvfrom,
	.shutdown = socket_shutdown,
	.setsockopt = socket_setsockopt,
	.getsockopt = socket_getsockopt,
	.sendmsg = socket_sendmsg,
	.recvmsg = socket_recvmsg,
	.sendmmsg = socket_sendmmsg,
};

DEFINE_SYSCALL(socket, int, domain, int, type, int, protocol)
{
	log_info("socket(domain=%d, type=0%o, protocol=%d)", domain, type, protocol);
	int fd = socket_open(domain, type, protocol);
	if (fd >= 0)
		log_info("socket fd: %d", fd);
	return fd;
}

DEFINE_SYSCALL(bind, int, sockfd, const struct sockaddr *, addr, int, addrlen)
{
	log_info("bind(%p, %d)", addr, addrlen);
	if (!mm_check_read(addr, sizeof(struct sockaddr)))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->bind)
	{
		log_error("bind() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->bind(f, addr, addrlen);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(connect, int, sockfd, const struct sockaddr *, addr, size_t, addrlen)
{
	log_info("connect(%d, %p, %d)", sockfd, addr, addrlen);
	if (!mm_check_read(addr, sizeof(struct sockaddr)))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->connect)
	{
		log_error("connect() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->connect(f, addr, addrlen);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(listen, int, sockfd, int, backlog)
{
	log_info("listen(%d, %d)", sockfd, backlog);
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->listen)
	{
		log_error("listen() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->listen(f, backlog);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(accept, int, sockfd, struct sockaddr *, addr, int *, addrlen)
{
	log_info("accept(%d, %p, %p)", sockfd, addr, addrlen);
	if (!mm_check_write(addr, sizeof(struct sockaddr)))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->listen)
	{
		log_error("accept() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->accept(f, addr, addrlen);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(getsockname, int, sockfd, struct sockaddr *, addr, int *, addrlen)
{
	log_info("getsockname(%d, %p, %p)", sockfd, addr, addrlen);
	if (!mm_check_write(addrlen, sizeof(*addrlen)))
		return -L_EFAULT;
	if (!mm_check_write(addr, *addrlen))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->getsockname)
	{
		log_error("getsockname() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->getsockname(f, addr, addrlen);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(getpeername, int, sockfd, struct sockaddr *, addr, int *, addrlen)
{
	log_info("getpeername(%d, %p, %p)", sockfd, addr, addrlen);
	if (!mm_check_write(addrlen, sizeof(*addrlen)))
		return -L_EFAULT;
	if (!mm_check_write(addr, *addrlen))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->getpeername)
	{
		log_error("getpeername() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->getpeername(f, addr, addrlen);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(send, int, sockfd, const void *, buf, size_t, len, int, flags)
{
	log_info("send(%d, %p, %d, %x)", sockfd, buf, len, flags);
	if (!mm_check_read(buf, len))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->sendto)
	{
		log_error("send() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->sendto(f, buf, len, flags, NULL, 0);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(recv, int, sockfd, void *, buf, size_t, len, int, flags)
{
	log_info("recv(%d, %p, %d, %x)", sockfd, buf, len, flags);
	if (!mm_check_write(buf, len))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->recvfrom)
	{
		log_error("recv() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->recvfrom(f, buf, len, flags, NULL, NULL);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(sendto, int, sockfd, const void *, buf, size_t, len, int, flags, const struct sockaddr *, dest_addr, int, addrlen)
{
	log_info("sendto(%d, %p, %d, %x, %p, %d)", sockfd, buf, len, flags, dest_addr, addrlen);
	if (!mm_check_read(buf, len))
		return -L_EFAULT;
	if (dest_addr && !mm_check_read(dest_addr, addrlen))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->sendto)
	{
		log_error("sendto() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->sendto(f, buf, len, flags, dest_addr, addrlen);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(recvfrom, int, sockfd, void *, buf, size_t, len, int, flags, struct sockaddr *, src_addr, int *, addrlen)
{
	log_info("recvfrom(%d, %p, %d, %x, %p, %p)", sockfd, buf, len, flags, src_addr, addrlen);
	if (!mm_check_write(buf, len))
		return -L_EFAULT;
	if (src_addr)
	{
		if (!mm_check_write(addrlen, sizeof(*addrlen)))
			return -L_EFAULT;
		if (!mm_check_write(src_addr, *addrlen))
			return -L_EFAULT;
	}
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->recvfrom)
	{
		log_error("recvfrom() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->recvfrom(f, buf, len, flags, src_addr, addrlen);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(shutdown, int, sockfd, int, how)
{
	log_info("shutdown(%d, %d)", sockfd, how);
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->shutdown)
	{
		log_error("shutdown() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->shutdown(f, how);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(setsockopt, int, sockfd, int, level, int, optname, const void *, optval, int, optlen)
{
	log_info("setsockopt(%d, %d, %d, %p, %d)", sockfd, level, optname, optval, optlen);
	if (optval && !mm_check_read(optval, optlen))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->setsockopt)
	{
		log_error("setsockopt() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->setsockopt(f, level, optname, optval, optlen);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(getsockopt, int, sockfd, int, level, int, optname, void *, optval, int *, optlen)
{
	log_info("getsockopt(%d, %d, %d, %p, %p)", sockfd, level, optname, optval, optlen);
	if (optlen && !mm_check_write(optlen, sizeof(*optlen)))
		return -L_EFAULT;
	if (optlen && !mm_check_write(optval, *optlen))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->getsockopt)
	{
		log_error("getsockopt() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->getsockopt(f, level, optname, optval, optlen);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(sendmsg, int, sockfd, const struct msghdr *, msg, int, flags)
{
	log_info("sendmsg(%d, %p, %x)", sockfd, msg, flags);
	if (!mm_check_read_msghdr(msg))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->sendmsg)
	{
		log_error("sendmsg() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = socket_sendmsg(f, msg, flags);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(recvmsg, int, sockfd, struct msghdr *, msg, int, flags)
{
	log_info("recvmsg(%d, %p, %x)", sockfd, msg, flags);
	if (!mm_check_write_msghdr(msg))
		return -L_EFAULT;
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->recvmsg)
	{
		log_error("recvmsg() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->recvmsg(f, msg, flags);
	vfs_release(f);
	return r;
}

DEFINE_SYSCALL(sendmmsg, int, sockfd, struct mmsghdr *, msgvec, unsigned int, vlen, unsigned int, flags)
{
	log_info("sendmmsg(sockfd=%d, msgvec=%p, vlen=%d, flags=%d)", sockfd, msgvec, vlen, flags);
	for (int i = 0; i < vlen; i++)
	{
		log_info("msgvec %d:", i);
		if (!mm_check_read_msghdr(&msgvec[i].msg_hdr))
			return -L_EFAULT;
	}
	struct file *f = vfs_get(sockfd);
	if (!f)
		return -L_EBADF;
	int r;
	if (!f->op_vtable->sendmmsg)
	{
		log_error("sendmmsg() not implemented.");
		r = -L_ENOTSOCK;
	}
	else
		r = f->op_vtable->sendmmsg(f, msgvec, vlen, flags);
	vfs_release(f);
	return r;
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
		return -L_EINVAL;
	if (!mm_check_read(args, nargs[call]))
		return -L_EFAULT;
	switch (call)
	{
	case SYS_SOCKET:
		return sys_socket(args[0], args[1], args[2]);

	case SYS_BIND:
		return sys_bind(args[0], (const struct sockaddr *)args[1], args[2]);

	case SYS_CONNECT:
		return sys_connect(args[0], (const struct sockaddr *)args[1], args[2]);

	case SYS_LISTEN:
		return sys_listen(args[0], args[1]);

	case SYS_ACCEPT:
		return sys_accept(args[0], (struct sockaddr *)args[1], (int *)args[2]);

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
		log_error("Unimplemented socketcall: %d", call);
		return -L_EINVAL;
	}
	}
}
