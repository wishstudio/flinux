#pragma once

#include <common/types.h>
#include <common/uio.h>

/* Supported address families. */
#define LINUX_AF_UNSPEC		0
#define LINUX_AF_UNIX		1		/* Unix domain sockets          */
#define LINUX_AF_LOCAL		1		/* POSIX name for AF_UNIX       */
#define LINUX_AF_INET		2		/* Internet IP Protocol         */
#define LINUX_AF_AX25		3		/* Amateur Radio AX.25          */
#define LINUX_AF_IPX		4		/* Novell IPX                   */
#define LINUX_AF_APPLETALK	5		/* AppleTalk DDP                */
#define LINUX_AF_NETROM		6		/* Amateur Radio NET/ROM        */
#define LINUX_AF_BRIDGE		7		/* Multiprotocol bridge         */
#define LINUX_AF_ATMPVC		8		/* ATM PVCs                     */
#define LINUX_AF_X25		9		/* Reserved for X.25 project    */
#define LINUX_AF_INET6		10		/* IP version 6                 */
#define LINUX_AF_ROSE		11		/* Amateur Radio X.25 PLP       */
#define LINUX_AF_DECnet		12		/* Reserved for DECnet project  */
#define LINUX_AF_NETBEUI	13		/* Reserved for 802.2LLC project*/
#define LINUX_AF_SECURITY	14		/* Security callback pseudo AF */
#define LINUX_AF_KEY		15		/* PF_KEY key management API */
#define LINUX_AF_NETLINK	16
#define LINUX_AF_ROUTE		LINUX_AF_NETLINK /* Alias to emulate 4.4BSD */
#define LINUX_AF_PACKET		17		/* Packet family                */
#define LINUX_AF_ASH		18		/* Ash                          */
#define LINUX_AF_ECONET		19		/* Acorn Econet                 */
#define LINUX_AF_ATMSVC		20		/* ATM SVCs                     */
#define LINUX_AF_RDS		21		/* RDS sockets                  */
#define LINUX_AF_SNA		22		/* Linux SNA Project (nutters!) */
#define LINUX_AF_IRDA		23		/* IRDA sockets                 */
#define LINUX_AF_PPPOX		24		/* PPPoX sockets                */
#define LINUX_AF_WANPIPE	25		/* Wanpipe API Sockets */
#define LINUX_AF_LLC		26		/* Linux LLC                    */
#define LINUX_AF_IB			27		/* Native InfiniBand address    */
#define LINUX_AF_CAN		29		/* Controller Area Network      */
#define LINUX_AF_TIPC		30		/* TIPC sockets                 */
#define LINUX_AF_BLUETOOTH	31		/* Bluetooth sockets            */
#define LINUX_AF_IUCV		32		/* IUCV sockets                 */
#define LINUX_AF_RXRPC		33		/* RxRPC sockets                */
#define LINUX_AF_ISDN		34		/* mISDN sockets                */
#define LINUX_AF_PHONET		35		/* Phonet sockets               */
#define LINUX_AF_IEEE802154	36		/* IEEE802154 sockets           */
#define LINUX_AF_CAIF		37		/* CAIF sockets                 */
#define LINUX_AF_ALG		38		/* Algorithm sockets            */
#define LINUX_AF_NFC		39		/* NFC sockets                  */
#define LINUX_AF_VSOCK		40		/* vSockets                     */
#define LINUX_AF_MAX		41		/* For now.. */

/* Socket types */
#define LINUX_SOCK_STREAM		1
#define LINUX_SOCK_DGRAM		2
#define LINUX_SOCK_RAW			3
#define LINUX_SOCK_RDM			4
#define LINUX_SOCK_SEQPACKET	5
#define LINUX_SOCK_DCCP			6
#define LINUX_SOCK_PACKET		10

#define LINUX_SOCK_MAX	(LINUX_SOCK_PACKET + 1)
#define LINUX_SOCK_TYPE_MASK	0xf

/* Flags to be used with send and recv */
#define LINUX_MSG_OOB				1
#define LINUX_MSG_PEEK				2
#define LINUX_MSG_DONTROUTE			4
#define LINUX_MSG_TRYHARD			4		/* Synonym for MSG_DONTROUTE for DECnet */
#define LINUX_MSG_CTRUNC			8
#define LINUX_MSG_PROBE				0x10	/* Do not send. Only probe path f.e. for MTU */
#define LINUX_MSG_TRUNC				0x20
#define LINUX_MSG_DONTWAIT			0x40	/* Nonblocking io                */
#define LINUX_MSG_EOR				0x80	/* End of record */
#define LINUX_MSG_WAITALL			0x100	/* Wait for a full request */
#define LINUX_MSG_FIN				0x200
#define LINUX_MSG_SYN				0x400
#define LINUX_MSG_CONFIRM			0x800	/* Confirm path validity */
#define LINUX_MSG_RST				0x1000
#define LINUX_MSG_ERRQUEUE			0x2000	/* Fetch message from error queue */
#define LINUX_MSG_NOSIGNAL			0x4000	/* Do not generate SIGPIPE */
#define LINUX_MSG_MORE				0x8000	/* Sender will send more */
#define LINUX_MSG_WAITFORONE		0x10000	/* recvmmsg(): block until 1+ packets avail */
#define LINUX_MSG_SENDPAGE_NOTLAST	0x20000	/* sendpage() internal : not the last page */
#define LINUX_MSG_FASTOPEN			0x20000000 /* Send data in TCP SYN */
#define LINUX_MSG_CMSG_CLOEXEC		0x40000000 /* Set close_on_exec for file descriptor received through SCM_RIGHTS */

/* For setsockopt(2) */
/* Setsockoptions(2) level. Thanks to BSD these must match IPPROTO_xxx */
#define LINUX_SOL_IP		0
#define LINUX_SOL_SOCKET	1 /* No-no-no! Due to Linux :-) we cannot use SOL_ICMP=1 */
#define LINUX_SOL_TCP		6
#define LINUX_SOL_UDP		17
#define LINUX_SOL_IPV6		41
#define LINUX_SOL_ICMPV6	58
#define LINUX_SOL_SCTP		132
#define LINUX_SOL_UDPLITE	136 /* UDP-Lite (RFC 3828) */
#define LINUX_SOL_RAW		255
#define LINUX_SOL_IPX		256
#define LINUX_SOL_AX25		257
#define LINUX_SOL_ATALK		258
#define LINUX_SOL_NETROM	259
#define LINUX_SOL_ROSE		260
#define LINUX_SOL_DECNET	261
#define	LINUX_SOL_X25		262
#define LINUX_SOL_PACKET	263
#define LINUX_SOL_ATM		264	/* ATM layer (cell level) */
#define LINUX_SOL_AAL		265	/* ATM Adaption Layer (packet level) */
#define LINUX_SOL_IRDA		266
#define LINUX_SOL_NETBEUI	267
#define LINUX_SOL_LLC		268
#define LINUX_SOL_DCCP		269
#define LINUX_SOL_NETLINK	270
#define LINUX_SOL_TIPC		271
#define LINUX_SOL_RXRPC		272
#define LINUX_SOL_PPPOL2TP	273
#define LINUX_SOL_BLUETOOTH	274
#define LINUX_SOL_PNPIPE	275
#define LINUX_SOL_RDS		276
#define LINUX_SOL_IUCV		277
#define LINUX_SOL_CAIF		278
#define LINUX_SOL_ALG		279
#define LINUX_SOL_NFC		280

#define LINUX_SO_DEBUG				1
#define LINUX_SO_REUSEADDR			2
#define LINUX_SO_TYPE				3
#define LINUX_SO_ERROR				4
#define LINUX_SO_DONTROUTE			5
#define LINUX_SO_BROADCAST			6
#define LINUX_SO_SNDBUF				7
#define LINUX_SO_RCVBUF				8
#define LINUX_SO_SNDBUFFORCE		32
#define LINUX_SO_RCVBUFFORCE		33
#define LINUX_SO_KEEPALIVE			9
#define LINUX_SO_OOBINLINE			10
#define LINUX_SO_NO_CHECK			11
#define LINUX_SO_PRIORITY			12
#define LINUX_SO_LINGER				13
#define LINUX_SO_BSDCOMPAT			14
#define LINUX_SO_REUSEPORT			15
#define LINUX_SO_PASSCRED			16
#define LINUX_SO_PEERCRED			17
#define LINUX_SO_RCVLOWAT			18
#define LINUX_SO_SNDLOWAT			19
#define LINUX_SO_RCVTIMEO			20
#define LINUX_SO_SNDTIMEO			21

/* Security levels - as per NRL IPv6 - don't actually do anything */
#define LINUX_SO_SECURITY_AUTHENTICATION			22
#define LINUX_SO_SECURITY_ENCRYPTION_TRANSPORT		23
#define LINUX_SO_SECURITY_ENCRYPTION_NETWORK		24
#define LINUX_SO_BINDTODEVICE		25

/* Socket filtering */
#define LINUX_SO_ATTACH_FILTER		26
#define LINUX_SO_DETACH_FILTER		27
#define LINUX_SO_GET_FILTER			SO_ATTACH_FILTER
#define LINUX_SO_PEERNAME			28
#define LINUX_SO_TIMESTAMP			29
#define LINUX_SCM_TIMESTAMP			SO_TIMESTAMP
#define LINUX_SO_ACCEPTCONN			30
#define LINUX_SO_PEERSEC			31
#define LINUX_SO_PASSSEC			34
#define LINUX_SO_TIMESTAMPNS		35
#define LINUX_SCM_TIMESTAMPNS		SO_TIMESTAMPNS
#define LINUX_SO_MARK				36
#define LINUX_SO_TIMESTAMPING		37
#define LINUX_SCM_TIMESTAMPING		SO_TIMESTAMPING
#define LINUX_SO_PROTOCOL			38
#define LINUX_SO_DOMAIN				39
#define LINUX_SO_RXQ_OVFL			40
#define LINUX_SO_WIFI_STATUS		41
#define LINUX_SCM_WIFI_STATUS		SO_WIFI_STATUS
#define LINUX_SO_PEEK_OFF			42

/* Instruct lower device to use last 4-bytes of skb data as FCS */
#define LINUX_SO_NOFCS				43
#define LINUX_SO_LOCK_FILTER		44
#define LINUX_SO_SELECT_ERR_QUEUE	45
#define LINUX_SO_BUSY_POLL			46
#define LINUX_SO_MAX_PACING_RATE	47
#define LINUX_SO_BPF_EXTENSIONS		48

struct linux_sockaddr_storage {
	unsigned short ss_family;
	char __data[128];
};

struct linux_linger {
	int l_onoff;   /* Linger active */
	int l_linger;  /* How long to linger for */
};

/* For recvmsg/sendmsg */
struct msghdr {
	void *msg_name;			/* ptr to socket address structure */
	int msg_namelen;		/* size of socket address structure */
	struct iovec *msg_iov;	/* scatter/gather array */
	size_t msg_iovlen;		/* # elements in msg_iov */
	void *msg_control;		/* ancillary data */
	size_t msg_controllen;	/* ancillary data buffer length */
	unsigned int msg_flags;	/* flags on received message */
};

/* For recvmmsg/sendmmsg */
struct mmsghdr {
	struct msghdr msg_hdr;
	unsigned int msg_len;
};

/* For shutdown */
#define SHUT_RD		0
#define SHUT_WR		1
#define SHUT_RDWR	2
