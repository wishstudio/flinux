#pragma once

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
