#pragma once

/* TCP socket options */
#define LINUX_TCP_NODELAY				1		/* Turn off Nagle's algorithm. */
#define LINUX_TCP_MAXSEG				2		/* Limit MSS */
#define LINUX_TCP_CORK					3		/* Never send partially complete segments */
#define LINUX_TCP_KEEPIDLE				4		/* Start keeplives after this period */
#define LINUX_TCP_KEEPINTVL				5		/* Interval between keepalives */
#define LINUX_TCP_KEEPCNT				6		/* Number of keepalives before death */
#define LINUX_TCP_SYNCNT				7		/* Number of SYN retransmits */
#define LINUX_TCP_LINGER2				8		/* Life time of orphaned FIN-WAIT-2 state */
#define LINUX_TCP_DEFER_ACCEPT			9		/* Wake up listener only when data arrive */
#define LINUX_TCP_WINDOW_CLAMP			10		/* Bound advertised window */
#define LINUX_TCP_INFO					11		/* Information about this connection. */
#define LINUX_TCP_QUICKACK				12		/* Block/reenable quick acks */
#define LINUX_TCP_CONGESTION			13		/* Congestion control algorithm */
#define LINUX_TCP_MD5SIG				14		/* TCP MD5 Signature (RFC2385) */
#define LINUX_TCP_THIN_LINEAR_TIMEOUTS	16		/* Use linear timeouts for thin streams*/
#define LINUX_TCP_THIN_DUPACK			17		/* Fast retrans. after 1 dupack */
#define LINUX_TCP_USER_TIMEOUT			18		/* How long for loss retry before timeout */
#define LINUX_TCP_REPAIR				19		/* TCP sock is under repair right now */
#define LINUX_TCP_REPAIR_QUEUE			20
#define LINUX_TCP_QUEUE_SEQ				21
#define LINUX_TCP_REPAIR_OPTIONS		22
#define LINUX_TCP_FASTOPEN				23		/* Enable FastOpen on listeners */
#define LINUX_TCP_TIMESTAMP				24
#define LINUX_TCP_NOTSENT_LOWAT			25		/* limit number of unsent bytes in write queue */
