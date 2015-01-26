#pragma once

#define LINUX_IP_TOS					1
#define LINUX_IP_TTL					2
#define LINUX_IP_HDRINCL				3
#define LINUX_IP_OPTIONS				4
#define LINUX_IP_ROUTER_ALERT			5
#define LINUX_IP_RECVOPTS				6
#define LINUX_IP_RETOPTS				7
#define LINUX_IP_PKTINFO				8
#define LINUX_IP_PKTOPTIONS				9
#define LINUX_IP_MTU_DISCOVER			10
#define LINUX_IP_RECVERR				11
#define LINUX_IP_RECVTTL				12
#define LINUX_IP_RECVTOS				13
#define LINUX_IP_MTU					14
#define LINUX_IP_FREEBIND				15
#define LINUX_IP_IPSEC_POLICY			16
#define LINUX_IP_XFRM_POLICY			17
#define LINUX_IP_PASSSEC				18
#define LINUX_IP_TRANSPARENT			19
#define LINUX_IP_RECVRETOPTS			IP_RETOPTS
#define LINUX_IP_ORIGDSTADDR			20
#define LINUX_IP_RECVORIGDSTADDR		IP_ORIGDSTADDR
#define LINUX_IP_MINTTL					21
#define LINUX_IP_NODEFRAG				22

#define LINUX_IP_MULTICAST_IF			32
#define LINUX_IP_MULTICAST_TTL			33
#define LINUX_IP_MULTICAST_LOOP			34
#define LINUX_IP_ADD_MEMBERSHIP			35
#define LINUX_IP_DROP_MEMBERSHIP		36
#define LINUX_IP_UNBLOCK_SOURCE			37
#define LINUX_IP_BLOCK_SOURCE			38
#define LINUX_IP_ADD_SOURCE_MEMBERSHIP	39
#define LINUX_IP_DROP_SOURCE_MEMBERSHIP	40
#define LINUX_IP_MSFILTER				41
#define LINUX_MCAST_JOIN_GROUP			42
#define LINUX_MCAST_BLOCK_SOURCE		43
#define LINUX_MCAST_UNBLOCK_SOURCE		44
#define LINUX_MCAST_LEAVE_GROUP			45
#define LINUX_MCAST_JOIN_SOURCE_GROUP	46
#define LINUX_MCAST_LEAVE_SOURCE_GROUP	47
#define LINUX_MCAST_MSFILTER			48
#define LINUX_IP_MULTICAST_ALL			49
#define LINUX_IP_UNICAST_IF				50

/* IP_MTU_DISCOVER values */
#define LINUX_IP_PMTUDISC_DONT			0		/* Never send DF frames */
#define LINUX_IP_PMTUDISC_WANT			1		/* Use per route hints  */
#define LINUX_IP_PMTUDISC_DO			2		/* Always DF            */
#define LINUX_IP_PMTUDISC_PROBE			3		/* Ignore dst pmtu      */
/* Always use interface mtu (ignores dst pmtu) but don't set DF flag.
 * Also incoming ICMP frag_needed notifications will be ignored on
 * this socket to prevent accepting spoofed ones.
 */
#define LINUX_IP_PMTUDISC_INTERFACE		4
/* weaker version of IP_PMTUDISC_INTERFACE, which allos packets to get
 * fragmented if they exeed the interface mtu
 */
#define LINUX_IP_PMTUDISC_OMIT			5
