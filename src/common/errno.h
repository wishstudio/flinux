#pragma once

#define	L_EPERM				1	/* Operation not permitted */
#define	L_ENOENT			2	/* No such file or directory */
#define	L_ESRCH				3	/* No such process */
#define	L_EINTR				4	/* Interrupted system call */
#define	L_EIO				5	/* I/O error */
#define	L_ENXIO				6	/* No such device or address */
#define	L_E2BIG				7	/* Argument list too long */
#define	L_ENOEXEC			8	/* Exec format error */
#define	L_EBADF				9	/* Bad file number */
#define	L_ECHILD			10	/* No child processes */
#define	L_EAGAIN			11	/* Try again */
#define	L_ENOMEM			12	/* Out of memory */
#define	L_EACCES			13	/* Permission denied */
#define	L_EFAULT			14	/* Bad address */
#define	L_ENOTBLK			15	/* Block device required */
#define	L_EBUSY				16	/* Device or resource busy */
#define	L_EEXIST			17	/* File exists */
#define	L_EXDEV				18	/* Cross-device link */
#define	L_ENODEV			19	/* No such device */
#define	L_ENOTDIR			20	/* Not a directory */
#define	L_EISDIR			21	/* Is a directory */
#define	L_EINVAL			22	/* Invalid argument */
#define	L_ENFILE			23	/* File table overflow */
#define	L_EMFILE			24	/* Too many open files */
#define	L_ENOTTY			25	/* Not a typewriter */
#define	L_ETXTBSY			26	/* Text file busy */
#define	L_EFBIG				27	/* File too large */
#define	L_ENOSPC			28	/* No space left on device */
#define	L_ESPIPE			29	/* Illegal seek */
#define	L_EROFS				30	/* Read-only file system */
#define	L_EMLINK			31	/* Too many links */
#define	L_EPIPE				32	/* Broken pipe */
#define	L_EDOM				33	/* Math argument out of domain of func */
#define	L_ERANGE			34	/* Math result not representable */

#define	L_EDEADLK			35	/* Resource deadlock would occur */
#define	L_ENAMETOOLONG		36	/* File name too long */
#define	L_ENOLCK			37	/* No record locks available */
#define	L_ENOSYS			38	/* Function not implemented */
#define	L_ENOTEMPTY			39	/* Directory not empty */
#define	L_ELOOP				40	/* Too many symbolic links encountered */
#define	L_EWOULDBLOCK		L_EAGAIN	/* Operation would block */
#define	L_ENOMSG			42	/* No message of desired type */
#define	L_EIDRM				43	/* Identifier removed */
#define	L_ECHRNG			44	/* Channel number out of range */
#define	L_EL2NSYNC			45	/* Level 2 not synchronized */
#define	L_EL3HLT			46	/* Level 3 halted */
#define	L_EL3RST			47	/* Level 3 reset */
#define	L_ELNRNG			48	/* Link number out of range */
#define	L_EUNATCH			49	/* Protocol driver not attached */
#define	L_ENOCSI			50	/* No CSI structure available */
#define	L_EL2HLT			51	/* Level 2 halted */
#define	L_EBADE				52	/* Invalid exchange */
#define	L_EBADR				53	/* Invalid request descriptor */
#define	L_EXFULL			54	/* Exchange full */
#define	L_ENOANO			55	/* No anode */
#define	L_EBADRQC			56	/* Invalid request code */
#define	L_EBADSLT			57	/* Invalid slot */

#define	L_EDEADLOCK			L_EDEADLK

#define	L_EBFONT			59	/* Bad font file format */
#define	L_ENOSTR			60	/* Device not a stream */
#define	L_ENODATA			61	/* No data available */
#define	L_ETIME				62	/* Timer expired */
#define	L_ENOSR				63	/* Out of streams resources */
#define	L_ENONET			64	/* Machine is not on the network */
#define	L_ENOPKG			65	/* Package not installed */
#define	L_EREMOTE			66	/* Object is remote */
#define	L_ENOLINK			67	/* Link has been severed */
#define	L_EADV				68	/* Advertise error */
#define	L_ESRMNT			69	/* Srmount error */
#define	L_ECOMM				70	/* Communication error on send */
#define	L_EPROTO			71	/* Protocol error */
#define	L_EMULTIHOP			72	/* Multihop attempted */
#define	L_EDOTDOT			73	/* RFS specific error */
#define	L_EBADMSG			74	/* Not a data message */
#define	L_EOVERFLOW			75	/* Value too large for defined data type */
#define	L_ENOTUNIQ			76	/* Name not unique on network */
#define	L_EBADFD			77	/* File descriptor in bad state */
#define	L_EREMCHG			78	/* Remote address changed */
#define	L_ELIBACC			79	/* Can not access a needed shared library */
#define	L_ELIBBAD			80	/* Accessing a corrupted shared library */
#define	L_ELIBSCN			81	/* .lib section in a.out corrupted */
#define	L_ELIBMAX			82	/* Attempting to link in too many shared libraries */
#define	L_ELIBEXEC			83	/* Cannot exec a shared library directly */
#define	L_EILSEQ			84	/* Illegal byte sequence */
#define	L_ERESTART			85	/* Interrupted system call should be restarted */
#define	L_ESTRPIPE			86	/* Streams pipe error */
#define	L_EUSERS			87	/* Too many users */
#define	L_ENOTSOCK			88	/* Socket operation on non-socket */
#define	L_EDESTADDRREQ		89	/* Destination address required */
#define	L_EMSGSIZE			90	/* Message too long */
#define	L_EPROTOTYPE		91	/* Protocol wrong type for socket */
#define	L_ENOPROTOOPT		92	/* Protocol not available */
#define	L_EPROTONOSUPPORT	93	/* Protocol not supported */
#define	L_ESOCKTNOSUPPORT	94	/* Socket type not supported */
#define	L_EOPNOTSUPP		95	/* Operation not supported on transport endpoint */
#define	L_EPFNOSUPPORT		96	/* Protocol family not supported */
#define	L_EAFNOSUPPORT		97	/* Address family not supported by protocol */
#define	L_EADDRINUSE		98	/* Address already in use */
#define	L_EADDRNOTAVAIL		99	/* Cannot assign requested address */
#define	L_ENETDOWN			100	/* Network is down */
#define	L_ENETUNREACH		101	/* Network is unreachable */
#define	L_ENETRESET			102	/* Network dropped connection because of reset */
#define	L_ECONNABORTED		103	/* Software caused connection abort */
#define	L_ECONNRESET		104	/* Connection reset by peer */
#define	L_ENOBUFS			105	/* No buffer space available */
#define	L_EISCONN			106	/* Transport endpoint is already connected */
#define	L_ENOTCONN			107	/* Transport endpoint is not connected */
#define	L_ESHUTDOWN			108	/* Cannot send after transport endpoint shutdown */
#define	L_ETOOMANYREFS		109	/* Too many references: cannot splice */
#define	L_ETIMEDOUT			110	/* Connection timed out */
#define	L_ECONNREFUSED		111	/* Connection refused */
#define	L_EHOSTDOWN			112	/* Host is down */
#define	L_EHOSTUNREACH		113	/* No route to host */
#define	L_EALREADY			114	/* Operation already in progress */
#define	L_EINPROGRESS		115	/* Operation now in progress */
#define	L_ESTALE			116	/* Stale file handle */
#define	L_EUCLEAN			117	/* Structure needs cleaning */
#define	L_ENOTNAM			118	/* Not a XENIX named type file */
#define	L_ENAVAIL			119	/* No XENIX semaphores available */
#define	L_EISNAM			120	/* Is a named type file */
#define	L_EREMOTEIO			121	/* Remote I/O error */
#define	L_EDQUOT			122	/* Quota exceeded */

#define	L_ENOMEDIUM			123	/* No medium found */
#define	L_EMEDIUMTYPE		124	/* Wrong medium type */
#define	L_ECANCELED			125	/* Operation Canceled */
#define	L_ENOKEY			126	/* Required key not available */
#define	L_EKEYEXPIRED		127	/* Key has expired */
#define	L_EKEYREVOKED		128	/* Key has been revoked */
#define	L_EKEYREJECTED		129	/* Key was rejected by service */

/* for robust mutexes */
#define	L_EOWNERDEAD		130	/* Owner died */
#define	L_ENOTRECOVERABLE	131	/* State not recoverable */

#define L_ERFKILL			132	/* Operation not possible due to RF-kill */

#define L_EHWPOISON			133	/* Memory page has hardware error */
