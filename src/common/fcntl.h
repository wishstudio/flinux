#pragma once

#define O_ACCMODE		00000003
#define O_RDONLY		00000000
#define O_WRONLY		00000001
#define O_RDWR			00000002
#define O_CREAT			00000100
#define O_EXCL			00000200
#define O_NOCTTY		00000400
#define O_TRUNC			00001000
#define O_APPEND		00002000
#define O_NONBLOCK		00004000
#define O_DSYNC			00010000
#define FASYNC			00020000
#define O_DIRECT		00040000
#define O_LARGEFILE		00100000
#define O_DIRECTORY		00200000
#define O_NOFOLLOW		00400000
#define O_NOATIME		01000000
#define O_CLOEXEC		02000000
#define __O_SYNC		04000000
#define O_SYNC			(__O_SYNC | O_DSYNC)
#define O_PATH			010000000
#define __O_TMPFILE		020000000
#define O_TMPFILE		(__O_TMPFILE | O_DIRECTORY)
#define O_TMPFILE_MASK	(__O_TMPFILE | O_DIRECTORY | O_CREAT)
#define O_NDELAY		O_NONBLOCK

#define AT_FDCWD				-100    /* Special value used to indicate openat should use the current working directory. */
#define AT_SYMLINK_NOFOLLOW     0x100   /* Do not follow symbolic links.  */
#define AT_REMOVEDIR            0x200   /* Remove directory instead of unlinking file.  */
#define AT_SYMLINK_FOLLOW       0x400   /* Follow symbolic links.  */
#define AT_NO_AUTOMOUNT         0x800   /* Suppress terminal automount traversal */
#define AT_EMPTY_PATH           0x1000  /* Allow empty relative pathname */

#define F_DUPFD			0		/* dup */
#define F_GETFD			1		/* get close_on_exec */
#define F_SETFD			2		/* set/clear close_on_exec */
#define F_GETFL			3		/* get file->f_flags */
#define F_SETFL			4		/* set file->f_flags */
#define F_GETLK			5
#define F_SETLK			6
#define F_SETLKW		7
#define F_SETOWN		8		/* for sockets. */
#define F_GETOWN		9		/* for sockets. */
#define F_SETSIG		10		/* for sockets. */
#define F_GETSIG		11		/* for sockets. */
#define F_GETLK64		12		/*  using 'struct flock64' */
#define F_SETLK64		13
#define F_SETLKW64		14
#define F_SETOWN_EX		15
#define F_GETOWN_EX		16
#define F_GETOWNER_UIDS	17

/* for F_[GET|SET]FL */
#define FD_CLOEXEC		1		/* actually anything with low bit set goes */
