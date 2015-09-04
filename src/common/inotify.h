#pragma once

#include <common/types.h>
#include <common/fcntl.h>

/*
 * struct inotify_event - structure read from the inotify device for each event
 *
 * When you are watching a directory, you will receive the filename for events
 * such as IN_CREATE, IN_DELETE, IN_OPEN, IN_CLOSE, ..., relative to the wd.
 */
struct inotify_event {
	int32_t		wd;			/* watch descriptor */
	uint32_t	mask;		/* watch mask */
	uint32_t	cookie;		/* cookie to synchronize two events */
	uint32_t	len;		/* length (including nulls) of name */
	char		name[0];	/* stub for possible name */
};

/* the following are legal, implemented events that user-space can watch for */
#define IN_ACCESS			0x00000001	/* File was accessed */
#define IN_MODIFY			0x00000002	/* File was modified */
#define IN_ATTRIB			0x00000004	/* Metadata changed */
#define IN_CLOSE_WRITE		0x00000008	/* Writtable file was closed */
#define IN_CLOSE_NOWRITE	0x00000010	/* Unwrittable file closed */
#define IN_OPEN				0x00000020	/* File was opened */
#define IN_MOVED_FROM		0x00000040	/* File was moved from X */
#define IN_MOVED_TO			0x00000080	/* File was moved to Y */
#define IN_CREATE			0x00000100	/* Subfile was created */
#define IN_DELETE			0x00000200	/* Subfile was deleted */
#define IN_DELETE_SELF		0x00000400	/* Self was deleted */

/* the following are legal events.  they are sent as needed to any watch */
#define IN_UNMOUNT			0x00002000	/* Backing fs was unmounted */
#define IN_Q_OVERFLOW		0x00004000	/* Event queued overflowed */
#define IN_IGNORED			0x00008000	/* File was ignored */

/* helper events */
#define IN_CLOSE			(IN_CLOSE_WRITE | IN_CLOSE_NOWRITE) /* close */
#define IN_MOVE				(IN_MOVED_FROM | IN_MOVED_TO) /* moves */

/* special flags */
#define IN_ISDIR			0x40000000	/* event occurred against dir */
#define IN_ONESHOT			0x80000000	/* only send event once */

/* Flags for sys_inotify_init1.  */
#define IN_CLOEXEC			O_CLOEXEC
#define IN_NONBLOCK			O_NONBLOCK
