#pragma once

#define SEEK_SET		0		/* seek relative to beginning of file */
#define SEEK_CUR		1		/* seek relative to current file position */
#define SEEK_END		2		/* seek relative to end of file */
#define SEEK_DATA		3		/* seek to the next data */
#define SEEK_HOLE		4		/* seek to the next hole */
#define SEEK_MAX		SEEK_HOLE
