#pragma once

/* Second argument to futex syscall */

#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_FD		2
#define FUTEX_REQUEUE		3
#define FUTEX_CMP_REQUEUE	4
#define FUTEX_WAKE_OP		5
#define FUTEX_LOCK_PI		6
#define FUTEX_UNLOCK_PI		7
#define FUTEX_TRYLOCK_PI	8
#define FUTEX_WAIT_BITSET	9
#define FUTEX_WAKE_BITSET	10
#define FUTEX_WAIT_REQUEUE_PI	11
#define FUTEX_CMP_REQUEUE_PI	12

#define FUTEX_PRIVATE_FLAG	128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

/*
 * Support for robust futexes: the kernel cleans up held futexes at
 * thread exit time.
 */

/*
 * Per-lock list entry - embedded in user-space locks, somewhere close
 * to the futex field. (Note: user-space uses a double-linked list to
 * achieve O(1) list add and remove, but the kernel only needs to know
 * about the forward link)
 *
 * NOTE: this structure is part of the syscall ABI, and must not be
 * changed.
 */
struct robust_list {
	struct robust_list *next;
};

/*
 * Per-thread list head:
 *
 * NOTE: this structure is part of the syscall ABI, and must only be
 * changed if the change is first communicated with the glibc folks.
 * (When an incompatible change is done, we'll increase the structure
 *  size, which glibc will detect)
 */
struct robust_list_head {
	/*
	 * The head of the list. Points back to itself if empty:
	 */
	struct robust_list list;
		/*
		 * This relative offset is set by user-space, it gives the kernel
		 * the relative position of the futex field to examine. This way
		 * we keep userspace flexible, to freely shape its data-structure,
		 * without hardcoding any particular offset into the kernel:
		 */
		long futex_offset;

		/*
		 * The death of the thread may race with userspace setting
		 * up a lock's links. So to handle this race, userspace first
		 * sets this field to the address of the to-be-taken lock,
		 * then does the lock acquire, and then adds itself to the
		 * list, and then clears this field. Hence the kernel will
		 * always have full knowledge of all locks that the thread
		 * _might_ have taken. We check the owner TID in any case,
		 * so only truly owned locks will be handled.
		 */
		struct robust_list *list_op_pending;
};

/*
 * Are there any waiters for this robust futex:
 */
#define FUTEX_WAITERS			0x80000000

/*
 * The kernel signals via this bit that a thread holding a futex
 * has exited without unlocking the futex. The kernel also does
 * a FUTEX_WAKE on such futexes, after setting the bit, to wake
 * up any possible waiters:
 */
#define FUTEX_OWNER_DIED		0x40000000

/*
 * The rest of the robust-futex field is for the TID:
 */
#define FUTEX_TID_MASK			0x3fffffff

/*
 * This limit protects against a deliberately circular list.
 * (Not worth introducing an rlimit for it)
 */
#define ROBUST_LIST_LIMIT		2048
