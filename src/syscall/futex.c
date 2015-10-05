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
#include <common/futex.h>
#include <common/time.h>
#include <syscall/process_info.h>
#include <syscall/sig.h>
#include <syscall/syscall.h>
#include <lib/list.h>
#include <log.h>

#include <ntdll.h>

/* TODO: How to implement interprocess futex? */

#define FUTEX_HASH_BUCKETS		256

struct futex_wait_block
{
	struct thread *thread;
	struct list_node list;
};

struct futex_hash_bucket
{
	volatile LONG spin_lock;
	struct list wait_list;
};

struct futex_data
{
	struct futex_hash_bucket hash[FUTEX_HASH_BUCKETS];
} static _futex;

static struct futex_data *const futex = &_futex;

static void lock_bucket(int bucket)
{
	while (InterlockedCompareExchange(&futex->hash[bucket].spin_lock, 1, 0))
		YieldProcessor();
}

static void unlock_bucket(int bucket)
{
	futex->hash[bucket].spin_lock = 0;
}

static int futex_hash(size_t addr)
{
	/* TODO: Improve this silly hash function */
	return addr % FUTEX_HASH_BUCKETS;
}

static int futex_wait(volatile int *addr, int val, DWORD timeout)
{
	struct futex_wait_block wait_block;
	int bucket = futex_hash((size_t)addr);
	lock_bucket(bucket);
	if (*addr != val)
	{
		/* The value changed */
		unlock_bucket(bucket);
		return 0;
	}
	/* Append wait block */
	wait_block.thread = current_thread;
	list_add(&futex->hash[bucket].wait_list, &wait_block.list);
	unlock_bucket(bucket);
	DWORD result = signal_wait(1, &current_thread->wait_event, timeout);
	if (result == WAIT_OBJECT_0)
	{
		log_info("Wait successful.");
		/* Wait successful, the waker should have removed us from the wait list */
		return 0;
	}
	else
	{
		/* Wait unsuccessful, we need to remove us from the wait list */
		lock_bucket(bucket);
		/* Check again if we're not woke, to avoid data race when we are woken between
		 * signal_wait() and lock_bucket()
		 */
		if (WaitForSingleObject(current_thread->wait_event, 0) != WAIT_OBJECT_0)
			list_remove(&futex->hash[bucket].wait_list, &wait_block.list);
		unlock_bucket(bucket);
		if (result == WAIT_INTERRUPTED)
		{
			log_info("Wait interrupted.");
			return -L_EINTR;
		}
		else //if (result == WAIT_TIMEOUT)
		{
			log_info("Wait timeout.");
			return -L_ETIMEDOUT;
		}
	}
}

static int futex_wake(int *addr, int count)
{
	int bucket = futex_hash((size_t)addr);
	lock_bucket(bucket);
	/* Wake up to count threads */
	int num_woken = 0;
	while (num_woken < count && !list_empty(&futex->hash[bucket].wait_list))
	{
		struct list_node *node = list_head(&futex->hash[bucket].wait_list);
		list_remove(&futex->hash[bucket].wait_list, node);
		struct futex_wait_block *wait_block = list_entry(node, struct futex_wait_block, list);
		NtSetEvent(wait_block->thread->wait_event, NULL);
		num_woken++;
	}
	unlock_bucket(bucket);
	return num_woken;
}

DEFINE_SYSCALL(futex, int *, uaddr, int, op, int, val, const struct timespec *, timeout, int *, uaddr2, int, val3)
{
	log_info("futex(%p, %d, %d, %p, %p, %d)", uaddr, op, val, timeout, uaddr2, val3);
	if (!mm_check_write(uaddr, sizeof(int)))
		return -L_EACCES;
	switch (op & FUTEX_CMD_MASK)
	{
	case FUTEX_WAIT:
	{
		if (timeout && !mm_check_read(timeout, sizeof(struct timespec)))
			return -L_EFAULT;
		DWORD time = timeout ? timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000 : INFINITE;
		return futex_wait((volatile int *)uaddr, val, time);
	}

	case FUTEX_WAKE:
		return futex_wake(uaddr, val);

	default:
		log_error("Unsupported futex operation, returning ENOSYS");
		return -L_ENOSYS;
	}
}

DEFINE_SYSCALL(set_robust_list, struct robust_list_head *, head, int, len)
{
	log_info("set_robust_list(head=%p, len=%d)", head, len);
	if (len != sizeof(struct robust_list_head))
		log_error("len (%d) != sizeof(struct robust_list_head)", len);
	log_error("set_robust_list() not supported.");
	return 0;
}
