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

#pragma once

#include <lib/core.h>

struct slist
{
	struct slist *next;
};

#define slist_entry(node, type, member) \
	container_of(node, type, member)

#define slist_init(node) \
	do \
	{ \
		(node)->next = NULL; \
	} while(0)

#define slist_empty(node) \
	((node)->next == NULL)

#define slist_next(node) \
	(node)->next

#define slist_next_entry(node, type, member) \
	slist_entry(slist_next(node), type, member)

#define slist_add(prev, node) \
	do \
	{ \
		(node)->next = (prev)->next; \
		(prev)->next = (node); \
	} while(0)

#define slist_remove(prev, node) \
	do \
	{ \
		(prev)->next = (node)->next; \
	} while(0)

#define slist_iterate(list, prev, cur) \
	for (struct slist *prev = (list), *cur = slist_next(prev); \
		cur; \
		prev = cur, cur = slist_next(cur))

#define slist_iterate_safe(list, prev, cur) \
	for (struct slist *prev = (list), *cur = slist_next(prev); \
		cur; \
		slist_next(prev) == cur? \
			prev = cur, cur = slist_next(cur): (cur = slist_next(prev)))
