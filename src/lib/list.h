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

struct list_node
{
	struct list_node *prev;
	struct list_node *next;
};

struct list
{
	struct list_node *head;
	struct list_node *tail;
};

#define list_entry(node, type, member) \
	container_of(node, type, member)

#define list_empty(list) \
	((list)->head == NULL)

#define list_head(list) \
	((list)->head)

#define list_tail(list) \
	((list)->tail)

#define list_prev(node) \
	((node)->prev)

#define list_next(node) \
	((node)->next)

#define list_init(list) \
	do \
	{ \
		(list)->head = NULL; \
		(list)->tail = NULL; \
	} while (0)

#define list_add(list, node) \
	do \
	{ \
		if ((list)->tail) \
		{ \
			(node)->prev = list_tail(list); \
			(node)->next = NULL; \
			(list)->tail->next = (node); \
			(list)->tail = (node); \
		} \
		else \
		{ \
			(node)->prev = (node)->next = NULL; \
			(list)->head = (node); \
			(list)->tail = (node); \
		} \
	} while (0)

#define list_remove(list, node) \
	do \
	{ \
		if ((list)->head == node) \
			(list)->head = (node)->next; \
		else if ((list)->tail == node) \
			(list)->tail = (node)->prev; \
		if ((node)->prev) \
			(node)->prev->next = (node)->next; \
		if ((node)->next) \
			(node)->next->prev = (node)->prev; \
	} while (0)

#define list_iterate(list, cur) \
	for (cur = (list)->head; cur; cur = cur->next)
