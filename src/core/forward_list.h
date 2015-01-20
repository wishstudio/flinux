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

#include <core/core.h>

#define FORWARD_LIST(type) \
	struct \
	{ \
		type *_fl_next; \
	}

#define FORWARD_LIST_NODE(type) \
	type *_fl_next

#define forward_list_init(list) \
	do \
	{ \
		(list)->_fl_next = NULL; \
	} while(0)

#define forward_list_empty(node) \
	((node)->_fl_next == NULL)

#define forward_list_next(node) \
	((node)->_fl_next)

#define forward_list_add(prev, node) \
	do \
	{ \
		(node)->_fl_next = (prev)->_fl_next; \
		(prev)->_fl_next = (node); \
	} while(0)

#define forward_list_remove(prev, node) \
	do \
	{ \
		(prev)->_fl_next = (node)->_fl_next; \
	} while(0)

#define forward_list_iterate(list, prev, node) \
	for (prev = (list), node = prev->_fl_next; node; prev = node, node = node->_fl_next)

#define forward_list_iterate_safe(list, prev, node) \
	for (prev = (list), node = prev->_fl_next; node; \
		prev->_fl_next == node? (prev = node), (node = node->_fl_next): (node = prev->_fl_next))
