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
