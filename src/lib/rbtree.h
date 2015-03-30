#pragma once

#include <lib/core.h>

struct rb_node
{
	size_t _parent;
	struct rb_node *left, *right;
};

#define rb_entry(node, type, member) \
	container_of(node, type, member)

struct rb_tree
{
	struct rb_node *root;
};

typedef int rb_cmp(const struct rb_node *left, const struct rb_node *right);

/* Test if the tree is empty */
#define rb_empty(tree)	((tree)->root == NULL)

/* Initialize a tree */
#define rb_init(tree)	\
	do { \
		(tree)->root = NULL; \
	} while (0)

/* Add a node to a tree */
void rb_add(struct rb_tree *tree, struct rb_node *node, rb_cmp *cmp);

/* Remove a node from a tree, the data in it is lost */
void rb_remove(struct rb_tree *tree, struct rb_node *node);

/* Find a node in tree which is equal to value */
struct rb_node *rb_find(struct rb_tree *tree, const struct rb_node *value, rb_cmp *cmp);

/* Find the smallest node in tree which is not less than value */
struct rb_node *rb_lower_bound(struct rb_tree *tree, const struct rb_node *value, rb_cmp *cmp);

/* Find the largest node in tree which is not larger than value */
struct rb_node *rb_upper_bound(struct rb_tree *tree, const struct rb_node *value, rb_cmp *cmp);

/* Get the first node of a tree, NULL if the tree is empty */
struct rb_node *rb_first(struct rb_tree *tree);

/* Get the last node of a tree, NULL if the tree is empty */
struct rb_node *rb_last(struct rb_tree *tree);

/* Get the precedent of a node, NULL if none */
struct rb_node *rb_prev(struct rb_node *node);

/* Get the precedent of a node, NULL if none */
struct rb_node *rb_next(struct rb_node *node);
