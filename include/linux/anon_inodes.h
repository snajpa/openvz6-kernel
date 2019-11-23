/*
 *  include/linux/anon_inodes.h
 *
 *  Copyright (C) 2007  Davide Libenzi <davidel@xmailserver.org>
 *
 */

#ifndef _LINUX_ANON_INODES_H
#define _LINUX_ANON_INODES_H

struct inode;
extern struct inode *anon_inode_inode;

struct file *anon_inode_getfile(const char *name,
				const struct file_operations *fops,
				void *priv, int flags);
int anon_inode_getfd(const char *name, const struct file_operations *fops,
		     void *priv, int flags);
int __anon_inode_getfd(const char *name, const struct file_operations *fops,
		       void *priv, int flags,
		       const struct dentry_operations *dops);

#endif /* _LINUX_ANON_INODES_H */

