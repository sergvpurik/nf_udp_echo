/*
 *  nf_udp_echo_proc_fs.c
 *
 *  Created on: Jul 21, 2015
 *      Author: Sergey Purik
 */

#ifdef __KERNEL__

#include "nf_udp_echo.h"

#include <linux/module.h>
#include <linux/stddef.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

extern const char * MODULE_NAME;
static const char * BASE_DIR_NAME = PROC_FS_NF_UDP_ECHO_DIR;
static const char * PORTS_FILE_NAME = PROC_FS_NF_UDP_POTRS;
static struct proc_dir_entry *base_dir = NULL, *ports_file = NULL;

#define PORTS_BUFF_SIZE 1024
static char ports_read_buff[PORTS_BUFF_SIZE + 1] = { 0 };


#if UDP_ECHO_FEATURE_STATUS
#define STATUS_BUFF_SIZE 1024
static const char * STATUS_FILE_NAME = PROC_FS_NF_UDP_STATUS;
static struct proc_dir_entry *status_file = NULL;
#endif // UDP_ECHO_FEATURE_STATUS

static ssize_t ports_read(struct file *file, char *user_buf, size_t count, loff_t *ppos)
{
	// user_buf - is a user space memory
	size_t len = strlen(ports_read_buff);
	printk( KERN_INFO "%s ports_read pos %lld, user buff %zu, data size %zu\n",
			MODULE_NAME, (*ppos), count, len);

	int res = 0; // 0 is EOF

	if (len == 0)
	{
		goto ports_read_end;
	}

	// check user space buffer size
	if (count < len)
	{
		printk( KERN_ERR "%s ports_read: user buffer is small\n", MODULE_NAME);
		res = -EINVAL;
		goto ports_read_end;
	}

	// check reading position
	if ((*ppos) > 0 && (*ppos) >= (loff_t) len)
	{
		printk( KERN_INFO "%s ports_read return EOF\n", MODULE_NAME);
		res = 0;
		goto ports_read_end;
	}

	unsigned long copy_n = len - (*ppos);
	res = copy_to_user((void*) user_buf, &ports_read_buff[*ppos], copy_n);
	if (res == 0)
	{
		//put_user('\n', user_buf + len);
		*ppos += copy_n; // update file position
		res = copy_n;
		printk( KERN_INFO "%s ports_read %d successfully\n", MODULE_NAME, res);
	}
	else
	{
		printk( KERN_ERR "%s ports_read: copy error %d\n", MODULE_NAME, res);
		res = -EFAULT;
	}

ports_read_end:
	return res;
}

static ssize_t ports_write(struct file *file, const char *user_buf, size_t count, loff_t *ppos)
{
	static char write_buff[PORTS_BUFF_SIZE + 1];
	write_buff[PORTS_BUFF_SIZE] = 0;

	int res = 0;

	printk( KERN_INFO "%s ports_write pos %lld, user data %zu, buff size %zu\n",
			MODULE_NAME, (*ppos), count, PORTS_BUFF_SIZE);

	// check buffer size
	unsigned long copy_n = count < PORTS_BUFF_SIZE ? count : PORTS_BUFF_SIZE;

	res = copy_from_user((void*) write_buff, user_buf, copy_n);
	if(res != 0)
	{
		printk( KERN_ERR "%s ports_write: copy error %d\n", MODULE_NAME, res);
		res = -EFAULT;
		goto ports_write_end;
	}

	printk( KERN_INFO "%s ports_write %lu successfully\n", MODULE_NAME, copy_n);
	res = copy_n;

	write_buff[copy_n] = 0; // set 0-charter at the end of string
	set_ports(write_buff);
	get_ports(ports_read_buff, sizeof(ports_read_buff));

ports_write_end:
	return res;
}

static const struct file_operations ports_fops =
{ .owner = THIS_MODULE, .read = ports_read, .write = ports_write };


#if UDP_ECHO_FEATURE_STATUS
static ssize_t status_read(struct file *file, char *user_buf, size_t count, loff_t *ppos)
{
	// user_buf - is a user space memory
	static char status_read_buff[STATUS_BUFF_SIZE + 1] = { 0 };

	size_t len = get_status(status_read_buff, sizeof(status_read_buff));

	printk( KERN_INFO "%s %s pos %lld, user buff %zu, data size %zu\n",
			MODULE_NAME, __FUNCTION__, (*ppos), count, len);

	int res = 0; // 0 is EOF

	if (len == 0)
	{
		goto end;
	}

	// check user space buffer size
	if (count < len)
	{
		printk( KERN_ERR "%s %s: user buffer is small\n", MODULE_NAME, __FUNCTION__);
		res = -EINVAL;
		goto end;
	}

	// check reading position
	if ((*ppos) > 0 && (*ppos) >= (loff_t) len)
	{
		printk( KERN_INFO "%s %s return EOF\n", MODULE_NAME, __FUNCTION__);
		res = 0;
		goto end;
	}

	unsigned long copy_n = len - (*ppos);
	res = copy_to_user((void*) user_buf, &status_read_buff[*ppos], copy_n);
	if (res == 0)
	{
		*ppos += copy_n; // update file position
		res = copy_n;
		printk( KERN_INFO "%s %s %d successfully\n", MODULE_NAME, __FUNCTION__, res);
	}
	else
	{
		printk( KERN_ERR "%s %s: copy error %d\n", MODULE_NAME, __FUNCTION__, res);
		res = -EFAULT;
	}

end:
	return res;
}

static ssize_t status_write(struct file *file, const char *user_buf, size_t count, loff_t *ppos)
{
	reset_status();
	return count;
}

static const struct file_operations status_fops =
{ .owner = THIS_MODULE, .read = status_read, .write = status_write};

#endif // UDP_ECHO_FEATURE_STATUS

int proc_fs_init(void)
{
	int ret;
	base_dir = proc_mkdir(BASE_DIR_NAME, NULL);
	if (base_dir == NULL)
	{
		ret = -ENOMEM;
		printk(KERN_ERR "%s can't create /proc/%s\n", MODULE_NAME, BASE_DIR_NAME);
		goto on_error_exit;
	}
	printk(KERN_INFO "%s created /proc/%s\n", MODULE_NAME, BASE_DIR_NAME);


	ports_file = create_proc_entry(PORTS_FILE_NAME, 0644, base_dir);
	if (ports_file == NULL)
	{
		ret = -ENOMEM;
		printk(KERN_ERR "can't create /proc/%s/%s\n", BASE_DIR_NAME,
			   PORTS_FILE_NAME);
		goto on_error_exit;
	}
	ports_file->uid = ports_file->gid = 0;
	ports_file->proc_fops = &ports_fops;

#if UDP_ECHO_FEATURE_STATUS
	status_file = create_proc_entry(STATUS_FILE_NAME, 0644, base_dir);
	if (status_file == NULL)
	{
		ret = -ENOMEM;
		printk(KERN_ERR "can't create /proc/%s/%s\n", BASE_DIR_NAME,
				STATUS_FILE_NAME);
		goto on_error_exit;
	}
	status_file->uid = ports_file->gid = 0;
	status_file->proc_fops = &status_fops;
#endif // UDP_ECHO_FEATURE_STATUS

	return 0;

on_error_exit:
	printk(KERN_ERR "%s proc_fs init error %i\n", MODULE_NAME, ret);
	return ret;
}

void proc_fs_clear(void)
{
	// firstly remove child

#if UDP_ECHO_FEATURE_STATUS
	if (base_dir != NULL && status_file != NULL)
	{
		remove_proc_entry(STATUS_FILE_NAME, base_dir);
		printk( KERN_INFO "%s removed /proc/%s/%s\n", MODULE_NAME, BASE_DIR_NAME, STATUS_FILE_NAME);
	}
#endif // UDP_ECHO_FEATURE_STATUS

	if (base_dir != NULL && ports_file != NULL)
	{
		remove_proc_entry(PORTS_FILE_NAME, base_dir);
		printk( KERN_INFO "%s removed /proc/%s/%s\n", MODULE_NAME, BASE_DIR_NAME, PORTS_FILE_NAME);
	}

	if (base_dir != NULL)
	{
		remove_proc_entry(BASE_DIR_NAME, NULL);
		printk( KERN_INFO "%s removed /proc/%s\n", MODULE_NAME, BASE_DIR_NAME);
	}
}

#endif /* __KERNEL__ */
