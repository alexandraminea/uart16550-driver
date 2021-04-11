// SPDX-License-Identifier: GPL-2.0+

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/miscdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/spinlock.h>

#include "uart16550.h"

MODULE_DESCRIPTION("uart 16550 driver");
MODULE_AUTHOR("Minea Alexandra");
MODULE_LICENSE("GPL");

#define MY_MAJOR		42
#define MODULE_NAME		"uart16550"
#define NUM_MINORS      2
#define COM1_START				0x3f8
#define COM2_START				0x2f8

static int major = 42;
static int option = OPTION_BOTH;

static struct class *chardev_class = NULL;
struct com_device_data {
    int baseport;
    struct cdev cdev;
};

/* COM1 and COM2 */
struct com_device_data devs[NUM_MINORS];


/* chardev functions */
static int uart_cdev_open(struct inode *inode, struct file *file)
{       
    int current_minor;
    current_minor = iminor(inode);
    return 0;
}

static int uart_cdev_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t
uart_cdev_read(struct file *file, char __user *user_buffer,
		size_t size, loff_t *offset)
{
    return size;
}
static ssize_t
uart_cdev_write(struct file *file, const char __user *user_buffer,
		        size_t size, loff_t *offset)
{
    return size;
}

static long
uart_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    return 0;
}

static const struct file_operations cdev_fops = {
	.owner = THIS_MODULE,
	.open = uart_cdev_open,
	.release = uart_cdev_release,
    .read = uart_cdev_read,
	.write = uart_cdev_write,
	.unlocked_ioctl = uart_cdev_ioctl,
};

static int init_com_device(int major, int minor)
{
    int err;
    struct device *dev;
    int start;

    /* get the baseport */
    if (minor == 0)
        start = COM1_START;
    else
        start = COM2_START;


    /* register chardev region */
    err = register_chrdev_region(MKDEV(major, minor), 1, MODULE_NAME);
    if (err != 0) {
		pr_info("register_chrdev_region");
		return err;
	}

    /* create /dev/uartX entry */
    dev = device_create(chardev_class, NULL, MKDEV(major, minor), NULL, "uart%d", minor);
    if (IS_ERR(dev)) {
        goto unregister_chrdev_region;
    }

    // if (!request_region(start, NR_PORTS, MODULE_NAME)) {
    //     err = -ENODEV;
    //     goto device_destroy;
    // }

    // IO ports

    // INTERRUPTS

    cdev_init(&devs[minor].cdev, &cdev_fops);
    cdev_add(&devs[minor].cdev, MKDEV(major, minor), 1);

    return 0;

device_destroy:
    device_destroy(chardev_class, MKDEV(major, minor));
unregister_chrdev_region:
    unregister_chrdev_region(MKDEV(major, minor), 1);

    return err;
}

static int delete_com_device(int major, int minor)
{
    device_destroy(chardev_class, MKDEV(major, minor));

    unregister_chrdev_region(MKDEV(major, minor), 1);

    cdev_del(&devs[minor].cdev);

    return 0;
}

static int uart16550_init(void)
{
    chardev_class = class_create(THIS_MODULE, MODULE_NAME);

    switch(option) {
    case OPTION_COM1:
        init_com_device(major, 0);
        break;
    case OPTION_COM2:
        init_com_device(major, 1);
        break;
    case OPTION_BOTH:
        init_com_device(major, 0);
        init_com_device(major, 1);
        break;
    default:
        return -EINVAL;
    }
    return 0;
}

static void uart16550_exit(void)
{
    switch(option) {
    case OPTION_COM1:
        delete_com_device(major, 0);
        break;
    case OPTION_COM2:
        delete_com_device(major, 1);
        break;
    case OPTION_BOTH:
        delete_com_device(major, 0);
        delete_com_device(major, 1);
        break;
    default:
        return;
    }
    //class_unregister(chardev_class);
    class_destroy(chardev_class);
}

module_param(major, int, S_IRUGO);
module_param(option, int, S_IRUGO);

module_init(uart16550_init);
module_exit(uart16550_exit);
