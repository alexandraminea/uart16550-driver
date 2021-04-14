// SPDX-License-Identifier: GPL-2.0+
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/io.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/slab.h>

#include "uart16550.h"

MODULE_DESCRIPTION("uart 16550 driver");
MODULE_AUTHOR("Minea Alexandra");
MODULE_LICENSE("GPL");


#define LOG_LEVEL		KERN_INFO
#define MY_MAJOR		42
#define MODULE_NAME		"uart16550"
#define NUM_MINORS      2
#define COM1_REG		0x3f8
#define COM2_REG		0x2f8
#define NR_PORTS		8
#define COM1_IRQ		4
#define COM2_IRQ        3

#define BUFFER_SIZE     4096
#define u_char          unsigned char

#define BIT_0           1
#define BIT_1           2
#define BIT_2           4
#define BIT_3           8
#define BIT_4           16
#define BIT_5           32
#define BIT_6           64
#define BIT_7           128

/* register offsets */
#define LCR_OFFSET      3
#define FCR_OFFSET      2
#define LSR_OFFSET      5
#define RBR_OFFSET      0
#define THR_OFFSET      0
#define IER_OFFSET      1
#define IIR_OFFSET      2
#define DLL_OFFSET      0
#define DLM_OFFSET      1


#define SET_BIT(address, bit)   outb(inb(address) | bit, address)         

static int major = 42;
static int option = OPTION_BOTH;

static struct class *chardev_class = NULL;
struct com_device_data {
    int port;

    /* spinlock for kfifo read buffer */
    spinlock_t read_lock;

    /* kfifo buffers */
    DECLARE_KFIFO(read_buffer, unsigned char, BUFFER_SIZE);
    DECLARE_KFIFO(write_buffer, unsigned char, BUFFER_SIZE);

    /* wait queues */
    wait_queue_head_t wq_read;
    wait_queue_head_t wq_write;

    struct cdev cdev;
};

/* COM1 and COM2 */
struct com_device_data devs[NUM_MINORS];


/* -------------- INTERRUPT FUNCTIONS -------------- */

static int get_reg(int minor)
{
    switch (minor) {
    case 0:
        return COM1_REG;
    default:
        return COM2_REG;
    }
}

static int get_irq(int minor)
{
    switch (minor) {
    case 0:
        return COM1_IRQ;
    default:
        return COM2_IRQ;
    }
}

static int get_minor(int irq)
{
    switch (irq) {
    case COM1_IRQ:
        return 0;
    default:
        return 1;
    }
}

static inline int get_interrupt_type(int port)
{
    return inb(port + IIR_OFFSET);
}

static inline u_char check_data_ready(int port)
{
    get_interrupt_type(port);

    /* check bit 0 of LSR register(data ready) */
    return inb(port + LSR_OFFSET) & BIT_0;
}

static inline u_char uart16550_read_data(int port)
{
    /* RBR register */
    return inb(port + RBR_OFFSET);
}

irqreturn_t uart16550_interrupt_handle(int irq_no, void *dev_id)
{
    int port, minor;
    u_char ch;

    minor = get_minor(irq_no);
    port = get_reg(minor);

    /* READ */
    while (check_data_ready(port)) {

        /* read character from RBR register */
        ch = uart16550_read_data(port);

        /* put character in read buffer */
        kfifo_put(&devs[minor].read_buffer, ch);
    }

    wake_up_interruptible(&devs[minor].wq_read);

    /* WRITE */



	return IRQ_NONE;
}

/* -------------- CHAR DEVICE FUNCTIONS -------------- */

static int uart16550_cdev_open(struct inode *inode, struct file *file)
{       
    int current_minor;
    current_minor = iminor(inode);

	file->private_data = (void *) &devs[current_minor];
    return 0;
}

static int uart_cdev_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t
uart16550_cdev_read(struct file *file, char __user *user_buffer,
		size_t size, loff_t *offset)
{
    unsigned char* buffer;
    struct com_device_data *dev = (struct com_device_data*) file->private_data;

    buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
    if (buffer == NULL)
        return -ENOMEM;

    /* block until data available */
    wait_event_interruptible(dev->wq_read, 
                                !kfifo_is_empty(&dev->read_buffer));

    /* read data from read_buffer */
    size = kfifo_out(&dev->read_buffer, buffer, size);

    /* copy to user */
    copy_to_user(user_buffer, buffer, size);

    /* signal data read done */
    wake_up_interruptible(&dev->wq_read);

    kfree(buffer);

    return size;
}

static ssize_t
uart16550_cdev_write(struct file *file, const char __user *user_buffer,
		        size_t size, loff_t *offset)
{
    return 0;
}

static int check_ioctl_data(struct uart16550_line_info* data)
{
    /* check baud rate */
    if (data->baud != UART16550_BAUD_1200 && data->baud != UART16550_BAUD_2400 
        && data->baud != UART16550_BAUD_4800 && data->baud != UART16550_BAUD_9600
        && data->baud != UART16550_BAUD_19200 && data->baud != UART16550_BAUD_38400
        && data->baud != UART16550_BAUD_56000 && data->baud != UART16550_BAUD_115200)
    {
        printk("invalid baud\n");
        printk("%d\n", data->baud);
        return -1;
    }

    /* check len */
    if (data->len != UART16550_LEN_5 && data->len != UART16550_LEN_6
        && data->len != UART16550_LEN_7 && data->len != UART16550_LEN_8) {
        printk("invalid data length\n");
        return -1;
    }


    /* check parity */
    if (data->par != UART16550_PAR_NONE && data->par != UART16550_PAR_ODD
        && data->par != UART16550_PAR_EVEN && data->par != UART16550_PAR_STICK)
    {
        printk("invalid parity\n");
        return -1;
    }

    /* check stop */
    if (data->stop != UART16550_STOP_1 && data->stop != UART16550_STOP_2)
    {
        printk("invalid stop\n");
        return -1;
    }
    return 0;
}

static inline void set_baud(int port, unsigned char baud)
{
    /* Divisor latch (DLL + DLM) registers */

    /* set bit 7(DLAB) of LCR reg to access Divisor Latch (DLL + DLM) */
    SET_BIT(port + LCR_OFFSET, BIT_7);

    /* set the baud rate in Divisor Latch */
    outb(baud, port + DLL_OFFSET);
    outb(0, port + DLM_OFFSET);
}

static inline void set_params(int port, u_char len, u_char par, u_char stop)
{
    u_char mask = 0;

    /* LCR register */

    /* set len, par, stop
    bit 0, 1      = length
    bit 2         = stop
    bit 3 | 4 | 5 = parity */

    mask = len | stop | par;
    outb(mask, port + LCR_OFFSET);
}

static inline void set_interrupts(int port)
{
    u_char mask = 0;

    /* IER register */

    /* enable Received Data Available Interrupt */
    mask = BIT_0;

    /* enable Transmitter Holding Register Empty Interrupt */
    mask |= BIT_1;

    outb(mask, port + IER_OFFSET);
}

static long
uart16550_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct com_device_data* dev = (struct com_device_data*) file->private_data;
    struct uart16550_line_info *line_info = (struct uart16550_line_info*) arg;
    struct uart16550_line_info line_copy;
    int port = dev->port;

    /* wrong operation */
    if (cmd != UART16550_IOCTL_SET_LINE) {
        printk("invalid command\n");
        return -EINVAL;
    }

    /* copy line_info to kernel space */
    if (copy_from_user(&line_copy, line_info, sizeof(line_copy)) != 0) {
        return -EFAULT;
    }

    /* check line parameters */
    if (check_ioctl_data(&line_copy) < 0) {
        return -EINVAL;
    }

    /* set baud rate */
    set_baud(port, line_info->baud);

    /* set len, par, stop */
    set_params(port, line_info->len, line_info->par, line_info->stop);

    /* set interrupts */
    set_interrupts(port);

    return 0;
}

static const struct file_operations cdev_fops = {
	.owner = THIS_MODULE,
	.open = uart16550_cdev_open,
	.release = uart_cdev_release,
    .read = uart16550_cdev_read,
	.write = uart16550_cdev_write,
	.unlocked_ioctl = uart16550_cdev_ioctl,
};


/* -------------- MODULE FUNCTIONS -------------- */
static int init_com_device(int major, int minor)
{
    int err;
    struct device *dev;
    int start, irq;

    start = get_reg(minor);
    irq = get_irq(minor);

    devs[minor].port = start;

    spin_lock_init(&devs[minor].read_lock);

    INIT_KFIFO(devs[minor].read_buffer);
    INIT_KFIFO(devs[minor].write_buffer);


    init_waitqueue_head(&devs[minor].wq_read);
    init_waitqueue_head(&devs[minor].wq_write);

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

    /* request the I/O ports */
    if (request_region(start, NR_PORTS, MODULE_NAME) == NULL) {
		err = -EBUSY;
		goto device_destroy;
	}

    /* register IRQ handler */
    err = request_irq(irq, uart16550_interrupt_handle,
			IRQF_SHARED, MODULE_NAME, &devs[minor]);
	if (err != 0) {
		pr_err("request_irq failed: %d\n", err);
		goto release_region;
	}

    cdev_init(&devs[minor].cdev, &cdev_fops);
    cdev_add(&devs[minor].cdev, MKDEV(major, minor), 1);

    return 0;

release_region:
    release_region(start, NR_PORTS);
device_destroy:
    device_destroy(chardev_class, MKDEV(major, minor));
unregister_chrdev_region:
    unregister_chrdev_region(MKDEV(major, minor), 1);

    return err;
}

static int delete_com_device(int major, int minor)
{
    int start, irq;

    start = get_reg(minor);
    irq = get_irq(minor);

    release_region(start, NR_PORTS);

    free_irq(irq, &devs[minor]);

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
    // default:
    //     return;
    }
    //class_unregister(chardev_class);
    class_destroy(chardev_class);
}

module_param(major, int, S_IRUGO);
module_param(option, int, S_IRUGO);

module_init(uart16550_init);
module_exit(uart16550_exit);


