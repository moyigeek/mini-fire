#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include "rule_filter.h"
#include "driver.h"
#include "stateful_check.h"
#define DEVICE_NAME "firewall_ctrl"
#define CLASS_NAME "firewall"

static int major_number;
static struct class* firewall_class = NULL;
static struct device* firewall_device = NULL;
static char *buffer;
static size_t buffer_size;
static size_t buffer_offset;

extern struct hlist_head connection_table[1 << 16]; // 从其他文件中导入连接表
extern void print_connection_table(void); // 从其他文件中导入打印函数

static int firewall_dev_open(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "Firewall device opened\n");
    return 0;
}

static ssize_t firewall_dev_read(struct file *filep, char *user_buffer, size_t len, loff_t *offset) {
    ssize_t ret;

    if (buffer_offset >= buffer_size) {
        return 0;
    }

    if (len > buffer_size - buffer_offset) {
        len = buffer_size - buffer_offset;
    }

    ret = copy_to_user(user_buffer, buffer + buffer_offset, len);
    if (ret) {
        return -EFAULT;
    }

    buffer_offset += len;
    return len;
}

static ssize_t firewall_dev_write(struct file *filep, const char *user_buffer, size_t len, loff_t *offset) {
    char command;

    if (len != 1) {
        return -EINVAL;
    }

    if (copy_from_user(&command, user_buffer, 1)) {
        return -EFAULT;
    }

    switch (command) {
        case 0x1:
            printk(KERN_INFO "Received command 0x1\n");
            if (filter_status == 0) {
                // 注册钩子
                firewall_in_hook.hook = rule_filter_apply_inbound;
                firewall_out_hook.hook = rule_filter_apply_outbound;
                if (nf_register_net_hook(&init_net, &firewall_in_hook) < 0) {
                    printk(KERN_ALERT "Failed to register inbound firewall hook\n");
                    return -EFAULT;
                }
                if (nf_register_net_hook(&init_net, &firewall_out_hook) < 0) {
                    printk(KERN_ALERT "Failed to register outbound firewall hook\n");
                    nf_unregister_net_hook(&init_net, &firewall_in_hook);
                    return -EFAULT;
                }
                filter_status = 1;
                printk(KERN_INFO "Firewall hooks registered\n");
            }
            break;
        case 0x2:
            printk(KERN_INFO "Received command 0x2\n");
            if (filter_status == 1) {
                // 注销钩子
                nf_unregister_net_hook(&init_net, &firewall_in_hook);
                nf_unregister_net_hook(&init_net, &firewall_out_hook);
                filter_status = 0;
                printk(KERN_INFO "Firewall hooks unregistered\n");
            }
            break;
        case 0x3:
            printk(KERN_INFO "Received command 0x3\n");
            if (rule_filter_load_rules() != 0) {
                printk(KERN_ALERT "Failed to reload rules\n");
                return -EFAULT;
            }
            printk(KERN_INFO "Firewall rules reloaded\n");
            break;
        case 0x4:
            printk(KERN_INFO "Received command 0x4\n");
            print_connection_table();
            buffer_offset=0;
            break;
        default:
            printk(KERN_INFO "Unknown command\n");
            return -EINVAL;
    }

    return len;
}

static int firewall_dev_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "Firewall device closed\n");
    return 0;
}

static struct file_operations fops = {
    .open = firewall_dev_open,
    .read = firewall_dev_read,
    .write = firewall_dev_write,
    .release = firewall_dev_release,
};

int register_firewall_device(void) {
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        printk(KERN_ALERT "Failed to register a major number\n");
        return major_number;
    }
    printk(KERN_INFO "Registered correctly with major number %d\n", major_number);

    firewall_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(firewall_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(firewall_class);
    }
    printk(KERN_INFO "Device class registered correctly\n");

    firewall_device = device_create(firewall_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(firewall_device)) {
        class_destroy(firewall_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(firewall_device);
    }
    printk(KERN_INFO "Device class created correctly\n");

    return 0;
}

void unregister_firewall_device(void) {
    device_destroy(firewall_class, MKDEV(major_number, 0));
    class_unregister(firewall_class);
    class_destroy(firewall_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    kfree(buffer);
}