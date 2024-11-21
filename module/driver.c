#include <linux/module.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include "rule_filter.h"
#include "driver.h"
#include "stateful_check.h"
#include "log.h"

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
    log_message(LOG_INFO, "Firewall device opened");
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
        case '0':
            printk(KERN_INFO "Received command on\n");
            log_message(LOG_INFO, "Received command on");
            if (filter_status == 0) {
                // 注册钩子
                firewall_in_hook.hook = rule_filter_apply_inbound;
                firewall_out_hook.hook = rule_filter_apply_outbound;
                if (nf_register_net_hook(&init_net, &firewall_in_hook) < 0) {
                    printk(KERN_ALERT "Failed to register inbound firewall hook\n");
                    log_message(LOG_WARN, "Failed to register inbound firewall hook");
                    return -EFAULT;
                }
                if (nf_register_net_hook(&init_net, &firewall_out_hook) < 0) {
                    printk(KERN_ALERT "Failed to register outbound firewall hook\n");
                    log_message(LOG_WARN, "Failed to register outbound firewall hook");
                    nf_unregister_net_hook(&init_net, &firewall_in_hook);
                    return -EFAULT;
                }
                filter_status = 1;
                printk(KERN_INFO "Firewall hooks registered\n");
                log_message(LOG_INFO, "Firewall hooks registered");
            }
            break;
        case '1':
            printk(KERN_INFO "Received command turn off\n");
            log_message(LOG_INFO, "Received command turn off");
            if (filter_status == 1) {
                // 注销钩子
                nf_unregister_net_hook(&init_net, &firewall_in_hook);
                nf_unregister_net_hook(&init_net, &firewall_out_hook);
                filter_status = 0;
                printk(KERN_INFO "Firewall hooks unregistered\n");
                log_message(LOG_INFO, "Firewall hooks unregistered");
            }
            break;
        case '2':
            printk(KERN_INFO "Received command reload\n");
            log_message(LOG_INFO, "Received command reload");
            if (rule_filter_load_rules() != 0) {
                printk(KERN_ALERT "Failed to reload rules\n");
                log_message(LOG_WARN, "Failed to reload rules");
                return -EFAULT;
            }
            printk(KERN_INFO "Firewall rules reloaded\n");
            log_message(LOG_INFO, "Firewall rules reloaded");
            break;
        case '3':
            printk(KERN_INFO "Received command printf\n");
            log_message(LOG_INFO, "Received command printf");
            print_connection_table();
            buffer_offset = 0;
            break;
        default:
            printk(KERN_INFO "Unknown command\n");
            log_message(LOG_INFO, "Unknown command");
            return -EINVAL;
    }

    return len;
}

static int firewall_dev_release(struct inode *inodep, struct file *filep) {
    printk(KERN_INFO "Firewall device closed\n");
    log_message(LOG_INFO, "Firewall device closed");
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
        log_message(LOG_WARN, "Failed to register a major number");
        return major_number;
    }
    printk(KERN_INFO "Registered correctly with major number %d\n", major_number);
    log_message(LOG_INFO, "Registered correctly with major number %d", major_number);

    firewall_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(firewall_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to register device class\n");
        log_message(LOG_WARN, "Failed to register device class");
        return PTR_ERR(firewall_class);
    }
    printk(KERN_INFO "Device class registered correctly\n");
    log_message(LOG_INFO, "Device class registered correctly");

    firewall_device = device_create(firewall_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(firewall_device)) {
        class_destroy(firewall_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        printk(KERN_ALERT "Failed to create the device\n");
        log_message(LOG_WARN, "Failed to create the device");
        return PTR_ERR(firewall_device);
    }
    printk(KERN_INFO "Device class created correctly\n");
    log_message(LOG_INFO, "Device class created correctly");

    return 0;
}

void unregister_firewall_device(void) {
    device_destroy(firewall_class, MKDEV(major_number, 0));
    class_unregister(firewall_class);
    class_destroy(firewall_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    kfree(buffer);
}