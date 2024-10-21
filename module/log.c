#include "log.h"
#include <linux/ip.h> // for struct iphdr
#include <linux/in.h> // for IPPROTO_* constants
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/timekeeping.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>

#define LOG_DEBUG 0
#define LOG_INFO  1
#define LOG_WARN  2
#define LOG_ERROR 3

char log_file_path[256] = "/home/moyi/ws/module/net_log.txt";

void log_message(uint8_t level, const char *fmt, ...) {
    struct file *log_file;
    char *buf;
    size_t buf_size = 512;
    loff_t pos = 0;
    int len;
    va_list args;
    char time_str[20];
    struct timespec64 ts;
    struct tm broken;

    log_file = filp_open(log_file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(log_file)) {
        printk(KERN_ERR "Failed to open log file: %ld\n", PTR_ERR(log_file));
        return;
    }

    buf = kmalloc(buf_size, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "Failed to allocate memory for log buffer\n");
        filp_close(log_file, NULL);
        return;
    }

    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &broken);
    snprintf(time_str, sizeof(time_str), "%04ld-%02d-%02d %02d:%02d:%02d",
             broken.tm_year + 1900, broken.tm_mon + 1, broken.tm_mday,
             broken.tm_hour, broken.tm_min, broken.tm_sec);

    const char *level_str;
    switch (level) {
        case LOG_DEBUG: level_str = "DEBUG"; break;
        case LOG_INFO:  level_str = "INFO"; break;
        case LOG_WARN:  level_str = "WARN"; break;
        case LOG_ERROR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }

    len = snprintf(buf, buf_size, "[%s] [%s] ", time_str, level_str);

    va_start(args, fmt);
    len += vscnprintf(buf + len, buf_size - len, fmt, args);
    va_end(args);

    len += snprintf(buf + len, buf_size - len, "\n");

    kernel_write(log_file, buf, len, &pos);

    kfree(buf);
    filp_close(log_file, NULL);
}