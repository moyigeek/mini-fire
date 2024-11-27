#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include "rule_filter.h"
#include "driver.h"
#include "stateful_check.h"
#include "nat.h"
#include "log.h"
#include <linux/timekeeping.h>
#include <linux/inet.h>

#define PROC_LOG_FILE_NAME "fw_log"
#define PROC_CONN_FILE_NAME "connection_table"
#define LOG_BUFFER_SIZE 4096

static struct nf_hook_ops nat_hook = {
    .hook = nat_apply,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};


static char log_buffer[LOG_BUFFER_SIZE];
static size_t log_buffer_pos = 0;
static struct proc_dir_entry *proc_log_file;
static struct proc_dir_entry *proc_conn_file;

extern struct hlist_head connection_table[1 << 16]; // 从其他文件中导入连接表

static ssize_t proc_log_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    return simple_read_from_buffer(buf, count, ppos, log_buffer, log_buffer_pos);
}

static ssize_t proc_log_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    return -EINVAL; // 不允许写入
}

static const struct proc_ops proc_log_file_ops = {
    .proc_read = proc_log_read,
    .proc_write = proc_log_write,
};

static const char* get_protocol_name(uint8_t proto) {
    switch (proto) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_IP:
            return "IP";
        default:
            return "UNKNOWN";
    }
}

static void get_current_time_str(char *buffer, size_t buffer_size) {
    struct timespec64 ts;
    struct tm tm;
    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);
    snprintf(buffer, buffer_size, "%02d:%02d:%02d",
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}


static ssize_t proc_conn_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    char *kbuf;
    struct connection_t *conn;
    int bkt;
    size_t offset = 0;
    char time_str[32];

    // 计算缓冲区大小
    size_t buffer_size = snprintf(NULL, 0, "src_ip,dst_ip,src_port,dst_port,proto,state,last_seen\n");
    hash_for_each(connection_table, bkt, conn, list) {
        buffer_size += snprintf(NULL, 0, "%pI4,%pI4,%u,%u,%s,%d,%s\n",
                                &conn->src_ip, &conn->dst_ip, conn->src_port, conn->dst_port,
                                get_protocol_name(conn->proto), conn->state, time_str);
    }

    kbuf = kmalloc(buffer_size + 1, GFP_KERNEL);
    if (!kbuf) {
        return -ENOMEM;
    }

    // 填充缓冲区
    offset += snprintf(kbuf + offset, buffer_size - offset + 1, "src_ip,dst_ip,src_port,dst_port,proto,state,last_seen\n");
    hash_for_each(connection_table, bkt, conn, list) {
        get_current_time_str(time_str, sizeof(time_str));
        offset += snprintf(kbuf + offset, buffer_size - offset + 1, "%pI4,%pI4,%u,%u,%s,%d,%s\n",
                           &conn->src_ip, &conn->dst_ip, conn->src_port, conn->dst_port,
                           get_protocol_name(conn->proto), conn->state, time_str);
    }

    if (*ppos >= offset) {
        kfree(kbuf);
        return 0;
    }

    if (count > offset - *ppos) {
        count = offset - *ppos;
    }

    if (copy_to_user(buf, kbuf + *ppos, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    *ppos += count;
    kfree(kbuf);
    return count;
}

static const struct proc_ops proc_conn_file_ops = {
    .proc_read = proc_conn_read,
};

void log_message(uint8_t level, const char *fmt, ...) {
    char temp_buf[256];
    va_list args;
    int len;
    char time_str[20];
    struct timespec64 ts;
    struct tm broken;
    const char *level_str;

    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &broken);
    snprintf(time_str, sizeof(time_str), "%04ld-%02d-%02d %02d:%02d:%02d",
             broken.tm_year + 1900, broken.tm_mon + 1, broken.tm_mday,
             broken.tm_hour, broken.tm_min, broken.tm_sec);

    switch (level) {
        case LOG_DEBUG: level_str = "DEBUG"; break;
        case LOG_INFO:  level_str = "INFO"; break;
        case LOG_WARN:  level_str = "WARN"; break;
        case LOG_ERROR: level_str = "ERROR"; break;
        default: level_str = "UNKNOWN"; break;
    }

    va_start(args, fmt);
    len = vsnprintf(temp_buf, sizeof(temp_buf), fmt, args);
    va_end(args);

    len = snprintf(log_buffer + log_buffer_pos, LOG_BUFFER_SIZE - log_buffer_pos, "[%s] [%s] %s\n", time_str, level_str, temp_buf);
    log_buffer_pos += len;

    if (log_buffer_pos >= LOG_BUFFER_SIZE) {
        log_buffer_pos = 0; // 环形缓冲区
    }
}

static int __init firewall_init(void) {
    // start_log();
    log_message(LOG_INFO, "Loading firewall module");

    // 创建 /proc/fw_log 文件
    proc_log_file = proc_create(PROC_LOG_FILE_NAME, 0444, NULL, &proc_log_file_ops);
    if (!proc_log_file) {
        log_message(LOG_ERROR, "Failed to create /proc/%s", PROC_LOG_FILE_NAME);
        return -ENOMEM;
    }

    // 创建 /proc/connection_table 文件
    proc_conn_file = proc_create(PROC_CONN_FILE_NAME, 0444, NULL, &proc_conn_file_ops);
    if (!proc_conn_file) {
        log_message(LOG_ERROR, "Failed to create /proc/%s", PROC_CONN_FILE_NAME);
        remove_proc_entry(PROC_LOG_FILE_NAME, NULL);
        return -ENOMEM;
    }

    // 注册字符设备
    if (register_firewall_device() < 0) {
        log_message(LOG_WARN, "Failed to register firewall device");
        remove_proc_entry(PROC_LOG_FILE_NAME, NULL);
        remove_proc_entry(PROC_CONN_FILE_NAME, NULL);
        return -1;
    }

    if (rule_filter_load_rules() != 0) {
        log_message(LOG_WARN, "Failed to load rules");
        unregister_firewall_device(); // 注销字符设备
        remove_proc_entry(PROC_LOG_FILE_NAME, NULL);
        remove_proc_entry(PROC_CONN_FILE_NAME, NULL);
        return -1;
    }

    // 设置钩子函数
    firewall_in_hook.hook = rule_filter_apply_inbound;
    firewall_out_hook.hook = rule_filter_apply_outbound;

    // 注册入站钩子
    if (nf_register_net_hook(&init_net, &firewall_in_hook) < 0) {
        log_message(LOG_WARN, "Failed to register inbound firewall hook");
        unregister_firewall_device(); // 注销字符设备
        remove_proc_entry(PROC_LOG_FILE_NAME, NULL);
        remove_proc_entry(PROC_CONN_FILE_NAME, NULL);
        return -1;
    }

    // 注册出站钩子
    if (nf_register_net_hook(&init_net, &firewall_out_hook) < 0) {
        log_message(LOG_WARN, "Failed to register outbound firewall hook");
        nf_unregister_net_hook(&init_net, &firewall_in_hook); // 注销已注册的入站钩子
        unregister_firewall_device(); // 注销字符设备
        remove_proc_entry(PROC_LOG_FILE_NAME, NULL);
        remove_proc_entry(PROC_CONN_FILE_NAME, NULL);
        return -1;
    }

    // 初始化状态检测功能
    if (stateful_firewall_init() != 0) {
        log_message(LOG_WARN, "Failed to initialize stateful firewall");
        nf_unregister_net_hook(&init_net, &firewall_in_hook); // 注销入站钩子
        nf_unregister_net_hook(&init_net, &firewall_out_hook); // 注销出站钩子
        unregister_firewall_device(); // 注销字符设备
        remove_proc_entry(PROC_LOG_FILE_NAME, NULL);
        remove_proc_entry(PROC_CONN_FILE_NAME, NULL);
        return -1;
    }

    // 注册NAT钩子
    if (nf_register_net_hook(&init_net, &nat_hook) < 0) {
        log_message(LOG_WARN, "Failed to register NAT hook");
        nf_unregister_net_hook(&init_net, &firewall_in_hook); // 注销入站钩子
        nf_unregister_net_hook(&init_net, &firewall_out_hook); // 注销出站钩子
        stateful_firewall_exit(); // 清理状态检测功能
        unregister_firewall_device(); // 注销字符设备
        remove_proc_entry(PROC_LOG_FILE_NAME, NULL);
        remove_proc_entry(PROC_CONN_FILE_NAME, NULL);
        return -1;
    }

    // 加载NAT规则
    if (nat_load_rules(get_nat_rule_file_path()) != 0) {
        log_message(LOG_WARN, "Failed to load NAT rules");
        nf_unregister_net_hook(&init_net, &firewall_in_hook); // 注销入站钩子
        nf_unregister_net_hook(&init_net, &firewall_out_hook); // 注销出站钩子
        nf_unregister_net_hook(&init_net, &nat_hook); // 注销NAT钩子
        stateful_firewall_exit(); // 清理状态检测功能
        unregister_firewall_device(); // 注销字符设备
        remove_proc_entry(PROC_LOG_FILE_NAME, NULL);
        remove_proc_entry(PROC_CONN_FILE_NAME, NULL);
        return -1;
    }

    filter_status = 1; // 开启过滤器
    log_message(LOG_INFO, "Module initialized");
    return 0;
}

static void __exit firewall_exit(void) {
    struct firewall_rule *rule, *tmp;
    list_for_each_entry_safe(rule, tmp, &rule_list, list) {
        list_del(&rule->list);
        kfree(rule);
    }

    // 注销钩子
    nf_unregister_net_hook(&init_net, &firewall_in_hook);
    nf_unregister_net_hook(&init_net, &firewall_out_hook);
    nf_unregister_net_hook(&init_net, &nat_hook);
    filter_status = 0; // 关闭过滤器

    // 清理状态检测功能
    stateful_firewall_exit();

    // 注销字符设备
    unregister_firewall_device();

    // 清理NAT规则
    while (!list_empty(&nat_rule_list)) {
        nat_rule_t *rule = list_first_entry(&nat_rule_list, nat_rule_t, list);
        list_del(&rule->list);
        kfree(rule);
    }

    // 删除 /proc/fw_log 文件
    remove_proc_entry(PROC_LOG_FILE_NAME, NULL);

    // 删除 /proc/connection_table 文件
    remove_proc_entry(PROC_CONN_FILE_NAME, NULL);

    log_message(LOG_INFO, "Module exiting");
    // stop_log();
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Firewall Module with NAT support");