#include "stateful_check.h"
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/jhash.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include "log.h"
#define TIMEOUT_INTERVAL (5 * HZ) // 超时时间间隔，5秒

struct hlist_head connection_table[1 << 16]; // 定义连接表
static struct timer_list timeout_timer;
static char *buffer;
static size_t buffer_size;

// TCP状态检测函数
static int check_tcp_state(struct sk_buff *skb, connection_t *conn) {
    struct tcphdr *tcph = tcp_hdr(skb);
    // 更新连接状态
    conn->last_seen = jiffies;
    // 简单的状态检测逻辑，可以根据需要扩展
    if (tcph->syn && !tcph->ack) {
        conn->state = 1; // SYN_SENT
    } else if (tcph->syn && tcph->ack) {
        conn->state = 2; // SYN_RECV
    } else if (tcph->fin) {
        conn->state = 3; // FIN_WAIT
    } else {
        conn->state = 4; // ESTABLISHED
    }
    return NF_ACCEPT;
}

// UDP状态检测函数
static int check_udp_state(struct sk_buff *skb, connection_t *conn) {
    // 更新连接状态
    conn->last_seen = jiffies;
    // UDP是无连接的，简单更新状态
    conn->state = 1; // ACTIVE
    return NF_ACCEPT;
}

// ICMP状态检测函数
static int check_icmp_state(struct sk_buff *skb, connection_t *conn) {
    struct icmphdr *icmph = icmp_hdr(skb);
    // 更新连接状态
    conn->last_seen = jiffies;
    // 简单的状态检测逻辑，可以根据需要扩展
    if (icmph->type == ICMP_ECHO) {
        conn->state = 1; // ECHO_REQUEST
    } else if (icmph->type == ICMP_ECHOREPLY) {
        conn->state = 2; // ECHO_REPLY
    } else {
        conn->state = 3; // OTHER
    }
    return NF_ACCEPT;
}

// 状态检测主函数
int stateful_firewall_check(struct sk_buff *skb, int direction) {
    struct iphdr *iph = ip_hdr(skb);
    uint32_t src_ip = iph->saddr;
    uint32_t dst_ip = iph->daddr;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = iph->protocol;
    connection_t *conn;
    uint32_t hash_key = jhash_3words(src_ip, dst_ip, proto, 0);

    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        struct tcphdr *tcph = tcp_hdr(skb);
        src_port = ntohs(tcph->source);
        dst_port = ntohs(tcph->dest);
    }

    hash_for_each_possible(connection_table, conn, list, hash_key) {
        if (conn->src_ip == src_ip && conn->dst_ip == dst_ip && conn->src_port == src_port && conn->dst_port == dst_port && conn->proto == proto) {
            switch (proto) {
                case IPPROTO_TCP:
                    return check_tcp_state(skb, conn);
                case IPPROTO_UDP:
                    return check_udp_state(skb, conn);
                case IPPROTO_ICMP:
                    return check_icmp_state(skb, conn);
                default:
                    return NF_ACCEPT;
            }
        }
    }

    // 如果没有找到现有连接，则添加新连接
    conn = kmalloc(sizeof(connection_t), GFP_KERNEL);
    if (!conn) {
        printk(KERN_ERR "Failed to allocate memory for connection\n");
        return NF_DROP;
    }
    conn->src_ip = src_ip;
    conn->dst_ip = dst_ip;
    conn->src_port = src_port;
    conn->dst_port = dst_port;
    conn->proto = proto;
    conn->state = 0;
    conn->last_seen = jiffies;
    hash_add(connection_table, &conn->list, hash_key);
    printk(KERN_INFO "New connection added: src_ip=%pI4, dst_ip=%pI4, src_port=%u, dst_port=%u, proto=%u\n",
           &conn->src_ip, &conn->dst_ip, conn->src_port, conn->dst_port, conn->proto);

    switch (proto) {
        case IPPROTO_TCP:
            return check_tcp_state(skb, conn);
        case IPPROTO_UDP:
            return check_udp_state(skb, conn);
        case IPPROTO_ICMP:
            return check_icmp_state(skb, conn);
        default:
            return NF_ACCEPT;
    }
}

// 超时检测函数
void timeout_check(struct timer_list *t) {
    int bkt;
    connection_t *conn;
    struct hlist_node *tmp;
    unsigned long now = jiffies;

    hash_for_each_safe(connection_table, bkt, tmp, conn, list) {
        if (time_after(now, (unsigned long)conn->last_seen + TIMEOUT_INTERVAL)) {
            hash_del(&conn->list);
            kfree(conn);
        }
    }

    // 重新启动定时器
    mod_timer(&timeout_timer, jiffies + TIMEOUT_INTERVAL);
}

// 打印连接表的函数

void print_connection_table(void) {
    struct file *file;
    int bkt;
    connection_t *conn;
    size_t offset = 0;
    loff_t pos = 0;
    mm_segment_t old_fs;

    // 计算缓冲区大小
    buffer_size = 0;
    hash_for_each(connection_table, bkt, conn, list) {
        buffer_size += snprintf(NULL, 0, "src_ip=%pI4, dst_ip=%pI4, src_port=%u, dst_port=%u, proto=%u, state=%d, last_seen=%lu\n",
                                &conn->src_ip, &conn->dst_ip, conn->src_port, conn->dst_port, conn->proto, conn->state, conn->last_seen);
    }
    printk(KERN_INFO "Buffer size: %zu\n", buffer_size);

    // 分配缓冲区
    buffer = kmalloc(buffer_size + 1, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate memory for buffer\n");
        return;
    }

    // 填充缓冲区
    hash_for_each(connection_table, bkt, conn, list) {
        offset += snprintf(buffer + offset, buffer_size - offset + 1, "src_ip=%pI4, dst_ip=%pI4, src_port=%u, dst_port=%u, proto=%u, state=%d, last_seen=%lu\n",
                           &conn->src_ip, &conn->dst_ip, conn->src_port, conn->dst_port, conn->proto, conn->state, conn->last_seen);
    }

    // 打开文件
    file = filp_open("/tmp/connection_table", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open /tmp/connection_table\n");
        kfree(buffer);
        return;
    }

    // 写入文件
    kernel_write(file, buffer, buffer_size, &pos);

    // 关闭文件
    filp_close(file, NULL);

    // 释放缓冲区
    kfree(buffer);
}

// 状态检测初始化函数
int stateful_firewall_init(void) {
    printk(KERN_INFO "Initializing Stateful Firewall\n");

    // 初始化连接表
    hash_init(connection_table);

    // 初始化定时器
    timer_setup(&timeout_timer, timeout_check, 0);
    mod_timer(&timeout_timer, jiffies + TIMEOUT_INTERVAL);

    return 0;
}

// 状态检测退出函数
void stateful_firewall_exit(void) {
    int bkt;
    connection_t *conn;
    struct hlist_node *tmp;

    printk(KERN_INFO "Exiting Stateful Firewall\n");

    // 删除定时器
    del_timer_sync(&timeout_timer);

    // 清理连接表
    hash_for_each_safe(connection_table, bkt, tmp, conn, list) {
        hash_del(&conn->list);
        kfree(conn);
    }

    // 释放缓冲区
    if (buffer) {
        kfree(buffer);
        buffer = NULL;
    }

    printk(KERN_INFO "Stateful Firewall exited successfully\n");
}

const char* get_protocol_type(uint8_t proto) {
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