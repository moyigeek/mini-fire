#ifndef STATEFUL_CHECK_H
#define STATEFUL_CHECK_H

#include <linux/types.h>       // 包含 uint32_t, uint16_t, uint8_t 类型
#include <linux/list.h>        // 包含 list_head 类型
#include <linux/jhash.h>       // 包含 jhash 函数
#include <linux/skbuff.h>      // 包含 sk_buff 类型
#include <linux/timer.h>       // 包含 timer_list 类型
#include <linux/hashtable.h>   // 包含 DEFINE_HASHTABLE 宏

typedef struct connection_t {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    int state;
    unsigned long last_seen;
    struct hlist_node list;
} connection_t;

extern struct hlist_head connection_table[1 << 16]; // 声明连接表

int stateful_firewall_check(struct sk_buff *skb, int direction);
int stateful_firewall_init(void);
void stateful_firewall_exit(void);
void print_connnection_table(void);
const char *get_protocol_type(uint8_t proto);
#endif // STATEFUL_CHECK_H