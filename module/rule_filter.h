#ifndef RULE_FILTER_H
#define RULE_FILTER_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

typedef struct firewall_rule {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    int flow_direction;
    int action;
    int log; // New field for logging
    struct list_head list;
} firewall_rule_t;
// 钩子操作结构体，用于处理入站流量
static struct nf_hook_ops firewall_in_hook = {
    .hook = NULL, // 将由模块加载时设置
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
};

// 钩子操作结构体，用于处理出站流量
static struct nf_hook_ops firewall_out_hook = {
    .hook = NULL, // 将由模块加载时设置
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};
extern struct list_head rule_list; // Declare as extern

void change_rule_file_path(char *path);
int rule_filter_load_rules(void);
unsigned int rule_filter_apply_inbound(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int rule_filter_apply_outbound(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// static int load_rules(void);
#define FLOW_INBOUND 0
#define FLOW_OUTBOUND 1

#define ACTION_ACCEPT 0
#define ACTION_DROP 1

#endif /* RULE_FILTER_H */