#ifndef NAT_H
#define NAT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>

typedef struct nat_rule {
    uint32_t orig_ip;
    uint16_t orig_port;
    uint32_t new_ip;
    uint16_t new_port;
    uint8_t proto;
    int direction; // 0 for source NAT, 1 for destination NAT
    struct list_head list;
} nat_rule_t;

extern struct list_head nat_rule_list; // Declare as extern
char* get_nat_rule_file_path(void);



int nat_load_rules(const char *path);
unsigned int nat_apply(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif /* NAT_H */