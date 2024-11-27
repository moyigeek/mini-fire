#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ctype.h>
#include <linux/icmp.h> // Include for ICMP handling
#include <linux/inet.h> // Include for in_aton
#include "rule_filter.h"
#include "stateful_check.h"
#include "log.h" // Include for logging

#define NIPQUAD(addr)                \
    ((unsigned char *)&addr)[3],     \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

LIST_HEAD(rule_list);
int default_action = ACTION_ACCEPT;

char rule_file_path[256] = "/home/moyi/ws/module/net_rule.csv";

static int read_line(char *buf, loff_t *offset, struct file *file)
{
    char ch;
    int i = 0;
    ssize_t ret;

    while (i < 255)
    {
        ret = kernel_read(file, &ch, 1, offset);
        if (ret != 1)
            return -1;
        if (ch == '\n' || ch == '\r')
        {
            if (i == 0) // Skip empty lines
                continue;
            break;
        }
        buf[i++] = ch;
    }
    buf[i] = '\0';

    log_message(LOG_INFO, "Read line: %s", buf); // Debug print
    return 0;
}

static int parse_rule(char *line, firewall_rule_t *rule)
{
    char *token;
    unsigned int temp;

    log_message(LOG_INFO, "Parsing line: %s", line); // Debug print
    printk(KERN_INFO "Parsing line: %s\n", line);    // Debug print

    // Parse source IP address
    token = strsep(&line, ",");
    rule->src_ip = token && *token ? in_aton(token) : 0;

    // Parse destination IP address
    token = strsep(&line, ",");
    rule->dst_ip = token && *token ? in_aton(token) : 0;

    // Parse source port
    token = strsep(&line, ",");
    rule->src_port = token && *token ? (uint16_t)kstrtouint(token, 0, &temp) ? 0 : temp : 0;

    // Parse destination port
    token = strsep(&line, ",");
    rule->dst_port = token && *token ? (uint16_t)kstrtouint(token, 0, &temp) ? 0 : temp : 0;

    // Parse protocol
    token = strsep(&line, ",");
    rule->proto = token && *token ? (uint8_t)kstrtouint(token, 0, &temp) ? 0 : temp : 0;

    // Parse flow direction
    token = strsep(&line, ",");
    rule->flow_direction = token && *token ? kstrtoint(token, 0, &rule->flow_direction) ? 0 : rule->flow_direction : 0;

    // Parse action
    token = strsep(&line, ",");
    if (token && *token)
    {
        if (kstrtoint(token, 0, &rule->action))
        {
            return -1; // Invalid action
        }
    }
    else
    {
        rule->action = 0;
    }

    // Parse log
    token = strsep(&line, ",");
    rule->log = token && *token ? kstrtoint(token, 0, &rule->log) ? 0 : rule->log : 0;

    log_message(LOG_INFO, "Parsed rule: src_ip=%pI4, dst_ip=%pI4, src_port=%u, dst_port=%u, proto=%u, direction=%d, action=%d, log=%d",
                &rule->src_ip, &rule->dst_ip, rule->src_port, rule->dst_port, rule->proto, rule->flow_direction, rule->action, rule->log); // Debug print
    printk(KERN_INFO "Parsed rule: src_ip=%pI4, dst_ip=%pI4, src_port=%u, dst_port=%u, proto=%u, direction=%d, action=%d, log=%d\n",
           &rule->src_ip, &rule->dst_ip, rule->src_port, rule->dst_port, rule->proto, rule->flow_direction, rule->action, rule->log); // Debug print

    return 0;
}

static int load_rules(void)
{
    struct file *file;
    loff_t pos = 0;
    char *buf;
    int ret;
    firewall_rule_t *rule;
    int i = 0;

    file = filp_open(rule_file_path, O_RDONLY, 0);
    if (IS_ERR(file))
    {
        log_message(LOG_WARN, "Failed to open rule file");
        return PTR_ERR(file);
    }

    buf = kmalloc(256, GFP_KERNEL);
    if (!buf)
    {
        filp_close(file, NULL);
        return -ENOMEM;
    }

    // Skip the header line
    if (read_line(buf, &pos, file) != 0)
    {
        log_message(LOG_WARN, "Failed to read header line");
        kfree(buf);
        filp_close(file, NULL);
        return -EIO;
    }

    while (read_line(buf, &pos, file) == 0)
    {
        log_message(LOG_INFO, "Processing line: %s", buf); // Debug print
        printk(KERN_INFO "Processing line: %s\n", buf);    // Debug print
        rule = kmalloc(sizeof(firewall_rule_t), GFP_KERNEL);
        if (!rule)
        {
            kfree(buf);
            filp_close(file, NULL);
            return -ENOMEM;
        }

        ret = parse_rule(buf, rule);
        if (ret)
        {
            kfree(rule);
            continue;
        }

        list_add(&rule->list, &rule_list);
        i++;
    }
    log_message(LOG_INFO, "Loaded %d rules", i);
    printk(KERN_INFO "Loaded %d rules\n", i);
    kfree(buf);
    filp_close(file, NULL);
    return 0;
}

static int apply_rule(struct sk_buff *skb, int direction)
{
    struct iphdr *iph = ip_hdr(skb);
    struct firewall_rule *rule;
    uint32_t src_ip = iph->saddr;
    uint32_t dst_ip = iph->daddr;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = iph->protocol;
    char src_ip_str[16], dst_ip_str[16];

    snprintf(src_ip_str, 16, "%pI4", &src_ip);
    snprintf(dst_ip_str, 16, "%pI4", &dst_ip);
    if (proto == IPPROTO_TCP || proto == IPPROTO_UDP)
    {
        struct tcphdr *tcph = tcp_hdr(skb);
        src_port = ntohs(tcph->source);
        dst_port = ntohs(tcph->dest);
    }

    list_for_each_entry(rule, &rule_list, list)
    {
        if ((rule->src_ip == 0 || rule->src_ip == src_ip) &&
            (rule->dst_ip == 0 || rule->dst_ip == dst_ip) &&
            (rule->src_port == 0 || rule->src_port == src_port) &&
            (rule->dst_port == 0 || rule->dst_port == dst_port) &&
            (rule->proto == proto||rule->proto==0) && rule->flow_direction == direction)
        {
            if (rule->log)
            {
                log_message(LOG_INFO, "Logging packet from %s to %s", src_ip_str, dst_ip_str);
                // printk(KERN_INFO "Logging packet from %s to %s\n", src_ip_str, dst_ip_str);
            }
            switch (rule->action)
            {
            case ACTION_ACCEPT:
                // log_message(LOG_INFO, "Accepting packet from %s to %s", src_ip_str, dst_ip_str);
                // printk(KERN_INFO "Accepting packet from %s to %s\n", src_ip_str, dst_ip_str);
                return stateful_firewall_check(skb, direction);
            case ACTION_DROP:
                log_message(LOG_WARN, "Dropping packet from %s to %s", src_ip_str, dst_ip_str);
                // printk(KERN_INFO "Dropping packet from %s to %s\n", src_ip_str, dst_ip_str);
                return NF_DROP;
            }
        }
    }
    // 默认动作处理
    switch (default_action)
    {
    // case ACTION_ACCEPT:
    //     log_message(LOG_INFO, "Default action: Accepting packet from %s to %s", src_ip_str, dst_ip_str);
    //     printk(KERN_INFO "Default action: Accepting packet from %s to %s\n", src_ip_str, dst_ip_str);
        return stateful_firewall_check(skb, direction);
    case ACTION_DROP:
        // log_message(LOG_INFO, "Default action: Dropping packet from %s to %s", src_ip_str, dst_ip_str);
        // printk(KERN_INFO "Default action: Dropping packet from %s to %s\n", src_ip_str, dst_ip_str);
        return NF_DROP;
    default:
        return stateful_firewall_check(skb, direction);
    }
}

unsigned int rule_filter_apply_inbound(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return apply_rule(skb, FLOW_INBOUND);
}

unsigned int rule_filter_apply_outbound(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    return apply_rule(skb, FLOW_OUTBOUND);
}

int rule_filter_load_rules(void)
{
    return load_rules();
}

void change_rule_file_path(char *path)
{
    strcpy(rule_file_path, path);
}

void switch_default_action()
{
    default_action = default_action == ACTION_ACCEPT ? ACTION_DROP : ACTION_ACCEPT;
    log_message(LOG_INFO, "Default action switched to %s", default_action == ACTION_ACCEPT ? "ACCEPT" : "DROP");
    printk(KERN_INFO "Default action switched to %s\n", default_action == ACTION_ACCEPT ? "ACCEPT" : "DROP");
}