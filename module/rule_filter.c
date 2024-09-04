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
#include "rule_filter.h"

#define NIPQUAD(addr)                \
    ((unsigned char *)&addr)[0],     \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

LIST_HEAD(rule_list);

static int read_line(char *buf, loff_t *offset, struct file *file)
{
    char ch;
    int i = 0;

    while (i < 255)
    {
        if (kernel_read(file, &ch, 1, offset) != 1)
            return -1;
        if (ch == '\n' || ch == '\r')
            break;
        buf[i++] = ch;
    }
    buf[i] = '\0';
    (*offset)++;

    printk(KERN_INFO "Read line: %s\n", buf); // Debug print
    return 0;
}

static int parse_rule(char *line, firewall_rule_t *rule)
{
    char *token;
    unsigned int temp;

    printk(KERN_INFO "Parsing line: %s\n", line); // Debug print

    token = strsep(&line, ",");
    if (!token || *token == '\0')
    {
        rule->src_ip = 0;
    }
    else if (kstrtouint(token, 0, &rule->src_ip))
    {
        printk(KERN_ALERT "Failed to parse src_ip\n"); // Debug print
        return -1;
    }

    token = strsep(&line, ",");
    if (!token || *token == '\0')
    {
        rule->dst_ip = 0;
    }
    else if (kstrtouint(token, 0, &rule->dst_ip))
    {
        printk(KERN_ALERT "Failed to parse dst_ip\n"); // Debug print
        return -1;
    }

    token = strsep(&line, ",");
    if (!token || *token == '\0')
    {
        rule->src_port = 0;
    }
    else if (kstrtouint(token, 0, &temp))
    {
        printk(KERN_ALERT "Failed to parse src_port\n"); // Debug print
        return -1;
    }
    else
    {
        rule->src_port = (uint16_t)temp;
    }

    token = strsep(&line, ",");
    if (!token || *token == '\0')
    {
        rule->dst_port = 0;
    }
    else if (kstrtouint(token, 0, &temp))
    {
        printk(KERN_ALERT "Failed to parse dst_port\n"); // Debug print
        return -1;
    }
    else
    {
        rule->dst_port = (uint16_t)temp;
    }

    token = strsep(&line, ",");
    if (!token || *token == '\0')
    {
        rule->proto = 0;
    }
    else if (kstrtouint(token, 0, &temp))
    {
        printk(KERN_ALERT "Failed to parse proto\n"); // Debug print
        return -1;
    }
    else
    {
        rule->proto = (uint8_t)temp;
    }

    token = strsep(&line, ",");
    if (!token || *token == '\0')
    {
        rule->flow_direction = 0;
    }
    else if (kstrtoint(token, 0, &rule->flow_direction))
    {
        printk(KERN_ALERT "Failed to parse flow_direction\n"); // Debug print
        return -1;
    }

    token = strsep(&line, ",");
    if (!token || *token == '\0')
    {
        rule->action = 0;
    }
    else if (kstrtoint(token, 0, &rule->action))
    {
        printk(KERN_ALERT "Failed to parse action\n"); // Debug print
        return -1;
    }

    printk(KERN_INFO "Parsed rule: src_ip=%u, dst_ip=%u, src_port=%u, dst_port=%u, proto=%u, direction=%d, action=%d\n",
           rule->src_ip, rule->dst_ip, rule->src_port, rule->dst_port, rule->proto, rule->flow_direction, rule->action); // Debug print

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

    file = filp_open("/home/moyi/ws/module/net_rule.csv", O_RDONLY, 0);
    if (IS_ERR(file))
    {
        printk(KERN_ALERT "Failed to open rule file\n");
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
        printk(KERN_ALERT "Failed to read header line\n");
        kfree(buf);
        filp_close(file, NULL);
        return -EIO;
    }

    while (read_line(buf, &pos, file) == 0)
    {
        printk(KERN_INFO "Processing line: %s\n", buf); // Debug print
        rule = kmalloc(sizeof(firewall_rule_t), GFP_KERNEL);
        if (!rule)
        {
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
    printk(KERN_INFO "Loaded %d rules\n", i);
    kfree(buf);
    filp_close(file, NULL);
    return 0;
}

static int apply_rule(struct sk_buff *skb, int direction)
{
    struct iphdr *iph = ip_hdr(skb);
    struct firewall_rule *rule;
    uint32_t src_ip = ntohl(iph->saddr);
    uint32_t dst_ip = ntohl(iph->daddr);
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = iph->protocol;

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
            rule->proto == proto && rule->flow_direction == direction)
        {
            if (proto == IPPROTO_ICMP)
            {
                struct icmphdr *icmph = icmp_hdr(skb);
                if (icmph->type == ICMP_ECHO)
                {
                    printk(KERN_INFO "ICMP Echo Request from %u.%u.%u.%u to %u.%u.%u.%u\n",
                           NIPQUAD(src_ip), NIPQUAD(dst_ip));
                }
            }
            switch (rule->action)
            {
            case ACTION_ACCEPT:
                return NF_ACCEPT;
            case ACTION_DROP:
                return NF_DROP;
            case ACTION_LOG:
                printk(KERN_INFO "Packet from %u.%u.%u.%u to %u.%u.%u.%u dropped\n",
                       NIPQUAD(src_ip), NIPQUAD(dst_ip));
                return NF_ACCEPT;
            }
        }
    }
    return NF_ACCEPT;
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
