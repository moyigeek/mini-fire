#include "nat.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/inet.h>

LIST_HEAD(nat_rule_list); // Define the nat_rule_list
char nat_rule_file_path[256]="/home/moyi/ws/module/nat_rule.csv";
static int parse_nat_rule(char *line, nat_rule_t *rule)
{
    char *token;
    unsigned int temp;
    int ret;

    // Parse original IP address
    token = strsep(&line, ",");
    if (token && *token) {
        ret = in4_pton(token, -1, (u8 *)&rule->orig_ip, -1, NULL);
        if (!ret) return -EINVAL;
    } else {
        rule->orig_ip = 0;
    }

    // Parse original port
    token = strsep(&line, ",");
    rule->orig_port = token && *token ? (uint16_t)kstrtouint(token, 0, &temp) ? 0 : temp : 0;

    // Parse new IP address
    token = strsep(&line, ",");
    if (token && *token) {
        ret = in4_pton(token, -1, (u8 *)&rule->new_ip, -1, NULL);
        if (!ret) return -EINVAL;
    } else {
        rule->new_ip = 0;
    }

    // Parse new port
    token = strsep(&line, ",");
    rule->new_port = token && *token ? (uint16_t)kstrtouint(token, 0, &temp) ? 0 : temp : 0;

    // Parse protocol
    token = strsep(&line, ",");
    rule->proto = token && *token ? (uint8_t)kstrtouint(token, 0, &temp) ? 0 : temp : 0;

    // Parse direction
    token = strsep(&line, ",");
    rule->direction = token && *token ? kstrtoint(token, 0, &rule->direction) ? 0 : rule->direction : 0;

    return 0;
}

int nat_load_rules(const char *path)
{
    struct file *file;
    char *buf;
    size_t buf_size = 512;
    loff_t pos = 0;
    ssize_t len;
    nat_rule_t *rule;

    file = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to open NAT rules file: %ld\n", PTR_ERR(file));
        return PTR_ERR(file);
    }

    buf = kmalloc(buf_size, GFP_KERNEL);
    if (!buf) {
        printk(KERN_ERR "Failed to allocate memory for NAT rules buffer\n");
        filp_close(file, NULL);
        return -ENOMEM;
    }

    while ((len = kernel_read(file, buf, buf_size, &pos)) > 0) {
        char *line = buf;
        while (line < buf + len) {
            char *next_line = strchr(line, '\n');
            if (next_line) {
                *next_line = '\0';
                next_line++;
            } else {
                next_line = buf + len;
            }

            rule = kmalloc(sizeof(nat_rule_t), GFP_KERNEL);
            if (!rule) {
                printk(KERN_ERR "Failed to allocate memory for NAT rule\n");
                kfree(buf);
                filp_close(file, NULL);
                return -ENOMEM;
            }

            if (parse_nat_rule(line, rule) == 0) {
                list_add_tail(&rule->list, &nat_rule_list);
            } else {
                kfree(rule);
            }

            line = next_line;
        }
    }

    kfree(buf);
    filp_close(file, NULL);

    return 0;
}

unsigned int nat_apply(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph;
    struct udphdr *udph;
    nat_rule_t *rule;
    uint16_t port = 0;

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        port = ntohs(tcph->source);
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        port = ntohs(udph->source);
    }

    list_for_each_entry(rule, &nat_rule_list, list) {
        if (rule->proto == iph->protocol) {
            if (rule->direction == 0) { // Source NAT
                if (rule->orig_ip == iph->saddr && rule->orig_port == port) {
                    iph->saddr = rule->new_ip;
                    if (iph->protocol == IPPROTO_TCP) {
                        tcph->source = htons(rule->new_port);
                    } else if (iph->protocol == IPPROTO_UDP) {
                        udph->source = htons(rule->new_port);
                    }
                    break;
                }
            } else if (rule->direction == 1) { // Destination NAT
                if (rule->orig_ip == iph->daddr && rule->orig_port == port) {
                    iph->daddr = rule->new_ip;
                    if (iph->protocol == IPPROTO_TCP) {
                        tcph->dest = htons(rule->new_port);
                    } else if (iph->protocol == IPPROTO_UDP) {
                        udph->dest = htons(rule->new_port);
                    }
                    break;
                }
            }
        }
    }

    return NF_ACCEPT;
}

char *get_nat_rule_file_path(void)
{
    return nat_rule_file_path;
}