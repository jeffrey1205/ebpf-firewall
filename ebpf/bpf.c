#include <stdbool.h>
#include <linux/bpf.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "bpf_helpers.h"

#define __section(NAME) \
    __attribute__((section(NAME), used))

/* 报文信息，五元组和TTL */
typedef struct
{
    __u16 flags;
    __u8 ttl;
    __u8 proto;
    __u32 dstip;
    __u32 srcip;
    __u16 sport;
    __u16 dport;
    __u32 id;
} conn;

/* 发送给用户态的报文信息 */
struct bpf_map_def __section("maps") flows_map = {
    .type = BPF_MAP_TYPE_QUEUE,
    .key_size = 0,
    .value_size = sizeof(conn),
    .max_entries = 10240,
};

/* 需要阻断的源IP地址HASH表 */
struct bpf_map_def __section("maps") saddr_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

/* 需要阻断的目的IP地址HASH表 */
struct bpf_map_def __section("maps") daddr_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};

/* 需要阻断的协议号HASH表 */
struct bpf_map_def __section("maps") proto_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8),
    .value_size = sizeof(__u32),
    .max_entries = 128,
};

/* 需要阻断的源端口号HASH表 */
struct bpf_map_def __section("maps") sport_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u32),
    .max_entries = 256,
};

/* 需要阻断的目的端口号HASH表 */
struct bpf_map_def __section("maps") dport_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u32),
    .max_entries = 256,
};

/* 动作HASH表,ID为key,动作为value, 1: pass; 0: deny */
struct bpf_map_def __section("maps") action_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 1024,
};

static __always_inline __u32 bitmap_get(void *map, const void *key)
{
    __u32 *value;
    __u32 key0 = 0;

    value = bpf_map_lookup_elem(map, key);
    if (value) // 查找到规则
    {
        return *value;
    }

    // 查找不到规则,查找是否有默认策略。如果没有证明MAP为NULL,全匹配
    return bpf_map_lookup_elem(map, &key0) ? 0 : 0XFFFFFFFF;
}

/* 过滤规则匹配:
   报文的五元组依次作为 key，分别查找对应的 eBPF Map，得到 5 个 value。
   我们将这 5个value(非NULL)进行按位与操作，得到一个 bitmap。
   这个bitmap的每个bit，就表示了对应的一条规则ID；被置位为1的 bit，表示对应的规则匹配成功。*/
static __always_inline bool rule_loolup(conn *conn)
{
    __u32 bitmap = 0xFFFFFFFF;
    __u8 *action = 0;

    bitmap &= bitmap_get(&saddr_map, &conn->srcip);
    bitmap &= bitmap_get(&daddr_map, &conn->dstip);
    bitmap &= bitmap_get(&proto_map, &conn->proto);
    if (conn->proto == IPPROTO_TCP || conn->proto == IPPROTO_UDP)
    {
        // TCP OR UDP才匹配端口号
        bitmap &= bitmap_get(&sport_map, &conn->sport);
        bitmap &= bitmap_get(&dport_map, &conn->dport);
    }

    if (bitmap != 0xFFFFFFFF) // 有匹配项
    {
        bitmap &= -bitmap; // 取优先级最高的规则ID
        conn->id = bitmap;
        action = bpf_map_lookup_elem(&action_map, &bitmap);
    }

    // 如果未查到, 默认放行
    return action ? *action : true;
}

/* Handle a packet: send its information to userspace and return whether it should be allowed */
static inline bool handle_pkt(struct __sk_buff *skb, bool egress)
{
    struct iphdr iph;
    struct tcphdr tcph;
    struct udphdr udph;
    conn c = {0};

    /* Load packet header */
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));

    // 解析IPv4报文
    if (iph.version != 4)
    {
        return true;
    }
    // 过滤掉环回接口
    if (ntohl(iph.saddr) == INADDR_LOOPBACK || ntohl(iph.daddr) == INADDR_LOOPBACK)
    {
        return true;
    }

    c.ttl = iph.ttl;
    c.proto = iph.protocol;
    c.srcip = iph.saddr;
    c.dstip = iph.daddr;

    if (iph.protocol == IPPROTO_TCP) // 解析TCP头
    {
        bpf_skb_load_bytes(skb, sizeof(struct iphdr), &tcph, sizeof(struct tcphdr));
        c.sport = tcph.source;
        c.dport = tcph.dest;
    }
    else if (iph.protocol == IPPROTO_UDP) // 解析UDP头
    {
        bpf_skb_load_bytes(skb, sizeof(struct iphdr), &udph, sizeof(struct udphdr));
        c.sport = udph.source;
        c.dport = udph.dest;
    }

    /* Check if IPs are in rule map */
    bool blocked = rule_loolup(&c);
    c.flags = egress | (!blocked << 1);

    /* Send packet info to user program to display */
    bpf_map_push_elem(&flows_map, &c, 0);

    /* Return whether it should be allowed or dropped */
    return blocked;
}

/* Ingress hook - handle incoming packets */
__section("cgroup_skb/ingress") int ingress(struct __sk_buff *skb)
{
    return (int)handle_pkt(skb, false);
}

/* Egress hook - handle outgoing packets */
__section("cgroup_skb/egress") int egress(struct __sk_buff *skb)
{
    return (int)handle_pkt(skb, true);
}

char __license[] __section("license") = "GPL";
