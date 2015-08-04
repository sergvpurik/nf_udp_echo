/**
 * Netfilter UDP echo kernel module.
 * For echo port configuration writes comma-separated ports into file /proc/nf_udp_echo/ports
 */


#include "nf_udp_echo.h"

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */

#include <linux/timer.h>
#include <linux/jiffies.h>

#include <linux/types.h>         //u_int && co
#include <linux/skbuff.h>        //struct sk_buff
#include <linux/in.h>            //basic internet

#include <linux/if_ether.h>      //protocol headers
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/if_packet.h>

#include <net/checksum.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netdevice.h>     //struct net_device

#include <linux/string.h>
#include <linux/types.h>
#include <linux/timex.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Send UDP packets back to source");
MODULE_AUTHOR("Sergey Purik <sergvpurik [at] ukr [dot] net>");

const char * MODULE_NAME = NF_UDP_ECHO_MODULE_NAME;

/**
 * Zero-terminated port sequence in network byte order.
 */
static __u16 echo_ports[UDP_ECHO_MAX_PORTS + 1] = { 0 };

/**
 * Creates string of comma-separated ports representation
 */
size_t get_ports(char * buff, size_t buff_size)
{
    *buff = 0;

    char * p = buff;
    int left = buff_size;
    for (size_t i = 0; i <= UDP_ECHO_MAX_PORTS && echo_ports[i] != 0 && left > 0; ++i)
    {
        int n = snprintf(p, left, "%hu,", ntohs(echo_ports[i]));
        left -= n;
        p += n;
    }

    // replace last char (must be ',' as defined in format of snprintf)  with '\n'
    if (p != buff)
    {
        *(p - 1) = '\n';
    }
    return 0;
}

/**
 * Parse port values form input comma-separated string and save its.
 */
void set_ports(const char * data)
{
	size_t j = 0; // index for insert

        int new_ports[UDP_ECHO_MAX_PORTS + 1] = { 0 };

        // parse comma-separated ports sequence
	get_options(data, (UDP_ECHO_MAX_PORTS + 1), new_ports);

	// store new port values
	for (size_t i = 1; i <= new_ports[0] && j < UDP_ECHO_MAX_PORTS; ++i)
	{
		// check port value
		if (new_ports[i] > 0 && new_ports[i] <= 0x0FFFF)
		{
			__u16 new_port = new_ports[i];
			echo_ports[j++] = htons(new_port); // convert to network byte order
			printk(KERN_INFO "%s %s new port[%zu] %hu\n", MODULE_NAME,
					__FUNCTION__, i, new_port);
		}
	}
	echo_ports[j] = 0; // set termination ZERO
	printk(KERN_INFO "%s %s ports number %zu\n", MODULE_NAME,
                        __FUNCTION__, j);
}

static inline bool is_echo_port(const __u16 value)
{
	for (size_t i = 0; echo_ports[i] != 0; ++i)
	{
		if (echo_ports[i] == value)
			return true;
	}
	return false;
}

#if UDP_ECHO_FEATURE_STATUS

static unsigned int count_ok = 0;
static unsigned int count_drop = 0;
static unsigned int count_cn = 0;
static unsigned int count_policed = 0;
static unsigned int count_err = 0;

void reset_status(void)
{
        count_ok = count_drop = count_cn = count_policed = count_err = 0;
}

size_t get_status(char * buff, size_t buff_size)
{
	*buff = 0;
	size_t len = snprintf(buff, buff_size,
                        "TX status: ok %u, drop %u, cn %u, policed %u, err %u\n",
                        count_ok, count_drop, count_cn, count_policed, count_err);

	if (len > buff_size)
	{
		len = buff_size;
	}

	return len;
}

static inline void print_stat(void)
{
        printk("%s TX status: ok %u, drop %u, cn %u, policed %u, err %u\n",
                        MODULE_NAME, count_ok, count_drop, count_cn, count_policed, count_err);
}

#endif // UDP_ECHO_FEATURE_STATUS

static inline int do_echo_udp(struct sk_buff *skb)
{
#if UDP_ECHO_FEATURE_STATUS
	int rc;
#endif // UDP_ECHO_FEATURE_STATUS

	struct ethhdr *ethh = eth_hdr(skb);
	struct iphdr *iph = ip_hdr(skb);
	struct udphdr *udph = udp_hdr(skb);
	register __u32 temp_addr;
	register __u16 temp_port;

#if DEBUG_MODULE
	char buf1[32];
	char buf2[32];
	char buf3[32];
	memset(buf1, 0, 32);
	memset(buf2, 0, 32);
	memset(buf3, 0, 32);

	if (ethh)
	{
		sysfs_format_mac(buf1, ethh->h_source, ETH_ALEN);
		sysfs_format_mac(buf2, ethh->h_dest, ETH_ALEN);
		sysfs_format_mac(buf3, skb->dev->dev_addr, ETH_ALEN);
		//sysfs_format_mac(buf3, skb->dev->perm_addr, ETH_ALEN);

        printk("...ethernet at [%zd]\n...src %s...dst %s...dev %s",
				(u8 *)ethh - (u8 *)skb->data, buf1, buf2, buf3);
	}
	else
	{
		printk("...ethernet header is NULL\n");
	}
#endif

	// check packet
        if (is_echo_port(udph->dest))
	{
#if DEBUG_MODULE
        printk("... udp at [%zd]: %hu -> %hu len %hu\n", (char*) udph - (char*) iph,
				ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len));
#endif

		// set destination MAC to source MAC
		// set source MAC to our Ethernet MAC
		memcpy(ethh->h_dest, ethh->h_source, ETH_ALEN);
		memcpy(ethh->h_source, skb->dev->dev_addr, ETH_ALEN);

		// swap IP addresses
		temp_addr = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = temp_addr;
		//iph->check = 0;
		//csum_replace4(&iph->check, iph->saddr, iph->daddr);
		//csum_replace4(&iph->check, iph->daddr, iph->saddr);

		// swap UDP ports
		temp_port = udph->source;
		udph->source = udph->dest;
		udph->dest = temp_port;
		//udph->check = 0;

		// set skb->data to point on Ethernet header
		skb_push(skb, skb->data - (unsigned char*) ethh);

		// in case NF_INET_LOCAL_IN
		skb->pkt_type = PACKET_OUTGOING;
		skb_dst_drop(skb);

#if !UDP_ECHO_FEATURE_STATUS
		if (dev_queue_xmit(skb) == NET_XMIT_SUCCESS)
		{
			return NF_STOLEN;
		}
#else
		rc = dev_queue_xmit(skb);
		if (rc == NET_XMIT_SUCCESS)
		{
			++count_ok;
			return NF_STOLEN;
		}
		else if (rc == NET_XMIT_DROP)
		{
			++count_drop;
		}
		else if (rc == NET_XMIT_CN)
		{
			++count_cn;
		}
		else if (rc == NET_XMIT_POLICED)
		{
			++count_policed;
		}
		else
		{
			++count_err;
		}
#endif // UDP_ECHO_FEATURE_STATUS
		return NF_DROP;
	}

	return NF_ACCEPT;
}

/**
 * Netfilter hook-function
 */
static unsigned int udp_hook(unsigned int hooknum,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = NULL;

	if (!skb)
		return NF_ACCEPT;

	// if packet not for local host - exit from hook
	if (skb->pkt_type != PACKET_HOST)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph)
		return NF_ACCEPT;

	/* skip lo packets */
	if (iph->saddr == iph->daddr)
	{
		return NF_ACCEPT;
	}
#if DEBUG_MODULE
	printk("skb %p len %u data_len %u\n", skb, skb->len, skb->data_len);

    printk("...IP at [%zd] in %s out %s %pI4 -> %pI4 proto %hhu\n",
			(u8 *)iph - (u8 *)skb->data,
			in->name, out->name, &(iph->saddr), &(iph->daddr), iph->protocol);
#endif

	if (iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	// IP header length is offset for transport header
	skb_set_transport_header(skb,
			iph->ihl * 4 + (char*) iph - (char*) skb->data);

        return do_echo_udp(skb);
}

static struct nf_hook_ops udp_hook_ops __read_mostly =
{
    .hook = udp_hook,
    .owner = THIS_MODULE,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
};

static int __init udp_echo_init(void)
{
    int ret = 0;

    ret = proc_fs_init();
    if (ret != 0)
    {
        goto err_proc_fs_init;
    }

    ret = nf_register_hook(&udp_hook_ops);
    if (ret != 0)
    {
        goto err_nf_register_hook;
    }

    printk( KERN_INFO "%s init: success!\n", MODULE_NAME);
    return 0;

err_nf_register_hook:
    proc_fs_clear();
err_proc_fs_init:
    printk( KERN_WARNING "%s init: error!\n", MODULE_NAME);
    return ret;
}

static void __exit udp_echo_exit(void)
{
    printk("%s exit\n", MODULE_NAME);
    proc_fs_clear();
    nf_unregister_hook(&udp_hook_ops);
#if UDP_ECHO_FEATURE_STATUS
    print_stat();
#endif // UDP_ECHO_FEATURE_STATUS
}

module_init(udp_echo_init);
module_exit(udp_echo_exit);
