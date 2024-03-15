// SPDX-License-Identifier: GPL-2.0-only
/*
 * This is the 1999 rewrite of IP Firewalling, aiming for kernel 2.3.x.
 *
 * Copyright (C) 1999 Paul `Rusty' Russell & Michael J. Neuling
 * Copyright (C) 2000-2004 Netfilter Core Team <coreteam@netfilter.org>
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/slab.h>
#include <net/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Netfilter Core Team <coreteam@netfilter.org>");
MODULE_DESCRIPTION("iptables filter table");
//HOOK点的位置： localin(input) forward localout(output)
#define FILTER_VALID_HOOKS ((1 << NF_INET_LOCAL_IN) | \
			    (1 << NF_INET_FORWARD) | \
			    (1 << NF_INET_LOCAL_OUT))

static const struct xt_table packet_filter = {
	.name		= "filter",                 //名称
	.valid_hooks	= FILTER_VALID_HOOKS,   //hook点
	.me		= THIS_MODULE,
	.af		= NFPROTO_IPV4,                 //ipv4
	.priority	= NF_IP_PRI_FILTER,         //优先级  NF_IP_PRI_FILTER=0
};

static unsigned int
iptable_filter_hook(void *priv, struct sk_buff *skb,
		    const struct nf_hook_state *state)
{
    // 遍历 filter 表
	return ipt_do_table(skb, state, priv);
}

// 主要是 filter_ops
static struct nf_hook_ops *filter_ops __read_mostly;

/* Default to forward because I got too much mail already. */
static bool forward __read_mostly = true;
module_param(forward, bool, 0000);

static int iptable_filter_table_init(struct net *net)
{
	struct ipt_replace *repl;
	int err;

	repl = ipt_alloc_initial_table(&packet_filter);
	if (repl == NULL)
		return -ENOMEM;
	/* Entry 1 is the FORWARD hook */
	((struct ipt_standard *)repl->entries)[1].target.verdict =
		forward ? -NF_ACCEPT - 1 : -NF_DROP - 1;
    // 调用 ipt_register_table 函数注册一个名为 iptable_filter 的表，
    // 并将 filter_ops 添加到 net 中。
	err = ipt_register_table(net, &packet_filter, repl, filter_ops);
	kfree(repl);
	return err;
}

// __net_init 这是一个section属性，告诉链接器将该函数放在用于网络初始化代码的特殊section中。
// 该代码将在网络子系统初始化过程开始时执行。
static int __net_init iptable_filter_net_init(struct net *net)
{
	if (!forward)
		return iptable_filter_table_init(net);

	return 0;
}

static void __net_exit iptable_filter_net_pre_exit(struct net *net)
{
	ipt_unregister_table_pre_exit(net, "filter");
}

static void __net_exit iptable_filter_net_exit(struct net *net)
{
	ipt_unregister_table_exit(net, "filter");
}

static struct pernet_operations iptable_filter_net_ops = {
	.init = iptable_filter_net_init,
	.pre_exit = iptable_filter_net_pre_exit,
	.exit = iptable_filter_net_exit,
};
// init 函数
static int __init iptable_filter_init(void)
{
    // 往 xt_templates list 中添加 packet_filter 节点, 初始化函数： iptable_filter_table_init
    // xt_templates 表的目的是 为了 网络表中没有存在的话，会考虑遍历 xt_templates
	int ret = xt_register_template(&packet_filter,
				       iptable_filter_table_init);

	if (ret < 0)
		return ret;
    // xt_hook_ops_alloc 函数是为新表创建一个hook函数
    // packet_filter 是 new table，这里的表代表的是 netfilter 中的四表五链的表
    // iptable_filter_hook 是 hook 函数
	filter_ops = xt_hook_ops_alloc(&packet_filter, iptable_filter_hook);
	if (IS_ERR(filter_ops)) {
		xt_unregister_template(&packet_filter);
		return PTR_ERR(filter_ops);
	}

	ret = register_pernet_subsys(&iptable_filter_net_ops);
	if (ret < 0) {
		xt_unregister_template(&packet_filter);
		kfree(filter_ops);
		return ret;
	}

	return 0;
}

static void __exit iptable_filter_fini(void)
{
	unregister_pernet_subsys(&iptable_filter_net_ops);
	xt_unregister_template(&packet_filter);
	kfree(filter_ops);
}

module_init(iptable_filter_init);
module_exit(iptable_filter_fini);
