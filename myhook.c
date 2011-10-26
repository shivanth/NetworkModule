#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/skbuff.h>
#include<linux/in.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/icmp.h>
#include<linux/netdevice.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/if_arp.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>

#define LOG_IP \xc0\xa8\x01\x01

/*structure used to register our hook function */
struct nf_hook_ops myhook;

/*hook function itself */
unsigned int my_func(unsigned int hooknum,struct sk_buff *skb,const struct net_device * in, const struct net_device * out,int (*okfn)(struct sk_buff*));

/* module initialisation */
int init_module(){
  myhook.hook=my_func;
  myhook.hooknum=NF_IP_PRE_ROUTING;
  myhook.pf=PF_INET;
  myhook.priority=NF_IP_PRI_FIRST;
  nf_register_hook(&myhook);
  return 0;
}
unsigned int my_func(unsigned int hooknum,struct sk_buff *skb,const struct net_device * in, const struct net_device * out,int (*okfn)(struct sk_buff*)){
  if(strcmp(in->name,LOG_IP)==0){
    printk("Caught a packet from the router");
    count ++;
    return NF_ACCEPT;
  }
  else
    return NF_ACCEPT;
}


void cleanup_module(){
  nf_unregister_hook(&myhook);
}


