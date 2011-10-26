#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/skbuff.h>
#include<linux/in.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<linux/icmp.h>
#include<linux/netdevice.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/if_arp.h>
#include<linux/if_ether.h>
#include<linux/if_packet.h>

char *  LOG_IP= "\xc0\xa8\x01\x01";
MODULE_LICENSE("GPL");
/*structure used to register our hook function */
struct nf_hook_ops myhook;

int count,count2,count_UDP;

/*hook function itself */
unsigned int my_func(unsigned int hooknum,struct sk_buff *skb,const struct net_device * in, const struct net_device * out,int (*okfn)(struct sk_buff*));

/* module initialisation */
int init_module(){
  myhook.hook=my_func;
  myhook.hooknum=NF_INET_PRE_ROUTING;
  myhook.pf=PF_INET;
  myhook.priority=NF_IP_PRI_FIRST;
  nf_register_hook(&myhook);
  printk("done registering the module\n");
  printk("%pI4\n",LOG_IP);
  return 0;
}


unsigned int my_func(unsigned int hooknum,struct sk_buff *skb,const struct net_device * in, const struct net_device * out,int (*okfn)(struct sk_buff*)){
  struct  iphdr * ih;
  struct udphdr * udp_header;
  
  
  ih=((struct iphdr *)skb_network_header(skb));

  if(!skb)
    return NF_ACCEPT;

  if(ih->saddr == *LOG_IP){
    printk("Caught a packet from the router\n");
    count ++;
    return NF_ACCEPT;
  }
  else if (ih->protocol==17){
    udp_header=(struct udphdr*)skb_transport_header(skb);
    printk("%d\n",udp_header->source);
    if(udp_header->source==67||udp_header->source==68)
      printk("Found a DHCP Packet");
    printk("Caught a UDP packet\n");
    printk("source:%pI4\n",&(((struct iphdr *)skb_network_header(skb))->saddr));  
    printk("dest:%pI4\n",&(((struct iphdr *)skb_network_header(skb))->daddr));  
    count_UDP++;
    return NF_ACCEPT;
  }

  else
    return NF_ACCEPT;
}


void cleanup_module(){
  nf_unregister_hook(&myhook);
  printk("count:%d\nCleaning up module",count);
}


