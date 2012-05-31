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

#define MAGIC 12

char *  LOG_IP= "\x0a\x00\x02\x02";
char *  LOOP_BACK="\x7f\x00\x00\x01";
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
  struct icmphdr *icmp_header;
  unsigned int daddr;
  
  
  ih=((struct iphdr *)skb_network_header(skb));

  if(!skb)
    return NF_ACCEPT;

    printk("Caught Packet from %pI4\n",&(ih->saddr));
  //if(ih->saddr == LOG_IP){
  //printk("Caught a packet from the host\n");
  // count ++;
  // }
  //if(strcmp(ih->saddr,LOOP_BACK))
  //  return NF_ACCEPT;
  if (ih->protocol!=IPPROTO_ICMP){
    return NF_ACCEPT;
  }
  //else{
  //return NF_ACCEPT;
  //}
  
    icmp_header=icmp_hdr(skb);
    printk("Caught a ICMP packet\n");
    printk("type:%d\n",icmp_header->type);
    printk("code:%d\n",icmp_header->code);
    if(icmp_header->type==ICMP_ECHO){
      printk("Found a Echo packet from Host\n");
    }
    printk("source:%pI4\n",&(ih->saddr));  
    printk("dest:%pI4\n",&(ih->daddr));
    //Process the Pocket only if code ==MAGIC
    if(icmp_header->code==MAGIC){
      daddr=ih->saddr;
      ih->saddr=ih->daddr;
      ih->daddr=daddr;
      skb->pkt_type=PACKET_OUTGOING;
      switch(skb->dev->type){
      case ARPHRD_PPP:
	break;
      case ARPHRD_LOOPBACK:
      case ARPHRD_ETHER:
	{
	  unsigned char t_hwaddr[ETH_ALEN];
	  skb->data=(unsigned char*)skb_mac_header(skb);
	  
	  skb->len+=ETH_HLEN;
	  memcpy(t_hwaddr,((struct ethhdr*)(skb_mac_header(skb)))->h_dest,ETH_ALEN);
	  memcpy(((struct ethhdr*)(skb_mac_header(skb)))->h_dest, ((struct ethhdr*)(skb_mac_header(skb)))->h_source,ETH_ALEN);
	  memcpy(((struct ethhdr*)(skb_mac_header(skb)))->h_source, t_hwaddr, ETH_ALEN);  
	  
	  dev_queue_xmit(skb);
	  return NF_STOLEN;
	  break;
	}
      }
      
    }
    return NF_ACCEPT;
     
}


void cleanup_module(){
  nf_unregister_hook(&myhook);
  printk("count:%d\nCleaning up module\n",count);
}


