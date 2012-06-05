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

#include<linux/timer.h>

static struct timer_list my_timer;
void my_timer_callback(unsigned long data){
  printk("my_timer_callback called(%ld).\n",jiffies);
if(mod_timer(&my_timer,jiffies+msecs_to_jiffies(200))!=0){
  printk("error resetting timer"); 
}
}
int init_module(void){
  printk("Setting Up Timer Module\n");
  setup_timer(&my_timer,my_timer_callback,0);
  if(mod_timer(&my_timer,jiffies+msecs_to_jiffies(200))!=0){
    printk("Error in mod_timer\n");
  }
    return 0;
}

void cleanup_module(void){
  if(del_timer(&my_timer)!=0)
    printk("Timer still in use");
  printk("Uninstalling Timer...");
  return;
}
