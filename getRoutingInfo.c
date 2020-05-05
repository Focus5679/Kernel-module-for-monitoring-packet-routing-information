//内核编程需要的头文件
#include <linux/module.h>
#include <linux/kernel.h>
//Netfilter需要的头文件
#include <linux/net.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>  
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/icmp.h>
#include <net/protocol.h>
//netlink需要的头文件
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/netlink.h>

//NIPQUAD宏便于把数字IP地址输出
#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

#define NETLINK_TEST 17         //用于自定义协议
#define MAX_PAYLOAD 1024        //最大载荷容量
#define ROUTING_INFO_LEN 100    //单个路由信息的容量

//函数声明
unsigned int kern_inet_addr(char *ip_str);
void kern_inet_ntoa(char *ip_str , unsigned int ip_num);
unsigned int getRoutingInfo(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static void nl_data_ready(struct sk_buff *skb);
int netlink_to_user(char *msg, int len);

//用于描述钩子函数信息
static struct nf_hook_ops nfho = {  
    .hook = getRoutingInfo,  
    .pf = PF_INET,  
    .hooknum =NF_INET_LOCAL_OUT ,  
    .priority = NF_IP_PRI_FIRST,
}; 
//用于描述Netlink处理函数信息
struct netlink_kernel_cfg cfg = {
    .input = nl_data_ready,
};

static struct sock *nl_sk = NULL;   //用于标记netlink
static int userpid = -1;            //用于存储用户程序的pid
static unsigned int filterip = 0;   //用于存储需要过滤的源IP，小端格式

unsigned int getRoutingInfo(void *priv, 
                    struct sk_buff *skb, 
                    const struct nf_hook_state *state){
    struct iphdr *iph=ip_hdr(skb);  //指向struct iphdr结构体
    struct tcphdr *tcph;            //指向struct tcphdr结构体
    struct udphdr *udph;            //指向struct udphdr结构体
    int header=0;
    char routingInfo[ROUTING_INFO_LEN] = {0};//用于存储路由信息
    if(ntohl(iph->saddr) == filterip){
        printk("=======equal========");
        printk("srcIP: %u.%u.%u.%u\n", NIPQUAD(iph->saddr));
        printk("dstIP: %u.%u.%u.%u\n", NIPQUAD(iph->daddr));
        if(likely(iph->protocol==IPPROTO_TCP)){
            tcph=tcp_hdr(skb);
            if(skb->len-header>0){
                printk("srcPORT:%d\n", ntohs(tcph->source));
                printk("dstPORT:%d\n", ntohs(tcph->dest));
                printk("PROTOCOL:TCP");

                sprintf(routingInfo, 
                    "srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s", 
                    NIPQUAD(iph->saddr), 
                    NIPQUAD(iph->daddr), 
                    ntohs(tcph->source), 
                    ntohs(tcph->dest), 
                    "TCP");
                netlink_to_user(routingInfo, ROUTING_INFO_LEN);
            }//判断skb是否有数据 结束
        }else if(likely(iph->protocol==IPPROTO_UDP)){
            udph=udp_hdr(skb);
            if(skb->len-header>0){
                printk("srcPORT:%d\n", ntohs(udph->source));
                printk("dstPORT:%d\n", ntohs(udph->dest));
                printk("PROTOCOL:UDP");

                sprintf(routingInfo, 
                    "srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s", 
                    NIPQUAD(iph->saddr), 
                    NIPQUAD(iph->daddr), 
                    ntohs(udph->source), 
                    ntohs(udph->dest), 
                    "UDP");
                netlink_to_user(routingInfo, ROUTING_INFO_LEN);
            }//判断skb是否有数据 结束
        }//判断传输层协议分支 结束
        printk("=====equalEnd=======");
    }//判断数据包源IP是否等于过滤IP 结束
    return NF_ACCEPT;
}
//用于给用户程序发送信息
int netlink_to_user(char *msg, int len){
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    skb = nlmsg_new(MAX_PAYLOAD, GFP_ATOMIC);
    if(!skb){
        printk(KERN_ERR"Failed to alloc skb\n");
        return 0;
    }
    nlh = nlmsg_put(skb, 0, 0, 0, MAX_PAYLOAD, 0);
    printk("sk is kernel %s\n", ((int *)(nl_sk+1))[3] & 0x1 ? "TRUE" : "FALSE");
    printk("Kernel sending routing infomation to client %d.\n", userpid);
    
    //发送信息
    memcpy(NLMSG_DATA(nlh), msg, len);
    if(netlink_unicast(nl_sk, skb, userpid, 1) < 0){    //此处设置为非阻塞,防止缓冲区已满导致内核停止工作
        printk(KERN_ERR"Failed to unicast skb\n");
        userpid = -1;
        filterip = 0;
        return 0;
    }
    return 1;
}
//当有netlink接收到信息时,此函数将进行处理
static void nl_data_ready(struct sk_buff *skb){
    struct nlmsghdr *nlh = NULL;
    if(skb == NULL){
        printk("skb is NULL\n");
        return;
    }
    nlh = (struct nlmsghdr *)skb->data;
    printk("kernel received message from %d: %s\n", nlh->nlmsg_pid, (char *)NLMSG_DATA(nlh));
    
    filterip=kern_inet_addr((char *)NLMSG_DATA(nlh));
    userpid=nlh->nlmsg_pid;
}

//用于将字符串IP地址转化为小端格式的数字IP地址
unsigned int kern_inet_addr(char *ip_str){
    unsigned int val = 0, part = 0;
    int i = 0;
    char c;
    for(i=0; i<4; ++i){
        part = 0;
        while ((c=*ip_str++)!='\0' && c != '.'){
            if(c < '0' || c > '9') return -1;//字符串存在非数字
            part = part*10 + (c-'0');
        }
        if(part>255) return -1;//单部分超过255
        val = ((val << 8) | part);//以小端格式存储数字IP地址
        if(i==3){
            if(c!='\0') //  结尾存在额外字符
                return -1;
        }else{
            if(c=='\0') //  字符串过早结束
                return -1;
        }//结束非法字符串判断
    }//结束for循环
    return val;
}

//用于将数字IP地址转化为字符串IP地址
void kern_inet_ntoa(char *ip_str , unsigned int ip_num){
    unsigned char *p = (unsigned char*)(&ip_num);
    sprintf(ip_str, "%u.%u.%u.%u", p[0],p[1],p[2],p[3]);
} 

static int __init getRoutingInfo_init(void)  {  
    nf_register_net_hook(&init_net, &nfho);     //注册钩子函数
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);   //注册Netlink处理函数
    if(!nl_sk){
        printk(KERN_ERR"Failed to create nerlink socket\n");
    }
    printk("register getRoutingInfo mod\n");
    printk("Start...\n");
    return 0;  
}  
static void __exit getRoutingInfo_exit(void){  
    nf_unregister_net_hook(&init_net, &nfho);   //取消注册钩子函数
    netlink_kernel_release(nl_sk);              //取消注册Netlink处理函数
    printk("unregister getRoutingInfo mod\n");
    printk("Exit...\n");
}  

module_init(getRoutingInfo_init);  
module_exit(getRoutingInfo_exit);  
MODULE_AUTHOR("zsw");  
MODULE_LICENSE("GPL"); 