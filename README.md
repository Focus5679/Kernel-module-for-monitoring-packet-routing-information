# Kernel-module-for-monitoring-packet-routing-information
Kernel module for monitoring packet routing information
# Linnux5.0.0下，基于`Netlink`与`NetFilter`对本机数据包进行筛选监控

## 需求：

  开发一个`Linux lkm` + `app program`，由`app program`提供需要监控的源`IP`地址，内核模块根据此`IP`地址监控本机发送处与该源`IP`地址相同的所有的`packet`的5元组，源地址、目标地址、原端口、目标端口、协议，并将相关的信息传给应用程序，应用程序将该信息保存在文件中。

## 程序逻辑：

​	通信由用户程序发起，用户程序在开始时发送给内核模块一个源`IP`地址，之后用户程序将进入监听状态，内核模块将该`IP`地址以及用户程序的`pid`存下来作为目标`IP`地址和目标用户程序。之后用`Netfilter`中钩子函数判断每一个从本机发出的数据包中的源`IP`是否与目标`IP`地址相同，如果相同则钩子程序将数据包中的路由信息保存下来，通过`Netlink`发送给用户程序。用户程序接收到路由信息后，存在操作系统文件中。

## 开发/运行环境：

内核版本：Linux5.0.-37

发行版本：Ubuntu 18.04.1

## 运行日志

![image-20200326003358635](https://i.loli.net/2020/05/05/nqc1IYAkZbLpEO6.png)

## 常用命令：

```shell
#查看系统日志
cat /var/log/kern.log
#打印系统日志到控制台
tail -f /var/log/kern.log &
#查看内核版本
cat /proc/version
#安装/卸载模块
insmod [mod]
rmmod [mod]

```

## 必备知识：

1. `Linux`内核模块编程
2. `Netfilter`子系统与`hook`函数编程
3. `struct sk_buff`,`struct iphdr`,`struct tcphdr`,`struct udphdr`等网络相关结构体使用
4. `Netlink`通讯机制

## 踩坑集锦：

#### 高内核版本`Netfilter` `hook`函数注册：

在`Linux4.13`之前，注册钩子使用的函数为：

```c
nf_register_hook(reg);
```

高于`Linux4.13`版本后，注册钩子使用的函数改变成了：

```
nf_register_net_hook(&init_net, reg);
```

若希望兼容`Linux4.13`之前和之后的版本，可以这样写：

```c
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_register_net_hook(&init_net, reg)
#else
    nf_register_hook(reg)
#endif
```

#### 高内核版本hook函数原型声明：

早期`linux`内核中，`Netfilter`的`hook`函数原型为：

```c
static unsigned int sample( unsigned int hooknum,
							struct sk_buff * skb,
							const struct net_device *in,
							const struct net_device *out,
							int (*okfn) (struct sk_buff *));
```

但在高版本`linux`内核（至少4.10以上已改变），`Netfilter`的`hook`函数原型变成了：

```c
int sample_nf_hookfn(void *priv,
                     struct sk_buff *skb,
                     const struct nf_hook_state *state);
```

#### 高内核版本创建`Netlink`处理函数：

在较低版本`linux`内核（Linux2.6）中，创建`Netlink`处理函数使用：

```c
//假设nl_data_ready为处理函数
nl_sk = netlink_kernel_create(&init_net,
                              NETLINK_TEST, 
                              1,
                              nl_data_ready, 
                              NULL, 
                              HIS_MODULE);
```

高版本`linux`内核（至少3.8.13以上已经改变）中，创建`netlink`处理函数使用：

```c
struct netlink_kernel_cfg cfg = {
    .input = nl_data_ready,//该函数原型可参考内核代码，其他参数默认即可，可参考内核中的调用
};
nl_sk = netlink_kernel_create(&init_net, 
                              NETLINK_TEST, 
                              &cfg);
```

#### 消息发送后，`skb`释放问题：

当执行完`netlink_unicast`函数后`skb`不需要内核模块去释放，也不能去释放，否则会导致崩溃。因为`netlink_unicast`函数的返回不能保证用户层已经接受到消息，如果此时内核模块释放`skb`，会导致用户程序接收到一个已经释放掉的消息，当内核尝试处理此消息时会导致崩溃。内核会处理`skb`的释放，所以不会出现内存泄露问题， [这里](https://stackoverflow.com/questions/10138848/kernel-crash-when-trying-to-free-the-skb-with-nlmsg-freeskb-out)给出了详细解释。

#### 消息封装：

![img](https://i.loli.net/2020/05/05/H6AfBgvtPzOjxNe.png)

​	在封装发送到`kernel`的消息时，我们需要依次对`struct nlmsghdr`，`struct iovec`，`struct msghdr`进行封装。

​	内核模块和用户程序之间通讯与正常的使用`socket`类似，还需要封装源地址和目的地址，但需要注意此处的地址本质上是进程`pid`，而不是`IP`地址。

## 程序代码：

getRoutingInfo.c:
Makefile
user.c

## 参考资料：

[lkm编程教程](https://www.tldp.org/LDP/lkmpg/2.6/html/lkmpg.html#AEN569)

[Netfilter hook点与函数解析](https://www.cnblogs.com/codestack/p/10850642.html)

[Netfilter基础实例](https://www.jianshu.com/p/8bf6284e832b)

[Linux4.10.0版本下Netfilter实例](https://blog.csdn.net/bw_yyziq/article/details/78290715?depth_1-utm_source=distribute.pc_relevant.none-task&utm_source=distribute.pc_relevant.none-task)

[解决Linux4.13以上找不到nf_register_hook()函数的问题](https://unix.stackexchange.com/questions/413797/nf-register-hook-not-found-in-linux-kernel-4-13-rc2-and-later)

[struct sk_buff结构体详解](https://blog.csdn.net/shanshanpt/article/details/21024465)

[struct iphdr结构体详解](https://www.cnblogs.com/wanghao-boke/p/11661694.html)

[struct_tcphdr结构体详解](https://www.cnblogs.com/wanghao-boke/p/11669744.html)

[struct_udphdr结构体详解](https://www.cnblogs.com/wanghao-boke/p/11669824.html)

[kernel调试 打印IP地址](https://www.cnblogs.com/wangjq19920210/p/10331106.html)

[Linux2.6下基于Netlink的用户空间与内核空间通信](https://blog.csdn.net/zhao_h/article/details/80943226)

[Linux3.8.13下基于Netlink的用户空间与内核空间的通讯实例](https://www.cnblogs.com/D3Hunter/p/3207670.html)

[大小端问题](https://www.cnblogs.com/isAndyWu/p/10788990.html)

