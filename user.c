#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
 
#define NETLINK_TEST 17         //用于自定义协议
#define MAX_PAYLOAD 1024        //最大载荷容量
#define RECEIVE_CNT 10          //接受路由信息的数量

int n = RECEIVE_CNT;                    //接受路由信息的数量
int sock_fd, store_fd;                   //套接字描述符, 文件描述符
struct iovec iov;                       //
struct msghdr msg;                      //存储发送的信息
struct nlmsghdr *nlh = NULL;            //用于封装信息的头部
struct sockaddr_nl src_addr, dest_addr; //源地址,目的地址(此处地址实际上就是pid)

int main(int argc, char *argv[])
{
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;        //协议族
    src_addr.nl_pid = getpid();             //本进程pid
    src_addr.nl_groups = 0;                 //多播组,0表示不加入多播组
    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
 
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;       //协议族
    dest_addr.nl_pid = 0;                   //0表示kernel的pid
    dest_addr.nl_groups = 0;                //多播组,0表示不加入多播组
     
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);  //设置缓存空间
    nlh->nlmsg_pid = getpid();                  //本进程pdi
    nlh->nlmsg_flags = 0;                       //额外说明信息

    if(argc != 2){
        printf("Usage : %s <ip>\n", argv[0]);
        exit(1);
    }
    strcpy(NLMSG_DATA(nlh), argv[1]);//将需要捞取的路由信息源地址
 
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
 
    sendmsg(sock_fd, &msg, 0);  // 发送信息到kernel
 
    // 从kernel接受信息
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    store_fd = open("./RoutingInfomation", O_CREAT|O_WRONLY, 0666);
    while(n--){
        int msgLen = recvmsg(sock_fd, &msg, 0);
        printf("Received mesage payload: %d|%s\n", msgLen, (char *)NLMSG_DATA(nlh));
        int ret = write(store_fd, (char *)NLMSG_DATA(nlh), strlen((char *)NLMSG_DATA(nlh)));
        if(ret <= 0){
            printf("write error.");
            return -1;
        }
        ret = write(store_fd, "\n", 1);
        if(ret <= 0){
            printf("write error.");
            return -1;
        }
    }
    close(store_fd);
    close(sock_fd);
    return 0;
}