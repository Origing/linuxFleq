# Linux  进程信息收集篇


在入侵检测的过程中，进程创建监控是必不可少的一点，因为攻击者的绝大多数攻击行为都是以进程的方式呈现，所以及时获取到新进程创建的信息能帮助我们快速地定位攻击行为。


### 目前大致五种方式:

- So preload ：Hook 库函数，不与内核交互，轻量但易被绕过。

- Netlink Connector ：从内核获取数据，监控系统调用，轻量，仅能直接获取 pid ，其他信息需要通过读取 /proc/<pid>/来补全。

- Audit ：从内核获取数据，监控系统调用，功能多，不只监控进程创建，获取的信息相对全面。
- Syscall hook ：从内核获取数据，监控系统调用，最接近实际系统调用，定制度高，兼容性差。
- 遍历/proc 信息: 数据收集不全,瞬时的进程信息根本无法获取。



> So preload

Preload技术是Linux系统自身支持的模块预加载技术
### 两种方法:
一种是环境变量配置(LD_PRELOAD)；另一种是文件配置：(/etc/ld.so.preload)



### TODO
1.Linux 中大部分的可执行程序是动态连接的，常用的进程启动函数execve 都在libc.so 库中；
2.Linux 提供了so preload机制，允许定义优先加载的动态连接库，可以有选择性的载入不同函数库中的相同函数 

```c++
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>

typedef ssize_t (*execve_func_t)(const char*    filename, char* const argv[], char* const envp[]);
static execve_func_t old_execve = NULL;

int execve(const char* filename, char* const argv[], char* const envp[]) {
    printf("Running hook\n");
    printf("Program executed: %s\n", filename);
    old_execve = dlsym(RTLD_NEXT, "execve");
    return old_execve(filename, argv, envp);
}
```


使用方法:
将你的重写代码,gcc 编译成so库
echo '/xxx/xx/hook.so' >> /etc/ld.so.preload
然后 写到/etc/ld.so.preload 里.


优缺点:
改动的很少，不需要动内核,


缺点:
只能影响preload 之后创建的进程,越早创建越好,跟hook一样
无法监控静态链接的程序：目前一些蠕虫木马为了降低对环境的依赖性都是用静态链接，不会加载共享库，这种情况下这种监控方式就失效了。
可以被绕过: int80h 可直接调用系统函数




重点讲:
> Netlink Connector

功能更process monitor 类似，
驱动层将事件发送到netlink 套接字，
netlink 通过socket api 发送到用户态

NetLink 使用条件:
内核 > 2.6.14
内核配置开启: cat /boot/config-$(uname -r) |egrep 'CONFIG_CONNECTOR|CONFIG_PROC_EVENTS'
![-w776](media/15779305515194/15780576787702.jpg)



https://www.cnblogs.com/LittleHann/p/6563811.html

Netlink 是一个套接字家族（socket family），它被用于内核与用户态进程以及用户态进程之间的 IPC(Inter-Process Communication，进程间通信) 通信，我们常用的 ss命令就是通过 Netlink 与内核通信获取的信息。

```c++
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * connect to netlink
 * returns netlink socket, or -1 on error
 */
static int nl_connect() //连接netlink函数
{
    int rc;
    int nl_sock;
    struct sockaddr_nl sa_nl;

    nl_sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (nl_sock == -1) {
        perror("socket");
        return -1;
    }

    sa_nl.nl_family = AF_NETLINK;
    sa_nl.nl_groups = CN_IDX_PROC;
    sa_nl.nl_pid = getpid();

    rc = bind(nl_sock, (struct sockaddr *)&sa_nl, sizeof(sa_nl));
    if (rc == -1) {
        perror("bind");
        close(nl_sock);
        return -1;
    }

    return nl_sock;
}

/*
 * subscribe on proc events (process notifications)
 */
static int set_proc_ev_listen(int nl_sock, bool enable)
{
    int rc;
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
    } nlcn_msg;

    memset(&nlcn_msg, 0, sizeof(nlcn_msg));
    nlcn_msg.nl_hdr.nlmsg_len = sizeof(nlcn_msg);
    nlcn_msg.nl_hdr.nlmsg_pid = getpid();
    nlcn_msg.nl_hdr.nlmsg_type = NLMSG_DONE;

    nlcn_msg.cn_msg.id.idx = CN_IDX_PROC;
    nlcn_msg.cn_msg.id.val = CN_VAL_PROC;
    nlcn_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);

    nlcn_msg.cn_mcast = enable ? PROC_CN_MCAST_LISTEN : PROC_CN_MCAST_IGNORE;

    rc = send(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
    if (rc == -1) {
        perror("netlink send");
        return -1;
    }

    return 0;
}

/*
 * handle a single process event
 */
static volatile bool need_exit = false;
static int handle_proc_ev(int nl_sock)
{
    int rc;
    struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;
        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
        };
    } nlcn_msg;

    while (!need_exit) {
        rc = recv(nl_sock, &nlcn_msg, sizeof(nlcn_msg), 0);
        if (rc == 0) {
            /* shutdown? */
            return 0;
        } else if (rc == -1) {
            if (errno == EINTR) continue;
            perror("netlink recv");
            return -1;
        }
        switch (nlcn_msg.proc_ev.what) {
            case PROC_EVENT_NONE:
                printf("set mcast listen ok\n");
                break;
            case PROC_EVENT_FORK:
                printf("fork: parent tid=%d pid=%d -> child tid=%d pid=%d\n",
                        nlcn_msg.proc_ev.event_data.fork.parent_pid,
                        nlcn_msg.proc_ev.event_data.fork.parent_tgid,
                        nlcn_msg.proc_ev.event_data.fork.child_pid,
                        nlcn_msg.proc_ev.event_data.fork.child_tgid);
                break;
            case PROC_EVENT_EXEC:
                printf("exec: tid=%d pid=%d\n",
                        nlcn_msg.proc_ev.event_data.exec.process_pid,
                        nlcn_msg.proc_ev.event_data.exec.process_tgid);
                break;
            case PROC_EVENT_UID:
                printf("uid change: tid=%d pid=%d from %d to %d\n",
                        nlcn_msg.proc_ev.event_data.id.process_pid,
                        nlcn_msg.proc_ev.event_data.id.process_tgid,
                        nlcn_msg.proc_ev.event_data.id.r.ruid,
                        nlcn_msg.proc_ev.event_data.id.e.euid);
                break;
            case PROC_EVENT_GID:
                printf("gid change: tid=%d pid=%d from %d to %d\n",
                        nlcn_msg.proc_ev.event_data.id.process_pid,
                        nlcn_msg.proc_ev.event_data.id.process_tgid,
                        nlcn_msg.proc_ev.event_data.id.r.rgid,
                        nlcn_msg.proc_ev.event_data.id.e.egid);
                break;
            case PROC_EVENT_EXIT:
                printf("exit: tid=%d pid=%d exit_code=%d\n",
                        nlcn_msg.proc_ev.event_data.exit.process_pid,
                        nlcn_msg.proc_ev.event_data.exit.process_tgid,
                        nlcn_msg.proc_ev.event_data.exit.exit_code);
                break;
            default:
                printf("unhandled proc event\n");
                break;
        }
    }

    return 0;
}

static void on_sigint(int unused)
{
    need_exit = true;
}

int main(int argc, const char *argv[])
{
    int nl_sock;
    int rc = EXIT_SUCCESS;

    signal(SIGINT, &on_sigint);
    siginterrupt(SIGINT, true);

    nl_sock = nl_connect();
    if (nl_sock == -1)
        exit(EXIT_FAILURE);

    rc = set_proc_ev_listen(nl_sock, true);
    if (rc == -1) {
        rc = EXIT_FAILURE;
        goto out;
    }

    rc = handle_proc_ev(nl_sock);
    if (rc == -1) {
        rc = EXIT_FAILURE;
        goto out;
    }

    set_proc_ev_listen(nl_sock, false);

out:
    close(nl_sock);
    exit(rc);
}

```

后面出一篇，netlink 获取进程id的代码解析；

优点
轻量级，在用户态即可获得内核提供的信息。

缺点
仅能获取到 pid ，详细信息需要查 /proc/<pid>/，这就存在时间差，可能有数据丢失。 个人建议采用这种方式，对系统的侵入性小些，且拿到的数据也多

> Audited 获取进程信息

通过内核态事件，
