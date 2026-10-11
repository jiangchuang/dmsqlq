# WSL 里连本机/虚拟机达梦 —— 环境准备

> 建立：2026-10-11　｜　适用：WSL2 + Debian（默认 NAT 模式）→ Windows 本机达梦 / VMware 虚拟机达梦

## 一、为什么需要它

WSL2 默认 **NAT 模式**下有三个硬事实：

1. **`127.0.0.1` 在 WSL 里指向 WSL 自己** —— 连不上 Windows 主机的达梦。
2. Windows 本机在 WSL 眼里的地址 = **WSL 默认路由的网关**（实测 `172.20.240.1`），
   而这个地址是**每次启动动态分配**的，**重启/更新 WSL 后可能变**。
3. 连**虚拟机**则用它自己的 IP（`192.168.16.x`），从 WSL 经 NAT 出站可达。

⇒ 所以需要一个「**每次现算、永不写死**」的取值方式 —— 这就是 `dmhost()`。

## 二、安装（在 WSL 的 Debian 终端执行一次）

把 `wsl-dmhost-setup.sh` 拷到 WSL 里（两条路都行）：

```bash
# 路 A：从 Windows 侧复制（在 WSL 里执行）
cp /mnt/d/dmdbms/log/…/wsl-dmhost-setup.sh ~/       # 换成你的实际路径
# 路 B：直接粘内容 —— 在 WSL 里 vim ~/wsl-dmhost-setup.sh 然后粘贴

# 安装
bash ~/wsl-dmhost-setup.sh
```

安装后**立即生效**（不用重开）：

```bash
source ~/.bashrc
dmhost          # 应打印 Windows 主机地址
```

**下次登录会自动打印**（形如）：

```
[dmhost] Windows 主机地址: 172.20.240.1
[dmhost] 连本机达梦: dmsqlq watch -H 172.20.240.1 -P 5236 -p <口令>
[dmhost] 虚拟机环境用其自身 IP: 192.168.16.135:15236(主) / 192.168.16.133:5236(单机)
```

## 三、用法

```bash
# 连 Windows 本机的达梦（日志在 /mnt/d）
dmsqlq watch /mnt/d/dmdbms/log -a manager.exe -H "$(dmhost)" -P 5236 -p <口令>

# 连虚拟机（给虚拟机自己的 IP；端口按台账）
dmsqlq watch -H 192.168.16.135 -P 15236 -p <口令>     # 主备集群主库
dmsqlq watch -H 192.168.16.133 -P 5236  -p <口令>     # 达梦单机
```

> 虚拟机 IP 与用途一律查 `E:\vos\VM台账.md`，别凭记忆。
> ⚠️ 主备集群对外端口是 **15236**（不是 5236）。

## 四、三个必须知道的边界

| 限制 | 表现 | 处置 |
|---|---|---|
| **自动定位日志目录失效** | `dmsqlq watch` 不带路径会报「没找到」 | WSL 里**显式给路径**（如 `/mnt/d/dmdbms/log`） |
| **`-Y` 会被拦** | 目标是远端地址时拒绝切同步刷盘 | 属**预期行为**。要切刷盘到 Windows 侧用原生 exe |
| **`/mnt/*` 是 drvfs** | 轮转感知不如原生，大日志读取偏慢 | WSL 里只做**只读跟随** |

## 五、卸载

```bash
bash ~/wsl-dmhost-setup.sh --uninstall
```

只删自己那一段受管块，其它 `.bashrc` 内容不动。

## 六、关于镜像模式（mirrored）—— 现状：**不开**

实测本机条件其实满足（WSL **2.3.26.0** + Windows build **26200**），
但**不建议开**，因为本机依赖 **aTrust VPN（`10.38.64.18`）+ 深信服 iNode 终端管控** ——
这两个恰好落在镜像模式的已知风险区（VPN 兼容性冲突、流量并入 Windows 栈后触发管控策略）。

若将来要试，按此顺序（**配置级、可无损回退**）：

1. 拍快照；确认当天**不依赖内网**交付
2. 先记基线：`ip route show default`
3. `~/.wslconfig` 只开一项，**别叠加** `firewall`/`autoProxy`：
   ```ini
   [wsl2]
   networkingMode=mirrored
   ```
4. `wsl --shutdown` → 重开 →**逐项验证**：
   ① WSL 能连 `127.0.0.1:5236` ② `ip route` 出现 4 块 VMware 网卡
   ③ **aTrust 仍能连内网** ④ WSL → `192.168.16.135` 仍通
5. 任一项失败 → 删 `.wslconfig` + `wsl --shutdown` 即完全回退

（收益：WSL 里可直接用 `127.0.0.1` 连本机达梦；代价：上述风险 + 端口空间共用可能冲突。）
