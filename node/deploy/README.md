# Go 节点部署（按节点 ID）

N1-2 起，一台 VPS 安装一份固定版本的 `nanmonee-node`，每个节点是一个独立 systemd 实例。实例标识是面板节点 ID，不再用协议名；同一 VPS 的两个 VLESS 节点各有自己的配置、状态目录、队列、面板密钥和控制秘密。

## 目录布局

| 项目 | 路径 |
| --- | --- |
| 系统用户 | `nanmonee-node`（`--system --no-create-home`） |
| 安装根 | `/opt/nanmonee-node/`，`releases/<version>/` 与 `current` 符号链接 |
| 二进制 | `/opt/nanmonee-node/current/bin/nanmonee-node`、`nanmonee-nodectl` |
| 启动配置 | `/etc/nanmonee-node/nodes/<node-id>.json`，`nanmonee-node:nanmonee-node`、`0400` |
| 状态与队列 | `/var/lib/nanmonee-node/<node-id>/`，`0700`（`StateDirectory=nanmonee-node/%i`） |
| 单元 | `nanmonee-node@<node-id>.service`，模板 `/etc/systemd/system/nanmonee-node@.service` |
| 日志 | `journalctl -u nanmonee-node@<node-id>` |

单元以非 root 运行，只授予 `CAP_NET_BIND_SERVICE` 用于监听 1–1023 端口；`CapabilityBoundingSet` 只保留这一项，其他硬化项（`ProtectSystem=strict`、`ProtectHome=true`、空 `ExecStartPost`）保持不变。控制入口只监听 `127.0.0.1` 的 39480–39579 高端口。节点 API 为 `/api/node/v1/*`，鉴权使用 `Authorization: Bearer` 与 `X-Nanmonee-Node-Id` 请求头。

## 面板生成安装脚本

管理员在节点页打开「部署说明」，下载 `node-<id>-install.sh`，上传到目标 VPS 后以 root 执行：

```sh
scp node-12-install.sh root@rn-sea.acris.cc:/root/
ssh root@rn-sea.acris.cc sh /root/node-12-install.sh
```

脚本会：

1. 检查 `/opt/nanmonee-node/current/bin/nanmonee-node` 和 `python3` 存在；二进制由发布流程单独安装，JSON 由系统 Python 3 读写，脚本不下载依赖。
2. 缺失时创建 `nanmonee-node` 用户，创建配置目录与节点状态目录。
3. 首次执行生成 32 字节控制秘密和空闲回环端口；重复执行会复用已有秘密与端口，不轮换。
4. 写入 `/etc/nanmonee-node/nodes/<id>.json`（服务用户所有、0400），安装/刷新模板单元，`daemon-reload`，`enable` 并 `restart` 这个实例。
5. 输出服务状态；失败时打印最近 30 行日志。

脚本只包含该节点的面板地址、API 密钥、节点 ID、协议、端口和 `traffic.data_dir`。控制秘密与端口在 VPS 本机生成并只写入该配置文件，面板不保存、也不通过 SSH 读取。

systemd 单元的唯一源码仍留在面板仓的 `resources/deploy/nanmonee-node@.service`，因为面板安装脚本直接嵌入它；手工安装也用面板那份资源。本仓不复制单元或生产启动配置，只链接回[面板仓](https://github.com/arukas/nanmonee/blob/master/resources/deploy/nanmonee-node@.service)。

二进制来自本仓发布的 `linux/amd64` 产物，构建、产物摘要与版本见[本仓 README](../../README.md)。安装时把对应版本的 `nanmonee-node` 与 `nanmonee-nodectl` 放进 `/opt/nanmonee-node/releases/<version>/bin/`，再把 `current` 指过去；Actions 不直连 VPS，换版与回退都是人工按固定版本执行。

安装脚本不修改 VPS 防火墙。部署前需放行节点业务端口：VLESS/AnyTLS 为 TCP，Hysteria2/TUIC 为 UDP；控制端口始终只监听回环，无需对公网放行。N1-4 的额外 VLESS 实例曾因现有业务端口白名单被阻断，临时按 gc-tyo 来源放行后双客户端通过，验收规则随临时实例一同清理。

## 配置模板

```json
{
  "control": {"listen": "127.0.0.1:39480", "secret": "<32-256 位无空白随机串>"},
  "panel": {
    "url": "https://nanmonee.shinai.co.uk",
    "token": "<面板中该节点的 API 密钥>",
    "node_id": 12,
    "protocol": "vless"
  },
  "agent": {"backend_protocol": "nanmonee-node-v1", "kernel": "singbox"},
  "traffic": {"data_dir": "/var/lib/nanmonee-node/12"}
}
```

`protocol` 使用规范协议名：`vless`、`hysteria2`、`anytls`、`tuic`。`traffic.data_dir` 必须等于该节点的 `StateDirectory`；不同节点不能共用。

## 证书（Hysteria2 / AnyTLS / TUIC）

证书路径由面板快照下发，内核以 `nanmonee-node` 用户读取。推荐：

```sh
install -d -m 0750 -o root -g nanmonee-node /etc/nanmonee-node/tls
install -m 0444 -o root -g nanmonee-node fullchain.pem /etc/nanmonee-node/tls/fullchain.pem
install -m 0440 -o root -g nanmonee-node privkey.pem   /etc/nanmonee-node/tls/privkey.pem
```

`ProtectHome=true` 会隐藏 `/root`，证书不能放在那里。

## 运维

- 正常停止：`systemctl stop nanmonee-node@12`，进程在 `TimeoutStopSec` 内完成最后采样并尝试清空队列。
- 异常重启：`systemctl kill -s SIGKILL nanmonee-node@12`；`Restart=on-failure` 三秒后拉起，已落盘 pending 批次由启动流程补报。
- 状态：`/opt/nanmonee-node/current/bin/nanmonee-nodectl -config /etc/nanmonee-node/nodes/12.json -op status`。
- 重装/升级配置：重新执行同一 `node-12-install.sh`；复用秘密与端口，保留队列，只重启该实例。
- 配置缺失、不是普通文件或 group/other 权限位非零时，进程以可读错误退出，单元不会进入 active。
- 卸载一个节点：`systemctl disable --now nanmonee-node@12`，删除 `/etc/nanmonee-node/nodes/12.json` 与 `/var/lib/nanmonee-node/12`。删除共享二进制/用户前先确认没有其他实例。

## 与旧协议实例的关系

旧生产实例按协议命名（`nanmonee-node.service`、`nanmonee-node-hysteria2.service` 等），使用 `/etc/nanmonee-node/<protocol>.json` 和协议级状态目录。N1-2 不改动这些运行中的单元；N1-4 破坏性重建时再停用并替换为按节点 ID 的实例。
