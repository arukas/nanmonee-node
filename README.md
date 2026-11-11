# nanmonee-node

面板 `arukas/nanmonee` 的 Go 节点 agent。它从面板拉取快照、把快照编译成 sing-box 内核配置、以内嵌方式运行内核，并把流量批次写回面板。

本仓只包含节点侧源码：`node/`（Go 模块 `nanmonee/node`）、根 `LICENSE`，以及三套固定上游补丁 `patches/sing-box-v1.14.4`、`patches/sing-quic-7e0a5869a5f4`、`patches/sing-anytls-130d2e61b889`。面板侧代码（API、安装脚本、systemd 单元、配额与订阅）留在面板仓。

## 目录

| 路径 | 内容 |
| --- | --- |
| `node/api/node/v1/` | proto 与固定工具生成的 Go 文件 |
| `node/cmd/nanmonee-node/` | agent 主程序 |
| `node/cmd/nanmonee-nodectl/` | 本机运维工具（`status`、`revoke` 等） |
| `node/internal/` | 面板客户端、gRPC 控制面、运行时、内核、流量队列、worker |
| `node/scripts/` | 源码准备、构建、proto 生成、内核测试与清单工具 |
| `node/deploy/README.md` | 按节点 ID 的安装、配置、证书与运维 |
| `patches/` | 三套上游补丁与固定校验和 |

## 版本与兼容

| 项目 | 固定值 |
| --- | --- |
| agent 版本（握手与 `User-Agent` 上报） | `0.10.0-n1` |
| 控制面 API | `nanmonee-node-v1`，端点 `/api/node/v1/{handshake,config,users,report}` |
| 内核 | sing-box `v1.14.4`（提交 `c005f35300ce76427dc285481ec5695f5b179cd2`）加本仓四份补丁 |
| QUIC 栈 | sing-quic 提交 `7e0a5869a5f49ed0a685143345dfda0448bbc708` 加两份补丁 |
| AnyTLS 会话层 | sing-anytls `v0.0.11`（`130d2e61b8895727bfed4942c535e91b246a9603`）加三份补丁 |
| 协议 | VLESS（Reality + `xtls-rprx-vision`）、Hysteria2、AnyTLS、TUIC v5 |
| 平台 | `linux/amd64`、`CGO_ENABLED=0`、`-trimpath`、`-buildvcs=false` |

兼容的面板版本：本仓源码与面板 `arukas/nanmonee` 的 `823ca5b4958458ce6dac056b08347bce58bb3e25` 快照一致，该面板提交是拆分基线。面板侧 `NodeApi` 握手会要求 Go agent 上报可解析的 `node_backend_version`，TUIC 节点最低 `0.7.0`；`0.10.0-n1` 满足全部门禁。分开维护后，面板每次改动 `/api/node/v1` 的请求或响应形状都必须与本仓同步升版并重新联调，联调结果另外记录所用面板提交。

## 构建

构建在固定 Go 镜像里进行，脚本自己校验三份上游源码与补丁，不依赖本机的 Go 工具链。需要 Docker、Python 3 和本机已安装的 [RTK](https://github.com/rtk-ai/rtk)（脚本以 `rtk` 前缀调用 `git`、`docker`、`shasum` 等命令）。

```sh
cd node
rtk ./scripts/build.sh
```

脚本会依次：克隆或复用 `.cache/` 下的三份上游源码树、核对提交、按固定顺序应用补丁、按 `patched-files.sha256` 校验每个被改文件的内容，然后用镜像 `golang@sha256:eb36c1664dd974cde625f736e02c204383deebe03977365caaec5bf49f794348` 以 `with_quic with_utls` 标签构建：

- `.build/nanmonee-node`
- `.build/nanmonee-nodectl`

`.cache/` 与 `.build/` 都是派生目录，不入库。本仓检出的两个产物 SHA-256 为：

```text
9e93c15966881d9cb85540c29bf72daf2890354e69195ca9083a97b5bd3e5d93  nanmonee-node
0aeaab1d1010dd5b9e54cc9147d397ee5a8aa82a0575560a5db00671aafdcb45  nanmonee-nodectl
```

这两份摘要与面板仓 `build-n1.json` 记录的线上产物（`0e8d4250…`、`915abd41…`）不同，原因是面板仓在 T42 改过 `node_control.proto` 的注释却没有重新生成 `node_control.pb.go`，两者在源仓本就不一致。本仓提交了重新生成的 `pb.go`，于是多出四条注释、两个二进制各改变几十字节。协议字段、序列化结果与 agent 版本 `0.10.0-n1` 均未改变；把源仓那份缺注释的 `pb.go` 放回来重建，可以逐字节复现线上基线，说明差异只来自这份生成文件。三次连续构建摘要一致。

生成 proto 与内核测试：

```sh
rtk ./scripts/generate-proto.sh   # 与已提交的 api/node/v1/*.go 逐字节一致
rtk ./scripts/test_kernels.sh     # 运行补丁自带的内核测试
```

## 清单

`node/scripts/write_manifest.py` 遍历本仓需要覆盖的目录，机械生成源码指纹，`--check` 在清单与检出不符时失败：

```sh
rtk python3 node/scripts/write_manifest.py            # 打印 JSON 映射
rtk python3 node/scripts/write_manifest.py --check MANIFEST
```

清单记录本仓提交、面板基线提交、三套固定依赖与补丁摘要、构建参数，以及两个产物的 SHA-256。面板联调结果只记录所用的面板提交，不复制面板文件指纹；面板仓里的历史 `build-*.json` 保持原样，不在本仓重写。

`build.sh` 在设置 `NANMONEE_MANIFEST` 时会先跑 `--check`，清单与当前检出不符即拒绝出包。

## 验收

从 `node/` 执行，顺序与 [拆仓指南](https://github.com/arukas/nanmonee/blob/master/docs/node-repo-split-guide.md)一致：

```sh
rtk ./scripts/build.sh
rtk ./scripts/generate-proto.sh
rtk git diff --exit-code -- api/node/v1
rtk proxy gofmt -l api cmd internal
rtk go vet -mod=readonly -tags 'with_quic with_utls' ./...
rtk go test -mod=readonly -race -count=1 -p=2 -tags 'with_quic with_utls' ./...
rtk ./scripts/test_kernels.sh
rtk python3 -m unittest discover -s scripts -p 'test_*.py'
rtk shasum -a 256 .build/nanmonee-node .build/nanmonee-nodectl
```

`gofmt` 不应列出文件；两个产物摘要应与清单一致；`generate-proto.sh` 之后 `git diff` 应为空。CI 在 `linux/amd64` runner 上跑同一套检查，只发布这次构建并校验过的产物。

## 部署

安装位置、启动配置、证书、端口、单元与回退步骤见 [node/deploy/README.md](node/deploy/README.md)。

systemd 单元模板的唯一源码仍在面板仓的 `resources/deploy/nanmonee-node@.service`，因为面板安装脚本直接嵌入它；本仓只链接回去，不复制单元或生产启动配置。节点二进制由发布流程固定版本安装到 `/opt/nanmonee-node/releases/<version>/`，`current` 指向在用版本，每个节点是独立的 `nanmonee-node@<id>.service`。

## 许可

本仓根 `LICENSE` 为 MIT，覆盖节点自有源码。三套上游补丁各自保留原许可证：sing-box 与 sing-quic 为 GPL-3.0-or-later，sing-anytls 为 MIT，随补丁放在 `patches/*/LICENSE`，其摘要由清单校验。

产物内嵌 GPL 内核，分发二进制时须同时向接收者提供可取得的对应源码和构建材料（补丁、上游提交与构建参数即本仓内容与清单记录），参照 [GPLv3 第 6 节](https://www.gnu.org/licenses/gpl-3.0.en.html#section6)。
