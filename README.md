# ms-model-ip

智网妙算基础 IPv4 & ARP 网络层模型

## 一、简介

本仓库提供一组基础网络层模型，用于在妙算仿真中实现 IPv4 转发与 ARP 地址解析，主要包含：

- IPv4 进程模型：负责 IP 报文的封装/解封装、路由选择、广播转发以及按需路由集成；
- ARP 进程模型：负责 IPv4 地址到 MAC 地址的解析与缓存管理，并与底层 MAC/桥接模块交互；
- 包与 ICI 定义：`ip_dgram_v4`、`arp_v2` 以及 IP/ARP/MAC/上层协议之间的 ICI 描述。

模型名称与实现位置：

- IPv4：`models/ipv4.pr.m` + `pycodes/ipv4/src/ipv4/*`，进程模型名为 `ipv4`；
- ARP：`models/arp.pr.m` + `pycodes/arp/src/arp/__init__.py`，进程模型名为 `arp`。

## 二、总体结构与数据流

典型分层关系如下：

上层协议（如 UDP/TCP、自定义协议） ↔ IPv4 ↔ ARP ↔ MAC/桥接 ↔ 物理链路

### 1. 上层 → IPv4 → ARP → MAC 方向

1. 上层协议通过与 IPv4 相连的流发送数据包，并附带 ICI `ip_ind`：  
   - `dest address`：目标 IPv4 地址（32 位整型）；  
   - `protocol`：IP 协议号（如 17=UDP，6=TCP）。
2. IPv4 将上层数据封装为 `ip_dgram_v4`：  
   - 在 `header` 字段中写入 `PacketHeader`（版本、TTL、协议号、源/目的地址等）；  
   - 在 `data` 字段中嵌入原始上层数据包。
3. 根据目标地址及路由表（或默认网关）计算下一跳和出接口；  
4. 通过对应接口的子进程 `ip_output_iface`，创建 ICI `ip_arp_req`，设置：  
   - `next_addr`：下一跳 IPv4 地址（32 位整型）；  
   并将 IP 报文发送给 ARP。
5. ARP 根据 `next_addr`：  
   - 若已在 ARP 缓存或全局表中存在，则直接取得 MAC 地址；  
   - 否则（非仿真效率模式）发起 ARP 请求，将后续 IP 报文暂存队列。
6. ARP 创建 ICI `ip_mac_req`，设置：  
   - `dest_addr`：目的 MAC 地址或广播地址；  
   - `protocol_type`：以太网类型（0x0800=IP，0x0806=ARP）；  
   将帧下发到 MAC/桥接模块。

### 2. MAC/桥接 → ARP → IPv4 → 上层 方向

1. MAC/桥接收到的帧通过连接流发送给 ARP：  
   - 非 ARP 帧（如 IP 数据）经 ARP 直接转发给 IPv4；  
   - ARP 帧（`arp_v2`）由 ARP 解析、更新缓存，并在需要时回复 ARP 应答。
2. IPv4 收到 `ip_dgram_v4` 报文后：  
   - 解析头部，检查 TTL、目的地址、广播地址；  
   - 目的为本机地址或广播地址时，向上交付。
3. 向上交付时，IPv4 解封装出业务数据包，并附带 ICI `ip_ind`：  
   - `src address`：源 IPv4 地址（32 位整型）；  
   - `in intf idx`：入方向接口索引（即 IP 侧输入流索引）；  
   上层协议据此获取对端 IP 与入接口信息。

## 三、IPv4 模型说明（`models/ipv4.pr.m`）

### 1. 主要功能

- 作为主机：为本机上注册的上层协议（UDP/TCP 等）发送/接收 IP 报文；
- 作为路由器：在启用路由功能时，根据本地 RIB/FIB 对 IP 报文进行转发；
- 支持多物理接口与回环接口，支持静态路由和默认网关；
- 支持按需路由协议，通过 ICI `ip_on_demand_routing_notify` 与外部路由协议进程交互；
- 简单的处理速率建模：通过“处理速率”属性控制单包处理延时。

### 2. 模型属性

IPv4 模型属性定义在 `models/ipv4.pr.m` 中，核心参数如下：

- `routing enabled`（启用路由功能，bool）  
  - `true`：节点作为路由器工作，使用 RIB/FIB 查找下一跳；  
  - `false`：仅处理本机流量；若配置了 `gateway`，对非本地目的地址统一转发给默认网关。

- `processing rate`（处理速率，int，单位 pkt/s）  
  - 控制 IPv4 对入队数据包的处理速率，内部按 `1 / processing rate` 计算每包处理延迟。

- `gateway`（默认网关，string）  
  - 可选；当未启用路由功能且目的地址非本地网络时，将所有报文转发至该网关；  
  - 网关必须位于某个物理接口子网内。

- `interfaces[]`（网络接口配置，array）  
  每个元素对应一个物理接口，与下层模块通过属性 `ip interface index` 关联。字段包括：  
  - `name`：接口名称，例如 `IF0`；  
  - `ip address`：接口 IPv4 地址，例如 `192.168.1.1`；  
  - `mask`：子网掩码，例如 `255.255.255.0`；  
  - `mtu`：MTU（字节）；  
  - `speed`：接口速率（kbps）；  
  - `routing protocols`：该接口启用的路由协议名称列表（逗号分隔，当前仅用于标记）。

- `loopback interfaces[]`（回环接口配置，array）  
  用于配置逻辑回环接口（不依赖物理链路）：  
  - `name`：接口名称，例如 `lo0`；  
  - `ip address`：回环地址，例如 `127.0.0.1`；  
  - `mask`：子网掩码，默认 `255.0.0.0`；  
  - `mtu`：默认较大，如 65536。

- `static routes[]`（静态路由表，array）  
  为路由器或多网段主机配置静态路由：  
  - `destination`：目标网络前缀，例如 `10.0.0.0/24`；  
  - `next hop`：下一跳 IPv4 地址；  
  - `metric`：路由代价；  
  所有静态路由在初始化时写入 RIB，结合直连网络一起生成 FIB。

### 3. 接口发现与初始化

在 `Init` 状态下，IPv4 完成以下操作：

- 通过 `pr_register` 在节点上注册自身，并将 `protocol` 属性设置为 `"ip"`，供上层协议发现；
- 根据当前进程的输入/输出流，结合下游模块的属性 `ip interface index` 构造接口表：  
  每个物理接口包含 IP 地址、掩码、广播地址、MTU、速率等信息；
- 可选地根据 `loopback interfaces` 创建回环接口；
- 将所有直连网络写入 RIB（`route_source = "connected"`），并结合静态路由生成 FIB。

## 四、ARP 模型说明（`models/arp.pr.m`）

### 1. 主要功能

- 维护本节点的 IPv4→MAC 地址映射表（ARP 缓存），支持学习与老化机制；
- 处理向外发送的 IP 报文，完成下一跳地址到 MAC 地址的解析；
- 解析来自 MAC/桥接模块的 ARP 请求与应答，根据需要应答或更新缓存；
- 提供“仿真效率模式”，可通过全局表直接映射 IP→MAC，跳过实际 ARP 报文过程。

### 2. 模型属性

ARP 模型属性定义在 `models/arp.pr.m` 中：

- `ip interface index`（IP 接口索引，int）  
  - 指明该 ARP 实例关联的 IPv4 接口编号；  
  - IPv4 在初始化物理接口时，会根据下游模块的该字段将接口与 ARP/MAC 关联。

- `ARP Parameters`（ARP 参数，对象）  
  仅在未启用仿真效率模式时生效：  
  - `Cache Size`：ARP 缓存最大条目数；  
  - `Response Wait Time`：等待 ARP 响应的时间；  
  - `Request Retry Limit`：ARP 请求最大重试次数；  
  - `Age Timeout`：已解析条目的老化时间；  
  - `Maximum Queue Size`：等待解析的 IP 报文队列长度上限；  
  - `Timer Granularity`：ARP 定时器粒度。

- `Simulation Efficiency`（仿真效率模式，枚举）  
  - `Disabled`：按真实 ARP 协议工作，发送 ARP 请求/响应并维护缓存；  
  - `Enabled`：启用全局 ARP 表 `_global_arp_table`，通过 IP→MAC 映射直接发送到 MAC，适用于大规模仿真场景。

### 3. 与 IPv4 / MAC 的连接

- ARP 在初始化时通过 `find_node_ip_module` / `find_node_ip_module_data` 定位本节点 IPv4 模块及其接口表；  
- 通过 `pr_discover` 查找同节点的 MAC 或桥接进程，获取 MAC 地址与模块 ID，并建立收发流索引：  
  - `instrm_from_ip_rte` / `outstrm_to_ip_rte`：与 IPv4 相连的输入/输出流；  
  - `instrm_from_mac` / `outstrm_to_mac`：与 MAC/桥接模块相连的输入/输出流；  
- 找到对应的 IPv4 接口后，将该接口的 `mac_address` 填为本地 MAC，并置 `up = True`。

## 五、数据包格式

### 1. IPv4 报文：`models/ip_dgram_v4.pkt.m`

- `header`（类型 7，指针）  
  - 指向 Python 中的 `PacketHeader` 对象，字段包括：  
    - `version`、`header_len`、`tos`、`total_len`、`packet_id`、`flags`、`frag_off`、`ttl`、`protocol`、`checksum`；  
    - `src_addr`、`dst_addr`：源/目的 IPv4 地址（32 位整型）。
- `data`（类型 5，数据包）  
  - 承载上层协议数据包。

### 2. ARP 报文：`models/arp_v2.pkt.m`

字段与经典 ARP 报文对应：

- `hardware type`：硬件类型，默认 1（以太网）；  
- `protocol type`：上层协议类型，默认 0x0800（IPv4）；  
- `hardware length`：硬件地址长度，默认 6；  
- `protocol length`：协议地址长度，默认 4；  
- `arp opcode`：操作码，1=请求，2=响应；  
- `src hw addr` / `dest hw addr`：源/目的 MAC 地址（48 位整型）；  
- `src protocol addr` / `dest protocol addr`：源/目的 IPv4 地址（32 位整型）。

## 六、ICI 定义与用法

### 1. 上层协议与 IPv4：`ip_ind`（`models/ip_ind.ici.m`）

字段：

- `dest address`（int）：目标 IPv4 地址；  
- `protocol`（int）：IP 协议号；  
- `src address`（int）：源 IPv4 地址；  
- `in intf idx`（int）：入方向接口索引。

用法约定：

- 上层 → IPv4：至少填写 `dest address` 和 `protocol`；  
- IPv4 → 上层：填写 `src address` 和 `in intf idx`，上层可忽略 `dest address`/`protocol` 或用于调试。

### 2. IPv4 与 ARP：`ip_arp_req`（`models/ip_arp_req.ici.m`）

- `next_addr`（int）：下一跳 IPv4 地址，由 `ip_output_iface` 填写；  
- `dest_addr`（int）：预留字段，目前未使用；  
- `protocol`（int）：预留字段，目前未使用。

ARP 在 `_handle_ip_packet` 中读取 `next_addr`，决定是否广播、查缓存或发起 ARP 请求。

### 3. ARP 与 MAC：`ip_mac_req`（`models/ip_mac_req.ici.m`）

- `dest_addr`（int）：目的 MAC 地址或广播地址；  
- `protocol_type`（int）：以太网类型（0x0800=IP，0x0806=ARP）；  
- `vlan_id`（int）：可选 VLAN 标识。

ARP 在 `_send_packet_to_mac` 中设置该 ICI 并下发数据包。

### 4. 按需路由通知：`ip_on_demand_routing_notify`（`models/ip_on_demand_routing_notify.ici.m`）

- `type`（int）：通知类型，取值对应：  
  - `1`：`ON_DEMAND_NOTIFY_TYPE_NEED`，IPv4 请求按需路由；  
  - `2`：`ON_DEMAND_NOTIFY_TYPE_FOUND`，路由已找到；  
  - `3`：`ON_DEMAND_NOTIFY_TYPE_FAILED`，路由查找失败；
- `dest address`（string）：目标地址字符串。

外部按需路由协议可通过 `routing.on_demand_routing_protocol_register` 注册自身，并使用该 ICI 与 IPv4 协调路由发现。

## 七、上层协议如何接入 IPv4

上层协议（例如 UDP 模型）需要完成两件事：

1. 在初始化时向 IPv4 注册协议号：

```python
from ipv4.ip_support import register_protocol

def register_udp_protocol(strm_to_ip, strm_from_ip) -> None:
    # 17 = UDP 协议号
    register_protocol(
        protocol=17,
        protocol_name="udp",
        strm_to_ip=strm_to_ip,
        strm_from_ip=strm_from_ip,
    )
```

2. 发送/接收时使用 `ip_ind` ICI：  
   - 发送：设置 `dest address` 和 `protocol`，再通过与 IPv4 的输出流发送业务数据包；  
   - 接收：从 ICI 中读取 `src address` 和 `in intf idx`，获取对端 IP 和入接口信息。

通过以上接口，模型用户可以较为方便地在妙算平台上组合 IPv4、ARP 与各类上层协议，构建完整的网络栈仿真场景。
