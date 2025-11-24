import ipaddress
import logging
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional

import miaosuan as ms
from miaosuan.engine.simobj import SimObj
from miaosuan.mms.process_registry import (
    AttrType,
    ProcessAttribute,
    pr_attr_get,
    pr_attr_set,
    pr_discover,
    pr_register,
)

from ipv4.ip_support import (
    Interface,
    ModuleData,
    find_node_ip_module,
    find_node_ip_module_data,
    addr_to_uint32,
    uint32_to_addr,
    LIMITED_BROADCAST_ADDR,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 仿真效率模式的全局ARP表
# ---------------------------------------------------------------------------

# ARP条目状态
class ArpEntryStatus(IntEnum):
    FREE = 0  # 空闲
    PENDING = 1  # 等待响应
    RESOLVED = 2  # 已解析
    PERMANENT = 3  # 永久条目


# ARP协议常量
ARP_BROADCAST_ADDR = 0xFFFF_FFFF_FFFF  # 广播地址
ARP_PHYS_ADDR_UNSET = 0xFFFF_FFFF_FFFE  # 未设置的物理地址
ARP_REQ_OPCODE = 1  # ARP请求操作码
ARP_REPLY_OPCODE = 2  # ARP响应操作码
NET_PROT_IP = 0x0800  # IP协议类型
NET_PROT_ARP = 0x0806  # ARP协议类型

_global_table_lock = threading.RLock()
_global_arp_table: Dict[ipaddress.IPv4Address, int] = {}


# AddGlobalArpEntry 向全局ARP表添加条目，用于仿真效率模式
def add_global_arp_entry(ip_addr: ipaddress.IPv4Address, mac_addr: int) -> None:
    with _global_table_lock:
        _global_arp_table[ip_addr] = mac_addr


# GetGlobalArpEntry 从全局ARP表获取条目
def get_global_arp_entry(ip_addr: ipaddress.IPv4Address) -> tuple[int, bool]:
    with _global_table_lock:
        mac_addr = _global_arp_table.get(ip_addr)
        if mac_addr is None:
            return 0, False
        return mac_addr, True


# ARP队列实体
@dataclass(slots=True)
class ArpQueueEntity:
    queued_pkt: object


# ArpEntry ARP缓存条目
@dataclass(slots=True)
class ArpEntry:
    state: ArpEntryStatus
    ip_addr: ipaddress.IPv4Address
    phys_addr: int = ARP_PHYS_ADDR_UNSET
    age: float = 0.0
    num_attempts: int = 0
    queue: List[ArpQueueEntity] = field(default_factory=list)
    protocol_type: int = NET_PROT_IP
    hardware_type: int = 1


def _iter_streams(streams: Optional[Dict[int, object]]) -> List[object]:
    if not streams:
        return []
    return list(streams.values())


@ms.process_model("arp")
class ArpProcess:
    def __init__(self) -> None:
        # 基本标识符
        self.my_module: Optional[SimObj] = None
        self.my_node: Optional[SimObj] = None
        self.proc_handle = None
        self.proc_model: str = "arp"

        # 进程注册
        self.own_process_record = None

        # 与MAC层通信的ICI
        self.mac_ici = None

        # IP模块信息
        self.ip_module: Optional[SimObj] = None
        self.ip_module_data: Optional[ModuleData] = None

        # ARP配置参数
        self.arp_sim_eff: bool = False
        self.cache_max_size: int = 0
        self.arp_gran: float = 0.0
        self.wait_time: float = 0.0
        self.max_age_timeout: float = 0.0
        self.arpreq_max_retry: int = 0
        self.max_queue_size: int = 0

        # ARP缓存
        self.arp_cache: Dict[ipaddress.IPv4Address, ArpEntry] = {}

        # 硬件地址（MAC地址）
        self.hardware_addr: int = 0

        # 本地IP接口
        self.local_interface: Optional[Interface] = None

        # 流索引
        self.instrm_from_ip_rte: int = -1
        self.outstrm_to_ip_rte: int = -1
        self.instrm_from_mac: int = -1
        self.outstrm_to_mac: int = -1

        # 辅助状态
        self.ip_port_num: Optional[int] = None
        self.mac_module_id: Optional[int] = None

    # # ------------------------------------------------------------------ FSM --
    # def init(self, builder: ms.ProcessBuilder) -> None:
    #     builder.begin("Init")
    #     builder.add_state("Init", self.enter_init, self.exit_init)
    #     builder.add_state("Wait", self.enter_wait, self.exit_wait)
    #     builder.add_state("Wait0", self.enter_wait0, self.exit_wait0)
    #     builder.add_state("Wait1", self.enter_wait1, self.exit_wait1)
    #     builder.add_state("ArpTable", self.enter_arp_table, self.exit_arp_table)
    #     builder.add_state("Idle", self.enter_idle, self.exit_idle)

    #     builder.add_transition("Init", "Wait", _always_true)
    #     builder.add_transition("Wait", "Wait0", _always_true)
    #     builder.add_transition("Wait0", "Wait1", _always_true)
    #     builder.add_transition("Wait1", "ArpTable", _always_true)
    #     builder.add_transition("ArpTable", "Idle", _always_true)
    #     builder.add_transition("Idle", "Idle", _always_true)

    # --------------------------------------------------------------- States --
    @ms.state_enter("Init", begin=True)
    def enter_init(self) -> None:
        # 初始化基本标识符
        self.my_module = ms.self_obj()
        if self.my_module is None:
            raise RuntimeError("ARP: 无法获取模块对象")

        self.my_node = ms.topo_parent(self.my_module)
        if self.my_node is None:
            raise RuntimeError("ARP: 无法获取节点对象")

        self.proc_handle = ms.pro_self()
        if self.proc_handle is None:
            raise RuntimeError("ARP: 无法获取进程句柄")

        try:
            self.proc_model = self.my_module.get_attr_string("process model")
        except Exception:
            self.proc_model = "arp"

        # 注册进程
        try:
            self.own_process_record = pr_register(
                self.my_node.get_id(),
                self.my_module.get_id(),
                self.proc_handle,
                self.proc_model,
            )
        except Exception as exc:
            raise RuntimeError(f"ARP: 注册ARP进程失败: {exc}") from exc

        pr_attr_set(self.own_process_record, "protocol", AttrType.STRING, "arp")
        pr_attr_set(self.own_process_record, "location", AttrType.STRING, "mac_if")
        pr_attr_set(self.own_process_record, "module objid", AttrType.OBJ_ID, self.my_module.get_id())
        pr_attr_set(self.own_process_record, "node objid", AttrType.OBJ_ID, self.my_node.get_id())

        # 创建与MAC层通信的ICI
        try:
            self.mac_ici = ms.ici_create("ip_mac_req")
        except Exception as exc:
            raise RuntimeError(f"ARP: 无法创建MAC通信ICI: {exc}") from exc

        # 调度自中断
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_exit("Init")
    def exit_init(self) -> None:
        # 获取ARP仿真效率设置
        self.arp_sim_eff = self._get_arp_sim_efficiency()

        if not self.arp_sim_eff:
            # 初始化ARP缓存
            self.arp_cache = {}
            self.cache_max_size = self._get_attr_int("ARP Parameters.Cache Size", 512)
            self.wait_time = self._get_attr_float("ARP Parameters.Response Wait Time", 1.0)
            self.arpreq_max_retry = self._get_attr_int("ARP Parameters.Request Retry Limit", 3)
            self.max_age_timeout = self._get_attr_float("ARP Parameters.Age Timeout", 1200.0)
            self.max_queue_size = self._get_attr_int("ARP Parameters.Maximum Queue Size", 10)
            self.arp_gran = self._get_attr_float("ARP Parameters.Timer Granularity", 1.0)
            if self.arp_gran <= 0:
                self.arp_gran = 1e-6
        else:
            self.cache_max_size = 0
            self.wait_time = 0.0
            self.arpreq_max_retry = 0
            self.max_age_timeout = 0.0
            self.max_queue_size = 0
            self.arp_gran = 0.0

    @ms.state_enter("Wait")
    def enter_wait(self) -> None:
        # 等待状态入口，无特殊处理
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_enter("Wait0")
    def enter_wait0(self) -> None:
        # 调度自中断等待IP接口表完成
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_enter("Wait1")
    def enter_wait1(self) -> None:
        # 调度自中断等待IP接口表完成
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_enter("ArpTable")
    def enter_arp_table(self) -> None:
        # 调度另一个自中断以允许下层模块注册
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_exit("ArpTable")
    def exit_arp_table(self) -> None:
        # 初始化ARP
        self._arp_init()

        # 如果启用了仿真效率模式，填充全局表
        if self.arp_sim_eff:
            self._populate_global_arp_table()

        # 如果未启用仿真效率模式，启动定时器
        if not self.arp_sim_eff and self.arp_gran > 0:
            ms.intrpt_schedule_self(ms.sim_time() + self.arp_gran, 0)

    @ms.state_enter("Idle")
    def enter_idle(self) -> None:
        # 空闲状态入口，无特殊处理
        return

    @ms.state_exit("Idle")
    def exit_idle(self) -> None:
        intrpt_type = ms.intrpt_type()

        if intrpt_type == ms.INTRPT_TYPE_STRM:
            stream_index = ms.intrpt_strm()
            if stream_index == self.instrm_from_ip_rte:
                # IP数据包到达
                self._handle_ip_packet(stream_index)
            elif stream_index == self.instrm_from_mac:
                # MAC数据包到达
                self._handle_mac_packet(stream_index)
            else:
                pkt = ms.pk_get(stream_index)
                if pkt is not None:
                    ms.pk_destroy(pkt)
        elif intrpt_type == ms.INTRPT_TYPE_SELF:
            # 定时器到期
            self._handle_timer_expiry()
        elif intrpt_type == ms.INTRPT_TYPE_REMOTE:
            # 当前版本暂不处理远程中断
            return


    @ms.transition("Init", "Wait")
    def init_to_wait(self) -> bool:
        return True

    @ms.transition("Wait", "Wait0")
    def wait_to_wait0(self) -> bool:
        return True

    @ms.transition("Wait0", "Wait1")
    def wait0_to_wait1(self) -> bool:
        return True

    @ms.transition("Wait1", "ArpTable")
    def wait1_to_arp_table(self) -> bool:
        return True

    @ms.transition("ArpTable", "Idle")
    def arp_table_to_idle(self) -> bool:
        return True

    @ms.transition("Idle", "Idle")
    def idle_to_idle(self) -> bool:
        return True


    # ----------------------------------------------------------- Operations --
    def _arp_init(self) -> None:
        # 查找连接的IP模块，并初始化对应的流号
        ip_port_num = self._find_connected_ip()

        # 查找连接的MAC模块，并初始化对应的流号
        self._find_connected_mac()

        # 遍历IP接口，找到当前模块对应的接口
        if self.ip_module_data is not None and ip_port_num is not None:
            for interface in self.ip_module_data.interface_table.values():
                if interface.port_num == ip_port_num:
                    # 设置MAC地址并启用接口
                    interface.mac_address = self.hardware_addr
                    interface.up = True
                    self.local_interface = interface
                    break

        # 调度自中断继续初始化
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    def _find_connected_ip(self) -> Optional[int]:
        if self.my_node is None:
            raise RuntimeError("ARP: 缺少节点信息")

        self.ip_module = find_node_ip_module(self.my_node)
        if self.ip_module is None:
            raise RuntimeError("ARP: 无法找到IP模块")

        self.ip_module_data = find_node_ip_module_data(self.my_node)
        if self.ip_module_data is None:
            raise RuntimeError("ARP: 无法获取IP模块数据")

        out_streams = _iter_streams(ms.get_out_streams())
        in_streams = _iter_streams(ms.get_in_streams())

        self.instrm_from_ip_rte = -1
        self.outstrm_to_ip_rte = -1

        ip_module_id = self.ip_module.get_id()
        port_num: Optional[int] = None

        for stream in out_streams:
            if stream.dst and stream.dst.get_id() == ip_module_id:
                self.outstrm_to_ip_rte = stream.src_index
                port_num = stream.dst_index
                break

        for stream in in_streams:
            if stream.src and stream.src.get_id() == ip_module_id:
                self.instrm_from_ip_rte = stream.dst_index
                if port_num is not None and stream.src_index != port_num:
                    raise RuntimeError("ARP: IP模块的输入输出流索引不匹配")
                break

        if self.instrm_from_ip_rte < 0 or self.outstrm_to_ip_rte < 0 or port_num is None:
            raise RuntimeError("ARP: 无法定位与IP模块连接的流")

        self.ip_port_num = port_num
        return port_num

    def _find_connected_mac(self) -> None:
        if self.my_module is None or self.my_node is None:
            raise RuntimeError("ARP: 缺少模块或节点信息")

        attrs = [
            ProcessAttribute("node objid", AttrType.OBJ_ID, self.my_node.get_id()),
            ProcessAttribute("protocol", AttrType.STRING, "mac"),
        ]
        handles = pr_discover(self.my_module.get_id(), *attrs)

        unconnected_node = False
        mac_module_id: Optional[int] = None

        if len(handles) == 1:
            try:
                address = pr_attr_get(handles[0], "address")
                self.hardware_addr = int(address)
            except Exception as exc:
                raise RuntimeError(f"ARP: 无法读取MAC地址: {exc}") from exc
            try:
                module_id = pr_attr_get(handles[0], "module objid")
                mac_module_id = int(module_id)
            except Exception as exc:
                raise RuntimeError(f"ARP: 无法读取MAC模块ID: {exc}") from exc
        elif len(handles) == 0:
            bridge_attrs = [
                ProcessAttribute("node objid", AttrType.OBJ_ID, self.my_node.get_id()),
                ProcessAttribute("protocol", AttrType.STRING, "bridge"),
                ProcessAttribute("location", AttrType.STRING, "mac_if"),
            ]
            handles = pr_discover(self.my_module.get_id(), *bridge_attrs)
            if len(handles) > 1:
                raise RuntimeError("ARP: 连接到该ARP模块的MAC模块数量大于1")
            if len(handles) == 0:
                unconnected_node = True
            else:
                try:
                    address = pr_attr_get(handles[0], "address")
                    self.hardware_addr = int(address)
                except Exception as exc:
                    raise RuntimeError(f"ARP: 无法从桥接模块获取MAC地址: {exc}") from exc
                try:
                    module_id = pr_attr_get(handles[0], "module objid")
                    mac_module_id = int(module_id)
                except Exception as exc:
                    raise RuntimeError(f"ARP: 无法从桥接模块获取模块ID: {exc}") from exc
        else:
            raise RuntimeError("ARP: More than one MAC module connected to this ARP module")

        if unconnected_node:
            self.mac_module_id = None
            return

        if mac_module_id is None:
            raise RuntimeError("ARP: 无法解析MAC模块ID")

        self.mac_module_id = mac_module_id

        out_streams = _iter_streams(ms.get_out_streams())
        in_streams = _iter_streams(ms.get_in_streams())

        self.outstrm_to_mac = -1
        self.instrm_from_mac = -1

        for stream in out_streams:
            if stream.dst and stream.dst.get_id() == mac_module_id:
                self.outstrm_to_mac = stream.src_index
        for stream in in_streams:
            if stream.src and stream.src.get_id() == mac_module_id:
                self.instrm_from_mac = stream.dst_index

        if self.outstrm_to_mac < 0 or self.instrm_from_mac < 0:
            raise RuntimeError("ARP: 无法定位与MAC模块连接的流")

    def _populate_global_arp_table(self) -> None:
        # 为仿真效率模式填充全局ARP表
        self._register_local_interfaces()

    def _register_local_interfaces(self) -> None:
        if self.ip_module_data is None:
            return

        if self.local_interface and self.local_interface.ip_address:
            add_global_arp_entry(self.local_interface.ip_address, self.hardware_addr)
            logger.info(
                "ARP: 注册接口到全局表 IP=%s MAC=%012x",
                self.local_interface.ip_address,
                self.hardware_addr,
            )

    def _handle_ip_packet(self, stream_index: int) -> None:
        # 获取数据包和ICI
        pkt = ms.pk_get(stream_index)
        if pkt is None:
            logger.warning("ARP: 无法从IP流获取数据包")
            return

        ici = ms.intrpt_ici()
        if ici is None:
            logger.warning("ARP: 无法从IP流获取ICI")
            ms.pk_destroy(pkt)
            return

        try:
            next_addr_value = int(ici.get_int("next_addr"))
        except Exception as exc:
            logger.warning("ARP: 无法从ICI获取下一跳地址: %s", exc)
            ms.pk_destroy(pkt)
            return

        next_addr = uint32_to_addr(next_addr_value)

        # 下一跳地址如果是广播地址，则直接发送
        if self._is_broadcast(next_addr):
            self._send_packet_to_mac(pkt, ARP_BROADCAST_ADDR)
            return

        # 根据ARP仿真效率模式处理数据包
        if self.arp_sim_eff:
            self._handle_ip_packet_sim_eff(pkt, next_addr)
        else:
            self._handle_ip_packet_with_cache(pkt, next_addr)

    def _handle_ip_packet_sim_eff(self, pkt, next_addr: ipaddress.IPv4Address) -> None:
        try:
            phys_addr = self._get_phys_addr_from_global_table(next_addr)
        except LookupError:
            logger.warning("ARP: 仿真效率模式下未找到地址映射 %s", next_addr)
            ms.pk_destroy(pkt)
            return
        self._send_packet_to_mac(pkt, phys_addr)

    def _handle_ip_packet_with_cache(self, pkt, next_addr: ipaddress.IPv4Address) -> None:
        entry = self._find_arp_cache_entry(next_addr)

        if entry is not None:
            if entry.state in (ArpEntryStatus.RESOLVED, ArpEntryStatus.PERMANENT):
                if entry.state != ArpEntryStatus.PERMANENT:
                    entry.age = self.max_age_timeout
                self._send_packet_to_mac(pkt, entry.phys_addr)
            else:
                self._queue_packet_in_arp_entry(entry, pkt)
            return

        if len(self.arp_cache) >= self.cache_max_size:
            logger.warning("ARP: 缓存已满，丢弃数据包")
            ms.pk_destroy(pkt)
            return

        new_entry = ArpEntry(
            state=ArpEntryStatus.PENDING,
            ip_addr=next_addr,
            phys_addr=ARP_PHYS_ADDR_UNSET,
            age=self.wait_time,
            num_attempts=1,
            queue=[ArpQueueEntity(queued_pkt=pkt)],
        )
        self.arp_cache[next_addr] = new_entry

        logger.info("ARP: 发送ARP请求查询 %s", next_addr)
        self._broadcast_arp_request(next_addr)

    def _handle_mac_packet(self, stream_index: int) -> None:
        pkt = ms.pk_get(stream_index)
        if pkt is None:
            logger.warning("ARP: 无法从MAC流获取数据包")
            return

        pkt_format = ms.pk_format(pkt)

        if pkt_format == "lac_pdu":
            if self.outstrm_to_ip_rte >= 0:
                ms.pk_send(pkt, self.outstrm_to_ip_rte)
            else:
                ms.pk_destroy(pkt)
            return

        if self.arp_sim_eff:
            self._forward_ip_packet_to_upper(pkt)
            return

        if pkt_format == "arp_v2":
            self._process_arp_packet(pkt)
        else:
            self._forward_ip_packet_to_upper(pkt)

    def _process_arp_packet(self, pkt) -> None:
        # 验证ARP数据包的有效性
        if not self._validate_arp_packet(pkt):
            logger.warning("ARP: 收到无效的ARP数据包，丢弃")
            ms.pk_destroy(pkt)
            return

        try:
            opcode = int(ms.pk_nfd_get_int(pkt, "arp opcode"))
            src_hw_addr = int(ms.pk_nfd_get_int(pkt, "src hw addr"))
            src_proto_value = int(ms.pk_nfd_get_int(pkt, "src protocol addr"))
            dest_proto_value = int(ms.pk_nfd_get_int(pkt, "dest protocol addr"))
        except Exception as exc:
            logger.warning("ARP: 无法解析ARP数据包字段: %s", exc)
            ms.pk_destroy(pkt)
            return

        src_protocol_addr = uint32_to_addr(src_proto_value)
        dest_protocol_addr = uint32_to_addr(dest_proto_value)

        # 更新源地址的ARP缓存条目（学习机制）
        if src_protocol_addr != ipaddress.IPv4Address("0.0.0.0"):
            self._update_arp_entry(src_protocol_addr, src_hw_addr, ArpEntryStatus.RESOLVED)

        # 检查目标地址是否是本地地址
        if self._is_arp_packet_for_us(dest_protocol_addr):
            if opcode == ARP_REQ_OPCODE:
                logger.info(
                    "[%.6f]ARP: 收到ARP请求 %s -> %s，发送响应",
                    ms.sim_time(),
                    src_protocol_addr,
                    dest_protocol_addr,
                )
                self._send_arp_reply(pkt, src_hw_addr, src_protocol_addr, dest_protocol_addr)
            elif opcode == ARP_REPLY_OPCODE:
                logger.info(
                    "[%.6f]ARP: 收到ARP响应 %s -> %s",
                    ms.sim_time(),
                    src_protocol_addr,
                    dest_protocol_addr,
                )
                entry = self._find_arp_cache_entry(src_protocol_addr)
                if entry is not None and entry.state == ArpEntryStatus.PENDING:
                    self._send_queued_packets(entry)
                ms.pk_destroy(pkt)
            else:
                logger.warning("ARP: 收到未知操作码 %d，丢弃", opcode)
                ms.pk_destroy(pkt)
        else:
            ms.pk_destroy(pkt)

    def _broadcast_arp_request(self, dest_ip: ipaddress.IPv4Address) -> None:
        if self.outstrm_to_mac < 0:
            logger.warning("ARP: 未配置到MAC的输出流，丢弃ARP请求")
            return

        # 创建ARP请求数据包
        pkt = ms.pk_create_fmt("arp_v2")
        local_ip = self._get_local_ip_address()

        ms.pk_nfd_set_int(pkt, "hardware type", 1)
        ms.pk_nfd_set_int(pkt, "protocol type", NET_PROT_IP)
        ms.pk_nfd_set_int(pkt, "hardware length", 6)
        ms.pk_nfd_set_int(pkt, "protocol length", 4)
        ms.pk_nfd_set_int(pkt, "arp opcode", ARP_REQ_OPCODE)
        ms.pk_nfd_set_int(pkt, "src hw addr", int(self.hardware_addr))
        ms.pk_nfd_set_int(pkt, "src protocol addr", addr_to_uint32(local_ip))
        ms.pk_nfd_set_int(pkt, "dest hw addr", int(ARP_BROADCAST_ADDR))
        ms.pk_nfd_set_int(pkt, "dest protocol addr", addr_to_uint32(dest_ip))

        # 发送广播数据包
        self._send_packet_to_mac(pkt, ARP_BROADCAST_ADDR)

    def _send_arp_reply(
        self,
        pkt,
        dest_hw_addr: int,
        dest_ip: ipaddress.IPv4Address,
        local_ip: ipaddress.IPv4Address,
    ) -> None:
        if self.outstrm_to_mac < 0:
            logger.warning("ARP: 未配置到MAC的输出流，丢弃ARP响应")
            ms.pk_destroy(pkt)
            return

        ms.pk_nfd_set_int(pkt, "arp opcode", ARP_REPLY_OPCODE)
        ms.pk_nfd_set_int(pkt, "src hw addr", int(self.hardware_addr))
        ms.pk_nfd_set_int(pkt, "src protocol addr", addr_to_uint32(local_ip))
        ms.pk_nfd_set_int(pkt, "dest hw addr", int(dest_hw_addr))
        ms.pk_nfd_set_int(pkt, "dest protocol addr", addr_to_uint32(dest_ip))

        # 发送单播响应
        self._send_packet_to_mac(pkt, dest_hw_addr)

    def _send_packet_to_mac(self, pkt, dest_phys_addr: int) -> None:
        if self.outstrm_to_mac < 0:
            logger.warning("ARP: 未配置到MAC的输出流，丢弃数据包")
            ms.pk_destroy(pkt)
            return

        if self.mac_ici is None:
            try:
                self.mac_ici = ms.ici_create("ip_mac_req")
            except Exception as exc:
                logger.warning("ARP: 无法创建MAC通信ICI: %s", exc)
                ms.pk_destroy(pkt)
                return

        self.mac_ici.set_int("dest_addr", int(dest_phys_addr))

        pkt_format = ms.pk_format(pkt)
        if pkt_format == "arp_v2":
            self.mac_ici.set_int("protocol_type", int(NET_PROT_ARP))
        else:
            self.mac_ici.set_int("protocol_type", int(NET_PROT_IP))

        ms.ici_install(self.mac_ici)
        ms.pk_send(pkt, self.outstrm_to_mac)
        ms.ici_install(None)

    def _forward_ip_packet_to_upper(self, pkt) -> None:
        if self.outstrm_to_ip_rte < 0:
            logger.warning("ARP: 未配置到IP路由的输出流，丢弃数据包")
            ms.pk_destroy(pkt)
            return
        ms.pk_send(pkt, self.outstrm_to_ip_rte)

    def _handle_timer_expiry(self) -> None:
        if self.arp_sim_eff:
            return

        for ip_addr, entry in list(self.arp_cache.items()):
            if entry.state == ArpEntryStatus.PERMANENT:
                continue

            entry.age -= self.arp_gran

            if entry.state == ArpEntryStatus.RESOLVED:
                if entry.age <= 0:
                    logger.info("ARP: 删除老化条目 %s", entry.ip_addr)
                    self._delete_entry(ip_addr)
            elif entry.state == ArpEntryStatus.PENDING:
                if entry.age <= 0:
                    if entry.num_attempts < self.arpreq_max_retry:
                        if entry.queue:
                            logger.info(
                                "ARP: 重试ARP请求 %s (第%d次)",
                                entry.ip_addr,
                                entry.num_attempts + 1,
                            )
                            self._broadcast_arp_request(entry.ip_addr)
                            entry.age = self.wait_time
                            entry.num_attempts += 1
                        else:
                            self._delete_entry(ip_addr)
                    else:
                        logger.info("ARP: IP地址 %s 无法到达，删除条目", entry.ip_addr)
                        self._delete_entry(ip_addr)

        if self.arp_gran > 0:
            ms.intrpt_schedule_self(ms.sim_time() + self.arp_gran, 0)

    def _delete_entry(self, ip_addr: ipaddress.IPv4Address) -> None:
        entry = self.arp_cache.pop(ip_addr, None)
        if entry is None:
            return
        for queue_entity in entry.queue:
            ms.pk_destroy(queue_entity.queued_pkt)
        entry.queue.clear()

    def _queue_packet_in_arp_entry(self, entry: ArpEntry, pkt) -> None:
        if len(entry.queue) < self.max_queue_size:
            entry.queue.append(ArpQueueEntity(queued_pkt=pkt))
            logger.info("ARP: 数据包排队等待地址解析 %s", entry.ip_addr)
        else:
            logger.info("ARP: 队列已满，丢弃数据包")
            ms.pk_destroy(pkt)

    def _send_queued_packets(self, entry: ArpEntry) -> None:
        logger.info("ARP: 发送%d个排队的数据包到 %s", len(entry.queue), entry.ip_addr)
        for queue_entity in entry.queue:
            self._send_packet_to_mac(queue_entity.queued_pkt, entry.phys_addr)
        entry.queue.clear()

    def _update_arp_entry(
        self,
        ip_addr: ipaddress.IPv4Address,
        mac_addr: int,
        state: ArpEntryStatus,
    ) -> None:
        if self.arp_sim_eff:
            add_global_arp_entry(ip_addr, mac_addr)
            return

        entry = self._find_arp_cache_entry(ip_addr)
        if entry is not None:
            if entry.state == ArpEntryStatus.PERMANENT:
                return
            entry.phys_addr = mac_addr
            entry.state = state
            entry.age = self.max_age_timeout
            entry.num_attempts = 0
            if state == ArpEntryStatus.RESOLVED and entry.queue:
                self._send_queued_packets(entry)
            return

        if len(self.arp_cache) < self.cache_max_size:
            new_entry = ArpEntry(
                state=state,
                ip_addr=ip_addr,
                phys_addr=mac_addr,
                age=self.max_age_timeout,
                num_attempts=0,
            )
            self.arp_cache[ip_addr] = new_entry

    def _find_arp_cache_entry(self, ip_addr: ipaddress.IPv4Address) -> Optional[ArpEntry]:
        return self.arp_cache.get(ip_addr)

    def _is_local_address(self, addr: ipaddress.IPv4Address) -> bool:
        if self.local_interface and self.local_interface.ip_address == addr:
            return True
        if self.ip_module_data:
            for interface in self.ip_module_data.interface_table.values():
                if interface.ip_address == addr:
                    return True
        return False

    def _get_local_ip_address(self) -> ipaddress.IPv4Address:
        if self.local_interface and self.local_interface.ip_address:
            return self.local_interface.ip_address
        if self.ip_module_data:
            for interface in self.ip_module_data.interface_table.values():
                if interface.up and interface.ip_address:
                    return interface.ip_address
        return ipaddress.IPv4Address("0.0.0.0")

    def _is_arp_packet_for_us(self, dest_protocol_addr: ipaddress.IPv4Address) -> bool:
        if self._is_local_address(dest_protocol_addr):
            return True
        return dest_protocol_addr == ipaddress.IPv4Address("0.0.0.0")

    def _validate_arp_packet(self, pkt) -> bool:
        try:
            hw_type = ms.pk_nfd_get_int(pkt, "hardware type")
            prot_type = ms.pk_nfd_get_int(pkt, "protocol type")
            opcode = ms.pk_nfd_get_int(pkt, "arp opcode")
        except Exception:
            return False
        if hw_type != 1:
            return False
        if prot_type != NET_PROT_IP:
            return False
        if opcode not in (ARP_REQ_OPCODE, ARP_REPLY_OPCODE):
            return False
        return True

    def _get_phys_addr_from_global_table(self, ip_addr: ipaddress.IPv4Address) -> int:
        mac_addr, exists = get_global_arp_entry(ip_addr)
        if not exists:
            raise LookupError(ip_addr)
        return mac_addr

    def _is_broadcast(self, addr: ipaddress.IPv4Address) -> bool:
        if addr == LIMITED_BROADCAST_ADDR:
            return True
        if self.local_interface and self.local_interface.broadcast_addr == addr:
            return True
        return False

    def _get_arp_sim_efficiency(self) -> bool:
        if self.my_module is None:
            return False
        try:
            value = self.my_module.get_attr_string("Simulation Efficiency")
        except Exception:
            return False
        return value == "Enabled"

    def _get_attr_int(self, name: str, default: int) -> int:
        if self.my_module is None:
            return default
        try:
            return int(self.my_module.get_attr_int(name))
        except Exception:
            return default

    def _get_attr_float(self, name: str, default: float) -> float:
        if self.my_module is None:
            return default
        try:
            return float(self.my_module.get_attr_double(name))
        except Exception:
            return default


