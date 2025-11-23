from __future__ import annotations

import ipaddress
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import miaosuan as ms
from miaosuan.engine.engine import Stream
from miaosuan.engine.simobj import SimObj, get_sim_obj
from miaosuan.mms.process_registry import AttrType, ProcessAttribute, pr_attr_get, pr_discover

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IP_INTERFACE_TYPE_ETHERNET = 1
IP_INTERFACE_TYPE_LOOPBACK = 2
IP_INTERFACE_TYPE_TDMA = 3

ON_DEMAND_NOTIFY_TYPE_NEED = 1
ON_DEMAND_NOTIFY_TYPE_FOUND = 2
ON_DEMAND_NOTIFY_TYPE_FAILED = 3

LIMITED_BROADCAST_ADDR_UINT32 = 0xFFFF_FFFF
LIMITED_BROADCAST_ADDR = ipaddress.IPv4Address("255.255.255.255")


# ---------------------------------------------------------------------------
# Dataclasses / DTOs
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Interface:
    name: str = ""
    index: int = -1
    ip_address: ipaddress.IPv4Address = field(default_factory=lambda: ipaddress.IPv4Address("0.0.0.0"))
    subnet_mask: ipaddress.IPv4Network = field(default_factory=lambda: ipaddress.IPv4Network("0.0.0.0/32"))
    broadcast_addr: ipaddress.IPv4Address = field(default_factory=lambda: ipaddress.IPv4Address("0.0.0.0"))
    mac_address: int = 0
    mtu: int = 1500
    up: bool = True
    port_num: int = -1
    port_type: int = IP_INTERFACE_TYPE_ETHERNET
    child_proc: Optional[Any] = None
    speed: float = 0.0  # kbps in configuration, converted to bps when needed
    routing_protocols: List[str] = field(default_factory=list)


@dataclass(slots=True)
class PktInfo:
    in_strm: int = -1
    re_enter: bool = False
    next_hop: ipaddress.IPv4Address = field(default_factory=lambda: ipaddress.IPv4Address("0.0.0.0"))
    out_intf: Optional[Interface] = None


@dataclass(slots=True)
class PktWithInfo:
    pkt: Any
    info: PktInfo

    def copy(self) -> PktWithInfo:
        copied_info = PktInfo(
            in_strm=self.info.in_strm,
            re_enter=self.info.re_enter,
            next_hop=self.info.next_hop,
            out_intf=self.info.out_intf,
        )
        return PktWithInfo(pkt=ms.pk_copy(self.pkt), info=copied_info)


@dataclass(slots=True)
class ProtocolEntry:
    protocol_name: str
    protocol_num: int
    strm_from_protocol: int
    strm_to_protocol: int


@dataclass(slots=True)
class ModuleData:
    interface_table: Dict[int, Interface] = field(default_factory=dict)
    rib: Dict[ipaddress.IPv4Network, List["RIBEntry"]] = field(default_factory=dict)
    fib: Dict[ipaddress.IPv4Network, "FIBEntry"] = field(default_factory=dict)
    protocol_registry: Dict[int, ProtocolEntry] = field(default_factory=dict)
    on_demand_routing_registry: Dict[ipaddress.IPv4Network, SimObj] = field(default_factory=dict)


@dataclass(slots=True)
class PacketHeader:
    version: int = 4
    header_len: int = 5
    tos: int = 0
    total_len: int = 0
    packet_id: int = 0
    flags: int = 0
    frag_off: int = 0
    ttl: int = 64
    protocol: int = 0
    checksum: int = 0
    src_addr: int = 0
    dst_addr: int = 0


@dataclass(slots=True)
class RIBEntry:
    destination: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address
    out_interface: Interface
    metric: int
    admin_dist: int
    route_source: str
    extra_info: Optional[object] = None


@dataclass(slots=True)
class FIBEntry:
    destination: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address
    out_interface: Interface


@dataclass(slots=True)
class OutputIfaceInitArgs:
    queue_name: str
    out_strm: int
    iface: Interface


@dataclass(slots=True)
class OutputIfaceInvokeArgs:
    cmd: str
    pkt: PktWithInfo


# ---------------------------------------------------------------------------
# Queue system registry
# ---------------------------------------------------------------------------


class QueueSystem(ABC):
    @abstractmethod
    def enqueue(self, pkt: PktWithInfo) -> None:
        raise NotImplementedError

    @abstractmethod
    def dequeue(self) -> Optional[PktWithInfo]:
        raise NotImplementedError

    @abstractmethod
    def is_empty(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_full(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def length(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def capacity(self) -> int:
        raise NotImplementedError


_queue_registry: Dict[str, Callable[[], QueueSystem]] = {}


def register_queue_system(name: str, factory: Callable[[], QueueSystem]) -> None:
    _queue_registry[name] = factory


def get_queue_system(name: str) -> Optional[QueueSystem]:
    factory = _queue_registry.get(name)
    if factory is None:
        return None
    return factory()


# ---------------------------------------------------------------------------
# Module discovery helpers
# ---------------------------------------------------------------------------


def _discover_ip_process(node: SimObj) -> Tuple[Optional[SimObj], Optional[ModuleData]]:
    if node is None:
        raise ValueError("node is required to discover IP module")

    attrs = [
        ProcessAttribute("node objid", AttrType.OBJ_ID, node.get_id()),
        ProcessAttribute("protocol", AttrType.STRING, "ip"),
    ]
    handles = pr_discover(0, *attrs)
    if not handles:
        return None, None
    if len(handles) > 1:
        logger.warning("IP support: multiple IP processes found on node %s; returning first match", node.get_id())
    handle = handles[0]

    try:
        module_obj_id = pr_attr_get(handle, "module objid")
    except Exception as exc:
        raise RuntimeError(f"IP support: failed to fetch module objid: {exc}") from exc

    module = get_sim_obj(int(module_obj_id))
    if module is None:
        return None, None

    try:
        module_data = pr_attr_get(handle, "module data")
    except Exception:
        module_data = None

    return module, module_data


def find_node_ip_module(node: SimObj) -> Optional[SimObj]:
    module, _ = _discover_ip_process(node)
    return module


def find_node_ip_module_data(node: SimObj) -> ModuleData:
    module, data = _discover_ip_process(node)
    if module is None or data is None:
        raise RuntimeError(f"IP support: node {node.get_id()} has no IP module registered")
    return data


def register_protocol(protocol: int, protocol_name: str, strm_to_ip: Optional[Stream], strm_from_ip: Optional[Stream]) -> None:
    module = ms.self_obj()
    if module is None:
        raise RuntimeError("IP support: register_protocol called without module context")

    node = ms.topo_parent(module)
    if node is None:
        raise RuntimeError("IP support: failed to resolve parent node when registering protocol")

    module_data = find_node_ip_module_data(node)
    to_ip_index = strm_to_ip.dst_index if strm_to_ip is not None else -1
    from_ip_index = strm_from_ip.src_index if strm_from_ip is not None else -1

    module_data.protocol_registry[protocol] = ProtocolEntry(
        protocol_name=protocol_name,
        protocol_num=protocol,
        strm_from_protocol=to_ip_index,
        strm_to_protocol=from_ip_index,
    )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def addr_to_uint32(addr: ipaddress.IPv4Address) -> int:
    return int(addr)


def uint32_to_addr(value: int) -> ipaddress.IPv4Address:
    return ipaddress.IPv4Address(value & 0xFFFF_FFFF)


def calculate_broadcast_addr(subnet: ipaddress.IPv4Network) -> ipaddress.IPv4Address:
    return subnet.broadcast_address


def update_interface_address(intf: Interface, ip_addr: ipaddress.IPv4Address, subnet: ipaddress.IPv4Network) -> None:
    intf.ip_address = ip_addr
    intf.subnet_mask = subnet
    intf.broadcast_addr = calculate_broadcast_addr(subnet)
