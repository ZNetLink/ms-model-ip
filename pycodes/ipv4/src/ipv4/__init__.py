import ipaddress
import logging
from typing import Dict, List, Optional

import miaosuan as ms
from miaosuan.mms.process_registry import AttrType, pr_attr_set, pr_register

from . import queue  # noqa: F401  # ensure queue systems are registered
from .ip_support import (
    LIMITED_BROADCAST_ADDR,
    ON_DEMAND_NOTIFY_TYPE_FAILED,
    ON_DEMAND_NOTIFY_TYPE_FOUND,
    ON_DEMAND_NOTIFY_TYPE_NEED,
    IP_INTERFACE_TYPE_LOOPBACK,
    Interface,
    ModuleData,
    OutputIfaceInitArgs,
    OutputIfaceInvokeArgs,
    PacketHeader,
    PktInfo,
    PktWithInfo,
    addr_to_uint32,
    get_queue_system,
    uint32_to_addr,
    update_interface_address,
)
from .routing import ADMIN_DIST_CONNECTED, ADMIN_DIST_STATIC, RIBEntry, add_route_entry, lookup_fib

from . import output_iface

logger = logging.getLogger(__name__)

INTRPT_CODE_PKT_DONE = 1
REMOTE_INTRPT_CODE_ON_DEMAND_NOTIFY = 1


@ms.process_model("ipv4")
class Ipv4Process:
    def __init__(self) -> None:
        self.my_module: Optional[ms.SimObj] = None
        self.module_data: Optional[ModuleData] = None
        self.in_queue = get_queue_system("FIFO")
        self.busy = False
        self.pending_pkt: Optional[PktWithInfo] = None
        self.processing_rate = 1_000_000
        self.pkt_processing_delay = 1e-6
        self.routing_enabled = False
        self.gateway: Optional[ipaddress.IPv4Address] = None
        self.gateway_intf: Optional[Interface] = None
        self.on_demand_pending_pkts: Dict[ipaddress.IPv4Address, List[PktWithInfo]] = {}


    @ms.state_enter("Init", begin=True)
    def enter_init(self) -> None:
        self._initialize()
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_enter("Wait")
    def enter_wait(self) -> None:
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_enter("Wait1")
    def enter_wait1(self) -> None:
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_enter("Wait2")
    def enter_wait2(self) -> None:
        ms.intrpt_schedule_self(ms.sim_time(), 0)

    @ms.state_enter("Idle")
    def enter_state_1(self) -> None:
        pass

    @ms.state_exit("Idle")
    def exit_idle(self) -> None:
        intr_type = ms.intrpt_type()
        code = ms.intrpt_code()

        if intr_type == ms.INTRPT_TYPE_SELF and code == INTRPT_CODE_PKT_DONE:
            self._handle_pkt_done()
            self._start_process_pkt()
            return

        if intr_type == ms.INTRPT_TYPE_REMOTE and code == REMOTE_INTRPT_CODE_ON_DEMAND_NOTIFY:
            self._handle_on_demand_notify()
            return

        if intr_type == ms.INTRPT_TYPE_STRM:
            self._handle_stream_interrupt()


    @ms.transition("Init", "Wait")
    def init_to_wait(self) -> bool:
        return True

    @ms.transition("Wait", "Wait1")
    def wait_to_wait1(self) -> bool:
        return True

    @ms.transition("Wait1", "Wait2")
    def wait1_to_wait2(self) -> bool:
        return True

    @ms.transition("Wait2", "Idle")
    def wait2_to_idle(self) -> bool:
        return True

    @ms.transition("Idle", "Idle")
    def idle_to_idle(self) -> bool:
        return True

    # ----------------------------------------------------------- Operations --
    def _initialize(self) -> None:
        self.my_module = ms.self_obj()
        if self.my_module is None:
            raise RuntimeError("ipv4: missing module context during initialization")

        self.busy = False
        self.pending_pkt = None
        self.on_demand_pending_pkts.clear()

        node = ms.topo_parent(self.my_module)
        if node is None:
            raise RuntimeError("ipv4: failed to resolve parent node")

        proc_handle = ms.pro_self()
        if proc_handle is None:
            raise RuntimeError("ipv4: missing process handle")

        record = pr_register(node.get_id(), self.my_module.get_id(), proc_handle, "ipv4")
        pr_attr_set(record, "protocol", AttrType.STRING, "ip")

        try:
            self.routing_enabled = self.my_module.get_attr_bool("routing enabled")
        except Exception:
            self.routing_enabled = False

        try:
            self.processing_rate = max(1, int(self.my_module.get_attr_int("processing rate")))
        except Exception:
            self.processing_rate = 1_000_000
        self.pkt_processing_delay = 1.0 / float(self.processing_rate)

        try:
            gateway_str = self.my_module.get_attr_string("gateway")
            gateway_str = gateway_str.strip()
            if gateway_str:
                self.gateway = ipaddress.IPv4Address(gateway_str)
        except Exception:
            self.gateway = None

        self.module_data = ModuleData()
        pr_attr_set(record, "module data", AttrType.POINTER, self.module_data)

        self.in_queue = get_queue_system("FIFO")
        if self.in_queue is None:
            raise RuntimeError("ipv4: default queue system FIFO not registered")

        self._initialize_interfaces()
        self._initialize_loopback_interfaces()
        self._initialize_routing_table()

    def _initialize_interfaces(self) -> None:
        assert self.my_module is not None
        assert self.module_data is not None

        out_streams = ms.get_out_streams() or {}
        in_streams = ms.get_in_streams() or {}

        for index, in_stream in in_streams.items():
            out_stream = out_streams.get(index)
            if out_stream is None:
                continue

            if in_stream.src is not out_stream.dst:
                raise RuntimeError("ipv4: in/out stream peer mismatch for index %s" % index)

            peer_module = in_stream.src
            if peer_module is None:
                continue

            try:
                iface_index = peer_module.get_attr_int("ip interface index")
            except Exception:
                continue

            interface = Interface()
            interface.index = iface_index
            interface.port_num = index
            interface.child_proc = ms.pro_create("ip_output_iface", None)
            if interface.child_proc is None:
                raise RuntimeError(f"ipv4: failed to create ip_output_iface for stream {index}")

            interface.name = self._get_module_attr_string(f"interfaces[{iface_index}].name")

            ip_addr_str = self._get_module_attr_string(f"interfaces[{iface_index}].ip address")
            ip_addr = ipaddress.IPv4Address(ip_addr_str)

            mask_str = self._get_module_attr_string(f"interfaces[{iface_index}].mask", default="255.255.255.0")
            subnet = self._build_network(ip_addr, mask_str)
            update_interface_address(interface, ip_addr, subnet)

            if self.gateway is not None and self.gateway in interface.subnet_mask:
                self.gateway_intf = interface

            try:
                interface.mtu = self.my_module.get_attr_int(f"interfaces[{iface_index}].mtu")
            except Exception:
                interface.mtu = 1500

            try:
                interface.speed = float(self.my_module.get_attr_double(f"interfaces[{iface_index}].speed"))
            except Exception:
                interface.speed = 1_000_000.0

            try:
                routing_protocols = self.my_module.get_attr_string(f"interfaces[{iface_index}].routing protocols")
                if routing_protocols:
                    interface.routing_protocols = [proto.strip() for proto in routing_protocols.split(",") if proto.strip()]
            except Exception:
                interface.routing_protocols = []

            ms.pro_invoke(
                interface.child_proc,
                OutputIfaceInitArgs(queue_name="FIFO", out_strm=index, iface=interface),
            )

            self.module_data.interface_table[index] = interface

    def _initialize_loopback_interfaces(self) -> None:
        assert self.my_module is not None
        assert self.module_data is not None

        try:
            count = self.my_module.get_attr_array_count("loopback interfaces")
        except Exception:
            count = 0

        for idx in range(count):
            interface = Interface()
            interface.index = idx
            interface.port_num = -(idx + 1)
            interface.port_type = IP_INTERFACE_TYPE_LOOPBACK
            interface.child_proc = None
            interface.up = True

            name = self._get_module_attr_string(f"loopback interfaces[{idx}].name", default=f"lo{idx}")
            interface.name = name

            ip_addr_str = self._get_module_attr_string(f"loopback interfaces[{idx}].ip address", default="127.0.0.1")
            ip_addr = ipaddress.IPv4Address(ip_addr_str)

            mask_str = self._get_module_attr_string(f"loopback interfaces[{idx}].mask", default="255.0.0.0")
            subnet = self._build_network(ip_addr, mask_str)
            update_interface_address(interface, ip_addr, subnet)

            try:
                interface.mtu = self.my_module.get_attr_int(f"loopback interfaces[{idx}].mtu")
            except Exception:
                interface.mtu = 65_536

            interface.speed = 1_000_000_000.0

            self.module_data.interface_table[interface.port_num] = interface
            logger.info("ipv4: initialized loopback interface %s with %s", interface.name, interface.ip_address)

    def _initialize_routing_table(self) -> None:
        assert self.module_data is not None

        zero_addr = ipaddress.IPv4Address("0.0.0.0")

        for interface in self.module_data.interface_table.values():
            entry = RIBEntry(
                destination=interface.subnet_mask,
                next_hop=zero_addr,
                out_interface=interface,
                metric=0,
                admin_dist=ADMIN_DIST_CONNECTED,
                route_source="connected",
            )
            add_route_entry(self.module_data, entry)

        try:
            count = self.my_module.get_attr_array_count("static routes") if self.my_module else 0
        except Exception:
            count = 0

        for idx in range(count):
            dest_str = self._get_module_attr_string(f"static routes[{idx}].destination")
            destination = ipaddress.ip_network(dest_str, strict=False)

            next_hop_str = self._get_module_attr_string(f"static routes[{idx}].next hop")
            next_hop = ipaddress.IPv4Address(next_hop_str)

            try:
                metric = int(self.my_module.get_attr_int(f"static routes[{idx}].metric"))
            except Exception:
                metric = 1

            out_intf = self._determine_interface_by_dest_addr(next_hop)
            if out_intf is None:
                raise RuntimeError(f"ipv4: unable to resolve interface for static next hop {next_hop}")

            entry = RIBEntry(
                destination=destination,
                next_hop=next_hop,
                out_interface=out_intf,
                metric=metric,
                admin_dist=ADMIN_DIST_STATIC,
                route_source="static",
            )
            add_route_entry(self.module_data, entry)

    def _handle_stream_interrupt(self) -> None:
        strm_index = ms.intrpt_strm()
        try:
            packet = ms.pk_get(strm_index)
        except Exception as exc:
            logger.warning("ipv4: failed to fetch packet from stream %s: %s", strm_index, exc)
            return

        ms.pk_stamp(packet)
        info = PktInfo(in_strm=strm_index)
        pkt_with_info = PktWithInfo(pkt=packet, info=info)

        if self.in_queue is None:
            logger.warning("ipv4: input queue not initialized, dropping packet")
            ms.pk_destroy(packet)
            return

        self.in_queue.enqueue(pkt_with_info)
        if not self.busy:
            self._start_process_pkt()

    def _start_process_pkt(self) -> None:
        if self.in_queue is None or self.in_queue.is_empty():
            self.busy = False
            return

        pkt = self.in_queue.dequeue()
        if pkt is None:
            self.busy = False
            return

        self.busy = True
        self.pending_pkt = pkt
        ms.intrpt_schedule_self(ms.sim_time() + self.pkt_processing_delay, INTRPT_CODE_PKT_DONE)

    def _handle_pkt_done(self) -> None:
        pkt = self.pending_pkt
        self.pending_pkt = None
        if pkt is None:
            self.busy = False
            return

        is_upper_pkt = ms.pk_format(pkt.pkt) != "ip_dgram_v4"
        dest_addr: ipaddress.IPv4Address
        protocol_num: int

        if is_upper_pkt:
            ici = ms.pk_ici(pkt.pkt)
            if ici is None:
                logger.warning("ipv4: missing ICI for upper-layer packet, dropping")
                ms.pk_destroy(pkt.pkt)
                return
            try:
                dest_addr = uint32_to_addr(int(ici.get_int("dest address")))
                protocol_num = int(ici.get_int("protocol"))
            except Exception as exc:
                logger.warning("ipv4: malformed ICI for upper pkt: %s", exc)
                ms.pk_destroy(pkt.pkt)
                return
        else:
            header_obj = ms.pk_nfd_get_pointer(pkt.pkt, "header")
            if not isinstance(header_obj, PacketHeader):
                logger.warning("ipv4: invalid IP header object, dropping packet")
                ms.pk_destroy(pkt.pkt)
                return
            if header_obj.ttl <= 0:
                ms.pk_destroy(pkt.pkt)
                return
            dest_addr = uint32_to_addr(header_obj.dst_addr)
            protocol_num = int(header_obj.protocol)

        is_broadcast = self._is_broadcast_addr(dest_addr)

        if self._is_my_ip_addr(dest_addr) or (not is_upper_pkt and is_broadcast):
            self._send_to_upper_layer(pkt, protocol_num)
            return

        if is_upper_pkt:
            total_bits = ms.pk_total_size_get(pkt.pkt)
            total_len = int(total_bits // 8 + 20)
            header = PacketHeader(
                version=4,
                header_len=5,
                tos=0,
                total_len=total_len,
                packet_id=0,
                flags=0,
                frag_off=0,
                ttl=64,
                protocol=protocol_num,
                checksum=0,
                src_addr=0,
                dst_addr=addr_to_uint32(dest_addr),
            )
            ip_pkt = ms.pk_create_fmt("ip_dgram_v4")
            ms.pk_nfd_set_pointer(ip_pkt, "header", header)
            ms.pk_nfd_set_packet(ip_pkt, "data", pkt.pkt)
            pkt.pkt = ip_pkt

            if is_broadcast:
                pkt.info.next_hop = dest_addr
                self._broadcast_to_interfaces(pkt, dest_addr)
                return

        if self.routing_enabled or is_upper_pkt:
            self._determine_next_hop(dest_addr, pkt)
            if pkt.info.out_intf is not None and pkt.info.next_hop is not None:
                self._forward_to_interface(pkt.info.out_intf, pkt)
                return

            if self._fallback_to_on_demand_routing(dest_addr, pkt):
                return

            ms.pk_destroy(pkt.pkt)
            return

        ms.pk_destroy(pkt.pkt)

    def _forward_to_interface(self, interface: Interface, pkt: PktWithInfo) -> None:
        header = ms.pk_nfd_get_pointer(pkt.pkt, "header")
        if not isinstance(header, PacketHeader):
            logger.warning("ipv4: missing header when forwarding, dropping")
            ms.pk_destroy(pkt.pkt)
            return

        header.ttl -= 1
        if header.ttl < 0:
            ms.pk_destroy(pkt.pkt)
            return

        if header.src_addr == 0:
            header.src_addr = addr_to_uint32(interface.ip_address)
        header = ms.pk_nfd_get_pointer(pkt.pkt, "header")

        if interface.port_num < 0:
            self._send_to_upper_layer(pkt, header.protocol)
            return

        invoke_args = OutputIfaceInvokeArgs(cmd="enqueue", pkt=pkt)
        ms.pro_invoke(interface.child_proc, invoke_args)

    def _determine_next_hop(self, dest_addr: ipaddress.IPv4Address, pkt: PktWithInfo) -> None:
        assert self.module_data is not None

        entry = lookup_fib(self.module_data, dest_addr)
        if entry is None:
            if not self.routing_enabled and self.gateway is not None and self.gateway_intf is not None:
                pkt.info.next_hop = self.gateway
                pkt.info.out_intf = self.gateway_intf
                return
            pkt.info.next_hop = None
            pkt.info.out_intf = None
            return

        pkt.info.out_intf = entry.out_interface
        next_hop = entry.next_hop
        if int(next_hop) == 0:
            pkt.info.next_hop = dest_addr
        else:
            pkt.info.next_hop = next_hop

    def _fallback_to_on_demand_routing(self, dest_addr: ipaddress.IPv4Address, pkt: PktWithInfo) -> bool:
        if pkt.info.re_enter:
            return False
        assert self.module_data is not None
        protocol = self._locate_on_demand_protocol(dest_addr)
        if protocol is None:
            return False

        pending_list = self.on_demand_pending_pkts.setdefault(dest_addr, [])
        notify_needed = not pending_list
        pending_list.append(pkt)

        if notify_needed:
            ici = ms.ici_create("ip_on_demand_routing_notify")
            ici.set_int("type", ON_DEMAND_NOTIFY_TYPE_NEED)
            ici.set_string("dest address", str(dest_addr))

            ms.ici_install(ici)
            ms.intrpt_schedule_remote(ms.sim_time(), REMOTE_INTRPT_CODE_ON_DEMAND_NOTIFY, protocol)
            ms.ici_install(None)
            logger.debug("ipv4: on-demand routing requested for %s", dest_addr)

        return True

    def _locate_on_demand_protocol(self, dest_addr: ipaddress.IPv4Address) -> Optional[ms.SimObj]:
        assert self.module_data is not None
        for subnet, module in self.module_data.on_demand_routing_registry.items():
            if dest_addr in subnet:
                return module
        return None

    def _handle_on_demand_notify(self) -> None:
        ici = ms.intrpt_ici()
        if ici is None:
            logger.warning("ipv4: on-demand notify missing ICI")
            return

        try:
            notify_type = int(ici.get_int("type"))
            dest_addr = ipaddress.IPv4Address(ici.get_string("dest address"))
        except Exception as exc:
            logger.warning("ipv4: malformed on-demand notify: %s", exc)
            return

        pending = self.on_demand_pending_pkts.get(dest_addr)
        if not pending:
            return

        if notify_type == ON_DEMAND_NOTIFY_TYPE_FOUND:
            for pkt in pending:
                pkt.info.re_enter = True
                if self.in_queue is not None:
                    self.in_queue.enqueue(pkt)
            if self.in_queue is not None and not self.busy:
                self._start_process_pkt()
        elif notify_type == ON_DEMAND_NOTIFY_TYPE_FAILED:
            for pkt in pending:
                ms.pk_destroy(pkt.pkt)

        self.on_demand_pending_pkts.pop(dest_addr, None)

    def _send_to_upper_layer(self, pkt: PktWithInfo, protocol: int) -> None:
        assert self.module_data is not None

        entry = self.module_data.protocol_registry.get(protocol)
        if entry is None:
            logger.warning("ipv4: protocol %s not registered, dropping packet", protocol)
            ms.pk_destroy(pkt.pkt)
            return

        data_pkt = pkt.pkt
        src_addr = 0
        if ms.pk_format(pkt.pkt) == "ip_dgram_v4":
            header = ms.pk_nfd_get_pointer(pkt.pkt, "header")
            if isinstance(header, PacketHeader):
                src_addr = header.src_addr
            try:
                data_pkt = ms.pk_nfd_get_packet(pkt.pkt, "data")
            except Exception:
                data_pkt = None
            ms.pk_destroy(pkt.pkt)

        if data_pkt is None:
            logger.warning("ipv4: missing payload when delivering to upper layer")
            return

        if entry.strm_to_protocol < 0:
            logger.warning("ipv4: protocol %s output stream not connected", protocol)
            ms.pk_destroy(data_pkt)
            return

        ici = ms.ici_create("ip_ind")
        ici.set_int("src address", src_addr)
        ici.set_int("in intf idx", pkt.info.in_strm)

        ms.ici_install(ici)
        ms.pk_send(data_pkt, entry.strm_to_protocol)
        ms.ici_install(None)

    def _broadcast_to_interfaces(self, pkt: PktWithInfo, dest_addr: ipaddress.IPv4Address) -> None:
        assert self.module_data is not None

        interfaces = list(self.module_data.interface_table.values())
        first = True
        for interface in interfaces:
            if dest_addr != LIMITED_BROADCAST_ADDR and interface.broadcast_addr != dest_addr:
                continue

            pkt_to_send = pkt if first else pkt.copy()
            first = False
            self._forward_to_interface(interface, pkt_to_send)

        if first:
            ms.pk_destroy(pkt.pkt)

    def _determine_interface_by_dest_addr(self, dest_addr: ipaddress.IPv4Address) -> Optional[Interface]:
        assert self.module_data is not None
        for interface in self.module_data.interface_table.values():
            if dest_addr in interface.subnet_mask:
                return interface
        return None

    def _is_my_ip_addr(self, addr: ipaddress.IPv4Address) -> bool:
        assert self.module_data is not None
        for interface in self.module_data.interface_table.values():
            if interface.ip_address == addr:
                return True
        return False

    def _is_broadcast_addr(self, addr: ipaddress.IPv4Address) -> bool:
        if addr == LIMITED_BROADCAST_ADDR:
            return True
        assert self.module_data is not None
        return any(interface.broadcast_addr == addr for interface in self.module_data.interface_table.values())

    # ---------------------------------------------------------- Misc helpers --
    def _get_module_attr_string(self, name: str, default: Optional[str] = None) -> str:
        assert self.my_module is not None
        try:
            value = self.my_module.get_attr_string(name)
        except Exception:
            if default is not None:
                return default
            raise
        return value

    @staticmethod
    def _build_network(ip_addr: ipaddress.IPv4Address, mask_str: str) -> ipaddress.IPv4Network:
        try:
            return ipaddress.IPv4Network(f"{ip_addr}/{mask_str}", strict=False)
        except Exception as exc:
            raise ValueError(f"ipv4: invalid mask {mask_str!r} for address {ip_addr}") from exc

