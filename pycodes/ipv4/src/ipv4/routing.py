from __future__ import annotations

import ipaddress
import logging
from typing import List, Optional

from miaosuan.engine.simobj import SimObj
from .ip_support import FIBEntry, ModuleData, RIBEntry

logger = logging.getLogger(__name__)

# Administrative distance constants
ADMIN_DIST_CONNECTED = 0
ADMIN_DIST_STATIC = 1
ADMIN_DIST_EIGRP_SUMMARY = 5
ADMIN_DIST_EBGP = 20
ADMIN_DIST_IN_EIGRP = 90
ADMIN_DIST_IGRP = 100
ADMIN_DIST_OLSR = 109
ADMIN_DIST_AODV = 105
ADMIN_DIST_OSPF = 110
ADMIN_DIST_ISIS = 115
ADMIN_DIST_RIP = 120
ADMIN_DIST_EGP = 140
ADMIN_DIST_ODR = 160
ADMIN_DIST_EX_EIGRP = 170
ADMIN_DIST_IN_BGP = 200
ADMIN_DIST_UNKNOWN = 255


def add_route_entry(module_data: ModuleData, entry: RIBEntry) -> None:
    candidates = module_data.rib.setdefault(entry.destination, [])
    candidates.append(entry)
    _recalculate_fib_for_prefix(module_data, entry.destination)


def remove_route_entry(module_data: ModuleData, entry: RIBEntry) -> None:
    candidates = module_data.rib.get(entry.destination)
    if not candidates:
        return

    try:
        candidates.remove(entry)
    except ValueError:
        pass

    if candidates:
        module_data.rib[entry.destination] = candidates
    else:
        module_data.rib.pop(entry.destination, None)

    _recalculate_fib_for_prefix(module_data, entry.destination)


def _recalculate_fib_for_prefix(module_data: ModuleData, prefix: ipaddress.IPv4Network) -> None:
    candidates = module_data.rib.get(prefix)
    if not candidates:
        module_data.fib.pop(prefix, None)
        return

    best = candidates[0]
    for candidate in candidates[1:]:
        if candidate.admin_dist < best.admin_dist:
            best = candidate
            continue
        if candidate.admin_dist == best.admin_dist and candidate.metric < best.metric:
            best = candidate

    current = module_data.fib.get(prefix)
    if current is None or current.next_hop != best.next_hop or current.out_interface != best.out_interface:
        module_data.fib[prefix] = FIBEntry(
            destination=prefix,
            next_hop=best.next_hop,
            out_interface=best.out_interface,
        )


def lookup_fib(module_data: ModuleData, dst_addr: ipaddress.IPv4Address) -> Optional[FIBEntry]:
    best_entry: Optional[FIBEntry] = None
    best_prefix_len = -1
    for prefix, entry in module_data.fib.items():
        if dst_addr in prefix:
            prefix_len = prefix.prefixlen
            if prefix_len > best_prefix_len:
                best_prefix_len = prefix_len
                best_entry = entry
    return best_entry


def get_routing_entries_for_dest(module_data: ModuleData, dest: ipaddress.IPv4Network) -> List[RIBEntry]:
    return list(module_data.rib.get(dest, ()))


def get_routing_entries_for_protocol(module_data: ModuleData, source: str) -> List[RIBEntry]:
    entries: List[RIBEntry] = []
    for candidates in module_data.rib.values():
        for candidate in candidates:
            if candidate.route_source == source:
                entries.append(candidate)
    return entries


def on_demand_routing_protocol_register(module_data: ModuleData, subnet: ipaddress.IPv4Network, module: SimObj) -> None:
    module_data.on_demand_routing_registry[subnet] = module


def print_routing_table(module_data: ModuleData) -> None:
    logger.info("RIB Table:")
    for candidates in module_data.rib.values():
        for candidate in candidates:
            logger.info(
                "  %s via %s on %s (admin dist: %s, metric: %s, source: %s)",
                candidate.destination,
                candidate.next_hop,
                candidate.out_interface.name,
                candidate.admin_dist,
                candidate.metric,
                candidate.route_source,
            )

    logger.info("FIB Table:")
    for entry in module_data.fib.values():
        logger.info("  %s via %s on %s", entry.destination, entry.next_hop, entry.out_interface.name)
