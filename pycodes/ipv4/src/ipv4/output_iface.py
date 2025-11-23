from __future__ import annotations

import logging
from typing import Optional

import miaosuan as ms

from .ip_support import OutputIfaceInitArgs, OutputIfaceInvokeArgs, PktWithInfo, QueueSystem, addr_to_uint32, get_queue_system

logger = logging.getLogger(__name__)


class OutputIfaceProcess:
    def __init__(self) -> None:
        self.queue: Optional[QueueSystem] = None
        self.busy = False
        self.out_strm: int = -1
        self.my_proc = None
        self.speed_bps: float = 0.0
        self.pending_pkt: Optional[PktWithInfo] = None

    # ------------------------------------------------------------------ FSM --
    def init(self, builder: ms.ProcessBuilder) -> None:
        builder.begin("Init")
        builder.add_state("Init", self.enter_init, self.exit_init)
        builder.add_state("Idle", self.enter_idle, self.exit_idle)

        builder.add_transition("Init", "Idle", _always_true)
        builder.add_transition("Idle", "Idle", _always_true)

    # --------------------------------------------------------------- States --
    def enter_init(self) -> None:
        args = ms.pro_arg_mem_access()
        if not isinstance(args, OutputIfaceInitArgs):
            raise RuntimeError("ip_output_iface: init arguments missing or invalid")

        self.my_proc = ms.pro_self()
        self.queue = get_queue_system(args.queue_name)
        if self.queue is None:
            raise RuntimeError(f"ip_output_iface: unknown queue system {args.queue_name!r}")

        self.out_strm = int(args.out_strm)
        self.speed_bps = max(float(args.iface.speed) * 1000.0, 1.0)
        self.busy = False
        self.pending_pkt = None

        ms.intrpt_schedule_self(ms.sim_time(), 0)

    def exit_init(self) -> None:
        return

    def enter_idle(self) -> None:
        return

    def exit_idle(self) -> None:
        self._handle_parent_invocation()
        if ms.intrpt_type() == ms.INTRPT_TYPE_SELF:
            self._handle_self_interrupt()

    # ----------------------------------------------------------- Operations --
    def _handle_parent_invocation(self) -> None:
        if self.my_proc is None:
            return

        _, mode = ms.pro_invoker(self.my_proc)
        if mode != ms.PROINV_INDIRECT:
            return

        args = ms.pro_arg_mem_access()
        if not isinstance(args, OutputIfaceInvokeArgs):
            logger.warning("ip_output_iface: unexpected invocation arguments %r", args)
            return

        if args.cmd != "enqueue":
            logger.warning("ip_output_iface: unsupported command %s", args.cmd)
            return

        if self.queue is None:
            logger.warning("ip_output_iface: queue not initialized, dropping packet")
            ms.pk_destroy(args.pkt.pkt)
            return

        self.queue.enqueue(args.pkt)
        if not self.busy:
            ms.intrpt_schedule_self(ms.sim_time(), 0)

    def _handle_self_interrupt(self) -> None:
        if self.queue is None:
            self.busy = False
            self.pending_pkt = None
            return

        if self.pending_pkt is not None:
            self._send_pending_packet()

        next_pkt = self.queue.dequeue()
        if next_pkt is None:
            self.pending_pkt = None
            self.busy = False
            return

        self.pending_pkt = next_pkt
        self.busy = True
        tx_delay = self._get_tx_delay(next_pkt)
        ms.intrpt_schedule_self(ms.sim_time() + tx_delay, 0)

    def _send_pending_packet(self) -> None:
        if self.pending_pkt is None:
            return

        ici = ms.ici_create("ip_arp_req")
        ici.set_int("next_addr", int(addr_to_uint32(self.pending_pkt.info.next_hop)))

        ms.ici_install(ici)
        ms.pk_send(self.pending_pkt.pkt, self.out_strm)
        ms.ici_install(None)

    def _get_tx_delay(self, pkt: PktWithInfo) -> float:
        size_bits = float(ms.pk_total_size_get(pkt.pkt))
        return size_bits / self.speed_bps if self.speed_bps > 0 else 0.0


def _always_true() -> bool:
    return True


ms.register_process_model("ip_output_iface", lambda: OutputIfaceProcess())
