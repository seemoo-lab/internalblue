#!/usr/bin/env python
#
# fw_0x220e.py
#
# Firmware file for BCM20702A1 chipsets. These chipsets are typically used for
# Bluetooth USB dongles (e.g. Asus USB-BT400, 0b05:17cb, LMP subversion 0x220e,
# firmware 001.002.014).
#
# Copyright (c) 2019 Jan Ruge and Jiska Classen. (MIT License)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# - The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
# - The Software is provided "as is", without warranty of any kind, express or
#   implied, including but not limited to the warranties of merchantability,
#   fitness for a particular purpose and noninfringement. In no event shall the
#   authors or copyright holders be liable for any claim, damages or other
#   liability, whether in an action of contract, tort or otherwise, arising from,
#   out of or in connection with the Software or the use or other dealings in the
#   Software.
from __future__ import absolute_import
from .fw import MemorySection, FirmwareDefinition


class BCM20702A1(FirmwareDefinition):
    # Firmware Infos
    FW_NAME = "BCM20702A1"  # (USB Bluetooth dongle)

    # Device Infos
    # Local device name buffer: [len-1 byte][pad][name] in patch RAM, written by
    # the vendor patch. Verified on a live Asus USB-BT400 (0b05:17cb).
    DEVICE_NAME = 0x90029
    # BD_ADDR, byte-reversed in memory as expected by readMem()[::-1]
    BD_ADDR = 0x80064

    # Memory Sections
    #                          start,    end,           is_rom? is_ram?
    SECTIONS = [
        MemorySection(0x00000000, 0x5FFFF, True, False),  # Internal ROM (readable via Read_RAM)
        MemorySection(0x80000, 0x9BFFF, False, True),  # Internal RAM
    ]

    # Heap (block pool). ROM table of 4 pool-list pointers; walker starts at the
    # first entry. Pool structs are tagged with the magic "BLOC".
    BLOC_HEAD = 0x3166C

    # Connection Structure and Table
    # find_connection_struct(index) = CONNECTION_ARRAY_ADDRESS + (index-1)*0x110
    CONNECTION_ARRAY_ADDRESS = 0x83888
    CONNECTION_MAX = 11
    CONNECTION_STRUCT_LENGTH = 0x110

    # ---- Verified hook-development data (informational; no runtime effect) ----
    #
    # The mask ROM (0x0-0x5ffff) is READ-ONLY: Write_RAM to ROM addresses is
    # silently ignored (verified on a live device). Hooking therefore has to go
    # through the RAM-resident indirection the firmware uses:
    #
    #   * 0x80200-0x8022c: table of 12 pointer cells into ROM code (Thumb),
    #     consumed via pc-relative loads in the transport/LM code.
    #   * 0x802e4, 0x80300, 0x80330, 0x803f4, 0x80410: pointer cells whose
    #     tables the vendor patch (001.002.014) replaces at boot; observed
    #     live values point into patch RAM.
    #
    # Custom hook code can be placed in the verified-unused tails of patch RAM
    # (all canary-verified against live traffic; see below).
    HCI_TRANSPORT_STRUCT = 0x852B8  # queue struct passed to the TX dispatcher
    ROM_MALLOC_HCI_EVENT_BUFFER = 0x2ABC6  # r0 = H4 type, r1 = size -> buffer
    ROM_SEND_HCI_EVENT = 0x2AADC  # r0 = H4 buffer
    ROM_MEMCPY = 0x54984
    ROM_FREE_BUFFER = 0x315CC

    # ---- Queue system (verified against runtime RAM dump) ----
    # 11 queue structs tagged "QUEU" (0x51554555), doubly linked via fields
    # f12 (next) / f13 (prev). Head variable lives in patch RAM (static):
    QUEUE_HEAD = 0x943B8
    QUEUE_NAMES = [
        "q0  8Bx12  0x84528 alloc-path list",
        "q1  4Bx8   0x84564 HCI event send path (0x2aa38)",
        "q2  8Bx6   0x849e8 signals HCI cmd task (via 0xfcbc)",
        "q3  4Bx31  0x852b8 transport layer",
        "q4  8Bx31  0x84f48 transport layer",
        "q5  4Bx3   0x853f4 transport layer",
        "q6  4Bx20  0x8547c transport layer",
        "q7  8Bx8   0x854f4 transport layer",
        "q8  8Bx6   0x8555c transport layer",
        "q9  8Bx1   0x8559c transport layer",
        "q10 8Bx1   0x855dc transport layer",
    ]

    # ---- Pointer-cell hook support (RAM indirection, statically verified) ----
    #
    # HCI TX (chip -> host): 0x2aadc (send_hci_event) -> 0x264a6 -> dispatch:
    #   * if TX_HOOK_CELL is non-zero, it is invoked as
    #       hook(r0 = H4 buffer, r1 = &stack_arg(0))
    #     via the bx-shim 0x26a64 (return 1 = buffer consumed, 2 = error,
    #     0 = fall through to the driver registry);
    #   * otherwise the driver registry 0x261c2 is consulted (gate = bit 13 of
    #     [0x81b50], lookup id 0x2d via 0x320fe, offset table [0x81b60]).
    #
    # NOTE: on the USB dongle firmware the transport init (0x575e4, caller
    # 0x42408) that registers the stock TX driver (0x57879) runs late, so
    # TX_HOOK_CELL is 0 right after boot and the registry fallback is taken.
    TX_HOOK_CELL = 0x8C8A0       # transport TX callback cell
    TX_CELL_STOCK_DRIVER = 0x57878  # registered by 0x575e4 via setter 0x3e83a
    HCI_TX_DEFAULT_SEND = 0x261C2  # registry dispatcher: f(struct, buffer, len)
    HCI_TX_PRE_CHECK = 0x32214    # default driver pre-dispatch, returns 0 if unhandled
    HCI_TX_STRUCT = 0x852B8       # struct passed on the event path
    # full transport hook-cell map (all share the wrapper pattern
    # token -> bx-shim call(r0=buf, r1=&sp) -> token, rc: 1=consumed 2=error):
    #   0x8c89c: TX wrapper 0x2669c (fallback send 0x2aa30)
    #   0x8c8a0: TX wrapper 0x264a6 (fallback registry 0x261c2)  <- primary TX
    #   0x8c8a4: TX wrapper 0x266ea (fallback send path 0x26732)
    #   0x8c8a8: UART TX (stock 0x57831, inert on USB dongles)
    #   0x8c8ac: transport state-change callback (stock 0x3c029)
    #   0x8c8b0: flags word (live value 3), consulted by many LM paths
    #   0x8c8b8: managed by init 0x26a70 (cleared there)
    #   0x8c8bc: LMP connection patch hook (stock 0x942bd, consumer
    #            0x273b2 - LMP connection setup; called only when the
    #            connection passes the 0x121f4 filter check)
    LM_STATE_TABLE = 0x80200
    LM_STATE_COUNT = 12

    # ---- Verified-free hook placement areas (canary-tested live) ----
    # The patch-RAM tail beyond the loaded image (0x9b000+) is live firmware
    # data (43 code references) and MUST NOT be used. The following zero runs
    # survived repeated live traffic without being touched:
    #   0x810dc: 320 B, 0x8b379: 223 B, 0x8e4d3: 160 B, 0x8e8a0: 46 B (only the
    #   first 46 bytes are verified free), 0x8f20b: 224 B.
    HOOK_CODE_BASE = 0x8F20B
    TRACEPOINT_HOOKS_LOCATION = 0x8F20B
    TRACEPOINT_BODY_ASM_LOCATION = 0x810DC

    # ---- Tracepoints (upstream model; see fw_0x4208.py) ----
    # Stage-1 hook (installed at the tracepoint address) saves all registers,
    # calls the body snippet, restores and branches back. The body dumps the
    # register file into a vendor HCI event ("TRACE_").
    TRACEPOINT_HOOK_SIZE = 40
    TRACEPOINT_HOOK_ASM = """
            push {r0-r12, lr}       // save all registers on the stack (except sp and pc)
            ldr  r6, =0x%x          // addTracepoint() injects pc of original tracepoint here
            bl   0x%x               // addTracepoint() injects TRACEPOINT_BODY_ASM_LOCATION here
            pop  {r0-r12, lr}       // restore registers

            // branch back to the original instruction
            b 0x%x                  // addTracepoint() injects the address of the tracepoint
    """

    TRACEPOINT_BODY_ASM_SNIPPET = """
            mov   r8, lr     // save link register in r8

            // save status register in r5
            mrs  r5, cpsr

            // malloc HCI event buffer
            mov  r0, 0xff    // event code is 0xff (vendor specific HCI Event)
            mov  r1, 76      // buffer size: size of registers (68 bytes) + type and length + 'TRACE_'
            bl   0x2ABC6     // hci_allocateEventBlockWithLen(0xff, 78)
            mov  r4, r0      // save pointer to the buffer in r4

            // append our custom header (the word 'TRACE_') after the event code and event length field
            add  r0, 2            // write after the length field
            ldr  r1, =0x43415254  // 'TRAC'
            str  r1, [r0]
            add  r0, 4            // advance the pointer.
            ldr  r1, =0x5f45      // 'E_'
            strh r1, [r0]
            add  r0, 2            // advance the pointer. r0 now points to the start of the register values

            // store pc
            str  r6, [r0]    // r6 still contains the address of the original pc
            add  r0, 4       // advance the pointer.

            // store sp
            mov  r1, 56      // 14 saved registers * 4
            add  r1, sp
            str  r1, [r0]
            add  r0, 4       // advance the pointer.

            // store status register
            str  r5, [r0]
            add  r0, 4       // advance the pointer.

            // store other registers
            mov  r1, sp
            mov  r2, 56
            bl   0x54984   // memcpy(dst, src, len)

            // send HCI buffer to the host
            mov  r0, r4      // r4 still points to the beginning of the HCI buffer
            bl   0x2AADC     // hci_sendEvent

            // restore status register
            msr  cpsr_f, r5

            mov  lr, r8      // restore lr from r8
            bx   lr          // return
    """

    # ---- Hardware patch engine (ROM driver, static findings) ----
    # Unlike the BCM43430A1 (fw_0x2209), the patchram slot tables in RAM are not
    # yet identified. The ROM drives a register-based patch engine at
    # MMIO 0xe8074/0xe8080/0xe8088/0xe8200 (functions 0x31b30, 0x31bf6,
    # 0x31c16, kick 0x31e38). The vendor .hcd additionally programs the
    # 0x362e0000-0x3631ffff region at boot (see PATCHRAM_* of sibling fw files).
    # patchRom()/addTracepoint() install support therefore remains TODO; the
    # TRACEPOINT_* constants above are in place for when the slot tables are
    # mapped. HCI packet logging, readmem/writemem, queue inspection,
    # connection inspection and device info work with the fields above.
