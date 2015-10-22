try:
    import lldb
except:
    pass
import re
import os
import thread
import time

BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
BOLD = "\033[1m"
NONE = "\033[0m"
UNDERLINE = "\033[4m"

GlobalListOutput = []
old_regs_data_list = []
hook_stop_added = 0
oplist = [["", ""]] * 4

def wait_for_hook_stop():
    while True:
        res = lldb.SBCommandReturnObject()
        lldb.debugger.GetCommandInterpreter().HandleCommand("target stop-hook add -o \"HandleHookStopOnTarget\"", res)
        if res.Succeeded() == True: return
        time.sleep(0.05)


def __lldb_init_module(debugger, internal_dict):
    global hook_stop_added

    var = lldb.debugger.GetInternalVariableValue("stop-disassembly-count", lldb.debugger.GetInstanceName())
    if var.IsValid():
        var = var.GetStringAtIndex(0)
        if var == "0":
            return

    dbgcall("settings set target.x86-disassembly-flavor intel")
    dbgcall("command script add -f lldbinit.stepo stepo")
    dbgcall("command script add -f lldbinit.HandleHookStopOnTarget HandleHookStopOnTarget")
    dbgcall("command script add -f lldbinit.dd dd")
    dbgcall("command script add -f lldbinit.HandleHookStopOnTarget ctx")
    dbgcall("command script add -f lldbinit.HandleHookStopOnTarget context")

    thread.start_new_thread(wait_for_hook_stop, ())

    dbgcall("settings set stop-disassembly-count 0")
    return


def dbgcall(command):
    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetCommandInterpreter().HandleCommand(command, res)
    return res.GetOutput()


def output(x):
    global GlobalListOutput
    GlobalListOutput.append(x)


def dump_regs():
    reg_data = ["", "", ""]
    regs_data_list = []
    global res

    data = dbgcall("register read")
    #print data.split("\n")[1:-2]
    for reg in data.split("\n")[1:-2]:
        reg = reg.strip("        ").split("=")
        try:
            reg_data[0] = reg[0].strip(" ").upper()
            reg_data[1] = reg[1].split(" ")
            if len(reg_data[1]) > 3: reg_data[2] = reg_data[1][3]
            reg_data[1] = reg_data[1][1]
            regs_data_list.append(reg_data[::])
        except:
            continue

    return regs_data_list


def print_registers():
    global old_regs_data_list
    count = 0
    regs_data_list = dump_regs()
    reg_long_list = []

    for i in range(len(regs_data_list)):
        #print regs_data_list[i]
        regname = regs_data_list[i][0]
        regval = regs_data_list[i][1]
        #regstr = regs_data_list[i][2]

        if len(old_regs_data_list) == 0: old_regs_data_list = regs_data_list[::]

        old_regval = old_regs_data_list[i][1]

        if len(regname) > 3:
            reg_long_list.append([regname.upper(), regval])
            continue

        output(GREEN)
        output(regname)
        output(" " * (4 - len(regname)))

        if int(regval, 16) != int(old_regval, 16):
            output(RED)
        else:
            output(WHITE)

        output("%s  " % regval)
        count = count + 1
        if count == 5:
            count = 0
            output("\n")

    for i in reg_long_list:
        output(GREEN)
        output("%s " % i[0])
        output(WHITE)
        output("%s  " % i[1])

    old_regs_data_list = regs_data_list[::]
    output("\n")


def get_frame():
    ret = None

    for t in lldb.debugger.GetSelectedTarget().process:
        if t.GetStopReason() != lldb.eStopReasonNone and t.GetStopReason() != lldb.eStopReasonInvalid:
            ret = t.GetFrameAtIndex(0)

    return ret


def is_x64():
    if "64" in lldb.debugger.GetSelectedTarget().triple.split('-')[0]: return True
    return False


def is_arm():
    if "arm" in lldb.debugger.GetSelectedTarget().triple.split('-')[0]: return True
    return False


def breakline(name):
    if is_x64():
        return "%s%s%s%s%s\n" % (BLUE, "-" * (120 - len(name)), BOLD, name, NONE)
    return "%s%s%s%s%s\n" % (BLUE, "-" * (80 - len(name)), BOLD, name, NONE)


def get_mod_info():
    target = lldb.debugger.GetSelectedTarget()
    mod = target.GetModuleAtIndex(0)
    sec = mod.GetSectionAtIndex(0)
    loadaddr = sec.GetLoadAddress(target)
    return mod, sec, loadaddr


def dump_stacks():
    data = dbgcall("disassemble -p --count=1")
    try:
        asm = data.split("\n")[1].split(":")[1].split("    ")
    except:
        return

    try:
        #if "bl" or "blx" or "call" in asm: return
        opcode = asm[1].split(",", 1)

        global oplist
        for i in range(len(opcode)):
            op = opcode[i].strip(" ")
            if len(op) > 1:
                first = op.find("[")
                last = op.find("]")
                if first != -1 or last != -1:
                    subop = op[first+1:last]
                    subop = subop.split()
                    if len(subop) > 1: continue
                        #print subop
                        #addr = int(dbgcall("memory read $%s" % (subop)).split()[2], 16)
                        #oplist[i] = [op, dbgcall("memory read '*(int **)$%s'" % (op[1:-1]))]
                    else:
                        oplist[i] = ["[%s]".upper() % subop[0], dbgcall("memory read '*(int **)$%s'" % (subop[0]))]
                    continue
            if op[0].isalpha():
                oplist[i] = [op.upper(), dbgcall("memory read $%s" % (op))]

        printed = ""

        for op in oplist:
            if op[0] != "":
                if op[1] == "": op[1] = "0x0\n"
                if op[0] == printed: continue
                output("%s%s\n" % (GREEN, op[0]))
                output("%s%s" % (YELLOW, op[1]))
                output(NONE)
                printed = op[0]
                oplist = [["", ""]] * 4

    except Exception, e:
        print str(e)
        return

def HandleHookStopOnTarget(debugger, command, result, dict):
    if os.getenv('PATH').startswith('/Applications/Xcode.app'):
        return

    global GlobalListOutput
    debugger.SetAsync(True)
    frame = get_frame()

    if not frame: return

    thread = frame.GetThread()

    while True:
        frame = get_frame()
        thread = frame.GetThread()

        if thread.GetStopReason() == lldb.eStopReasonNone or thread.GetStopReason() == lldb.eStopReasonInvalid:
            time.sleep(0.001)
        else:
            break

    GlobalListOutput = []

    output(breakline("regs"))
    print_registers()

    output(breakline("info"))
    target = lldb.debugger.GetSelectedTarget()
    mod = target.GetModuleAtIndex(0)
    sec = mod.GetSectionAtIndex(0)
    loadaddr = sec.GetLoadAddress(target)

    if loadaddr == lldb.LLDB_INVALID_ADDRESS: loadaddr = 0x0

    output("%sLoaded Address: %s\n" % (CYAN, (loadaddr)))
    dump_stacks()

    output(breakline("asm"))
    output(dbgcall("disassemble -p --count=10"))
    output(breakline(""))

    output("Stop reason : " + str(thread.GetStopDescription(100)))  # str(dbg.GetSelectedTarget().process.selected_thread.GetStopDescription(100)))
    output("\r")
    data = "".join(GlobalListOutput)
    result.PutCString(data)
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
    return 0


def stepo(debugger, command, result, dict):
    global GlobalListOutput
    GlobalListOutput = []
    debugger.SetAsync(True)
    result.SetStatus(lldb.eReturnStatusSuccessFinishNoResult)

    err = lldb.SBError()
    target = lldb.debugger.GetSelectedTarget()
    res = lldb.SBCommandReturnObject()
    lldb.debugger.GetCommandInterpreter().HandleCommand("disassemble -p --count=2", res)
    stuff = res.GetOutput()

    if res.Succeeded() != True:
        output("[X] Error in stepo... can't disassemble at pc")
        return

    stuff = stuff.splitlines(True)
    p = re.compile("0x[\da-fA-F]{4,16}")
    try:
        current_pc = p.search(stuff[0]).group(0)
    except:
        stuff = stuff[1:]
        current_pc = p.search(stuff[0]).group(0)

    next_pc = p.search(stuff[1]).group(0)

    current_pc = long(current_pc, 16)
    next_pc = long(next_pc, 16)

    pc_inst = stuff[0].split(": ")[1]
    pc_inst = pc_inst.split()[0]

    if "call" or "movs" or "stos" or "loop" or "cmps" or "blx" or "bl" in pc_inst:
        breakpoint = target.BreakpointCreateByAddress(next_pc)
        breakpoint.SetOneShot(True)
        breakpoint.SetThreadID(get_frame().GetThread().GetThreadID())
        target.GetProcess().Continue()
    else:
        lldb.debugger.GetSelectedTarget().process.selected_thread.StepInstruction(False)

