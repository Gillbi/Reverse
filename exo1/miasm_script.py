from argparse import ArgumentParser
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.os_dep.common import set_win_str_w
from pdb import pm

parser = ArgumentParser(description="x86 32 basic Jitter")
parser.add_argument("filename", help="x86 32 shellcode filename")
parser.add_argument("-j", "--jitter",
                    help="Jitter engine (default is 'gcc')",
                    default="gcc")
args = parser.parse_args()

def code_sentinelle(jitter):
    print("Breakpoint!")
    jitter.running = False
    jitter.pc = 0
    return True

def dump_shellcode(jitter):
    jitter.vm.get_mem(run_addr, len(data))
    open("dump.bin", "wb").write(dump)
    return False


loc_db = LocationDB()

myjit = Machine("x86_32").jitter(loc_db, args.jitter)
myjit.init_stack()


data = open(args.filename, 'rb').read()
run_addr = 0x40000000
myjit.vm.add_memory_page(run_addr, PAGE_READ | PAGE_WRITE, data)

myjit.set_trace_log(trace_regs=False, trace_instr=False  , trace_new_blocks=True)
#myjit.set_trace_log()
myjit.push_uint32_t(0x1337beef)

#myjit.add_breakpoint(0x40000057, dump_shellcode)
myjit.cpu.EAX = run_addr

myjit.run(run_addr)
