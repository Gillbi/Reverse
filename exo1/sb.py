from pdb import pm
from miasm.analysis.sandbox import Sandbox_Win_x86_32
from miasm.core.locationdb import LocationDB
import struct
from miasm.os_dep.common import get_win_str_w, get_win_str_a, set_win_str_w
# Insert here user defined methods
def ole32_CoInitializeEx(jitter):
    S_OK = 0
    ret_ad, _ = jitter.func_args_stdcall(["pvReserved", "dwCoInit"])
    jitter.func_ret_stdcall(ret_ad, S_OK)

def ntdll_swprintf(jitter):
    ret_ad, args = jitter.func_args_stdcall(["buffer", "fmt"])
    fmt = get_win_str_w(jitter, args.fmt)
    if fmt == "%S":
        argl = jitter.pop_uint32_t()
        print(hex(argl))
        toto = get_win_str_a(jitter, argl)
        print(toto)
        set_win_str_w(jitter, args.buffer, toto)
        l = len(toto)
    elif fmt == '/c start "" "%s"':
        argl = jitter.pop_uint32_t()
        print(hex(argl))
        toto = get_win_str_w(jitter, argl)
        print(fmt%toto)
        set_win_str_w(jitter, args.buffer, fmt%toto)
        l = len(toto)
    else:
       fds 
    jitter.func_ret_stdcall(ret_ad, l)
    
   
def urlmon_URLDownloadToCacheFileW(jitter):
    S_OK = 0
    ret_ad, args = jitter.func_args_stdcall(["lpUnkcaller", "szURL", "szFileName", "cchFileName", "dwReserved", "pBSC"])
    url = get_win_str_w(sb.jitter, 0x20000000)
    set_win_str_w(jitter, args.szFileName, "toto")
    print("URL: ", url)
    jitter.func_ret_stdcall(ret_ad, S_OK)


def kernel32_CreateProcessW(jitter):
    ret_ad, args = jitter.func_args_stdcall(["lpApplicationName","ntdll.dll","lpCommandLine","lpProcessAttributes","lpThreadAttributes","bInheritHandles","dwCreationFlags", "lpEnvironment","lpCurrentDirectory","lpStartupInfo", "lpProcessInformation"])
    print(get_win_str_w(jitter, args[0]))
    jitter.func_ret_stdcall(ret_ad, 1)

def dump_hash(jitter):
    print("hash:", hex(jitter.cpu.EDI))
    return False

# Parse arguments
parser = Sandbox_Win_x86_32.parser(description="PE sandboxer")
parser.add_argument("filename", help="PE Filename")
options = parser.parse_args()

# Create sandbox
loc_db = LocationDB()
sb = Sandbox_Win_x86_32(loc_db, options.filename, options, globals())
sb.jitter.vm.add_memory_page(0x7FFDF008, PAGE_READ | PAGE_WRITE, "1", "0")

#sb.jitter.vm.add_memory_page(0x7FF70000+0x34, 7, struct.pack("<L", 0x2E4))
sb.jitter.cpu.EAX = 0x401000

# Run
sb.run()
assert(sb.jitter.running is False)
sb.jitter.add_breakpoint(0x4010D8,dump_hash )

