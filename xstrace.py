#coding:utf-8

import os, sys, re, glob, socket, struct 
import time, subprocess, ctypes, json


class Process():
    def __init__(self):
        self.process_dict = {}
    
    def _getProcessInfo(self, pid):
        pinfo = {
            'pid': pid,
            'comm': '',
            'exe': '',
            'ppid': 0,
            'cmdline': '',
        }
        try:
            with open('/proc/%d/comm' % pid, 'rb') as f:
                pinfo['comm'] = f.read().rstrip()
        except:
            pass 
        
        try:
            pinfo['exe'] = os.readlink('/proc/%d/exe' % pid)
        except:
            pass 

        try:
            with open('/proc/%d/cmdline' % pid, 'rb') as f:
                pinfo['cmdline'] = ' '.join(f.read(1024).split('\x00')).rstrip()
        except:
            pass 

        return pinfo
    

    def update_fork(self, pid, ppid):
        if ppid not in self.process_dict:
            self.process_dict[ppid] = self._getProcessInfo(ppid)
        
        self.process_dict[pid] = self.process_dict[ppid].copy()
        self.process_dict[pid]['ppid'] = ppid

        # print 'fork', self.process_dict

    def update_exec(self, pid, comm, cmdline, exe): 
        # if pid not in self.process_dict:
        ppid = self.process_dict.get(pid, {}).get('ppid', 0)
        # pinfo = self._getProcessInfo(pid)
        pinfo = {}
        pinfo['ppid'] = ppid
        pinfo['comm'] = comm
        pinfo['exe'] = exe 
        pinfo['cmdline'] = cmdline
        
        self.process_dict[pid] = pinfo

    def get_process(self, pid):
        if pid not in self.process_dict:
            self.process_dict[pid] = self._getProcessInfo(pid)

        ppid = self.process_dict[pid].get('ppid', 0)
        ppinfo = self.process_dict.get(ppid, {})
        return self.process_dict[pid], ppinfo



class Network():
    @classmethod 
    def hex2ip(cls, hexip):
        return socket.inet_ntoa(struct.pack("<L", int(hexip, 16)))

    @classmethod 
    def hex2port(cls, hexport):
        return socket.htons(int(hexport, 16))

### 
# uprobe: r:uprobes/readline /usr/bin/bash:0x000000000008aea0 bash_readline=+0($retval):string
# bash uprobe.sh  -F 'p:/lib64/libc.so.6:getaddrinfo +0(%di):string' | grep getaddrinfo
class Uprobe():
    def getLibAbspath(self, libname):
        # from ctypes import *
        import ctypes
        from ctypes.util import find_library
        #linkmap structure, we only need the second entry
        class LINKMAP(ctypes.Structure):
            _fields_ = [
                ("l_addr", ctypes.c_void_p),
                ("l_name", ctypes.c_char_p)
            ]

        # libc = CDLL(find_library('c'))
        libc = ctypes.CDLL(find_library(libname))

        if libc is None:
            return ''

        libdl = ctypes.CDLL(find_library('dl'))

        dlinfo = libdl.dlinfo
        dlinfo.argtypes  = ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p
        dlinfo.restype = ctypes.c_int

        #gets typecasted later, I dont know how to create a ctypes struct pointer instance
        lmptr = ctypes.c_void_p()

        #2 equals RTLD_DI_LINKMAP, pass pointer by reference
        dlinfo(libc._handle, 2, ctypes.byref(lmptr))

        #typecast to a linkmap pointer and retrieve the name.
        abspath = ctypes.cast(lmptr, ctypes.POINTER(LINKMAP)).contents.l_name

        return abspath

    def getBaseAddress(self, filepath):
        raw_output = subprocess.check_output(['objdump', '-x', filepath])
        for line in raw_output.splitlines():
            cols = line.split()
            if len(cols) > 5:
                if cols[0] == 'LOAD' and cols[2].startswith('0x'):
                    return int(cols[4], 16)

        raise "Can not find elf base address"
    
    def getSymAddress(self, filepath,  symname):
        raw_output = subprocess.check_output(['objdump', '-tT', filepath])
        for line in raw_output.splitlines():
            cols = line.split()
            if len(cols) >= 7:
                if cols[3] == '.text' and cols[6] == symname:
                    return int(cols[0], 16)

        raise "Can not find elf sym address"

    def getMemAddress(self, filepath, symname):
        return self.getSymAddress(filepath, symname) - self.getBaseAddress(filepath)


    ## java
    ## /usr/lib/jvm/java-1.8.0-openjdk-1.8.0.262.b10-0.el7_8.x86_64/jre/lib/amd64/server/libjvm.so
    #   stapsdt              0x00000062       NT_STAPSDT (SystemTap probe descriptors)
    # Provider: hotspot
    # Name: method__entry
    # Location: 0x00000000009eb7ad, Base: 0x0000000000bfdc98, Semaphore: 0x0000000000000000
    # Arguments: -8@%rax 8@%rdx -4@%ecx 8@%rsi -4@%edi 8@%r8 -4@%r9d

class xstrce():

    def __init__(self):
        self.tracer_name = 'xstrace'
        # self.dir_tracing = '/sys/kernel/debug/tracing/instances/%s' % self.tracer_name
        self.dir_tracing = '/sys/kernel/debug/tracing/'

        if not os.path.exists(self.dir_tracing):
            os.mkdir(self.dir_tracing)

        self.bits = 64
        self.offset = self.bits/8
        self.path_kprobe_events = os.path.join(self.dir_tracing, 'kprobe_events')
        self.path_uprobe_events = os.path.join(self.dir_tracing, 'uprobe_events')
        self.path_fork_enable = os.path.join(self.dir_tracing, 'events/sched/sched_process_fork/enable')
        self.path_result_pipe = os.path.join(self.dir_tracing, 'trace_pipe')
        self.dir_kprobe_events = os.path.join(self.dir_tracing, 'events/kprobes')

        self.kprobe_config = {
            'xstrace_exec': self.get_exec_kprobe_string('xstrace_exec'),
            'xstrace_open': 'p:xstrace_open do_sys_open filename=+0(%si):string flags=%cx mode=+4($stack)',
            'xstrace_tcp': 'p:xstrace_tcp tcp_connect saddr=+4(%di):u32 daddr=+0(%di):u32 sport=+14(%di):u16 dport=+12(%di):u16',
            'xstrace_connect': self.get_connect_kprobe_string('xstrace_connect'),
            'xstrace_kill': 'p:xstrace_kill sys_kill pid=%di:u32 signal=%si:u32',
            'xstrace_ptrace': 'p:xstrace_ptrace sys_ptrace request=%di:u32 pid=%si:u32',
        }
        self.kprobe_raw = {
            # 'sys_enter_kill': os.path.join(self.dir_tracing, 'events/syscalls/sys_enter_kill/enable'),
            # 'sys_enter_connect': os.path.join(self.dir_tracing, 'events/syscalls/sys_enter_connect/enable'),
            'sched_process_fork': os.path.join(self.dir_tracing, 'events/sched/sched_process_fork/enable'),            
        }
        
        uprober = Uprobe()
        # uprobe: r:uprobes/readline /usr/bin/bash:0x000000000008aea0 bash_readline=+0($retval):string
        self.uprobe_config = {
            'xs_bash_readline': 'r:uprobes/xs_bash_readline /usr/bin/bash:0x%X bash_readline=+0($retval):string' % uprober.getMemAddress('/usr/bin/bash', 'readline'),
            'xs_libc_getaddrinfo': 'p:uprobes/xs_libc_getaddrinfo %s:0x%x name=+0(%%di):string'  % (uprober.getLibAbspath('c'), uprober.getMemAddress(uprober.getLibAbspath('c'), 'getaddrinfo')),
            'xs_dlopen': 'p:uprobes/xs_dlopen %s:0x%x dlname=+0(%%di):string'  % (uprober.getLibAbspath('dl'), uprober.getMemAddress(uprober.getLibAbspath('dl'), 'dlopen'))
        }
        print self.uprobe_config

        self.process_util = Process()

        print self.dir_kprobe_events

    def get_enable_path(self, kname):
        return os.path.join(self.dir_tracing, 'events/kprobes/%s/enable' % kname)
    
    def get_enable_path_uprobe(self, kname):
        return os.path.join(self.dir_tracing, 'events/uprobes/%s/enable' % kname)

    def get_exec_kprobe_string(self, kname):
        kprobe = "p:%s %s exe=+0(%%di):string" % (kname, 'sys_execve')
        for i in range(8):
            kprobe = '%s +0(+%d(%%si)):string'  % (kprobe, i*self.offset)
        return kprobe

    def get_connect_kprobe_string(self, kname):
        s = [
            ("info_family", "+4(%si):s32"),
            ("info_socktype", "+8(%si):s32"),
            ("info_ipv4", "+24(%si):u32"),
            ("info_ipv6_1", "+28(%si):u64"),
            ("info_ipv6_2", "+36(%si):u64"),
            ("info_port", "+22(%si):u16"),
            ("sock_ipv4", "+4(%si):u32"),
            ("sock_ipv6_1", "+8(%si):u64"),
            ("sock_ipv6_2", "+16(%si):u64"),
            ("sock_family", "+0(%si):s16"),
            ("sock_port", "+2(%si):u16")
        ]
        result = []
        for i in s:
            name = i[0]
            content = i[1]
            result.append('%s=%s' % (name, content))

        result = 'p:%s sys_connect %s' % (kname, ' '.join(result))

        print result

        return result


    def parse_raw_log(self, raw_info):
        rgx = r'(?:(?<=\n)|^)\s*(.{1,16})\-(\d+)\s*\S+\s\S+\s+\S+\s(\w+):\s(?:\(.+?\)\s)?(.+)'

        # debuger
        if 'xs_dlopen' in raw_info:
            print raw_info

        for i in re.finditer(rgx, raw_info):
            data = dict(
                comm = i.group(1),
                pid = int(i.group(2)),
                tracer_name = i.group(3),
                args = i.group(4),
                args_dict = {},
            )

            if data['tracer_name'] == 'xstrace_exec':
                # print data['args']
                exe = ''
                cmdline_arr = []

                m_exe = re.match(r'exe="(.+?)" arg2=', data['args'])
                if m_exe:
                    exe = m_exe.group(1)

                for m_exec in re.finditer(r'(arg\d+)=([\s\S]+?)(?=\sarg|$)', data['args']):
                
                    arg_key = m_exec.group(1)
                    arg_val = m_exec.group(2)

                    if arg_val == "(fault)":
                        break

                    if len(arg_val) > 2:
                        arg_val = arg_val[1:-1]

                    cmdline_arr.append(arg_val)

                cmdline = ' '.join(cmdline_arr)


                self.process_util.update_exec(data['pid'], comm=data['comm'], cmdline=cmdline, exe=exe)
                pinfo, ppinfo = self.process_util.get_process(data['pid'])

                newdata = dict(
                    logType='exec',
                    pid=data['pid'],
                    comm=data['comm'],
                    exe=exe,
                    cmdline=cmdline,
                    ppid=ppinfo.get('pid', 0),
                    pcmdline=ppinfo.get('cmdline', ''),
                )

                yield newdata
                # print data['args']

            elif data['tracer_name'] == 'xstrace_open':
                m_open = re.match(r'filename="(.+)"\sflags=(\w+)\smode=(\w+)$', data['args'])
                if m_open:
                    pinfo, ppinfo = self.process_util.get_process(data['pid'])
                    newdata = dict(
                        logType='open',
                        pid=data['pid'],
                        comm=data['comm'],
                        exe=pinfo['exe'],
                        cmdline=pinfo['exe'],
                        ppid=ppinfo.get('pid', 0),
                        pcmdline=ppinfo.get('cmdline', ''),
                        filepath=m_open.group(1),
                        flags=m_open.group(2),
                        mode=m_open.group(3),
                    )
                    yield newdata


            elif data['tracer_name'] == 'xstrace_connect':
                tmpdict = {}
                for m_connect in re.finditer(r'(?:(\w+)=(\w+)(?:\s|$))', data['args']):
                    tmpdict[m_connect.group(1)] = m_connect.group(2)
                if tmpdict['sock_family'] == '2':
                    dst_ip = Network.hex2ip(tmpdict['sock_ipv4'])
                    dst_port = Network.hex2port(tmpdict['sock_port'])
                    data['args_dict'] = {
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        # 'sock_family': tmpdict['sock_family']
                    }
                # print tmpdict
            
            elif data['tracer_name'] == 'xstrace_kill':
                m = re.match(r'pid=(\w+)\ssignal=(\w+)', data['args'])
                if m:
                    signal = int(m.group(2), 16)
                    if signal > 0:
                        target_pid = int(m.group(1), 16)

                        pinfo, ppinfo = self.process_util.get_process(data['pid'])

                        newdata = dict(
                            logType='kill',
                            pid=data['pid'],
                            comm=data['comm'],
                            exe=pinfo['exe'],
                            cmdline=pinfo['cmdline'],
                            signal=signal,
                            target_pid=target_pid,
                        )

                        yield newdata

            elif data['tracer_name'] == 'xstrace_tcp':
                # saddr=0xc2fe10ac daddr=0x9426b5dc sport=0xe7cc dport=0x5000
                m = re.match(r'saddr=(\w+) daddr=(\w+) sport=(\w+) dport=(\w+)', data['args'])
                if m:
                    
                    pinfo, ppinfo = self.process_util.get_process(data['pid'])

                    newdata = dict(
                        logType='tcp_connect',
                        pid=data['pid'],
                        comm=data['comm'],
                        exe=pinfo['exe'],
                        cmdline=pinfo['cmdline'],
                        src_ip= Network.hex2ip(m.group(1)),
                        dst_ip= Network.hex2ip(m.group(2)),
                        src_port= Network.hex2port(m.group(3)),
                        dst_port= Network.hex2port(m.group(4)),
                    )
                    yield newdata


            elif data['tracer_name'] == 'sched_process_fork':
                m = re.match(r'comm=.+ pid=(\d+) child_comm=(.+) child_pid=(\d+)', data['args'])
                if m:
                    pid = int(m.group(3))
                    ppid = int(data['pid'])
                    

                    self.process_util.update_fork(pid, ppid)

                    # print 'fork %d -> %d' % (ppid, pid)
            
            elif data['tracer_name'] == 'xstrace_ptrace':
                m = re.match(r'request=(\w+) pid=(\w+)', data['args'])
                if m:
                    request = int(m.group(1), 16)
                    target_pid = int(m.group(2), 16)

                    pinfo, ppinfo = self.process_util.get_process(data['pid'])

                    newdata = dict(
                        logType='ptrace',
                        pid=data['pid'],
                        comm=data['comm'],
                        exe=pinfo['exe'],
                        cmdline=pinfo['cmdline'],
                        ptrace_request=request,
                        ptrace_target_pid=target_pid,
                    )

                    yield newdata
            
            elif data['tracer_name'] == 'xs_bash_readline':
                m = re.match(r'bash_readline="(.+)"$', data['args'])
                if m:
                    pinfo, ppinfo = self.process_util.get_process(data['pid'])
                    the_line = m.group(1)
                    newdata = dict(
                        logType='bash_readline',
                        pid=data['pid'],
                        comm=data['comm'],
                        exe=pinfo['exe'],
                        cmdline=pinfo['cmdline'],
                        line=the_line,
                    )

                    yield newdata

            elif data['tracer_name'] == 'xs_libc_getaddrinfo':
                m = re.match(r'name="(.+)"$', data['args'])
                if m:
                    pinfo, ppinfo = self.process_util.get_process(data['pid'])
                    the_line = m.group(1)
                    newdata = dict(
                        logType='getaddrinfo',
                        pid=data['pid'],
                        comm=data['comm'],
                        exe=pinfo['exe'],
                        cmdline=pinfo['cmdline'],
                        line=the_line,
                    )

                    yield newdata

            '''
            if len(data['args_dict']) == 0:
                print data 
            else:
                print data['tracer_name'], data['pid'], data['comm'], data['args_dict']
            '''


    
    def clean_up(self):
        # clear

        for fullpath in glob.glob('%s/events/*/*/enable' % self.dir_tracing):
            if os.path.exists(fullpath):
                with open(fullpath, 'wb') as f:
                    f.write('0')

        with open(self.path_kprobe_events, 'wb') as f:
            f.write('')

    def start_tracing(self):

        # print 'kprobe', self.kprobe_config

        self.clean_up()
        

        #  setup raw kprobe
        for enable_path in self.kprobe_raw.values():
            with open(enable_path, 'wb') as f:
                f.write('1')

        # setup function kprobe 
        with open(self.path_kprobe_events, 'wb') as f:
            f.write('\n'.join(self.kprobe_config.values()))

        for kname, kconfig in self.kprobe_config.items():
            with open(self.get_enable_path(kname), 'wb') as f:
                f.write('1')

        # setup uprobe
        with open(self.path_uprobe_events, 'wb') as f:
            f.write('\n'.join(self.uprobe_config.values()))
        
        for kname, kconfig in self.uprobe_config.items():
            with open(self.get_enable_path_uprobe(kname), 'wb') as f:
                f.write('1')

        
        '''
        with open(self.path_result_pipe, 'rb') as f:
            while True:
                raw = f.read(4096)
                print '~', raw 
        '''

        fd = os.open(self.path_result_pipe, os.O_RDONLY)
        # os.read(fd)
        while True:
            # time.sleep(0.1)
            buf = os.read(fd, 1024 * 8)
            # print buf 
            for log in self.parse_raw_log(buf):
                logType = log['logType']
                
                yield logType, log


### todo 
### dns udp icmp kill ptrace dlopen mv java mysql http redis getdents modinit 



def log_to_file(filepath='/var/log/xstrace'):
    tracer = xstrce()

    with open(filepath, mode='wb') as f:
        for log in tracer.start_tracing():
            f.write(json.dumps(log))
            f.write('\n')
            f.flush()
            
if __name__ == "__main__":
    # print 123
    
    log_to_file()
