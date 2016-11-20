## Circumventing OpenBSD 6.0's W^X Protections

OpenBSD 6.0 and above enforces data-execution prevention (DEP or
W^X) by default, preventing memory from being mapped as 
simultaneously writeable and executable (i.e., W|X). This causes
problems for Unicorn, if left in place.  If you're seeing
errors like the following:
```
/home/git/unicorn >> ./sample_arm
Emulate ARM code
zsh: abort (core dumped)  ./sample_arm
```
then W^X is likely the culprit. If we run it again with ktrace
and look at the output with kdump, we see that this is indeed
the issue:
``` 
 82192 sample_arm CALL  mmap(0,0x800000,0x7<PROT_READ|PROT_WRITE|PROT_EXEC>,0x1002<MAP_PRIVATE|MAP_ANON>,-1,0)
 82192 sample_arm PSIG  SIGABRT SIG_DFL
 82192 sample_arm NAMI  "sample_arm.core"
```
Right now, we're in the /home filesystem. Let's look at its mount
options in /etc/fstab:
```
1234abcdcafef00d.g /home ffs rw,nodev,nosuid 1 2
```
If we edit the options to include ```wxallowed```, appending
this after nosuid, for example, then we're golden:
```
1234abcdcafef00d.g /home ffs rw,nodev,nosuid,wxallowed 1 2
```

Note that this *does* diminish the security of your filesystem 
somewhat, and so if you're particularly particular about such
things, we recommend setting up a dedicated filesystem for 
any activities that require ```(W|X)```, such as unicorn
development and testing. 

In order for these changes to take effect, you will need to
reboot. 

_Time passes..._

Let's try this again. There's no need to recompile unicorn or 
the samples, as (W^X) is strictly a runtime issue. 

First, we double check to see if /home has been mounted with
wxallowed:
```
/home >> mount | grep home
/dev/sd3g on /home type ffs (local, nodev, nosuid, wxallowed)
```
Okay, now let's try running that sample again...
```
/home/git/unicorn/samples >> ./sample_arm
Emulate ARM code
>>> Tracing basic block at 0x10000, block size = 0x8
>>> Tracing instruction at 0x10000, instruction size = 0x4
>>> Emulation done. Below is the CPU context
>>> R0 = 0x37
>>> R1 = 0x3456
==========================
Emulate THUMB code
>>> Tracing basic block at 0x10000, block size = 0x2
>>> Tracing instruction at 0x10000, instruction size = 0x2
>>> Emulation done. Below is the CPU context
>>> SP = 0x1228
```
works fine. 

