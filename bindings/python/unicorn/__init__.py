# Forwarding defs for compatibility
from . import arm_const, arm64_const, mips_const, sparc_const, m68k_const, x86_const, riscv_const, s390x_const, tricore_const
from .unicorn_const import *
from .unicorn import Uc, ucsubclass, uc_version, uc_arch_supported, version_bind, debug, UcError, __version__
