/*

Ruby bindings for the Unicorn Emulator Engine

Copyright(c) 2016 Sascha Schirra

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
#include "ruby.h"
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include "unicorn.h"
#include "types.h"

VALUE UnicornModule = Qnil;
VALUE UcClass = Qnil;
VALUE UcError = Qnil;
VALUE SavedContext = Qnil;
VALUE Hook = Qnil;


void Init_unicorn_engine() {
    rb_require("unicorn_engine/unicorn_const");
    UnicornModule = rb_define_module("UnicornEngine");
    UcError = rb_define_class_under(UnicornModule, "UcError", rb_eStandardError);
    SavedContext = rb_define_class_under(UnicornModule, "SavedContext", rb_cObject);
    Hook = rb_define_class_under(UnicornModule, "Hook", rb_cObject);
    
    UcClass = rb_define_class_under(UnicornModule, "Uc", rb_cObject);
    rb_define_method(UcClass, "initialize", m_uc_initialize, 2);
    rb_define_method(UcClass, "emu_start", m_uc_emu_start, -1);
    rb_define_method(UcClass, "emu_stop", m_uc_emu_stop, 0);
    rb_define_method(UcClass, "reg_read", m_uc_reg_read, 1);
    rb_define_method(UcClass, "reg_write", m_uc_reg_write, 2);
    rb_define_method(UcClass, "mem_read", m_uc_mem_read, 2);
    rb_define_method(UcClass, "mem_write", m_uc_mem_write, 2);
    rb_define_method(UcClass, "mem_map", m_uc_mem_map, -1);
    rb_define_method(UcClass, "mem_unmap", m_uc_mem_unmap, 2);
    rb_define_method(UcClass, "mem_protect", m_uc_mem_protect, 3);
    rb_define_method(UcClass, "hook_add", m_uc_hook_add, -1);
    rb_define_method(UcClass, "hook_del", m_uc_hook_del, 1);
    rb_define_method(UcClass, "query", m_uc_query, 1);
    rb_define_method(UcClass, "context_save", m_uc_context_save, 0);
    rb_define_method(UcClass, "context_update", m_uc_context_update, 1);
    rb_define_method(UcClass, "context_restore", m_uc_context_restore, 1);
}

VALUE m_uc_initialize(VALUE self, VALUE arch, VALUE mode) {
    uc_engine *_uc;
    uc_err err;
    err = uc_open(NUM2INT(arch), NUM2INT(mode), &_uc);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }

    VALUE uc = Data_Wrap_Struct(UcClass, 0, uc_close, _uc);
    rb_iv_set(self, "@uch", uc);
    rb_iv_set(self, "@hooks", rb_ary_new());
    
    return self;
}

VALUE m_uc_emu_start(int argc, VALUE* argv, VALUE self){
    VALUE begin;
    VALUE until;
    VALUE timeout;
    VALUE count;
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);

    rb_scan_args(argc, argv, "22",&begin, &until, &timeout, &count);
    if (NIL_P(timeout))
        timeout = INT2NUM(0);

    if (NIL_P(count))
        count = INT2NUM(0);

    err = uc_emu_start(_uc, NUM2ULL(begin), NUM2ULL(until), NUM2INT(timeout), NUM2INT(count));
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}

VALUE m_uc_emu_stop(VALUE self){
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);

    err = uc_emu_stop(_uc);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}

VALUE m_uc_reg_read(VALUE self, VALUE reg_id){
    uc_err err;
    int32_t tmp_reg = NUM2INT(reg_id);
    int64_t reg_value = 0;
    VALUE to_ret;
    uc_x86_mmr mmr;
    uc_x86_float80 float80;

    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);

    uc_arch arch;
    uc_query(_uc, UC_QUERY_ARCH, &arch);

    if(arch == UC_ARCH_X86) {
        switch(tmp_reg){
            case UC_X86_REG_GDTR:
            case UC_X86_REG_IDTR:
            case UC_X86_REG_LDTR:
            case UC_X86_REG_TR:
                mmr.selector = 0;
                mmr.base = 0;
                mmr.limit = 0;
                mmr.flags = 0;
                err = uc_reg_read(_uc, tmp_reg, &mmr);

                if (err != UC_ERR_OK) {
                  rb_raise(UcError, "%s", uc_strerror(err));
                }
                VALUE mmr_ary = rb_ary_new();
                reg_value = mmr.selector;
                rb_ary_store(mmr_ary, 0, UINT2NUM(reg_value));
                rb_ary_store(mmr_ary, 1, ULL2NUM(mmr.base));
                rb_ary_store(mmr_ary, 2, UINT2NUM(mmr.limit));
                rb_ary_store(mmr_ary, 3, UINT2NUM(mmr.flags));
                return mmr_ary;

            case UC_X86_REG_FP0:
            case UC_X86_REG_FP1:
            case UC_X86_REG_FP2:
            case UC_X86_REG_FP3:
            case UC_X86_REG_FP4:
            case UC_X86_REG_FP5:
            case UC_X86_REG_FP6:
            case UC_X86_REG_FP7:
                float80.mantissa = 0;
                float80.exponent = 0;

                err = uc_reg_read(_uc, tmp_reg, &float80);

                if (err != UC_ERR_OK) {
                    rb_raise(UcError, "%s", uc_strerror(err));
                }

                VALUE float80_ary = rb_ary_new();

                rb_ary_store(float80_ary, 0, ULL2NUM(float80.mantissa));
                rb_ary_store(float80_ary, 1, UINT2NUM(float80.exponent));

                return float80_ary;
        }
    }
    if(arch == UC_ARCH_ARM64) {
        // V & Q registers are the same
        if(tmp_reg >= UC_ARM64_REG_V0 && tmp_reg <= UC_ARM64_REG_V31) {
            tmp_reg += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
        }
        if(tmp_reg >= UC_ARM64_REG_Q0 && tmp_reg <= UC_ARM64_REG_Q31) {
            uint64_t neon128_value[2];
            err = uc_reg_read(_uc, tmp_reg, &neon128_value);
            if (err != UC_ERR_OK) {
              rb_raise(UcError, "%s", uc_strerror(err));
            }
            VALUE float128_ary = rb_ary_new();
            rb_ary_store(float128_ary, 0, ULL2NUM(neon128_value[0]));
            rb_ary_store(float128_ary, 1, ULL2NUM(neon128_value[1]));
            return float128_ary;
        }
    }
    err = uc_reg_read(_uc, tmp_reg, &reg_value);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return ULL2NUM(reg_value);
}

VALUE m_uc_reg_write(VALUE self, VALUE reg_id, VALUE reg_value){
    uc_err err;
    int32_t tmp_reg = NUM2INT(reg_id);
    uc_x86_mmr mmr;
    uc_x86_float80 float80;
    int64_t tmp;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);
    
    uc_arch arch;
    uc_query(_uc, UC_QUERY_ARCH, &arch);

    if(arch == UC_ARCH_X86) {
        switch(tmp_reg){
            case UC_X86_REG_GDTR:
            case UC_X86_REG_IDTR:
            case UC_X86_REG_LDTR:
            case UC_X86_REG_TR:
                Check_Type(reg_value, T_ARRAY);

                mmr.selector = NUM2USHORT(rb_ary_entry(reg_value,0));
                mmr.base = NUM2ULL(rb_ary_entry(reg_value,1));
                mmr.limit = NUM2UINT(rb_ary_entry(reg_value,2));
                mmr.flags = NUM2UINT(rb_ary_entry(reg_value,3));
                err = uc_reg_write(_uc, tmp_reg, &mmr);
                if (err != UC_ERR_OK) {
                  rb_raise(UcError, "%s", uc_strerror(err));
                }
                return Qnil;

            case UC_X86_REG_FP0:
            case UC_X86_REG_FP1:
            case UC_X86_REG_FP2:
            case UC_X86_REG_FP3:
            case UC_X86_REG_FP4:
            case UC_X86_REG_FP5:
            case UC_X86_REG_FP6:
            case UC_X86_REG_FP7:
                Check_Type(reg_value, T_ARRAY);

                float80.mantissa = NUM2ULL(rb_ary_entry(reg_value,0));
                float80.exponent = NUM2USHORT(rb_ary_entry(reg_value,1));

                err = uc_reg_write(_uc, tmp_reg, &float80);

                if (err != UC_ERR_OK) {
                  rb_raise(UcError, "%s", uc_strerror(err));
                }

                return Qnil;
        }
    }
    if(arch == UC_ARCH_ARM64) {
        // V & Q registers are the same
        if(tmp_reg >= UC_ARM64_REG_V0 && tmp_reg <= UC_ARM64_REG_V31) {
            tmp_reg += UC_ARM64_REG_Q0 - UC_ARM64_REG_V0;
        }
        if(tmp_reg >= UC_ARM64_REG_Q0 && tmp_reg <= UC_ARM64_REG_Q31) {
            Check_Type(reg_value, T_ARRAY);

            uint64_t neon128_value[2];
            neon128_value[0] = NUM2ULL(rb_ary_entry(reg_value, 0));
            neon128_value[1] = NUM2ULL(rb_ary_entry(reg_value, 1));
            err = uc_reg_write(_uc, NUM2INT(reg_id), &neon128_value);
            if (err != UC_ERR_OK) {
              rb_raise(UcError, "%s", uc_strerror(err));
            }
            return Qnil;
        }
    }
    
    tmp = NUM2ULL(reg_value);
    err = uc_reg_write(_uc, NUM2INT(reg_id), &tmp);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}

VALUE m_uc_mem_read(VALUE self, VALUE address, VALUE size){
    size_t isize = NUM2UINT(size);
    uint8_t bytes[isize];
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);

    err = uc_mem_read(_uc, NUM2ULL(address), &bytes, isize);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return rb_str_new(bytes, isize);
}

VALUE m_uc_mem_write(VALUE self, VALUE address, VALUE bytes){
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);
    err = uc_mem_write(_uc, NUM2ULL(address), StringValuePtr(bytes), RSTRING_LEN(bytes));
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}

VALUE m_uc_mem_map(int argc, VALUE* argv, VALUE self){
    uc_err err;
    VALUE address;
    VALUE size;
    VALUE perms;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);
    rb_scan_args(argc, argv, "21",&address, &size, &perms);
    if (NIL_P(perms))
        perms = INT2NUM(UC_PROT_ALL);

    err = uc_mem_map(_uc, NUM2ULL(address), NUM2UINT(size), NUM2UINT(perms));
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}

VALUE m_uc_mem_unmap(VALUE self, VALUE address, VALUE size){
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self, "@uch"), uc_engine, _uc);
    err = uc_mem_unmap(_uc, NUM2ULL(address), NUM2UINT(size));
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}

VALUE m_uc_mem_protect(VALUE self, VALUE address, VALUE size, VALUE perms){
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);
    err = uc_mem_protect(_uc, NUM2ULL(address), NUM2UINT(size), NUM2UINT(perms));
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}

static void cb_hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data){
    struct hook *hook = (struct hook *)user_data;
    VALUE cb;
    VALUE ud;
    VALUE rUc;

    cb = hook->cb;
    ud = hook->ud;
    rUc = hook->rUc;
    rb_funcall(cb, rb_intern("call"), 4, rUc, ULL2NUM(address), UINT2NUM(size), ud);
}

static void cb_hook_mem_access(uc_engine *uc, uint32_t access, uint64_t address, uint32_t size, int64_t value, void *user_data){
      struct hook *hook = (struct hook *)user_data;
    VALUE cb;
    VALUE ud;
    VALUE rUc;

    cb = hook->cb;
    ud = hook->ud;
    rUc = hook->rUc;
    rb_funcall(cb, rb_intern("call"), 6, rUc, UINT2NUM(access), ULL2NUM(address), UINT2NUM(size), LL2NUM(value), ud);
}

static bool cb_hook_mem_invalid(uc_engine *uc, uint32_t access, uint64_t address, uint32_t size, int64_t value, void *user_data){
    struct hook *hook = (struct hook *)user_data;
    VALUE cb;
    VALUE ud;
    VALUE rUc;

    cb = hook->cb;
    ud = hook->ud;
    rUc = hook->rUc;
    
    return RTEST(rb_funcall(cb, rb_intern("call"), 6, rUc, UINT2NUM(access), ULL2NUM(address), UINT2NUM(size), LL2NUM(value), ud));
}

static uint32_t cb_hook_insn_in(uc_engine *uc, uint32_t port, int size, void *user_data){
    struct hook *hook = (struct hook *)user_data;
    VALUE cb;
    VALUE ud;
    VALUE rUc;

    cb = hook->cb;
    ud = hook->ud;
    rUc = hook->rUc;
    return NUM2UINT(rb_funcall(cb, rb_intern("call"), 4, rUc, UINT2NUM(port), INT2NUM(size), ud));
}

static void cb_hook_insn_out(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data){
    struct hook *hook = (struct hook *)user_data;
    VALUE cb;
    VALUE ud;
    VALUE rUc;

    cb = hook->cb;
    ud = hook->ud;
    rUc = hook->rUc;
    rb_funcall(cb, rb_intern("call"), 5, rUc, UINT2NUM(port), INT2NUM(size), UINT2NUM(value), ud);
}

static void cb_hook_insn_syscall(uc_engine *uc, void *user_data){
    struct hook *hook = (struct hook *)user_data;
    VALUE cb;
    VALUE ud;
    VALUE rUc;

    cb = hook->cb;
    ud = hook->ud;
    rUc = hook->rUc;
    rb_funcall(cb, rb_intern("call"), 2, rUc, ud);
}

static void cb_hook_intr(uc_engine *uc, uint32_t intno, void *user_data){
    struct hook *hook = (struct hook *)user_data;
    VALUE cb;
    VALUE ud;
    VALUE rUc;

    cb = hook->cb;
    ud = hook->ud;
    rUc = hook->rUc;
    rb_funcall(cb, rb_intern("call"), 3, rUc, ULL2NUM(intno), ud);
}

static void mark_hook(void *p){
    struct hook *hook = (struct hook *)p;
    rb_gc_mark(hook->cb);
    rb_gc_mark(hook->ud);
    rb_gc_mark(hook->rUc); // just for completeness sake even though this should already be marked
}

VALUE m_uc_hook_add(int argc, VALUE* argv, VALUE self){
    VALUE hook_type;
    VALUE callback;
    VALUE user_data;
    VALUE begin;
    VALUE end;
    VALUE arg1;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self, "@uch"), uc_engine, _uc);
    
    rb_scan_args(argc, argv, "24",&hook_type, &callback, &user_data, &begin, &end, &arg1);
    if (NIL_P(begin))
        begin = ULL2NUM(1);

    if (NIL_P(end))
        end = ULL2NUM(0);

    if (NIL_P(arg1))
        arg1 = INT2NUM(0);

    uc_err err;

    if (rb_class_of(callback) != rb_cProc)
        rb_raise(UcError, "Expected Proc callback");

    struct hook *hook = (struct hook *)malloc(sizeof(struct hook));
    hook->cb = callback;
    hook->ud = user_data;
    hook->rUc = self;
    VALUE r_hook;
    VALUE hooks_list;
    r_hook = Data_Wrap_Struct(Hook, mark_hook, free, hook);
    hooks_list = rb_iv_get(self, "@hooks");
    rb_ary_push(hooks_list, r_hook);
    
    uint32_t htype = NUM2UINT(hook_type);
    if(htype == UC_HOOK_INSN){
            switch(NUM2INT(arg1)){
                case UC_X86_INS_IN:
                    err = uc_hook_add(_uc, &hook->trace,  htype, cb_hook_insn_in,(void *)hook, NUM2ULL(begin), NUM2ULL(end), NUM2INT(arg1));
                    break;
                case UC_X86_INS_OUT:
                    err = uc_hook_add(_uc, &hook->trace,  htype, cb_hook_insn_out,(void *)hook, NUM2ULL(begin), NUM2ULL(end), NUM2INT(arg1));
                    break;
                case UC_X86_INS_SYSCALL:
                case UC_X86_INS_SYSENTER:
                    err = uc_hook_add(_uc, &hook->trace,  htype, cb_hook_insn_syscall,(void *)hook, NUM2ULL(begin), NUM2ULL(end), NUM2INT(arg1));
                    break;
            }
    }
    else if(htype == UC_HOOK_INTR){
            err = uc_hook_add(_uc, &hook->trace,  htype, cb_hook_intr,(void *)hook, NUM2ULL(begin), NUM2ULL(end));
    }
    else if(htype == UC_HOOK_CODE || htype == UC_HOOK_BLOCK){
            err = uc_hook_add(_uc, &hook->trace,  htype, cb_hook_code,(void *)hook, NUM2ULL(begin), NUM2ULL(end));
    }
    else if (htype & UC_HOOK_MEM_READ_UNMAPPED
            || htype & UC_HOOK_MEM_WRITE_UNMAPPED
            || htype & UC_HOOK_MEM_FETCH_UNMAPPED
            || htype & UC_HOOK_MEM_READ_PROT
            || htype & UC_HOOK_MEM_WRITE_PROT
            || htype & UC_HOOK_MEM_FETCH_PROT
            || htype & UC_HOOK_MEM_READ_INVALID
            || htype & UC_HOOK_MEM_WRITE_INVALID
            || htype & UC_HOOK_MEM_FETCH_INVALID
            || htype & UC_HOOK_MEM_UNMAPPED
            || htype & UC_HOOK_MEM_PROT
            || htype & UC_HOOK_MEM_INVALID) {
            err = uc_hook_add(_uc, &hook->trace,  htype, cb_hook_mem_invalid,(void *)hook, NUM2ULL(begin), NUM2ULL(end));
    }
    else{
            err = uc_hook_add(_uc, &hook->trace,  htype, cb_hook_mem_access,(void *)hook, NUM2ULL(begin), NUM2ULL(end));
    }

    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return r_hook;
}

VALUE m_uc_hook_del(VALUE self, VALUE hook){
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);
    struct hook *h;
    Data_Get_Struct(hook, struct hook, h);
    err = uc_hook_del(_uc, h->trace);
    
    rb_ary_delete(rb_iv_get(self, "@hooks"), hook);

    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}

VALUE m_uc_query(VALUE self, VALUE query_mode){
    int qm = NUM2INT(query_mode);
    size_t result;
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);
    err = uc_query(_uc, qm, &result);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return INT2NUM(result);
}

VALUE m_uc_context_save(VALUE self){
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);

    uc_context *_context;
    err = uc_context_alloc(_uc, &_context);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }

    err = uc_context_save(_uc, _context);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }

    VALUE sc = Data_Wrap_Struct(SavedContext, 0, uc_free, _context);
    return sc;
}

VALUE m_uc_context_update(VALUE self, VALUE context){
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);

    uc_context *_context;
    Data_Get_Struct(context, uc_context, _context);

    err = uc_context_save(_uc, _context);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}

VALUE m_uc_context_restore(VALUE self, VALUE context){
    uc_err err;
    uc_engine *_uc;
    Data_Get_Struct(rb_iv_get(self,"@uch"), uc_engine, _uc);

    uc_context *_context;
    Data_Get_Struct(context, uc_context, _context);

    err = uc_context_restore(_uc, _context);
    if (err != UC_ERR_OK) {
      rb_raise(UcError, "%s", uc_strerror(err));
    }
    return Qnil;
}
