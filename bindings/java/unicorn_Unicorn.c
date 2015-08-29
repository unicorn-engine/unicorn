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

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#include <unicorn/unicorn.h>
#include "unicorn_Unicorn.h"

//cache jmethodID values as we look them up
static jmethodID invokeBlockCallbacks = 0;
static jmethodID invokeInterruptCallbacks = 0;
static jmethodID invokeCodeCallbacks = 0;

static jmethodID invokeMemInvalidCallbacks = 0;
static jmethodID invokeReadCallbacks = 0;
static jmethodID invokeWriteCallbacks = 0;
static jmethodID invokeReadWriteCallbacks = 0;
static jmethodID invokeInCallbacks = 0;
static jmethodID invokeOutCallbacks = 0;
static jmethodID invokeSyscallCallbacks = 0;

static JavaVM* cachedJVM;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *jvm, void *reserved) {
   cachedJVM = jvm;
   return JNI_VERSION_1_6;
}

// Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)
// @address: address where the code is being executed
// @size: size of machine instruction being executed
// @user_data: user data passed to tracing APIs.
static void cb_hookcode(uch handle, uint64_t address, uint32_t size, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jclass clz = (*env)->FindClass(env, "unicorn/Unicorn");
   if ((*env)->ExceptionCheck(env)) {
      return;
   }
   (*env)->CallStaticVoidMethod(env, clz, invokeCodeCallbacks, (jlong)handle, (jlong)address, (int)size);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

// Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)
// @address: address where the code is being executed
// @size: size of machine instruction being executed
// @user_data: user data passed to tracing APIs.
static void cb_hookblock(uch handle, uint64_t address, uint32_t size, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jclass clz = (*env)->FindClass(env, "unicorn/Unicorn");
   if ((*env)->ExceptionCheck(env)) {
      return;
   }
   (*env)->CallStaticVoidMethod(env, clz, invokeBlockCallbacks, (jlong)handle, (jlong)address, (int)size);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

// Callback function for tracing interrupts (for uc_hook_intr())
// @intno: interrupt number
// @user_data: user data passed to tracing APIs.
static void cb_hookintr(uch handle, uint32_t intno, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jclass clz = (*env)->FindClass(env, "unicorn/Unicorn");   
   if ((*env)->ExceptionCheck(env)) {
      return;
   }
   (*env)->CallStaticVoidMethod(env, clz, invokeInterruptCallbacks, (jlong)handle, (int)intno);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

// Callback function for tracing IN instruction of X86
// @port: port number
// @size: data size (1/2/4) to be read from this port
// @user_data: user data passed to tracing APIs.
static uint32_t cb_insn_in(uch handle, uint32_t port, int size, void *user_data) {
   JNIEnv *env;
   uint32_t res = 0;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jclass clz = (*env)->FindClass(env, "unicorn/Unicorn");   
   if ((*env)->ExceptionCheck(env)) {
      return 0;
   }
   res = (uint32_t)(*env)->CallStaticIntMethod(env, clz, invokeInCallbacks, (jlong)handle, (jint)port, (jint)size);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
   return res;
}

// x86's handler for OUT
// @port: port number
// @size: data size (1/2/4) to be written to this port
// @value: data value to be written to this port
static void cb_insn_out(uch handle, uint32_t port, int size, uint32_t value, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jclass clz = (*env)->FindClass(env, "unicorn/Unicorn");   
   if ((*env)->ExceptionCheck(env)) {
      return;
   }
   (*env)->CallStaticVoidMethod(env, clz, invokeOutCallbacks, (jlong)handle, (jint)port, (jint)size, (jint)value);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

// x86's handler for SYSCALL/SYSENTER
static void cb_insn_syscall(uch handle, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jclass clz = (*env)->FindClass(env, "unicorn/Unicorn");   
   if ((*env)->ExceptionCheck(env)) {
      return;
   }
   (*env)->CallStaticVoidMethod(env, clz, invokeSyscallCallbacks, (jlong)handle);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

// Callback function for hooking memory (UC_HOOK_MEM_*)
// @type: this memory is being READ, or WRITE
// @address: address where the code is being executed
// @size: size of data being read or written
// @value: value of data being written to memory, or irrelevant if type = READ.
// @user_data: user data passed to tracing APIs
static void cb_hookmem(uch handle, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jclass clz = (*env)->FindClass(env, "unicorn/Unicorn");   
   if ((*env)->ExceptionCheck(env)) {
      return;
   }
   switch (type) {
      case UC_MEM_READ:
         (*env)->CallStaticVoidMethod(env, clz, invokeReadCallbacks, (jlong)handle, (jlong)address, (int)size);
         break;
      case UC_MEM_WRITE:
         (*env)->CallStaticVoidMethod(env, clz, invokeWriteCallbacks, (jlong)handle, (jlong)address, (int)size, (jlong)value);
         break;
      case UC_MEM_READ_WRITE:
         (*env)->CallStaticVoidMethod(env, clz, invokeReadWriteCallbacks, (jlong)handle, (int)type, (jlong)address, (int)size, (jlong)value);
         break;
   }
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
}

// Callback function for handling memory events (for UC_HOOK_MEM_INVALID)
// @type: this memory is being READ, or WRITE
// @address: address where the code is being executed
// @size: size of data being read or written
// @value: value of data being written to memory, or irrelevant if type = READ.
// @user_data: user data passed to tracing APIs
// @return: return true to continue, or false to stop program (due to invalid memory).
static bool cb_eventmem(uch handle, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data) {
   JNIEnv *env;
   (*cachedJVM)->AttachCurrentThread(cachedJVM, (void **)&env, NULL);
   jclass clz = (*env)->FindClass(env, "unicorn/Unicorn");   
   if ((*env)->ExceptionCheck(env)) {
      return false;
   }
   jboolean res = (*env)->CallStaticBooleanMethod(env, clz, invokeMemInvalidCallbacks, (jlong)handle, (int)type, (jlong)address, (int)size, (jlong)value);
   (*cachedJVM)->DetachCurrentThread(cachedJVM);
   return res;
}

static void throwException(JNIEnv *env, uc_err err) {
   //throw exception
   jclass clazz = (*env)->FindClass(env, "unicorn/UnicornException");
   if (err != UC_ERR_OK) {
      const char *msg = uc_strerror(err);
      (*env)->ThrowNew(env, clazz, msg);
   }
}

static uch getHandle(JNIEnv *env, jobject self) {
   static int haveFid = 0;
   static jfieldID fid;
   if (haveFid == 0) {
      //cache the field id
      jclass clazz = (*env)->GetObjectClass(env, self);
      fid = (*env)->GetFieldID(env, clazz, "handle", "J");
      haveFid = 1;
   }
   return (uch)(*env)->GetLongField(env, self, fid);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    open
 * Signature: (II)J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_open
  (JNIEnv *env, jobject self, jint arch, jint mode) {
   uch handle = -1;
   uc_err err = uc_open((uc_arch)arch, (uc_mode)mode, &handle);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   return (jlong)handle;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    version
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_unicorn_Unicorn_version
  (JNIEnv *env, jclass clz) {
  	return (jint)uc_version(NULL, NULL);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    arch_supported
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_unicorn_Unicorn_arch_1supported
  (JNIEnv *env, jclass clz, jint arch) {
  	return (jboolean)(uc_arch_supported((uc_arch)arch) != 0);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    close
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_close
  (JNIEnv *env, jobject self) {
   uch handle = getHandle(env, self);
   uc_close(&handle);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    errno
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_unicorn_Unicorn_errno
  (JNIEnv *env, jobject self) {
   uch handle = getHandle(env, self);
   return (jint)uc_errno(handle);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    strerror
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_unicorn_Unicorn_strerror
  (JNIEnv *env, jclass clz, jint code) {
   const char *err = uc_strerror((int)code);
   jstring s = (*env)->NewStringUTF(env, err);   
   return s;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    reg_write
 * Signature: (I[B)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_reg_1write
  (JNIEnv *env, jobject self, jint regid, jbyteArray value) {
   uch handle = getHandle(env, self);
   jbyte *array = (*env)->GetByteArrayElements(env, value, NULL);
   uc_err err = uc_reg_write(handle, (int)regid, (void *)array);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   (*env)->ReleaseByteArrayElements(env, value, array, JNI_ABORT);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    reg_read
 * Signature: (II)[B
 */
JNIEXPORT jbyteArray JNICALL Java_unicorn_Unicorn_reg_1read
  (JNIEnv *env, jobject self, jint regid, jint regsz) {
   uch handle = getHandle(env, self);
   jbyteArray regval = (*env)->NewByteArray(env, (jsize)regsz);
   jbyte *array = (*env)->GetByteArrayElements(env, regval, NULL);
   uc_err err = uc_reg_read(handle, (int)regid, (void *)array);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   (*env)->ReleaseByteArrayElements(env, regval, array, 0);
   return regval;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_write
 * Signature: (J[B)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_mem_1write
  (JNIEnv *env , jobject self, jlong address, jbyteArray bytes) {

   uch handle = getHandle(env, self);
   jbyte *array = (*env)->GetByteArrayElements(env, bytes, NULL);
   jsize size = (*env)->GetArrayLength(env, bytes);
   uc_err err = uc_mem_write(handle, (uint64_t)address, (uint8_t *)array, (size_t)size);

   if (err != UC_ERR_OK) {
      throwException(env, err);
   }

   (*env)->ReleaseByteArrayElements(env, bytes, array, JNI_ABORT);
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_read
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL Java_unicorn_Unicorn_mem_1read
  (JNIEnv *env, jobject self, jlong address, jlong size) {
   uch handle = getHandle(env, self);

   jbyteArray bytes = (*env)->NewByteArray(env, (jsize)size);
   jbyte *array = (*env)->GetByteArrayElements(env, bytes, NULL);
   uc_err err = uc_mem_read(handle, (uint64_t)address, (uint8_t *)array, (size_t)size);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
   (*env)->ReleaseByteArrayElements(env, bytes, array, 0);
   return bytes;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    emu_start
 * Signature: (JJJJ)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_emu_1start
  (JNIEnv *env, jobject self, jlong begin, jlong until, jlong timeout, jlong count) {
   uch handle = getHandle(env, self);

   uc_err err = uc_emu_start(handle, (uint64_t)begin, (uint64_t)until, (uint64_t)timeout, (size_t)count);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    emu_stop
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_emu_1stop
  (JNIEnv *env, jobject self) {
   uch handle = getHandle(env, self);

   uc_err err = uc_emu_stop(handle);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    registerHook
 * Signature: (JI)J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_registerHook__JI
  (JNIEnv *env, jclass clz, jlong handle, jint type) {
   uch h2 = 0;
   uc_err err = 0;
   switch (type) {
      case UC_HOOK_INTR:           // Hook all interrupt events
         if (invokeInterruptCallbacks == 0) {
            invokeInterruptCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeInterruptCallbacks", "(JI)V");
         }
         err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_hookintr, env);
         break;
      case UC_HOOK_MEM_INVALID:    // Hook for all invalid memory access events
         if (invokeMemInvalidCallbacks == 0) {
            invokeMemInvalidCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeMemInvalidCallbacks", "(JIJIJ)Z");
         }
         err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_eventmem, env);
         break;
   }
   return (jlong)h2;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    registerHook
 * Signature: (JII)J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_registerHook__JII
  (JNIEnv *env, jclass clz, jlong handle, jint type, jint arg1) {
   uch h2 = 0;
   uc_err err = 0;
   switch (type) {
      case UC_HOOK_INSN:           // Hook a particular instruction
         switch (arg1) {
            case UC_X86_INS_OUT:
               if (invokeOutCallbacks == 0) {
                  invokeOutCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeOutCallbacks", "(JIII)V");
               }
               err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_insn_out, env, arg1);
            case UC_X86_INS_IN:
               if (invokeInCallbacks == 0) {
                  invokeInCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeInCallbacks", "(JII)I");
               }
               err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_insn_in, env, arg1);
            case UC_X86_INS_SYSENTER:
            case UC_X86_INS_SYSCALL:
               if (invokeSyscallCallbacks == 0) {
                  invokeSyscallCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeSyscallCallbacks", "(J)V");
               }
               err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_insn_syscall, env, arg1);
         }
         break;
   }
   return (jlong)h2;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    registerHook
 * Signature: (JIJJ)J
 */
JNIEXPORT jlong JNICALL Java_unicorn_Unicorn_registerHook__JIJJ
  (JNIEnv *env, jclass clz, jlong handle, jint type, jlong arg1, jlong arg2) {
   uch h2 = 0;
   uc_err err = 0;
   switch (type) {
      case UC_HOOK_CODE:           // Hook a range of code
         if (invokeCodeCallbacks == 0) {
            invokeCodeCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeCodeCallbacks", "(JJI)V");
         }
         err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_hookcode, env, arg1, arg2);
         break;
      case UC_HOOK_BLOCK:          // Hook basic blocks
         if (invokeBlockCallbacks == 0) {
            invokeBlockCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeBlockCallbacks", "(JJI)V");
         }
         err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_hookblock, env, arg1, arg2);
         break;
      case UC_HOOK_MEM_READ:       // Hook all memory read events.
         if (invokeReadCallbacks == 0) {
            invokeReadCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeReadCallbacks", "(JJI)V");
         }
         err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_hookmem, env, arg1, arg2);
         break;
      case UC_HOOK_MEM_WRITE:      // Hook all memory write events.
         if (invokeWriteCallbacks == 0) {
            invokeWriteCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeWriteCallbacks", "(JJIJ)V");
         }
         err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_hookmem, env, arg1, arg2);
         break;
      case UC_HOOK_MEM_READ_WRITE: // Hook all memory accesses (either READ or WRITE).
         if (invokeReadWriteCallbacks == 0) {
            invokeReadWriteCallbacks = (*env)->GetStaticMethodID(env, clz, "invokeReadWriteCallbacks", "(JIJIJ)V");
         }
         err = uc_hook_add((uch)handle, &h2, (uc_hook_t)type, cb_hookmem, env, arg1, arg2);
         break;
   }
   return (jlong)h2;
}

/*
 * Class:     unicorn_Unicorn
 * Method:    hook_del
 * Signature: (J)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_hook_1del
  (JNIEnv *env, jobject self, jlong hook) {
   uch handle = getHandle(env, self);
   uch h2 = (uch)hook;
   
   //**** TODO remove hook from any internal hook tables as well
   
   uc_err err = uc_hook_del(handle, &h2);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}

/*
 * Class:     unicorn_Unicorn
 * Method:    mem_map
 * Signature: (JJI)V
 */
JNIEXPORT void JNICALL Java_unicorn_Unicorn_mem_1map
  (JNIEnv *env, jobject self, jlong address, jlong size, jint perms) {
   uch handle = getHandle(env, self);

   uc_err err = uc_mem_map(handle, (uint64_t)address, (size_t)size, (uint32_t)perms);
   if (err != UC_ERR_OK) {
      throwException(env, err);
   }
}
