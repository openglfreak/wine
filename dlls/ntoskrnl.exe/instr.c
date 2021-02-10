/*
 * Emulation of privileged instructions
 *
 * Copyright 1995 Alexandre Julliard
 * Copyright 2005 Ivan Leo Puoti
 * Copyright 2005 Laurent Pinchart
 * Copyright 2014-2015 Sebastian Lackner
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#define NONAMELESSUNION
#define NONAMELESSSTRUCT
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#define WIN32_NO_STATUS
#include "ddk/wdm.h"
#include "excpt.h"
#include "wine/debug.h"
#include "wine/exception.h"
#include "wine/rbtree.h"

#include "ntoskrnl_private.h"

#define KSHARED_USER_DATA_PAGE_SIZE 0x1000

#define CR0_PE 0x00000001 /* Protected Mode */
#define CR0_ET 0x00000010 /* Extension Type */
#define CR0_NE 0x00000020 /* Numeric Error */
#define CR0_WP 0x00010000 /* Write Protect */
#define CR0_AM 0x00040000 /* Alignment Mask */
#define CR0_PG 0x80000000 /* Paging */

enum instr_op
{
    INSTR_OP_MOV,
    INSTR_OP_OR,
    INSTR_OP_XOR,
};

#ifdef __i386__

WINE_DEFAULT_DEBUG_CHANNEL(int);

#include "pshpack1.h"
struct idtr
{
    WORD  limit;
    BYTE *base;
};
#include "poppack.h"

static LDT_ENTRY idt[256];

static inline struct idtr get_idtr(void)
{
    struct idtr ret;
#ifdef __GNUC__
    __asm__( "sidtl %0" : "=m" (ret) );
#else
    ret.base = (BYTE *)idt;
    ret.limit = sizeof(idt) - 1;
#endif
    return ret;
}

/* store an operand into a register */
static void store_reg_word( CONTEXT *context, BYTE regmodrm, const BYTE *addr, int long_op )
{
    switch((regmodrm >> 3) & 7)
    {
    case 0:
        if (long_op) context->Eax = *(const DWORD *)addr;
        else context->Eax = (context->Eax & 0xffff0000) | *(const WORD *)addr;
        break;
    case 1:
        if (long_op) context->Ecx = *(const DWORD *)addr;
        else context->Ecx = (context->Ecx & 0xffff0000) | *(const WORD *)addr;
        break;
    case 2:
        if (long_op) context->Edx = *(const DWORD *)addr;
        else context->Edx = (context->Edx & 0xffff0000) | *(const WORD *)addr;
        break;
    case 3:
        if (long_op) context->Ebx = *(const DWORD *)addr;
        else context->Ebx = (context->Ebx & 0xffff0000) | *(const WORD *)addr;
        break;
    case 4:
        if (long_op) context->Esp = *(const DWORD *)addr;
        else context->Esp = (context->Esp & 0xffff0000) | *(const WORD *)addr;
        break;
    case 5:
        if (long_op) context->Ebp = *(const DWORD *)addr;
        else context->Ebp = (context->Ebp & 0xffff0000) | *(const WORD *)addr;
        break;
    case 6:
        if (long_op) context->Esi = *(const DWORD *)addr;
        else context->Esi = (context->Esi & 0xffff0000) | *(const WORD *)addr;
        break;
    case 7:
        if (long_op) context->Edi = *(const DWORD *)addr;
        else context->Edi = (context->Edi & 0xffff0000) | *(const WORD *)addr;
        break;
    }
}

/* store an operand into a byte register */
static void store_reg_byte( CONTEXT *context, BYTE regmodrm, const BYTE *addr )
{
    switch((regmodrm >> 3) & 7)
    {
    case 0: context->Eax = (context->Eax & 0xffffff00) | *addr; break;
    case 1: context->Ecx = (context->Ecx & 0xffffff00) | *addr; break;
    case 2: context->Edx = (context->Edx & 0xffffff00) | *addr; break;
    case 3: context->Ebx = (context->Ebx & 0xffffff00) | *addr; break;
    case 4: context->Eax = (context->Eax & 0xffff00ff) | (*addr << 8); break;
    case 5: context->Ecx = (context->Ecx & 0xffff00ff) | (*addr << 8); break;
    case 6: context->Edx = (context->Edx & 0xffff00ff) | (*addr << 8); break;
    case 7: context->Ebx = (context->Ebx & 0xffff00ff) | (*addr << 8); break;
    }
}

static DWORD *get_reg_address( CONTEXT *context, BYTE rm )
{
    switch (rm & 7)
    {
    case 0: return &context->Eax;
    case 1: return &context->Ecx;
    case 2: return &context->Edx;
    case 3: return &context->Ebx;
    case 4: return &context->Esp;
    case 5: return &context->Ebp;
    case 6: return &context->Esi;
    case 7: return &context->Edi;
    }
    return NULL;
}


/***********************************************************************
 *           INSTR_GetOperandAddr
 *
 * Return the address of an instruction operand (from the mod/rm byte).
 */
static void *INSTR_GetOperandAddr( CONTEXT *context, BYTE *instr,
                                   int long_addr, int segprefix, int *len )
{
    int mod, rm, base = 0, index = 0, ss = 0, off;

#define GET_VAL(val,type) \
    { *val = *(type *)instr; instr += sizeof(type); *len += sizeof(type); }

    *len = 0;
    GET_VAL( &mod, BYTE );
    rm = mod & 7;
    mod >>= 6;

    if (mod == 3) return get_reg_address( context, rm );

    if (long_addr)
    {
        if (rm == 4)
        {
            BYTE sib;
            GET_VAL( &sib, BYTE );
            rm = sib & 7;
            ss = sib >> 6;
            switch((sib >> 3) & 7)
            {
            case 0: index = context->Eax; break;
            case 1: index = context->Ecx; break;
            case 2: index = context->Edx; break;
            case 3: index = context->Ebx; break;
            case 4: index = 0; break;
            case 5: index = context->Ebp; break;
            case 6: index = context->Esi; break;
            case 7: index = context->Edi; break;
            }
        }

        switch(rm)
        {
        case 0: base = context->Eax; break;
        case 1: base = context->Ecx; break;
        case 2: base = context->Edx; break;
        case 3: base = context->Ebx; break;
        case 4: base = context->Esp; break;
        case 5: base = context->Ebp; break;
        case 6: base = context->Esi; break;
        case 7: base = context->Edi; break;
        }
        switch (mod)
        {
        case 0:
            if (rm == 5)  /* special case: ds:(disp32) */
            {
                GET_VAL( &base, DWORD );
            }
            break;

        case 1:  /* 8-bit disp */
            GET_VAL( &off, BYTE );
            base += (signed char)off;
            break;

        case 2:  /* 32-bit disp */
            GET_VAL( &off, DWORD );
            base += (signed long)off;
            break;
        }
    }
    else  /* short address */
    {
        switch(rm)
        {
        case 0:  /* ds:(bx,si) */
            base = LOWORD(context->Ebx) + LOWORD(context->Esi);
            break;
        case 1:  /* ds:(bx,di) */
            base = LOWORD(context->Ebx) + LOWORD(context->Edi);
            break;
        case 2:  /* ss:(bp,si) */
            base = LOWORD(context->Ebp) + LOWORD(context->Esi);
            break;
        case 3:  /* ss:(bp,di) */
            base = LOWORD(context->Ebp) + LOWORD(context->Edi);
            break;
        case 4:  /* ds:(si) */
            base = LOWORD(context->Esi);
            break;
        case 5:  /* ds:(di) */
            base = LOWORD(context->Edi);
            break;
        case 6:  /* ss:(bp) */
            base = LOWORD(context->Ebp);
            break;
        case 7:  /* ds:(bx) */
            base = LOWORD(context->Ebx);
            break;
        }

        switch(mod)
        {
        case 0:
            if (rm == 6)  /* special case: ds:(disp16) */
            {
                GET_VAL( &base, WORD );
            }
            break;

        case 1:  /* 8-bit disp */
            GET_VAL( &off, BYTE );
            base += (signed char)off;
            break;

        case 2:  /* 16-bit disp */
            GET_VAL( &off, WORD );
            base += (signed short)off;
            break;
        }
        base &= 0xffff;
    }
    /* FIXME: we assume that all segments have a base of 0 */
    return (void *)(base + (index << ss));
#undef GET_VAL
}


/***********************************************************************
 *           emulate_instruction
 *
 * Emulate a privileged instruction.
 * Returns exception continuation status.
 */
static DWORD emulate_instruction( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    static const char *reg_names[8] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
    int prefix, segprefix, prefixlen, len, long_op, long_addr;
    BYTE *instr;

    long_op = long_addr = 1;
    instr = (BYTE *)context->Eip;
    if (!instr) return ExceptionContinueSearch;

    /* First handle any possible prefix */

    segprefix = -1;  /* no prefix */
    prefix = 1;
    prefixlen = 0;
    while(prefix)
    {
        switch(*instr)
        {
        case 0x2e:
            segprefix = context->SegCs;
            break;
        case 0x36:
            segprefix = context->SegSs;
            break;
        case 0x3e:
            segprefix = context->SegDs;
            break;
        case 0x26:
            segprefix = context->SegEs;
            break;
        case 0x64:
            segprefix = context->SegFs;
            break;
        case 0x65:
            segprefix = context->SegGs;
            break;
        case 0x66:
            long_op = !long_op;  /* opcode size prefix */
            break;
        case 0x67:
            long_addr = !long_addr;  /* addr size prefix */
            break;
        case 0xf0:  /* lock */
	    break;
        case 0xf2:  /* repne */
	    break;
        case 0xf3:  /* repe */
            break;
        default:
            prefix = 0;  /* no more prefixes */
            break;
        }
        if (prefix)
        {
            instr++;
            prefixlen++;
        }
    }

    /* Now look at the actual instruction */

    switch(*instr)
    {
    case 0x0f: /* extended instruction */
        switch(instr[1])
        {
        case 0x20: /* mov crX, Rd */
            {
                int reg = (instr[2] >> 3) & 7;
                DWORD *data = get_reg_address( context, instr[2] );
                TRACE( "mov cr%u,%s at 0x%08x\n", reg, reg_names[instr[2] & 7], context->Eip );
                switch (reg)
                {
                case 0: *data = CR0_PE|CR0_ET|CR0_NE|CR0_WP|CR0_AM|CR0_PG; break;
                case 2: *data = 0; break;
                case 3: *data = 0; break;
                case 4: *data = 0; break;
                default: return ExceptionContinueSearch;
                }
                context->Eip += prefixlen + 3;
                return ExceptionContinueExecution;
            }
        case 0x21: /* mov drX, Rd */
            {
                int reg = (instr[2] >> 3) & 7;
                DWORD *data = get_reg_address( context, instr[2] );
                TRACE( "mov dr%u,%s at 0x%08x\n", reg, reg_names[instr[2] & 7], context->Eip );
                switch (reg)
                {
                case 0: *data = context->Dr0; break;
                case 1: *data = context->Dr1; break;
                case 2: *data = context->Dr2; break;
                case 3: *data = context->Dr3; break;
                case 6: *data = context->Dr6; break;
                case 7: *data = 0x400; break;
                default: return ExceptionContinueSearch;
                }
                context->Eip += prefixlen + 3;
                return ExceptionContinueExecution;
            }
        case 0x22: /* mov Rd, crX */
            {
                int reg = (instr[2] >> 3) & 7;
                DWORD *data = get_reg_address( context, instr[2] );
                TRACE( "mov %s,cr%u at 0x%08x, %s=%08x\n", reg_names[instr[2] & 7],
                       reg, context->Eip, reg_names[instr[2] & 7], *data );
                switch (reg)
                {
                case 0: break;
                case 2: break;
                case 3: break;
                case 4: break;
                default: return ExceptionContinueSearch;
                }
                context->Eip += prefixlen + 3;
                return ExceptionContinueExecution;
            }
        case 0x23: /* mov Rd, drX */
            {
                int reg = (instr[2] >> 3) & 7;
                DWORD *data = get_reg_address( context, instr[2] );
                TRACE( "mov %s,dr%u at 0x%08x %s=%08x\n", reg_names[instr[2] & 7],
                       reg, context->Eip, reg_names[instr[2] & 7], *data );
                switch (reg)
                {
                case 0: context->Dr0 = *data; break;
                case 1: context->Dr1 = *data; break;
                case 2: context->Dr2 = *data; break;
                case 3: context->Dr3 = *data; break;
                case 6: context->Dr6 = *data; break;
                case 7: context->Dr7 = *data; break;
                default: return ExceptionContinueSearch;
                }
                context->Eip += prefixlen + 3;
                return ExceptionContinueExecution;
            }
        }
        break;

    case 0x8a: /* mov Eb, Gb */
    case 0x8b: /* mov Ev, Gv */
    {
        BYTE *data = INSTR_GetOperandAddr(context, instr + 1, long_addr,
                                          segprefix, &len);
        unsigned int data_size = (*instr == 0x8b) ? (long_op ? 4 : 2) : 1;
        struct idtr idtr = get_idtr();
        unsigned int offset = data - idtr.base;

        if (offset <= idtr.limit + 1 - data_size)
        {
            idt[1].LimitLow = 0x100; /* FIXME */
            idt[2].LimitLow = 0x11E; /* FIXME */
            idt[3].LimitLow = 0x500; /* FIXME */

            switch (*instr)
            {
            case 0x8a: store_reg_byte( context, instr[1], (BYTE *)idt + offset ); break;
            case 0x8b: store_reg_word( context, instr[1], (BYTE *)idt + offset, long_op ); break;
            }
            context->Eip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;  /* Unable to emulate it */
    }

    case 0xfa: /* cli */
    case 0xfb: /* sti */
        context->Eip += prefixlen + 1;
        return ExceptionContinueExecution;
    }
    return ExceptionContinueSearch;  /* Unable to emulate it */
}


/***********************************************************************
 *           vectored_handler
 *
 * Vectored exception handler used to emulate protected instructions
 * from 32-bit code.
 */
LONG CALLBACK vectored_handler( EXCEPTION_POINTERS *ptrs )
{
    EXCEPTION_RECORD *record = ptrs->ExceptionRecord;
    CONTEXT *context = ptrs->ContextRecord;

    if ((record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
         record->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION))
    {
        if (emulate_instruction( record, context ) == ExceptionContinueExecution)
            return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void *register_kernel_struct(void *obj, unsigned int size, kernel_struct_accessed callback)
{
    return obj;
}

void forget_kernel_struct(void *obj)
{
    return;
}

#elif defined(__x86_64__)  /* __i386__ */

WINE_DEFAULT_DEBUG_CHANNEL(int);

extern PVOID MmHighestUserAddress;

static const UINT_PTR page_mask = 0xfff;

#define ROUND_ADDR(addr,mask) \
   ((void *)((UINT_PTR)(addr) & ~(UINT_PTR)(mask)))

#define ROUND_SIZE(addr,size) \
   (((SIZE_T)(size) + ((UINT_PTR)(addr) & page_mask) + page_mask) & ~page_mask)

#define PROT_NONE 0x0
#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define MAP_FIXED 0x10
#define MAP_PRIVATE 0x2
#define MAP_ANONYMOUS 0x20

static DWORD active_thread;
#if 0
static PKTHREAD active_kthread;
#endif

extern ULONG_PTR syscall (long long unsigned int __sysno, ...) __attribute__((sysv_abi));
__ASM_GLOBAL_FUNC( syscall,
    "movq %rdi, %rax\n\t"
	"movq %rsi, %rdi\n\t"
	"movq %rdx, %rsi\n\t"
	"movq %rcx, %rdx\n\t"
	"movq %r8, %r10\n\t"
	"movq %r9, %r8\n\t"
	"movq 8(%rsp),%r9\n\t"
	"syscall\n\t"
    "ret\n\t"
);

ULONG_PTR mmap(void *addr, size_t length, int prot, int flags,
                  int fd, size_t offset)
{
    return (ULONG_PTR) syscall(9, addr, length, prot, flags, fd, offset);
}

int mprotect(void *addr, size_t length, unsigned int prot)
{
    return (int) syscall(10, addr, length, prot);
}

#if 0
int write_emulated_memory(BYTE *addr, void *buf, unsigned int length);
void unmap_user_memory(LPVOID arg, DWORD low, DWORD high)
{
    CONTEXT ctx;
    PVOID address = (PVOID) ((ULONG_PTR) arg & 0x0000ffffffffffff);
    WORD page_count = (WORD) ((ULONG_PTR) arg >> 48);

    TRACE("unmapping on behalf of %04x\n", active_thread);

    HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, active_thread);
    SuspendThread(thread);
    GetThreadContext(thread, &ctx);

    NtCurrentTeb()->SystemReserved1[15] = active_kthread;
    write_emulated_memory(address, address, -1);
    NtCurrentTeb()->SystemReserved1[15] = 0;
    TRACE("%d\n", mprotect(ROUND_ADDR(address, page_mask), page_count * 0x1000, PROT_NONE));

    active_thread = 0;
    resume_system_threads();
    ResumeThread(thread);
    CloseHandle(thread);
}

static HANDLE unmap_thread, current_timer, start_event, gotten_event;
static ULONG_PTR current_arg;

DWORD unmap_user_thread(PVOID context)
{
    while(TRUE)
    {
        /* 1ms should be enough for any copy */
        if (current_timer)
        {
            LARGE_INTEGER wait_time = {.QuadPart = -10000};
            TRACE("timer starts now\n");
            SetWaitableTimer(current_timer, &wait_time, 0, unmap_user_memory, (PVOID) current_arg, FALSE);
            current_arg = 0;
            current_timer = 0;
            SetEvent(gotten_event);
        }
        WaitForSingleObjectEx(start_event, INFINITE, TRUE);
    }
    return 1;
}
#endif

/* of course, we have to do this with page granularity, so if the range isn't page aligned, some data may be innacurate */
int read_emulated_memory(void *buf, BYTE *addr, unsigned int length);
void map_user_memory(BYTE *user_address, DWORD size)
{
    ULONG_PTR map_result;
#if 0

    if (!unmap_thread)
    {
        start_event = CreateEventW(NULL, FALSE, FALSE, NULL);
        gotten_event = CreateEventW(NULL, FALSE, FALSE, NULL);
        unmap_thread = CreateThread(NULL, 0, unmap_user_thread, NULL, 0, NULL);
    }

    if (!(suspend_all_other_threads()))
    {
        ERR("Failed to suspend all threads, not mapping user memory\n");
        resume_system_threads();
        return;
    }
#endif
    if ((map_result = mmap(ROUND_ADDR(user_address, page_mask), ROUND_SIZE(user_address, size), PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) >= (unsigned long int)-0x1000)
    {
        ERR("failed to map userspace memory, err=%ld\n", map_result);
        //resume_system_threads();
        return;
    }

    read_emulated_memory(user_address, user_address, size);
#if 0
    /* queue end of thread exclusivity */
    /*current_arg = user_address;
    current_arg |= (((ULONG_PTR)ROUND_SIZE(user_address, size) / 0x1000) << 48);
    active_thread = GetCurrentThreadId();
    active_kthread = KeGetCurrentThread();

    current_timer = CreateWaitableTimerW(NULL, TRUE, NULL);
    SetEvent(start_event);
    WaitForSingleObject(gotten_event, INFINITE);*/
#endif
    return;
}

void flush_emulated_memory(void)
{
    //LARGE_INTEGER li = {.QuadPart = -10000};
    //NtDelayExecution(TRUE, &li);
    if (KeGetCurrentThread()->user_output_copy)
        memcpy(KeGetCurrentThread()->user_output_copy, KeGetCurrentThread()->user_output, HeapSize( GetProcessHeap(), 0, KeGetCurrentThread()->user_output_copy ));
}

struct kernel_struct
{
    BYTE *base;
    unsigned int size;
    kernel_struct_accessed callback;
    struct wine_rb_entry entry;
};

static int compare_kernel_struct( const void *key, const struct wine_rb_entry *entry )
{
    const struct kernel_struct *kernel_struct = WINE_RB_ENTRY_VALUE( entry, const struct kernel_struct, entry );
    const BYTE *access_address = key;

    if (access_address < kernel_struct->base)
        return -1;
    else if (access_address < (kernel_struct->base + kernel_struct->size))
        return 0;
    else
        return 1;
}

static struct wine_rb_tree kernel_structs = {compare_kernel_struct};

static struct kernel_struct *get_kernel_struct (void *addr)
{
    struct wine_rb_entry *entry = wine_rb_get(&kernel_structs, addr);
    return entry ? WINE_RB_ENTRY_VALUE( entry, struct kernel_struct, entry ) : NULL;
}

void *register_kernel_struct(void *base, unsigned int size, kernel_struct_accessed callback)
{
    struct kernel_struct *new_struct;

    base = TO_KRNL(base);

    TRACE("(%p, %u)\n", base, size);

    if ((get_kernel_struct(base)))
        return NULL;

    new_struct = HeapAlloc(GetProcessHeap(), 0, (sizeof(*new_struct)));
    new_struct->base = base;
    new_struct->size = size;
    new_struct->callback = callback;

    wine_rb_put(&kernel_structs, new_struct->base, &new_struct->entry);

    return base;
}

void forget_kernel_struct(void *obj)
{
    struct kernel_struct *kernel_struct = get_kernel_struct(obj);

    if (obj != kernel_struct->base)
        return;

    wine_rb_remove(&kernel_structs, &kernel_struct->entry);
    HeapFree(GetProcessHeap(), 0, kernel_struct);
    return;
}

/* keep in sync with dlls/ntdll/thread.c:thread_init */
static const BYTE *wine_user_shared_data = (BYTE *)0x7ffe0000;
static const BYTE *user_shared_data      = (BYTE *)0xfffff78000000000;

static DWORD64 current_rip;

int read_emulated_memory(void *buf, BYTE *addr, unsigned int length)
{
    SIZE_T offset;
    struct kernel_struct *kernel_struct;
    struct _KTHREAD *current_thread;
    struct _EPROCESS *current_process = NULL;

    TRACE("(%p, %u)\n", addr, length);

    if ((current_thread = TO_USER(NtCurrentTeb()->SystemReserved1[15])))
    {
        current_process = TO_USER(current_thread->process);

        if (current_thread->user_input_copy)
        {
            ULONG size = HeapSize( GetProcessHeap(), 0, current_thread->user_input_copy );
            offset = addr - current_thread->user_input;
            if (size != -1 && offset + length <= size)
            {
                memcpy(buf, (BYTE*)current_thread->user_input_copy + offset, length);
                goto done;
            }
        }
        if (current_thread->user_output_copy)
        {
            ULONG size = HeapSize( GetProcessHeap(), 0, current_thread->user_output_copy );
            offset = addr - current_thread->user_output;
            if (size != -1 && offset + length <= size)
            {
                memcpy(buf, (BYTE*)current_thread->user_output_copy + offset, length);
                goto done;
            }
        }
    }

    /* first check user shared data */
    offset = addr - user_shared_data;
    if (offset + length <= sizeof(KSHARED_USER_DATA))
    {
        WARN("user_shared_data accessed at offset %x @ %016llx\n", offset, current_rip);
        memcpy(buf, wine_user_shared_data + offset, length);
        return 1;
    }

    /* Then look through struct mappings */
    if ((kernel_struct = get_kernel_struct(addr)))
    {
        offset = addr - kernel_struct->base;
        if (offset + length <= kernel_struct->size)
        {
            if (kernel_struct->callback)
                kernel_struct->callback(TO_USER(kernel_struct->base), offset, 0, (void *)current_rip);
            memcpy(buf, TO_USER(kernel_struct->base) + offset, length);
            return 1;
        }
    }

    if (current_process && addr <= (PBYTE)MmHighestUserAddress)
    {
        if (current_process->info.UniqueProcessId != GetCurrentProcessId())
        {
            HANDLE process;
            WARN("Emulating access to arbitrary user space process memory (%p, %u) from %016llx\n", addr, length, current_rip);
            if ((process = OpenProcess(PROCESS_VM_READ, FALSE, (DWORD)(ULONG_PTR) current_process->info.UniqueProcessId)))
            {
                BOOL ret = ReadProcessMemory(process, addr, buf, length, NULL);
                CloseHandle(process);
                if (!ret)
                    ERR("Failed to read memory from process. %u\n", GetLastError());
                return ret;
            }
            else
                goto fail;
        }
    }

    fail:
    ERR("Failed to emulate memory access to %p+%u from %016llx\n", addr, length, current_rip);
    return 0;
    done:
    return 1;
}

int write_emulated_memory(BYTE *addr, void *buf, unsigned int length)
{
    SIZE_T offset;
    struct _KTHREAD *current_thread;
    struct _EPROCESS *current_process = NULL;
    struct kernel_struct *kernel_struct;

    TRACE("(%p, %u)\n", addr, length);

    if ((current_thread = TO_USER(NtCurrentTeb()->SystemReserved1[15])))
    {
        current_process = TO_USER(current_thread->process);
        if (current_thread->user_output_copy)
        {
            ULONG size = HeapSize( GetProcessHeap(), 0, current_thread->user_output_copy );
            offset = addr - current_thread->user_output;
            if (length == -1 && buf == addr && addr == current_thread->user_output)
                length = size;
            if (size != -1 && offset + length <= size)
            {
                memcpy((BYTE*)current_thread->user_output_copy + offset, buf, length);
                goto done;
            }
        }
        if (current_thread->user_input_copy)
        {
            ULONG size = HeapSize( GetProcessHeap(), 0, current_thread->user_input_copy );
            offset = addr - current_thread->user_input;
            if (length == -1 && buf == addr && addr == current_thread->user_input)
                length = size;
            if (size != -1 && offset + length <= size)
            {
                FIXME("ignoring write to input IRP memory\n");
                memcpy((BYTE*)current_thread->user_input_copy + offset, buf, length);
                goto done;
            }
        }
    }

    offset = addr - user_shared_data;
    if (offset + length <= sizeof(KSHARED_USER_DATA))
    {
        FIXME("Writing to KSHARED_USER_DATA unsupported!\n");
        goto fail;
    }

    if ((kernel_struct = get_kernel_struct(addr)))
    {
        offset = addr - kernel_struct->base;
        if (offset + length <= kernel_struct->size)
        {
            if (kernel_struct->callback)
                kernel_struct->callback(TO_USER(kernel_struct->base), offset, 1, (void *)current_rip);
            memcpy(TO_USER(kernel_struct->base) + offset, buf, length);
            return 1;
        }
    }

    if (current_process && addr <= (PBYTE)MmHighestUserAddress)
    {
        if (current_process->info.UniqueProcessId != GetCurrentProcessId())
        {
            HANDLE process;
            WARN("arbitrary user space process memory access (%p, %u) from %016llx\n", addr, length, current_rip);
            if ((process = OpenProcess(PROCESS_VM_WRITE, FALSE, (DWORD)(ULONG_PTR) current_process->info.UniqueProcessId)))
            {
                BOOL ret = WriteProcessMemory(process, addr, buf, length, NULL);
                CloseHandle(process);
                return ret;
            }
            else
                goto fail;
        }
    }

    fail:
    ERR("Failed to emulate memory access to %p+%u\n", addr, length);
    return 0;
    done:
    return 1;
}

#define REX_B   1
#define REX_X   2
#define REX_R   4
#define REX_W   8

#define MSR_LSTAR   0xc0000082

#define REGMODRM_MOD( regmodrm, rex )   ((regmodrm) >> 6)
#define REGMODRM_REG( regmodrm, rex )   (((regmodrm) >> 3) & 7) | (((rex) & REX_R) ? 8 : 0)
#define REGMODRM_RM( regmodrm, rex )    (((regmodrm) & 7) | (((rex) & REX_B) ? 8 : 0))

#define SIB_SS( sib, rex )      ((sib) >> 6)
#define SIB_INDEX( sib, rex )   (((sib) >> 3) & 7) | (((rex) & REX_X) ? 8 : 0)
#define SIB_BASE( sib, rex )    (((sib) & 7) | (((rex) & REX_B) ? 8 : 0))

static inline DWORD64 *get_int_reg( CONTEXT *context, int index )
{
    return &context->Rax + index; /* index should be in range 0 .. 15 */
}

static inline int get_op_size( int long_op, int rex )
{
    if (rex & REX_W)
        return sizeof(DWORD64);
    else if (long_op)
        return sizeof(DWORD);
    else
        return sizeof(WORD);
}

/* store an operand into a register */
static void store_reg_word( CONTEXT *context, BYTE regmodrm, const BYTE *addr, int long_op, int rex,
        enum instr_op op )
{
    int index = REGMODRM_REG( regmodrm, rex );
    BYTE *reg = (BYTE *)get_int_reg( context, index );
    int op_size = get_op_size( long_op, rex );
    int i;

    switch (op)
    {
        case INSTR_OP_MOV:
            memcpy( reg, addr, op_size );
            break;
        case INSTR_OP_OR:
            for (i = 0; i < op_size; ++i)
                reg[i] |= addr[i];
            break;
        case INSTR_OP_XOR:
            for (i = 0; i < op_size; ++i)
                reg[i] ^= addr[i];
            break;
    }
}

/* store an operand into a byte register */
static void store_reg_byte( CONTEXT *context, BYTE regmodrm, const BYTE *addr, int rex, enum instr_op op )
{
    int index = REGMODRM_REG( regmodrm, rex );
    BYTE *reg = (BYTE *)get_int_reg( context, index );
    if (!rex && index >= 4 && index < 8) reg -= (4 * sizeof(DWORD64) - 1); /* special case: ah, ch, dh, bh */

    switch (op)
    {
        case INSTR_OP_MOV:
            *reg = *addr;
            break;
        case INSTR_OP_OR:
            *reg |= *addr;
            break;
        case INSTR_OP_XOR:
            *reg ^= *addr;
            break;
    }
}

/***********************************************************************
 *           INSTR_GetOperandAddr
 *
 * Return the address of an instruction operand (from the mod/rm byte).
 */
static BYTE *INSTR_GetOperandAddr( CONTEXT *context, BYTE *instr, int addl_instr_len,
                                   int long_addr, int rex, int segprefix, int *len )
{
    int mod, rm, ss = 0, off, have_sib = 0;
    DWORD64 base = 0, index = 0;

#define GET_VAL( val, type ) \
    { *val = *(type *)instr; instr += sizeof(type); *len += sizeof(type); }

    *len = 0;
    GET_VAL( &mod, BYTE );
    rm  = REGMODRM_RM( mod, rex );
    mod = REGMODRM_MOD( mod, rex );

    if (mod == 3)
        return (BYTE *)get_int_reg( context, rm );

    if ((rm & 7) == 4)
    {
        BYTE sib;
        int id;

        GET_VAL( &sib, BYTE );
        rm = SIB_BASE( sib, rex );
        id = SIB_INDEX( sib, rex );
        ss = SIB_SS( sib, rex );

        index = (id != 4) ? *get_int_reg( context, id ) : 0;
        if (!long_addr) index &= 0xffffffff;
        have_sib = 1;
    }

    base = *get_int_reg( context, rm );
    if (!long_addr) base &= 0xffffffff;

    switch (mod)
    {
    case 0:
        if (rm == 5)  /* special case */
        {
            base = have_sib ? 0 : context->Rip;
            if (!long_addr) base &= 0xffffffff;
            GET_VAL( &off, DWORD );
            base += (signed long)off;
            base += (signed long)*len + (signed long)addl_instr_len;
        }
        break;

    case 1:  /* 8-bit disp */
        GET_VAL( &off, BYTE );
        base += (signed char)off;
        break;

    case 2:  /* 32-bit disp */
        GET_VAL( &off, DWORD );
        base += (signed long)off;
        break;
    }

    /* FIXME: we assume that all segments have a base of 0 */
    return (BYTE *)(base + (index << ss));
#undef GET_VAL
}


static void fake_syscall_function(void)
{
    TRACE("() stub\n");
}


/***********************************************************************
 *           emulate_instruction
 *
 * Emulate a privileged instruction.
 * Returns exception continuation status.
 */
static DWORD emulate_instruction( EXCEPTION_RECORD *rec, CONTEXT *context )
{
    static const char *reg_names[16] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
    int prefix, segprefix, prefixlen, len, long_op, long_addr, rex;
    BYTE *instr;

    long_op = long_addr = 1;
    instr = (BYTE *)context->Rip;
    if (!instr) return ExceptionContinueSearch;

    /* First handle any possible prefix */

    segprefix = -1;  /* no seg prefix */
    rex = 0;  /* no rex prefix */
    prefix = 1;
    prefixlen = 0;
    while(prefix)
    {
        switch(*instr)
        {
        case 0x2e:
            segprefix = context->SegCs;
            break;
        case 0x36:
            segprefix = context->SegSs;
            break;
        case 0x3e:
            segprefix = context->SegDs;
            break;
        case 0x26:
            segprefix = context->SegEs;
            break;
        case 0x64:
            segprefix = context->SegFs;
            break;
        case 0x65:
            segprefix = context->SegGs;
            break;
        case 0x66:
            long_op = !long_op;  /* opcode size prefix */
            break;
        case 0x67:
            long_addr = !long_addr;  /* addr size prefix */
            break;
        case 0x40:  /* rex */
        case 0x41:
        case 0x42:
        case 0x43:
        case 0x44:
        case 0x45:
        case 0x46:
        case 0x47:
        case 0x48:
        case 0x49:
        case 0x4a:
        case 0x4b:
        case 0x4c:
        case 0x4d:
        case 0x4e:
        case 0x4f:
            rex = *instr;
            break;
        case 0xf0:  /* lock */
            break;
        case 0xf2:  /* repne */
            break;
        case 0xf3:  /* repe */
            break;
        default:
            prefix = 0;  /* no more prefixes */
            break;
        }
        if (prefix)
        {
            instr++;
            prefixlen++;
        }
    }

    /* Now look at the actual instruction */

    switch(*instr)
    {
    case 0x0f: /* extended instruction */
        switch(instr[1])
        {
        case 0x20: /* mov crX, Rd */
        {
            int reg = REGMODRM_REG( instr[2], rex );
            int rm = REGMODRM_RM( instr[2], rex );
            DWORD64 *data = get_int_reg( context, rm );
            TRACE( "mov cr%u,%s at %lx\n", reg, reg_names[rm], context->Rip );
            switch (reg)
            {
            case 0: *data = 0x10; break; /* FIXME: set more bits ? */
            case 2: *data = 0; break;
            case 3: *data = 0; break;
            case 4: *data = 0; break;
            case 8: *data = 0; break;
            default: return ExceptionContinueSearch;
            }
            context->Rip += prefixlen + 3;
            return ExceptionContinueExecution;
        }
        case 0x21: /* mov drX, Rd */
        {
            int reg = REGMODRM_REG( instr[2], rex );
            int rm = REGMODRM_RM( instr[2], rex );
            DWORD64 *data = get_int_reg( context, rm );
            TRACE( "mov dr%u,%s at %lx\n", reg, reg_names[rm], context->Rip );
            switch (reg)
            {
            case 0: *data = context->Dr0; break;
            case 1: *data = context->Dr1; break;
            case 2: *data = context->Dr2; break;
            case 3: *data = context->Dr3; break;
            case 4:  /* dr4 and dr5 are obsolete aliases for dr6 and dr7 */
            case 6: *data = context->Dr6; break;
            case 5:
            case 7: *data = 0x400; break;
            default: return ExceptionContinueSearch;
            }
            context->Rip += prefixlen + 3;
            return ExceptionContinueExecution;
        }
        case 0x22: /* mov Rd, crX */
        {
            int reg = REGMODRM_REG( instr[2], rex );
            int rm = REGMODRM_RM( instr[2], rex );
            DWORD64 *data = get_int_reg( context, rm );
            TRACE( "mov %s,cr%u at %lx, %s=%lx\n", reg_names[rm], reg, context->Rip, reg_names[rm], *data );
            switch (reg)
            {
            case 0: break;
            case 2: break;
            case 3: break;
            case 4: break;
            case 8: break;
            default: return ExceptionContinueSearch;
            }
            context->Rip += prefixlen + 3;
            return ExceptionContinueExecution;
        }
        case 0x23: /* mov Rd, drX */
        {
            int reg = REGMODRM_REG( instr[2], rex );
            int rm = REGMODRM_RM( instr[2], rex );
            DWORD64 *data = get_int_reg( context, rm );
            TRACE( "mov %s,dr%u at %lx, %s=%lx\n", reg_names[rm], reg, context->Rip, reg_names[rm], *data );
            switch (reg)
            {
            case 0: context->Dr0 = *data; break;
            case 1: context->Dr1 = *data; break;
            case 2: context->Dr2 = *data; break;
            case 3: context->Dr3 = *data; break;
            case 4:  /* dr4 and dr5 are obsolete aliases for dr6 and dr7 */
            case 6: context->Dr6 = *data; break;
            case 5:
            case 7: context->Dr7 = *data; break;
            default: return ExceptionContinueSearch;
            }
            context->Rip += prefixlen + 3;
            return ExceptionContinueExecution;
        }
        case 0x32: /* rdmsr */
        {
            ULONG reg = context->Rcx;
            TRACE("rdmsr CR 0x%08x\n", reg);
            switch (reg)
            {
            case MSR_LSTAR:
            {
                ULONG_PTR syscall_address = (ULONG_PTR)fake_syscall_function;
                context->Rdx = (ULONG)(syscall_address >> 32);
                context->Rax = (ULONG)syscall_address;
                break;
            }
            default:
                FIXME("reg %#x, returning 0.\n", reg);
                context->Rdx = 0;
                context->Rax = 0;
                break;
            }
            context->Rip += prefixlen + 2;
            return ExceptionContinueExecution;
        }
        case 0xb6: /* movzx Eb, Gv */
        case 0xb7: /* movzx Ew, Gv */
        {
            BYTE *data = INSTR_GetOperandAddr( context, instr + 2, prefixlen + 2, long_addr,
                                               rex, segprefix, &len );
            unsigned int data_size = (instr[1] == 0xb7) ? 2 : 1;
            BYTE temp[8] = {0};

            if (read_emulated_memory(temp, data, data_size))
            {
                store_reg_word( context, instr[2], temp, long_op, rex, INSTR_OP_MOV );
                context->Rip += prefixlen + len + 2;
                return ExceptionContinueExecution;
            }
            break;  /* Unable to emulate it */
        }
        }
        break;  /* Unable to emulate it */

    case 0x8a: /* mov Eb, Gb */
    case 0x8b: /* mov Ev, Gv */
    case 0x0b: /* or  Ev, Gv */
    case 0x33: /* xor Ev, Gv */
    {
        BYTE *data = INSTR_GetOperandAddr( context, instr + 1, prefixlen + 1, long_addr,
                                           rex, segprefix, &len );
        unsigned int data_size = (*instr == 0x8b) ? get_op_size( long_op, rex ) : 1;
        BYTE temp[8];
        if (read_emulated_memory(temp, data, data_size))
        {
            switch (*instr)
            {
                case 0x8a:
                    store_reg_byte( context, instr[1], temp, rex, INSTR_OP_MOV );
                    break;
                case 0x8b:
                    store_reg_word( context, instr[1], temp, long_op, rex, INSTR_OP_MOV );
                    break;
                case 0x0b:
                    store_reg_word( context, instr[1], temp, long_op, rex, INSTR_OP_OR );
                    break;
                case 0x33:
                    store_reg_word( context, instr[1], temp, long_op, rex, INSTR_OP_XOR );
                    break;
            }
            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;  /* Unable to emulate it */
    }

    case 0xa0: /* mov Ob, AL */
    case 0xa1: /* mov Ovqp, rAX */
    {
        BYTE *data = (BYTE *)(long_addr ? *(DWORD64 *)(instr + 1) : *(DWORD *)(instr + 1));
        unsigned int data_size = (*instr == 0xa1) ? get_op_size( long_op, rex ) : 1;
        BYTE temp[8];
        len = long_addr ? sizeof(DWORD64) : sizeof(DWORD);

        if (read_emulated_memory(temp, data, data_size))
        {
            memcpy( &context->Rax, temp, data_size );
            context->Rip += prefixlen + len + 1;
            return ExceptionContinueExecution;
        }
        break;  /* Unable to emulate it */
    }

    case 0xfa: /* cli */
    case 0xfb: /* sti */
        context->Rip += prefixlen + 1;
        return ExceptionContinueExecution;
    }
    return ExceptionContinueSearch;  /* Unable to emulate it */
}


/***********************************************************************
 *           vectored_handler
 *
 * Vectored exception handler used to emulate protected instructions
 * from 64-bit code.
 */
LONG CALLBACK vectored_handler( EXCEPTION_POINTERS *ptrs )
{
    EXCEPTION_RECORD *record = ptrs->ExceptionRecord;
    CONTEXT *context = ptrs->ContextRecord;

    if (record->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION ||
        (record->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
         record->ExceptionInformation[0] == EXCEPTION_READ_FAULT))
    {
        if (emulate_instruction( record, context ) == ExceptionContinueExecution)
        {
            TRACE( "next instruction rip=%lx\n", context->Rip );
            TRACE( "  rax=%016lx rbx=%016lx rcx=%016lx rdx=%016lx\n",
                   context->Rax, context->Rbx, context->Rcx, context->Rdx );
            TRACE( "  rsi=%016lx rdi=%016lx rbp=%016lx rsp=%016lx\n",
                   context->Rsi, context->Rdi, context->Rbp, context->Rsp );
            TRACE( "   r8=%016lx  r9=%016lx r10=%016lx r11=%016lx\n",
                   context->R8, context->R9, context->R10, context->R11 );
            TRACE( "  r12=%016lx r13=%016lx r14=%016lx r15=%016lx\n",
                   context->R12, context->R13, context->R14, context->R15 );

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

#endif  /* __x86_64__ */
