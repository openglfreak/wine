/*
 * Server-side ptrace support
 *
 * Copyright (C) 1999 Alexandre Julliard
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

#include "config.h"
#include "wine/port.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>
#ifdef HAVE_SYS_PTRACE_H
# include <sys/ptrace.h>
#endif
#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifdef HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#ifdef HAVE_SYS_UCONTEXT_H
# include <sys/ucontext.h>
#endif
#ifdef HAVE_SYS_THR_H
# include <sys/thr.h>
#endif
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winternl.h"

#include "file.h"
#include "process.h"
#include "thread.h"

#ifdef USE_PTRACE

#ifndef PTRACE_CONT
#define PTRACE_CONT PT_CONTINUE
#endif
#ifndef PTRACE_SINGLESTEP
#define PTRACE_SINGLESTEP PT_STEP
#endif
#ifndef PTRACE_ATTACH
#define PTRACE_ATTACH PT_ATTACH
#endif
#ifndef PTRACE_DETACH
#define PTRACE_DETACH PT_DETACH
#endif
#ifndef PTRACE_PEEKDATA
#define PTRACE_PEEKDATA PT_READ_D
#endif
#ifndef PTRACE_POKEDATA
#define PTRACE_POKEDATA PT_WRITE_D
#endif
#ifndef PTRACE_PEEKUSER
#define PTRACE_PEEKUSER PT_READ_U
#endif
#ifndef PTRACE_POKEUSER
#define PTRACE_POKEUSER PT_WRITE_U
#endif

#ifdef PT_GETDBREGS
#define PTRACE_GETDBREGS PT_GETDBREGS
#endif
#ifdef PT_SETDBREGS
#define PTRACE_SETDBREGS PT_SETDBREGS
#endif

#ifndef HAVE_SYS_PTRACE_H
#define PT_CONTINUE 0
#define PT_ATTACH   1
#define PT_DETACH   2
#define PT_READ_D   3
#define PT_WRITE_D  4
#define PT_STEP     5
static inline int ptrace(int req, ...) { errno = EPERM; return -1; /*FAIL*/ }
#endif  /* HAVE_SYS_PTRACE_H */

#ifndef __WALL
#define __WALL 0
#endif

/* handle a status returned by waitpid */
static int handle_child_status( struct thread *thread, int pid, int status, int want_sig )
{
    if (WIFSTOPPED(status))
    {
        int sig = WSTOPSIG(status);
        if (debug_level && thread)
            fprintf( stderr, "%04x: *signal* signal=%d\n", thread->id, sig );
        if (sig != want_sig)
        {
            /* ignore other signals for now */
            ptrace( PTRACE_CONT, pid, (caddr_t)1, sig );
        }
        return sig;
    }
    if (thread && (WIFSIGNALED(status) || WIFEXITED(status)))
    {
        thread->unix_pid = -1;
        thread->unix_tid = -1;
        if (debug_level)
        {
            if (WIFSIGNALED(status))
                fprintf( stderr, "%04x: *exited* signal=%d\n",
                         thread->id, WTERMSIG(status) );
            else
                fprintf( stderr, "%04x: *exited* status=%d\n",
                         thread->id, WEXITSTATUS(status) );
        }
    }
    return 0;
}

/* handle a SIGCHLD signal */
void sigchld_callback(void)
{
    int pid, status;

    for (;;)
    {
        if (!(pid = waitpid( -1, &status, WUNTRACED | WNOHANG | __WALL ))) break;
        if (pid != -1)
        {
            struct thread *thread = get_thread_from_tid( pid );
            if (!thread) thread = get_thread_from_pid( pid );
            handle_child_status( thread, pid, status, -1 );
        }
        else break;
    }
}

/* return the Unix pid to use in ptrace calls for a given process */
static int get_ptrace_pid( struct thread *thread )
{
#ifdef linux  /* linux always uses thread id */
    if (thread->unix_tid != -1) return thread->unix_tid;
#endif
    return thread->unix_pid;
}

/* return the Unix tid to use in ptrace calls for a given thread */
static int get_ptrace_tid( struct thread *thread )
{
    if (thread->unix_tid != -1) return thread->unix_tid;
    return thread->unix_pid;
}

/* wait for a ptraced child to get a certain signal */
static int waitpid_thread( struct thread *thread, int signal )
{
    int res, status;

    start_watchdog();
    for (;;)
    {
        if ((res = waitpid( get_ptrace_pid(thread), &status, WUNTRACED | __WALL )) == -1)
        {
            if (errno == EINTR)
            {
                if (!watchdog_triggered()) continue;
                if (debug_level) fprintf( stderr, "%04x: *watchdog* waitpid aborted\n", thread->id );
            }
            else if (errno == ECHILD)  /* must have died */
            {
                thread->unix_pid = -1;
                thread->unix_tid = -1;
            }
            else perror( "waitpid" );
            stop_watchdog();
            return 0;
        }
        res = handle_child_status( thread, res, status, signal );
        if (!res || res == signal) break;
    }
    stop_watchdog();
    return (thread->unix_pid != -1);
}

/* send a signal to a specific thread */
static inline int tkill( int tgid, int pid, int sig )
{
#ifdef __linux__
    int ret = syscall( __NR_tgkill, tgid, pid, sig );
    if (ret < 0 && errno == ENOSYS) ret = syscall( __NR_tkill, pid, sig );
    return ret;
#elif (defined(__FreeBSD__) || defined (__FreeBSD_kernel__)) && defined(HAVE_THR_KILL2)
    return thr_kill2( tgid, pid, sig );
#else
    errno = ENOSYS;
    return -1;
#endif
}

/* initialize the process tracing mechanism */
void init_tracing_mechanism(void)
{
    /* no initialization needed for ptrace */
}

/* initialize the per-process tracing mechanism */
void init_process_tracing( struct process *process )
{
    /* ptrace setup is done on-demand */
}

/* terminate the per-process tracing mechanism */
void finish_process_tracing( struct process *process )
{
}

/* send a Unix signal to a specific thread */
int send_thread_signal( struct thread *thread, int sig )
{
    int ret = -1;

    if (thread->unix_pid != -1)
    {
        if (thread->unix_tid != -1)
        {
            ret = tkill( thread->unix_pid, thread->unix_tid, sig );
            if (ret == -1 && errno == ENOSYS) ret = kill( thread->unix_pid, sig );
        }
        else ret = kill( thread->unix_pid, sig );

        if (ret == -1 && errno == ESRCH) /* thread got killed */
        {
            thread->unix_pid = -1;
            thread->unix_tid = -1;
        }
    }
    if (debug_level && ret != -1)
        fprintf( stderr, "%04x: *sent signal* signal=%d\n", thread->id, sig );
    return (ret != -1);
}

/* resume a thread after we have used ptrace on it */
static void resume_after_ptrace( struct thread *thread )
{
    if (thread->unix_pid == -1) return;
    if (ptrace( PTRACE_DETACH, get_ptrace_pid(thread), (caddr_t)1, 0 ) == -1)
    {
        if (errno == ESRCH) thread->unix_pid = thread->unix_tid = -1;  /* thread got killed */
    }
}

/* suspend a thread to allow using ptrace on it */
/* you must do a resume_after_ptrace when finished with the thread */
static int suspend_for_ptrace( struct thread *thread )
{
    /* can't stop a thread while initialisation is in progress */
    if (thread->unix_pid == -1 || !is_process_init_done(thread->process)) goto error;

    /* this may fail if the client is already being debugged */
    if (ptrace( PTRACE_ATTACH, get_ptrace_pid(thread), 0, 0 ) == -1)
    {
        if (errno == ESRCH) thread->unix_pid = thread->unix_tid = -1;  /* thread got killed */
        goto error;
    }
    if (waitpid_thread( thread, SIGSTOP )) return 1;
    resume_after_ptrace( thread );
 error:
    set_error( STATUS_ACCESS_DENIED );
    return 0;
}

/* read a long from a thread address space */
static int read_thread_long( struct thread *thread, void *addr, unsigned long *data )
{
    errno = 0;
    *data = ptrace( PTRACE_PEEKDATA, get_ptrace_pid(thread), (caddr_t)addr, 0 );
    if ( *data == -1 && errno)
    {
        file_set_error();
        return -1;
    }
    return 0;
}

static int read_thread_int( struct thread *thread, void *addr, unsigned int *data )
{
    unsigned long long_data;
    int ret;

    ret = read_thread_long( thread, addr, &long_data );
    *data = long_data;
    return ret;
}

/* write a long to a thread address space */
static long write_thread_long( struct thread *thread, void *addr, unsigned long data, unsigned long mask )
{
    unsigned long old_data;
    int res;

    if (mask != ~0ul)
    {
        if (read_thread_long( thread, addr, &old_data ) == -1) return -1;
        data = (data & mask) | (old_data & ~mask);
    }
    if ((res = ptrace( PTRACE_POKEDATA, get_ptrace_pid(thread), (caddr_t)addr, data )) == -1)
        file_set_error();
    return res;
}

/* return a thread of the process suitable for ptracing */
static struct thread *get_ptrace_thread( struct process *process )
{
    struct thread *thread;

    LIST_FOR_EACH_ENTRY( thread, &process->thread_list, struct thread, proc_entry )
    {
        if (thread->unix_pid != -1) return thread;
    }
    set_error( STATUS_PROCESS_IS_TERMINATING );  /* process is dead */
    return NULL;
}

/* read data from a process memory space */
int read_process_memory( struct process *process, client_ptr_t ptr, data_size_t size, char *dest )
{
    struct thread *thread = get_ptrace_thread( process );
    unsigned int first_offset, last_offset, len;
    unsigned long data, *addr;

    if (!thread) return 0;

    if ((unsigned long)ptr != ptr)
    {
        set_error( STATUS_ACCESS_DENIED );
        return 0;
    }

    first_offset = ptr % sizeof(long);
    last_offset = (size + first_offset) % sizeof(long);
    if (!last_offset) last_offset = sizeof(long);

    addr = (unsigned long *)(unsigned long)(ptr - first_offset);
    len = (size + first_offset + sizeof(long) - 1) / sizeof(long);

    if (suspend_for_ptrace( thread ))
    {
        if (len > 3)  /* /proc/pid/mem should be faster for large sizes */
        {
            char procmem[24];
            int fd;

            sprintf( procmem, "/proc/%u/mem", process->unix_pid );
            if ((fd = open( procmem, O_RDONLY )) != -1)
            {
                ssize_t ret = pread( fd, dest, size, ptr );
                close( fd );
                if (ret == size)
                {
                    len = 0;
                    goto done;
                }
            }
        }

        if (len > 1)
        {
            if (read_thread_long( thread, addr++, &data ) == -1) goto done;
            memcpy( dest, (char *)&data + first_offset, sizeof(long) - first_offset );
            dest += sizeof(long) - first_offset;
            first_offset = 0;
            len--;
        }

        while (len > 1)
        {
            if (read_thread_long( thread, addr++, &data ) == -1) goto done;
            memcpy( dest, &data, sizeof(long) );
            dest += sizeof(long);
            len--;
        }

        if (read_thread_long( thread, addr++, &data ) == -1) goto done;
        memcpy( dest, (char *)&data + first_offset, last_offset - first_offset );
        len--;

    done:
        resume_after_ptrace( thread );
    }
    return !len;
}

/* make sure we can write to the whole address range */
/* len is the total size (in ints) */
static int check_process_write_access( struct thread *thread, long *addr, data_size_t len )
{
    int page = get_page_size() / sizeof(long);

    for (;;)
    {
        if (write_thread_long( thread, addr, 0, 0 ) == -1) return 0;
        if (len <= page) break;
        addr += page;
        len -= page;
    }
    return (write_thread_long( thread, addr + len - 1, 0, 0 ) != -1);
}

/* write data to a process memory space */
int write_process_memory( struct process *process, client_ptr_t ptr, data_size_t size, const char *src )
{
    struct thread *thread = get_ptrace_thread( process );
    int ret = 0;
    long data = 0;
    data_size_t len;
    long *addr;
    unsigned long first_mask, first_offset, last_mask, last_offset;

    if (!thread) return 0;

    if ((unsigned long)ptr != ptr)
    {
        set_error( STATUS_ACCESS_DENIED );
        return 0;
    }

    /* compute the mask for the first long */
    first_mask = ~0;
    first_offset = ptr % sizeof(long);
    memset( &first_mask, 0, first_offset );

    /* compute the mask for the last long */
    last_offset = (size + first_offset) % sizeof(long);
    if (!last_offset) last_offset = sizeof(long);
    last_mask = 0;
    memset( &last_mask, 0xff, last_offset );

    addr = (long *)(unsigned long)(ptr - first_offset);
    len = (size + first_offset + sizeof(long) - 1) / sizeof(long);

    if (suspend_for_ptrace( thread ))
    {
        if (!check_process_write_access( thread, addr, len ))
        {
            set_error( STATUS_ACCESS_DENIED );
            goto done;
        }

        if (len > 3)
        {
            char procmem[24];
            int fd;

            sprintf( procmem, "/proc/%u/mem", process->unix_pid );
            if ((fd = open( procmem, O_WRONLY )) != -1)
            {
                ssize_t r = pwrite( fd, src, size, ptr );
                close( fd );
                if (r == size)
                {
                    ret = 1;
                    goto done;
                }
            }
        }

        /* first word is special */
        if (len > 1)
        {
            memcpy( (char *)&data + first_offset, src, sizeof(long) - first_offset );
            src += sizeof(long) - first_offset;
            if (write_thread_long( thread, addr++, data, first_mask ) == -1) goto done;
            first_offset = 0;
            len--;
        }
        else last_mask &= first_mask;

        while (len > 1)
        {
            memcpy( &data, src, sizeof(long) );
            src += sizeof(long);
            if (write_thread_long( thread, addr++, data, ~0ul ) == -1) goto done;
            len--;
        }

        /* last word is special too */
        memcpy( (char *)&data + first_offset, src, last_offset - first_offset );
        if (write_thread_long( thread, addr, data, last_mask ) == -1) goto done;
        ret = 1;

    done:
        resume_after_ptrace( thread );
    }
    return ret;
}

static int try_procmem_transfer( unsigned int src_pid, off_t src_ptr, unsigned int dst_pid, off_t dst_ptr,
                                 size_t *size, int allow_partial, char *scratch_space )
{
    char procmem[32];
    int src_fd, dst_fd;
    size_t read = 0, written = 0;

    /* if there is no data to transfer, return success */
    if (*size == 0)
        return 1;

    /* open the source process's memory */
    sprintf( procmem, "/proc/%u/mem", src_pid );
    if ((src_fd = open( procmem, (dst_pid == src_pid ? O_RDWR : O_RDONLY) )) == -1)
        return 0;

    /* open the destination process's memory */
    if (dst_pid == src_pid)
        dst_fd = src_fd;
    else
    {
        sprintf( procmem, "/proc/%u/mem", dst_pid );
        if ((dst_fd = (dst_pid == src_pid ? src_fd : open( procmem, O_WRONLY ))) == -1)
        {
            close( src_fd );
            return 0;
        }
    }

    /* read the data from the source process */
    while (read < *size)
    {
        ssize_t r = pread( src_fd, scratch_space + read, *size - read, src_ptr );
        if (r == 0 || (r == -1 && errno == EIO)) break;
        if (r == -1)
        {
            if (src_fd != dst_fd) close( src_fd );
            close( dst_fd );
            return 0;
        }
        read += (size_t)r;
    }
    if (src_fd != dst_fd) close( src_fd );
    if (!allow_partial && read != *size)
    {
        close( dst_fd );
        return 0;
    }

    /* write the data to the destination process */
    while (written < read)
    {
        ssize_t r = pwrite( dst_fd, scratch_space + written, read - written, dst_ptr );
        if (r == 0 || (r == -1 && errno == EIO)) break;
        if (r == -1)
        {
            /* this shouldn't happen - but what should we do here in case of !allow_partial? */
            close( dst_fd );
            return 0;
        }
        written += (size_t)r;
    }
    close( dst_fd );
    if (!allow_partial && written != *size) /* should never happen, could break things otherwise */
        return 0;

    *size = written;
    return 1;
}

static int try_ptrace_transfer( struct thread *src_thread, void* src_ptr, struct thread *dst_thread,
                                void* dst_ptr, size_t *size, int allow_partial, char *scratch_space )
{
    unsigned int first_offset, last_offset;
    unsigned long *addr;
    size_t len;
    unsigned long data, first_mask, last_mask;
    size_t read, written;
    char *p;

    /* if there is no data to transfer, return success */
    if (*size == 0)
        return 1;

    first_offset = (size_t)src_ptr % sizeof(long);
    last_offset = (*size + first_offset) % sizeof(long);
    if (!last_offset) last_offset = sizeof(long);

    addr = (unsigned long*)((char*)src_ptr - first_offset);
    len = (*size + first_offset + sizeof(long) - 1) / sizeof(long);

    p = scratch_space;

    /* first word is special */
    if (len > 1)
    {
        if (read_thread_long( src_thread, addr++, &data ) == -1) goto write;
        memcpy( p, (char *)&data + first_offset, sizeof(long) - first_offset );
        p += sizeof(long) - first_offset;
        first_offset = 0;
        len--;
    }

    while (len > 1)
    {
        if (read_thread_long( src_thread, addr++, &data ) == -1) goto write;
        memcpy( p, &data, sizeof(long) );
        p += sizeof(long);
        len--;
    }

    /* last word is special too */
    if (read_thread_long( src_thread, addr++, &data ) == -1) goto write;
    memcpy( p, (char *)&data + first_offset, last_offset - first_offset );
    p += last_offset - first_offset;

write:
    read = p - scratch_space;
    p = scratch_space;
    if (!allow_partial && read != *size) goto done;

    first_offset = (size_t)dst_ptr % sizeof(long);
    last_offset = (read + first_offset) % sizeof(long);
    if (!last_offset) last_offset = sizeof(long);

    addr = (unsigned long*)((char*)dst_ptr - first_offset);
    len = (read + first_offset + sizeof(long) - 1) / sizeof(long);

    /* compute the mask for the first long */
    first_mask = ~0ul;
    memset( &first_mask, 0, first_offset );
    /* compute the mask for the last long */
    last_mask = 0;
    memset( &last_mask, 0xff, last_offset );

    /* first word is special */
    if (len > 1)
    {
        memcpy( (char *)&data + first_offset, p, sizeof(long) - first_offset );
        if (write_thread_long( dst_thread, addr++, data, first_mask ) == -1) goto done;
        p += sizeof(long) - first_offset;
        first_offset = 0;
        len--;
    }
    else last_mask &= first_mask;

    while (len > 1)
    {
        memcpy( &data, p, sizeof(long) );
        if (write_thread_long( dst_thread, addr++, data, ~0ul ) == -1) goto done;
        p += sizeof(long);
        len--;
    }

    /* last word is special too */
    memcpy( (char *)&data + first_offset, p, last_offset - first_offset );
    if (write_thread_long( dst_thread, addr, data, last_mask ) == -1) goto done;
    p += last_offset - first_offset;

done:
    written = p - scratch_space;
    if (!allow_partial && written != *size)
        return 0;
    *size = written;
    return 1;
}

/* transfer data from one process's memory space to another's */
int transfer_process_memory( struct process *src_process, client_ptr_t src_ptr, struct process *dst_process,
                             client_ptr_t dst_ptr, data_size_t *size, int allow_partial )
{
    struct thread *src_thread = get_ptrace_thread( src_process );
    struct thread *dst_thread = src_process == dst_process ? src_thread : get_ptrace_thread( dst_process );
    void *scratch_space;
    size_t tmp;
    int ret = 0;

    /* if there is no data to transfer, return success */
    if (*size == 0)
        return 1;

    if (!src_thread || !dst_thread) return 0;

    scratch_space = mem_alloc( *size );
    if (!scratch_space)
    {
        set_error( STATUS_INSUFFICIENT_RESOURCES );
        return 0;
    }

    if (!suspend_for_ptrace( src_thread ))
        goto done;
    if (dst_thread != src_thread && !suspend_for_ptrace( dst_thread ))
    {
        resume_after_ptrace( src_thread );
        goto done;
    }

    if (!allow_partial)
    {
        unsigned int first_offset;
        unsigned long *addr;
        size_t len;

        if ((client_ptr_t)(void*)dst_ptr != dst_ptr)
        {
            set_error( STATUS_ACCESS_DENIED );
            goto resume;
        }

        first_offset = dst_ptr % sizeof(long);
        addr = (unsigned long*)((char*)dst_ptr - first_offset);
        len = (*size + first_offset + sizeof(long) - 1) / sizeof(long);

        if (!check_process_write_access( dst_thread, (long*)addr, len ))
        {
            set_error( STATUS_ACCESS_DENIED );
            goto resume;
        }
    }

    /* /proc/pid/mem should be faster for large sizes */
    if ((size_t)*size == *size && (off_t)src_ptr == src_ptr && (off_t)dst_ptr == dst_ptr && *size > 3)
    {
        tmp = (size_t)*size;
        if (try_procmem_transfer( src_process->unix_pid, (off_t)src_ptr, dst_process->unix_pid,
                                  (off_t)dst_ptr, &tmp, allow_partial, (char*)scratch_space ))
        {
            if (tmp != *size) set_error( STATUS_PARTIAL_COPY );
            *size = tmp;
            goto resume;
        }
    }

    if ((size_t)*size == *size && (client_ptr_t)(void*)src_ptr == src_ptr && (client_ptr_t)(void*)dst_ptr == dst_ptr)
    {
        tmp = (size_t)*size;
        if (try_ptrace_transfer( src_thread, (void*)src_ptr, dst_thread, (void*)dst_ptr, &tmp,
                                 allow_partial, (char*)scratch_space ))
        {
            if (tmp != *size) set_error( STATUS_PARTIAL_COPY );
            *size = tmp;
            goto resume;
        }
    }

    *size = 0;
    set_error( STATUS_ACCESS_DENIED );

resume:
    if (dst_thread != src_thread)
        resume_after_ptrace( dst_thread );
    resume_after_ptrace( src_thread );
done:
    free( scratch_space );
    return ret;
}

/* retrieve an LDT selector entry */
void get_selector_entry( struct thread *thread, int entry, unsigned int *base,
                         unsigned int *limit, unsigned char *flags )
{
    if (!thread->process->ldt_copy)
    {
        set_error( STATUS_ACCESS_DENIED );
        return;
    }
    if (entry >= 8192)
    {
        set_error( STATUS_ACCESS_VIOLATION );
        return;
    }
    if (suspend_for_ptrace( thread ))
    {
        unsigned int flags_buf;
        unsigned long addr = (unsigned long)thread->process->ldt_copy + (entry * 4);

        if (read_thread_int( thread, (void *)addr, base ) == -1) goto done;
        if (read_thread_int( thread, (void *)(addr + (8192 * 4)), limit ) == -1) goto done;
        addr = (unsigned long)thread->process->ldt_copy + (2 * 8192 * 4) + (entry & ~3);
        if (read_thread_int( thread, (void *)addr, &flags_buf ) == -1) goto done;
        *flags = flags_buf >> (entry & 3) * 8;
    done:
        resume_after_ptrace( thread );
    }
}


#if defined(linux) && (defined(HAVE_SYS_USER_H) || defined(HAVE_ASM_USER_H)) \
    && (defined(__i386__) || defined(__x86_64__))

#ifdef HAVE_SYS_USER_H
#include <sys/user.h>
#elif defined(HAVE_ASM_USER_H)
#include <asm/user.h>
#endif

/* debug register offset in struct user */
#define DR_OFFSET(dr) ((((struct user *)0)->u_debugreg) + (dr))

/* initialize registers in new thread if necessary */
void init_thread_context( struct thread *thread )
{
    /* Linux doesn't clear all registers, but hopefully enough to avoid spurious breakpoints */
    thread->system_regs = 0;
}

/* retrieve the thread x86 registers */
void get_thread_context( struct thread *thread, context_t *context, unsigned int flags )
{
    int i, pid = get_ptrace_tid(thread);
    long data[8];

    /* all other regs are handled on the client side */
    assert( flags == SERVER_CTX_DEBUG_REGISTERS );

    if (!suspend_for_ptrace( thread )) return;

    if (!(thread->system_regs & SERVER_CTX_DEBUG_REGISTERS))
    {
        /* caller has initialized everything to 0 already, just return */
        context->flags |= SERVER_CTX_DEBUG_REGISTERS;
        goto done;
    }

    for (i = 0; i < 8; i++)
    {
        if (i == 4 || i == 5) continue;
        errno = 0;
        data[i] = ptrace( PTRACE_PEEKUSER, pid, DR_OFFSET(i), 0 );
        if ((data[i] == -1) && errno)
        {
            file_set_error();
            goto done;
        }
    }
    switch (context->cpu)
    {
    case CPU_x86:
        context->debug.i386_regs.dr0 = data[0];
        context->debug.i386_regs.dr1 = data[1];
        context->debug.i386_regs.dr2 = data[2];
        context->debug.i386_regs.dr3 = data[3];
        context->debug.i386_regs.dr6 = data[6];
        context->debug.i386_regs.dr7 = data[7];
        break;
    case CPU_x86_64:
        context->debug.x86_64_regs.dr0 = data[0];
        context->debug.x86_64_regs.dr1 = data[1];
        context->debug.x86_64_regs.dr2 = data[2];
        context->debug.x86_64_regs.dr3 = data[3];
        context->debug.x86_64_regs.dr6 = data[6];
        context->debug.x86_64_regs.dr7 = data[7];
        break;
    default:
        set_error( STATUS_INVALID_PARAMETER );
        goto done;
    }
    context->flags |= SERVER_CTX_DEBUG_REGISTERS;
done:
    resume_after_ptrace( thread );
}

/* set the thread x86 registers */
void set_thread_context( struct thread *thread, const context_t *context, unsigned int flags )
{
    int pid = get_ptrace_tid( thread );

    /* all other regs are handled on the client side */
    assert( flags == SERVER_CTX_DEBUG_REGISTERS );

    if (!suspend_for_ptrace( thread )) return;

    /* force all breakpoint lengths to 1, workaround for kernel bug 200965 */
    ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(7), 0x11110055 );

    switch (context->cpu)
    {
    case CPU_x86:
        /* Linux 2.6.33+ does DR0-DR3 alignment validation, so it has to know LEN bits first */
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(7), context->debug.i386_regs.dr7 & 0xffff0000 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(0), context->debug.i386_regs.dr0 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(1), context->debug.i386_regs.dr1 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(2), context->debug.i386_regs.dr2 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(3), context->debug.i386_regs.dr3 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(6), context->debug.i386_regs.dr6 ) == -1) goto error;
        /* Linux 2.6.33+ needs enable bits set briefly to update value returned by PEEKUSER later */
        ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(7), context->debug.i386_regs.dr7 | 0x55 );
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(7), context->debug.i386_regs.dr7 ) == -1) goto error;
        thread->system_regs |= SERVER_CTX_DEBUG_REGISTERS;
        break;
    case CPU_x86_64:
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(7), context->debug.x86_64_regs.dr7 & 0xffff0000 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(0), context->debug.x86_64_regs.dr0 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(1), context->debug.x86_64_regs.dr1 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(2), context->debug.x86_64_regs.dr2 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(3), context->debug.x86_64_regs.dr3 ) == -1) goto error;
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(6), context->debug.x86_64_regs.dr6 ) == -1) goto error;
        ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(7), context->debug.x86_64_regs.dr7 | 0x55 );
        if (ptrace( PTRACE_POKEUSER, pid, DR_OFFSET(7), context->debug.x86_64_regs.dr7 ) == -1) goto error;
        thread->system_regs |= SERVER_CTX_DEBUG_REGISTERS;
        break;
    default:
        set_error( STATUS_INVALID_PARAMETER );
    }
    resume_after_ptrace( thread );
    return;
 error:
    file_set_error();
    resume_after_ptrace( thread );
}

#elif defined(__i386__) && defined(PTRACE_GETDBREGS) && defined(PTRACE_SETDBREGS) && \
    (defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__))

#include <machine/reg.h>

/* initialize registers in new thread if necessary */
void init_thread_context( struct thread *thread )
{
    if (!(thread->system_regs & SERVER_CTX_DEBUG_REGISTERS)) return;

    /* FreeBSD doesn't clear the debug registers in new threads */
    if (suspend_for_ptrace( thread ))
    {
        struct dbreg dbregs;

        memset( &dbregs, 0, sizeof(dbregs) );
        ptrace( PTRACE_SETDBREGS, get_ptrace_tid( thread ), (caddr_t)&dbregs, 0 );
        resume_after_ptrace( thread );
    }
    thread->system_regs = 0;
}

/* retrieve the thread x86 registers */
void get_thread_context( struct thread *thread, context_t *context, unsigned int flags )
{
    int pid = get_ptrace_tid(thread);
    struct dbreg dbregs;

    /* all other regs are handled on the client side */
    assert( flags == SERVER_CTX_DEBUG_REGISTERS );

    if (!suspend_for_ptrace( thread )) return;

    if (ptrace( PTRACE_GETDBREGS, pid, (caddr_t) &dbregs, 0 ) == -1) file_set_error();
    else
    {
#ifdef DBREG_DRX
        /* needed for FreeBSD, the structure fields have changed under 5.x */
        context->debug.i386_regs.dr0 = DBREG_DRX((&dbregs), 0);
        context->debug.i386_regs.dr1 = DBREG_DRX((&dbregs), 1);
        context->debug.i386_regs.dr2 = DBREG_DRX((&dbregs), 2);
        context->debug.i386_regs.dr3 = DBREG_DRX((&dbregs), 3);
        context->debug.i386_regs.dr6 = DBREG_DRX((&dbregs), 6);
        context->debug.i386_regs.dr7 = DBREG_DRX((&dbregs), 7);
#elif defined(__NetBSD__)
        context->debug.i386_regs.dr0 = dbregs.dr[0];
        context->debug.i386_regs.dr1 = dbregs.dr[1];
        context->debug.i386_regs.dr2 = dbregs.dr[2];
        context->debug.i386_regs.dr3 = dbregs.dr[3];
        context->debug.i386_regs.dr6 = dbregs.dr[6];
        context->debug.i386_regs.dr7 = dbregs.dr[7];
#else
        context->debug.i386_regs.dr0 = dbregs.dr0;
        context->debug.i386_regs.dr1 = dbregs.dr1;
        context->debug.i386_regs.dr2 = dbregs.dr2;
        context->debug.i386_regs.dr3 = dbregs.dr3;
        context->debug.i386_regs.dr6 = dbregs.dr6;
        context->debug.i386_regs.dr7 = dbregs.dr7;
#endif
        context->flags |= SERVER_CTX_DEBUG_REGISTERS;
    }
    resume_after_ptrace( thread );
}

/* set the thread x86 registers */
void set_thread_context( struct thread *thread, const context_t *context, unsigned int flags )
{
    int pid = get_ptrace_tid(thread);
    struct dbreg dbregs;

    /* all other regs are handled on the client side */
    assert( flags == SERVER_CTX_DEBUG_REGISTERS );

    if (!suspend_for_ptrace( thread )) return;

#ifdef DBREG_DRX
    /* needed for FreeBSD, the structure fields have changed under 5.x */
    DBREG_DRX((&dbregs), 0) = context->debug.i386_regs.dr0;
    DBREG_DRX((&dbregs), 1) = context->debug.i386_regs.dr1;
    DBREG_DRX((&dbregs), 2) = context->debug.i386_regs.dr2;
    DBREG_DRX((&dbregs), 3) = context->debug.i386_regs.dr3;
    DBREG_DRX((&dbregs), 4) = 0;
    DBREG_DRX((&dbregs), 5) = 0;
    DBREG_DRX((&dbregs), 6) = context->debug.i386_regs.dr6;
    DBREG_DRX((&dbregs), 7) = context->debug.i386_regs.dr7;
#elif defined(__NetBSD__)
    dbregs.dr[0] = context->debug.i386_regs.dr0;
    dbregs.dr[1] = context->debug.i386_regs.dr1;
    dbregs.dr[2] = context->debug.i386_regs.dr2;
    dbregs.dr[3] = context->debug.i386_regs.dr3;
    dbregs.dr[4] = 0;
    dbregs.dr[5] = 0;
    dbregs.dr[6] = context->debug.i386_regs.dr6;
    dbregs.dr[7] = context->debug.i386_regs.dr7;
#else
    dbregs.dr0 = context->debug.i386_regs.dr0;
    dbregs.dr1 = context->debug.i386_regs.dr1;
    dbregs.dr2 = context->debug.i386_regs.dr2;
    dbregs.dr3 = context->debug.i386_regs.dr3;
    dbregs.dr4 = 0;
    dbregs.dr5 = 0;
    dbregs.dr6 = context->debug.i386_regs.dr6;
    dbregs.dr7 = context->debug.i386_regs.dr7;
#endif
    if (ptrace( PTRACE_SETDBREGS, pid, (caddr_t)&dbregs, 0 ) != -1)
    {
        thread->system_regs |= SERVER_CTX_DEBUG_REGISTERS;
    }
    else file_set_error();

    resume_after_ptrace( thread );
}

#else  /* linux || __FreeBSD__ */

/* initialize registers in new thread if necessary */
void init_thread_context( struct thread *thread )
{
}

/* retrieve the thread x86 registers */
void get_thread_context( struct thread *thread, context_t *context, unsigned int flags )
{
}

/* set the thread x86 debug registers */
void set_thread_context( struct thread *thread, const context_t *context, unsigned int flags )
{
}

#endif  /* linux || __FreeBSD__ */

#endif  /* USE_PTRACE */
