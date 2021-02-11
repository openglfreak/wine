/*
 * ntoskrnl.exe implementation
 *
 * Copyright (C) 2007 Alexandre Julliard
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

#ifndef __WINE_NTOSKRNL_PRIVATE_H
#define __WINE_NTOSKRNL_PRIVATE_H

#include "wine/asm.h"

static inline LPCSTR debugstr_us( const UNICODE_STRING *us )
{
    if (!us) return "<null>";
    return debugstr_wn( us->Buffer, us->Length / sizeof(WCHAR) );
}

struct _OBJECT_TYPE
{
    const WCHAR *name;            /* object type name used for type validation */
    void *(*constructor)(HANDLE); /* used for creating an object from server handle */
    void (*release)(void*);       /* called when the last reference is released */
};

struct _EPROCESS;
struct _KTHREAD;
struct _ETHREAD;

extern RTL_OSVERSIONINFOEXW windows_version;

#define _DEFINE_ACCESSOR(struct_name, return_type, field) \
    static inline return_type * struct_name ## _ACCESS_ ## field ## _PTR ( struct struct_name *ptr ) \
    { \
        if (windows_version.dwMajorVersion > 6 || (windows_version.dwMajorVersion == 6 && windows_version.dwMinorVersion >= 2)) \
            return (return_type*)&((struct struct_name ## _10_0_17763 *)ptr)->field; \
        return (return_type*)&((struct struct_name ## _6_1 *)ptr)->field; \
    }
#define _DEFINE_GET_SIZE(struct_name) \
    static inline size_t struct_name ## _GET_SIZE ( void ) \
    { \
        if (windows_version.dwMajorVersion > 6 || (windows_version.dwMajorVersion == 6 && windows_version.dwMinorVersion >= 2)) \
            return sizeof(struct struct_name ## _10_0_17763); \
        return sizeof(struct struct_name ## _6_1); \
    }

struct _EPROCESS_6_1
{
    DISPATCHER_HEADER header;
    PROCESS_BASIC_INFORMATION info;
    BOOL wow64;
};
struct _EPROCESS_10_0_17763
{
    DISPATCHER_HEADER header;
    PROCESS_BASIC_INFORMATION info;
    BOOL wow64;
};
_DEFINE_ACCESSOR(_EPROCESS, DISPATCHER_HEADER, header)
_DEFINE_ACCESSOR(_EPROCESS, PROCESS_BASIC_INFORMATION, info)
_DEFINE_ACCESSOR(_EPROCESS, BOOL, wow64)
_DEFINE_GET_SIZE(_EPROCESS)

struct _KTHREAD_6_1
{
    DISPATCHER_HEADER header;
    PEPROCESS process;
    CLIENT_ID id;
    unsigned int critical_region;
    KAFFINITY user_affinity;
};
struct _KTHREAD_10_0_17763
{
    DISPATCHER_HEADER header;
    PEPROCESS process;
    CLIENT_ID id;
    unsigned int critical_region;
    KAFFINITY user_affinity;
};
_DEFINE_ACCESSOR(_KTHREAD, DISPATCHER_HEADER, header)
_DEFINE_ACCESSOR(_KTHREAD, PEPROCESS, process)
_DEFINE_ACCESSOR(_KTHREAD, CLIENT_ID, id)
_DEFINE_ACCESSOR(_KTHREAD, unsigned int, critical_region)
_DEFINE_ACCESSOR(_KTHREAD, KAFFINITY, user_affinity)
_DEFINE_GET_SIZE(_KTHREAD)

struct _ETHREAD_6_1
{
    struct _KTHREAD_6_1 kthread;
};
struct _ETHREAD_10_0_17763
{
    struct _KTHREAD_6_1 kthread;
};
_DEFINE_ACCESSOR(_ETHREAD, struct _KTHREAD, kthread)
_DEFINE_GET_SIZE(_ETHREAD)

#define _EPROCESS_ACCESS(ptr, field) (*_EPROCESS_ACCESS_ ## field ## _PTR ( (ptr) ))
#define _KTHREAD_ACCESS(ptr, field) (*_KTHREAD_ACCESS_ ## field ## _PTR ( (ptr) ))
#define _ETHREAD_ACCESS(ptr, field) (*_ETHREAD_ACCESS_ ## field ## _PTR ( (ptr) ))

#define _EPROCESS_SIZE (_EPROCESS_GET_SIZE())
#define _KTHREAD_SIZE (_KTHREAD_GET_SIZE())
#define _ETHREAD_SIZE (_ETHREAD_GET_SIZE())

void *alloc_kernel_object( POBJECT_TYPE type, HANDLE handle, SIZE_T size, LONG ref ) DECLSPEC_HIDDEN;
NTSTATUS kernel_object_from_handle( HANDLE handle, POBJECT_TYPE type, void **ret ) DECLSPEC_HIDDEN;

extern POBJECT_TYPE ExEventObjectType;
extern POBJECT_TYPE ExSemaphoreObjectType;
extern POBJECT_TYPE IoDeviceObjectType;
extern POBJECT_TYPE IoDriverObjectType;
extern POBJECT_TYPE IoFileObjectType;
extern POBJECT_TYPE PsProcessType;
extern POBJECT_TYPE PsThreadType;
extern POBJECT_TYPE SeTokenObjectType;

#define DECLARE_CRITICAL_SECTION(cs) \
    static CRITICAL_SECTION cs; \
    static CRITICAL_SECTION_DEBUG cs##_debug = \
    { 0, 0, &cs, { &cs##_debug.ProcessLocksList, &cs##_debug.ProcessLocksList }, \
      0, 0, { (DWORD_PTR)(__FILE__ ": " # cs) }}; \
    static CRITICAL_SECTION cs = { &cs##_debug, -1, 0, 0, 0, 0 };

void ObReferenceObject( void *obj ) DECLSPEC_HIDDEN;

void pnp_manager_enumerate_root_devices( const WCHAR *driver_name ) DECLSPEC_HIDDEN;
void pnp_manager_start(void) DECLSPEC_HIDDEN;
void pnp_manager_stop(void) DECLSPEC_HIDDEN;

static const WCHAR servicesW[] = {'\\','R','e','g','i','s','t','r','y',
                                  '\\','M','a','c','h','i','n','e',
                                  '\\','S','y','s','t','e','m',
                                  '\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t',
                                  '\\','S','e','r','v','i','c','e','s',
                                  '\\',0};

struct wine_device
{
    DEVICE_OBJECT device_obj;
    DEVICE_RELATIONS *children;
};
#endif
