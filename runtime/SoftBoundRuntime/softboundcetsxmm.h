//=== SoftBoundRuntime/softboundcetsxmm.h - headers for functions introduced by SoftBound+CETS--*- C -*===// 
// Copyright (c) 2011 Santosh Nagarakatte, Milo M. K. Martin. All rights reserved.

// Developed by: Santosh Nagarakatte, Milo M.K. Martin,
//               Jianzhou Zhao, Steve Zdancewic
//               Department of Computer and Information Sciences,
//               University of Pennsylvania
//               http://www.cis.upenn.edu/acg/softbound/

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal with the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

//   1. Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimers.

//   2. Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimers in the
//      documentation and/or other materials provided with the distribution.

//   3. Neither the names of Santosh Nagarakatte, Milo M. K. Martin,
//      Jianzhou Zhao, Steve Zdancewic, University of Pennsylvania, nor
//      the names of its contributors may be used to endorse or promote
//      products derived from this Software without specific prior
//      written permission.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// WITH THE SOFTWARE.
//===---------------------------------------------------------------------===//


#ifndef __SOFTBOUNDCETSXMM_H__
#define __SOFTBOUNDCETSXMM_H__

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <smmintrin.h>

#ifdef __SBCETS_STATS_MODE
extern size_t __sbcets_stats_spatial_load_dereference_checks;
extern size_t __sbcets_stats_spatial_store_dereference_checks ;
extern size_t __sbcets_stats_temporal_load_dereference_checks ;
extern size_t __sbcets_stats_temporal_store_dereference_checks;
extern size_t __sbcets_stats_metadata_loads;
extern size_t __sbcets_stats_metadata_stores;
extern size_t __sbcets_stats_heap_allocations;
extern size_t __sbcets_stats_stack_allocations;
extern size_t __sbcets_stats_heap_deallocations;
extern size_t __sbcets_stats_stack_deallocations;
extern size_t __sbcets_stats_metadata_memcopies;
extern size_t __sbcets_stats_memcpy_checks;
#endif


#if 0
#define __SOFTBOUNDCETS_TRIE 1
#define __SOFTBOUNDCETS_SPATIAL_TEMPORAL 1
#endif

/* Trie represented by the following by a structure with four fields
 * if both __SOFTBOUNDCETS_SPATIAL and __SOFTBOUNDCETS_TEMPORAL are
 * specified. It has key and lock with size_t
 */

typedef struct {

#ifdef __SOFTBOUNDCETS_SPATIAL
  void* base;
  void* bound;  

#define __SOFTBOUNDCETS_METADATA_NUM_FIELDS 2
#define __BASE_INDEX 0
#define __BOUND_INDEX 1
#define __KEY_INDEX 10000000
#define __LOCK_INDEX 10000000

#elif __SOFTBOUNDCETS_TEMPORAL  
  size_t key;
  void* lock;
#define __SOFTBOUNDCETS_METADATA_NUM_FIELDS 2
#define __KEY_INDEX 0
#define __LOCK_INDEX 1
#define __BASE_INDEX  10000000
#define __BOUND_INDEX 10000000

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

  void* base;
  void* bound;
  size_t key;
  void* lock;
#define __SOFTBOUNDCETS_METADATA_NUM_FIELDS 4

#define __BASE_INDEX 0
#define __BOUND_INDEX 1
#define __KEY_INDEX 2
#define __LOCK_INDEX 3

#else 

  void* base;
  void* bound;
  size_t key;
  void* lock;  

#define __SOFTBOUNDCETS_METADATA_NUM_FIELDS 4

#define __BASE_INDEX 0
#define __BOUND_INDEX 1
#define __KEY_INDEX 2
#define __LOCK_INDEX 3

#endif

} __softboundcets_trie_entry_t;


#if defined(__APPLE__)
#define SOFTBOUNDCETS_MMAP_FLAGS (MAP_ANON|MAP_NORESERVE|MAP_PRIVATE)
#else
#define SOFTBOUNDCETS_MMAP_FLAGS (MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE)
#endif


// Check to make sure at least one and only one metadata representation is defined
#ifndef __SOFTBOUNDCETS_TRIE
#ifndef __SOFTBOUNDCETS_DISABLE
#error "Softboundcets error: configuration type not specified (-D__SOFTBOUNDCETS_TRIE, or -D__SOFTBOUNDCETS_DISABLE)"
#endif
#endif

#ifdef __SOFTBOUNDCETS_DISABLE
#undef __SOFTBOUNDCETS_DISABLE
static const int __SOFTBOUNDCETS_DISABLE = 1;
#else
static const int __SOFTBOUNDCETS_DISABLE = 0;
#endif

#ifdef __SOFTBOUNDCETS_DEBUG
#undef __SOFTBOUNDCETS_DEBUG
static const int __SOFTBOUNDCETS_DEBUG = 1;
#define __SOFTBOUNDCETS_NORETURN 
#else 
static const int __SOFTBOUNDCETS_DEBUG = 0;
#define __SOFTBOUNDCETS_NORETURN __attribute__((__noreturn__))
#endif

#ifdef __SOFTBOUNDCETS_METADATA_LOAD_STORE_DEBUG
#undef __SOFTBOUNDCETS_METADATA_LOAD_STORE_DEBUG
static const int __SOFTBOUNDCETS_METADATA_LOAD_STORE_DEBUG = 1;
#else
static const int __SOFTBOUNDCETS_METADATA_LOAD_STORE_DEBUG = 0;
#endif



#ifdef __SOFTBOUNDCETS_SHADOW_STACK_DEBUG
#undef __SOFTBOUNDCETS_SHADOW_STACK_DEBUG
static const int __SOFTBOUNDCETS_SHADOW_STACK_DEBUG = 1;
#else
static const int __SOFTBOUNDCETS_SHADOW_STACK_DEBUG = 0;
#endif

#ifdef __SOFTBOUNDCETS_TRIE
#undef __SOFTBOUNDCETS_TRIE
static const int __SOFTBOUNDCETS_TRIE = 1;
#else
static const int __SOFTBOUNDCETS_TRIE = 0;
#endif

#ifdef __SOFTBOUNDCETS_PREALLOCATE_TRIE
#undef __SOFTBOUNDCETS_PREALLOCATE_TRIE
static const int __SOFTBOUNDCETS_PREALLOCATE_TRIE = 1;
#else
static const int __SOFTBOUNDCETS_PREALLOCATE_TRIE = 0;
#endif

#ifdef __SOFTBOUNDCETS_SPATIAL_TEMPORAL 
#define __SOFTBOUNDCETS_FREE_MAP
#endif

#ifdef __SOFTBOUNDCETS_TEMPORAL
#define __SOFTBOUNDCETS_FREE_MAP
#endif

#ifdef __SOFTBOUNDCETS_FREE_MAP
#undef __SOFTBOUNDCETS_FREE_MAP
static const int __SOFTBOUNDCETS_FREE_MAP = 1;
#else 
static const int __SOFTBOUNDCETS_FREE_MAP = 0;
#endif



// check if __WORDSIZE works with clang on both Linux and MacOSX
/* Allocating one million entries for the temporal key */
#if __WORDSIZE == 32
static const size_t __SOFTBOUNDCETS_N_TEMPORAL_ENTRIES = ((size_t) 4 * (size_t) 1024 * (size_t) 1024); 
static const size_t __SOFTBOUNDCETS_LOWER_ZERO_POINTER_BITS = 2;
static const size_t __SOFTBOUNDCETS_N_STACK_TEMPORAL_ENTRIES = ((size_t) 1024 * (size_t) 64);
static const size_t __SOFTBOUNDCETS_N_GLOBAL_LOCK_SIZE = ((size_t) 1024 * (size_t) 32);
// 2^23 entries each will be 8 bytes each 
static const size_t __SOFTBOUNDCETS_TRIE_PRIMARY_TABLE_ENTRIES = ((size_t) 8*(size_t) 1024 * (size_t) 1024);
static const size_t __SOFTBOUNDCETS_SHADOW_STACK_ENTRIES = ((size_t) 128 * (size_t) 32 );
/* 256 Million simultaneous objects */
static const size_t __SOFTBOUNDCETS_N_FREE_MAP_ENTRIES = ((size_t) 32 * (size_t) 1024* (size_t) 1024);
// each secondary entry has 2^ 22 entries 
static const size_t __SOFTBOUNDCETS_TRIE_SECONDARY_TABLE_ENTRIES = ((size_t) 4 * (size_t) 1024 * (size_t) 1024); 

#else

static const size_t __SOFTBOUNDCETS_N_TEMPORAL_ENTRIES = ((size_t) 64*(size_t) 1024 * (size_t) 1024); 
static const size_t __SOFTBOUNDCETS_LOWER_ZERO_POINTER_BITS = 3;

static const size_t __SOFTBOUNDCETS_N_STACK_TEMPORAL_ENTRIES = ((size_t) 1024 * (size_t) 64);
static const size_t __SOFTBOUNDCETS_N_GLOBAL_LOCK_SIZE = ((size_t) 1024 * (size_t) 32);

// 2^23 entries each will be 8 bytes each 
static const size_t __SOFTBOUNDCETS_TRIE_PRIMARY_TABLE_ENTRIES = ((size_t) 8*(size_t) 1024 * (size_t) 1024);

static const size_t __SOFTBOUNDCETS_SHADOW_STACK_ENTRIES = ((size_t) 128 * (size_t) 32 );

/* 256 Million simultaneous objects */
static const size_t __SOFTBOUNDCETS_N_FREE_MAP_ENTRIES = ((size_t) 32 * (size_t) 1024* (size_t) 1024);
// each secondary entry has 2^ 22 entries 
static const size_t __SOFTBOUNDCETS_TRIE_SECONDARY_TABLE_ENTRIES = ((size_t) 4 * (size_t) 1024 * (size_t) 1024); 

#endif

#define __WEAK__ __attribute__((__weak__))

#define __WEAK_INLINE __attribute__((__weak__,__always_inline__)) 

#if __WORDSIZE == 32
#define __METADATA_INLINE 
#else
#define __METADATA_INLINE __attribute__((__weak__, __always_inline__))
#endif

#define __NO_INLINE __attribute__((__noinline__))

extern __softboundcets_trie_entry_t** __softboundcets_trie_primary_table;

extern size_t* __softboundcets_shadow_stack_ptr;
extern size_t* __softboundcets_temporal_space_begin;

extern size_t* __softboundcets_stack_temporal_space_begin;
extern size_t* __softboundcets_free_map_table;


extern void __softboundcets_init(int is_trie);
extern __SOFTBOUNDCETS_NORETURN void __softboundcets_abort();
extern void __softboundcets_printf(const char* str, ...);
extern size_t* __softboundcets_global_lock; 
extern size_t __softboundcets_statistics_metadata_stores;
extern size_t __softboundcets_statistics_metadata_loads;
extern size_t __softboundcets_statistics_load_dereference_checks;
extern size_t __softboundcets_statistics_store_dereference_checks;
extern size_t __softboundcets_statistics_temporal_load_dereference_checks;
extern size_t __softboundcets_statistics_temporal_store_dereference_checks;

void* __softboundcets_safe_calloc(size_t, size_t);
void* __softboundcets_safe_malloc(size_t);
void __softboundcets_safe_free(void*);

void * __softboundcets_safe_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
__WEAK_INLINE void __softboundcets_allocation_secondary_trie_allocate(void* addr_of_ptr);
__WEAK_INLINE void __softboundcets_add_to_free_map(size_t ptr_key, void* ptr) ;

/******************************************************************************/

static __attribute__ ((__constructor__)) void __softboundcets_global_init();

extern __NO_INLINE void __softboundcets_stub(void);

__WEAK_INLINE void* __softboundcets_extract_base(__v2di base_bound) {

  void* base = (void*) base_bound[0];
  return base;
}

__WEAK_INLINE void* __softboundcets_extract_bound(__v2di base_bound) {
  
  void* bound = (void*) base_bound[1];
  return bound;
}

__WEAK_INLINE size_t __softboundcets_extract_key(__v2di key_lock) {
  
  size_t key = key_lock[0];
  return key;

}

__WEAK_INLINE void* __softboundcets_extract_lock(__v2di key_lock) {

  void* lock = (void*)key_lock[1];
  return lock;

}

__WEAK_INLINE __v2di __softboundcets_construct_v2di(size_t key1, size_t key2) {
   
  __v2di temp = {key1, key2};
  return temp;
}


__WEAK_INLINE __v2di __softboundcets_get_global_key_lock(){
  
  __v2di temp = __softboundcets_construct_v2di(1, (size_t)__softboundcets_global_lock);
  return temp;

}

__WEAK_INLINE __v2di __softboundcets_convert_v2di_sizet_ptr(size_t val1, void* ptr) {

  __v2di temp = __softboundcets_construct_v2di(val1, (size_t) ptr);
  return temp;
}

__WEAK_INLINE __v2di __softboundcets_convert_v2di_ptr_ptr(void* ptr1, void* ptr2) {

  __v2di temp = __softboundcets_construct_v2di((size_t) ptr1, (size_t) ptr2);
  return temp;
}


void __softboundcets_global_init()
{
  __softboundcets_init( __SOFTBOUNDCETS_TRIE);
  __softboundcets_stub();
}


/* Layout of the shadow stack

  1) size of the previous stack frame
  2) size of the current stack frame
  3) base/bound/key/lock of each argument

  Allocation: read the current stack frames size, increment the
  shadow_stack_ptr by current_size + 2, store the previous size into
  the new prev value, calcuate the allocation size and store in the
  new current stack size field; Deallocation: read the previous size,
  and decrement the shadow_stack_ptr */
  
__WEAK_INLINE void __softboundcets_allocate_shadow_stack_space(int num_pointer_args){
 

  size_t* prev_stack_size_ptr = __softboundcets_shadow_stack_ptr + 1;
  size_t prev_stack_size = *((size_t*)prev_stack_size_ptr);

  if(__SOFTBOUNDCETS_SHADOW_STACK_DEBUG){
    printf("[allocate_stack] shadow_stack_ptr = %p, prev_stack_size = %zx, prev_stack_size_ptr = %p\n", __softboundcets_shadow_stack_ptr, prev_stack_size, prev_stack_size_ptr);
  }

  __softboundcets_shadow_stack_ptr = __softboundcets_shadow_stack_ptr + prev_stack_size + 2;

  if(__SOFTBOUNDCETS_SHADOW_STACK_DEBUG){
    printf("[allocate_stack] new_shadow_stack_ptr = %p\n", __softboundcets_shadow_stack_ptr);
  }
  
  *((size_t*) __softboundcets_shadow_stack_ptr) = prev_stack_size;
  size_t* current_stack_size_ptr = __softboundcets_shadow_stack_ptr + 1;
  
  ssize_t size = num_pointer_args * __SOFTBOUNDCETS_METADATA_NUM_FIELDS;
  *((size_t*) current_stack_size_ptr) = size;
}
   
__WEAK_INLINE __v2di __softboundcets_load_base_bound_shadow_stack(int arg_no){
  assert (arg_no >= 0 );
  size_t count = 2 +  arg_no * __SOFTBOUNDCETS_METADATA_NUM_FIELDS + __BASE_INDEX ;
  size_t* base_ptr = (__softboundcets_shadow_stack_ptr + count); 

  __v2di base_bound = *((__m128*)base_ptr);
  //  __v2di base_bound = __builtin_ia32_loaddqu((char* const*)(&(base_ptr));
  
  if(__SOFTBOUNDCETS_SHADOW_STACK_DEBUG){
    //    printf("[load_base] loading base=%p from shadow_stack_ptr=%p\n", base, base_ptr);
  }
  return base_bound;
}

__WEAK_INLINE __v2di __softboundcets_load_key_lock_shadow_stack(int arg_no){

  assert (arg_no >= 0 );
  size_t count = 2 + arg_no * __SOFTBOUNDCETS_METADATA_NUM_FIELDS  + __KEY_INDEX ;
  size_t* key_ptr = (__softboundcets_shadow_stack_ptr + count); 
  
  __v2di key_lock = *((__m128*)key_ptr);

  if(__SOFTBOUNDCETS_SHADOW_STACK_DEBUG){
    //    printf("[load_key] loading key=%zx from shadow_stack_ptr=%p\n", key, key_ptr);
  }
  return key_lock;

}

__WEAK_INLINE void __softboundcets_store_base_bound_shadow_stack(__v2di base_bound, int arg_no){
  
  assert(arg_no >= 0);
  size_t count = 2 +  arg_no * __SOFTBOUNDCETS_METADATA_NUM_FIELDS + __BASE_INDEX ;
  void** base_ptr = (void**)(__softboundcets_shadow_stack_ptr + count); 
  
  *((__m128*)base_ptr) = base_bound;
//  __builtin_ia32_storedqu((char*)(base_ptr), base_bound);

  if(__SOFTBOUNDCETS_SHADOW_STACK_DEBUG){
    //    printf("[store_base] storing base=%p from shadow_stack_ptr=%p\n", base, base_ptr);
  }

}

 
 __WEAK_INLINE void 
   __softboundcets_store_key_lock_shadow_stack(__v2di key_lock, 
                                               int arg_no){
  assert(arg_no >= 0);
  size_t count = 2 +  arg_no * __SOFTBOUNDCETS_METADATA_NUM_FIELDS + __KEY_INDEX ;
  size_t* key_ptr = (__softboundcets_shadow_stack_ptr + count); 

  __builtin_ia32_storedqu((char*)key_ptr, key_lock);

  if(__SOFTBOUNDCETS_SHADOW_STACK_DEBUG){
    //    printf("[store_base] storing key=%zx from shadow_stack_ptr=%p\n", key, key_ptr);
  }
}


__WEAK_INLINE void __softboundcets_deallocate_shadow_stack_space(){

  size_t* reserved_space_ptr = __softboundcets_shadow_stack_ptr;
  size_t read_value = *((size_t*) reserved_space_ptr);
  assert((read_value >=0 && read_value <= __SOFTBOUNDCETS_SHADOW_STACK_ENTRIES));            
  size_t* prev_ptr;

  if(__SOFTBOUNDCETS_SHADOW_STACK_DEBUG){
    prev_ptr = __softboundcets_shadow_stack_ptr;
  }

  __softboundcets_shadow_stack_ptr =  __softboundcets_shadow_stack_ptr - read_value - 2;

  if(__SOFTBOUNDCETS_SHADOW_STACK_DEBUG){
    printf("[deallocate] current_shadow_stack_ptr=%p, prev_stack_ptr=%p\n", __softboundcets_shadow_stack_ptr, prev_ptr);
  }
}

__WEAK_INLINE __softboundcets_trie_entry_t* __softboundcets_trie_allocate(){
  
  __softboundcets_trie_entry_t* secondary_entry;
  size_t length = (__SOFTBOUNDCETS_TRIE_SECONDARY_TABLE_ENTRIES) * sizeof(__softboundcets_trie_entry_t);
  secondary_entry = __softboundcets_safe_mmap(0, length, PROT_READ| PROT_WRITE, SOFTBOUNDCETS_MMAP_FLAGS, -1, 0);
  //assert(secondary_entry != (void*)-1); 
  //printf("snd trie table %p %lx\n", secondary_entry, length);
  return secondary_entry;
}

__WEAK_INLINE void __softboundcets_introspect_metadata(void* ptr, __v2di base_bound, int arg_no){
  
  void* base = (void*) __softboundcets_extract_base(base_bound);
  void* bound = (void*) __softboundcets_extract_bound(base_bound);
  
  printf("[introspect_metadata]ptr=%p, base=%p, bound=%p, arg_no=%d\n", ptr, base, bound, arg_no);
}

__METADATA_INLINE void __softboundcets_copy_metadata(void* dest, void* from, size_t size){
  
  //  printf("dest=%p, from=%p, size=%zx\n", dest, from, size);
  
  size_t dest_ptr = (size_t) dest;
  size_t dest_ptr_end = dest_ptr + size;

  size_t from_ptr = (size_t) from;
  size_t from_ptr_end = from_ptr + size;

  // Making memcopy source and destination world aligned

  if(from_ptr % 8 != 0){
    return;
    // from_ptr = from_ptr %8;
    // dest_ptr = dest_ptr %8;
  }
#if 0
  if(from_ptr % 8 != 0){
    printf("memcopy unaligned\n");
    abort();
    size_t offset = from_ptr % 8;
    from_ptr = from_ptr - 8 + offset;
    dest_ptr = dest_ptr - 8 + offset;

  }
#endif

  __softboundcets_trie_entry_t* trie_secondary_table_dest_begin;
  __softboundcets_trie_entry_t* trie_secondary_table_from_begin;
  
  size_t dest_primary_index_begin = (dest_ptr >> 25);
  size_t dest_primary_index_end = (dest_ptr_end >> 25);

  size_t from_primary_index_begin = (from_ptr >> 25);
  size_t from_primary_index_end =  (from_ptr_end >> 25);


  if((from_primary_index_begin != from_primary_index_end) || 
     (dest_primary_index_begin != dest_primary_index_end)){

    size_t from_sizet = from_ptr;
    size_t dest_sizet = dest_ptr;

    size_t trie_size = size;
    size_t index = 0;

    for(index=0; index < trie_size; index = index + 8){
      
      void* temp_from_addr = (void*)(from_sizet +index);
      void* temp_to_addr = (void*) (dest_sizet + index);

      size_t temp_from_pindex = (from_sizet + index) >> 25;
      size_t temp_to_pindex = (dest_sizet + index) >> 25;

      size_t dest_secondary_index = (((dest_sizet + index) >> 3) & 0x3fffff);
      size_t from_secondary_index = (((from_sizet + index) >> 3) & 0x3fffff);
      
      __softboundcets_trie_entry_t* temp_from_strie = __softboundcets_trie_primary_table[temp_from_pindex];

      if(temp_from_strie == NULL){
        temp_from_strie = __softboundcets_trie_allocate();
        __softboundcets_trie_primary_table[temp_from_pindex] = temp_from_strie;
      }
     __softboundcets_trie_entry_t* temp_to_strie = __softboundcets_trie_primary_table[temp_to_pindex];

      if(temp_to_strie == NULL){
        temp_to_strie = __softboundcets_trie_allocate();
        __softboundcets_trie_primary_table[temp_to_pindex] = temp_to_strie;
      }

      void* dest_entry_ptr = &temp_to_strie[dest_secondary_index];
      void* from_entry_ptr = &temp_from_strie[from_secondary_index];
  
#ifdef __SOFTBOUNDCETS_SPATIAL
      memcpy(dest_entry_ptr, from_entry_ptr, 16);
#elif __SOFTBOUNDCETS_TEMPORAL
      memcpy(dest_entry_ptr, from_entry_ptr, 16);
#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL
      memcpy(dest_entry_ptr, from_entry_ptr, 32);
#else
      memcpy(dest_entry_ptr, from_entry_ptr, 32);
#endif
    }    
    return;

  }
    
  trie_secondary_table_dest_begin = __softboundcets_trie_primary_table[dest_primary_index_begin];
  trie_secondary_table_from_begin = __softboundcets_trie_primary_table[from_primary_index_begin];
  
  if(trie_secondary_table_from_begin == NULL)
    return;

  if(trie_secondary_table_dest_begin == NULL){
    trie_secondary_table_dest_begin = __softboundcets_trie_allocate();
    __softboundcets_trie_primary_table[dest_primary_index_begin] = trie_secondary_table_dest_begin;
    //    printf("[copy_metadata] allocating secondary trie for dest_primary_index=%zx, orig_dest=%p, orig_from=%p\n", dest_primary_index_begin, dest, from);
  }

  size_t dest_secondary_index = ((dest_ptr>> 3) & 0x3fffff);
  size_t from_secondary_index = ((from_ptr>> 3) & 0x3fffff);
  
  assert(dest_secondary_index < __SOFTBOUNDCETS_TRIE_SECONDARY_TABLE_ENTRIES);
  assert(from_secondary_index < __SOFTBOUNDCETS_TRIE_SECONDARY_TABLE_ENTRIES);

  void* dest_entry_ptr = &trie_secondary_table_dest_begin[dest_secondary_index];
  void* from_entry_ptr = &trie_secondary_table_from_begin[from_secondary_index];
  
#ifdef __SOFTBOUNDCETS_SPATIAL
  //  printf("doing 16 byte spatial metadata\n");
  memcpy(dest_entry_ptr, from_entry_ptr, 16* (size>>3));
#elif __SOFTBOUNDCETS_TEMPORAL
  //  printf("doing 16 byte temporal metadata\n");
  memcpy(dest_entry_ptr, from_entry_ptr, 16* (size>>3));
#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL
  //  printf("doing 32 byte metadata\n");
  memcpy(dest_entry_ptr, from_entry_ptr, 32* (size >> 3));
#else
  //  printf("doing 32 byte metadata\n");
  memcpy(dest_entry_ptr, from_entry_ptr, 32* (size>> 3));
#endif
  return;
}

__WEAK_INLINE void 
__softboundcets_shrink_bounds(void* new_base, void* new_bound, 
                              void* old_base, void* old_bound, 
                              void** base_alloca, void** bound_alloca)
{

  assert(0 && "shrink not handled");
}

__WEAK_INLINE void 
__softboundcets_spatial_call_dereference_check(__v2di base_bound, void* ptr) 
{

  void* base = __softboundcets_extract_base(base_bound);
  void* bound = __softboundcets_extract_bound(base_bound);
  if (__SOFTBOUNDCETS_DISABLE) {
    return;
  }

#ifndef __NOSIM_CHECKS
  if ((base != bound) && (ptr != base)) {
    if (__SOFTBOUNDCETS_DEBUG) {
      __softboundcets_printf("In Call Dereference Check, base=%p, bound=%p, ptr=%p\n", 
                             base, bound, ptr);
    }
    __softboundcets_abort();
  }
#endif

}

extern void* malloc_address;
__WEAK_INLINE void 
__softboundcets_spatial_load_dereference_check(__v2di base_bound, void *ptr, size_t size_of_type)
{

#ifdef __SBCETS_XMM_ASM_MODE_SCHK
  __asm__("icschkx %0, %1\n\t"
          : 
          : "r"(ptr), "x"(base_bound)
          );
  return;

#endif

#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_spatial_load_dereference_checks++;
#endif


  if (__SOFTBOUNDCETS_DISABLE) {
    return;
  }

  void* base = (void*)__softboundcets_extract_base(base_bound);
  void* bound = (void*)__softboundcets_extract_bound(base_bound);

  if (__SOFTBOUNDCETS_DEBUG) {
    __softboundcets_printf("In Spatial LDC, base=%p, bound=%p, ptr=%p, sizeof_type=%zx\n", 
                           base, bound, ptr, size_of_type);
  }
  
  if ((ptr < base) || ((void*)((char*) ptr + size_of_type) > bound)) {
    __softboundcets_printf("In Spatial LDC, base=%zx, bound=%zx, ptr=%zx, malloc_address=%p\n", 
                           base, bound, ptr, malloc_address);
    __softboundcets_abort();
  }
}


__WEAK_INLINE void 
__softboundcets_spatial_store_dereference_check(__v2di base_bound, void *ptr, 
                                                size_t size_of_type)
{


#ifdef __SBCETS_XMM_ASM_MODE_SCHK
  __asm__("icschkx %0, %1\n\t"
          : 
          : "r"(ptr), "x"(base_bound)
          );
  return;

#endif


#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_spatial_store_dereference_checks++;
#endif

  if (__SOFTBOUNDCETS_DISABLE) {
    return;
  } 

  void* base = (void*) __softboundcets_extract_base(base_bound);
  void* bound = (void*) __softboundcets_extract_bound(base_bound);

  if (__SOFTBOUNDCETS_DEBUG) {
    __softboundcets_printf("In Spatial SDC, base=%p, bound=%p, ptr=%p, size_of_type=%zx, ptr+size = %zx\n", 
                           base, bound, ptr, size_of_type, (char*)ptr+size_of_type);
  }

  if ((ptr < base) || ((void*)((char*)ptr + size_of_type) > bound)) {
    if(__SOFTBOUNDCETS_DEBUG) {
      __softboundcets_printf("In Spatial SDC  base=%p, bound=%p, ptr=%p, size_of_type=%zx, ptr+size=%p\n", 
                             base, bound, ptr, size_of_type, (char*)ptr+size_of_type);
    }
    __softboundcets_abort();
  }
}


/* Memcopy check, different variants based on spatial, temporal and
   spatial+temporal modes
*/

#ifdef __SOFTBOUNDCETS_SPATIAL
__WEAK_INLINE void 
__softboundcets_memcopy_check(void* dest, void* src, size_t size,
                              __v2di dest_base_bound,
                              __v2di src_base_bound) {


  void* dest_base = (char*) __softboundcets_extract_base(dest_base_bound);
  void* dest_bound = (char*) __softboundcets_extract_bound(dest_base_bound);

  void* src_base = (char*) __softboundcets_extract_base(src_base_bound);
  void* src_bound = (char*) __softboundcets_extract_bound(src_base_bound);

#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_memcpy_checks++;
#endif

  if(size >= LONG_MAX)
    __softboundcets_abort();
  
  if(dest < dest_base || dest + size > dest_bound)
    __softboundcets_abort();

  if(src < src_base || src + size > src_bound)
    __softboundcets_abort();

}
#elif __SOFTBOUNDCETS_TEMPORAL

__WEAK_INLINE void 
__softboundcets_memcopy_check(void* dest, void* src, size_t size,
                              __v2di dest_key_lock, __v2di src_key_lock){


  size_t dest_key = __softboundcets_extract_key(dest_key_lock);
  void* dest_lock = (void*) __softboundcets_extract_lock(dest_key_lock);

  size_t src_key = __softboundcets_extract_key(src_key_lock);
  void* src_lock = (void*) __softboundcets_extract_lock(src_key_lock);

#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_memcpy_checks++;
#endif

  if(size >= LONG_MAX)
    __softboundcets_abort();

  if(dest_key != *((size_t*)(dest_lock))){
    __softboundcets_abort();
  }

  if(src_key != *((size_t*)(src_lock))){
    __softboundcets_abort();
  }

}

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

__WEAK_INLINE void 
__softboundcets_memcopy_check(void* dest, void* src, size_t size,
                              __v2di dest_base_bound, __v2di src_base_bound,
                              __v2di dest_key_lock , __v2di src_key_lock){

#ifndef __NOSIM_CHECKS

  void* dest_base = (char*) __softboundcets_extract_base(dest_base_bound);
  void* dest_bound = (char*) __softboundcets_extract_bound(dest_base_bound);
  
  void* src_base = (char*) __softboundcets_extract_base(src_base_bound);
  void* src_bound = (char*) __softboundcets_extract_bound(src_base_bound);

  size_t dest_key = __softboundcets_extract_key(dest_key_lock);
  void* dest_lock = (void*) __softboundcets_extract_lock(dest_key_lock);

  size_t src_key = __softboundcets_extract_key(src_key_lock);
  void* src_lock = (void*) __softboundcets_extract_lock(src_key_lock);



#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_memcpy_checks++;
#endif

  /* printf("dest=%zx, src=%zx, size=%zx, ulong_max=%zx\n",  */
  /*        dest, src, size, ULONG_MAX); */
  if(size >= LONG_MAX)
    __softboundcets_abort();


  if(dest < dest_base || dest + size > dest_bound)
    __softboundcets_abort();

  if(src < src_base || src + size > src_bound)
    __softboundcets_abort();

  if(dest_key != *((size_t*)(dest_lock))){
    __softboundcets_abort();
  }

  if(src_key != *((size_t*)(src_lock))){
    __softboundcets_abort();
  }

#endif

}
#else

__WEAK_INLINE void 
__softboundcets_memcopy_check(void* dest, void* src, size_t size,
                              void* dest_base, void* dest_bound, 
                              void* src_base, void* src_bound,
                              size_t dest_key, void* dest_lock, 
                              size_t src_key, void* src_lock) {  

  printf("not handled\n");
  __softboundcets_abort();

}
#endif

/* Memset check, different variants based on spatial, temporal and
   spatial+temporal modes */


#ifdef __SOFTBOUNDCETS_SPATIAL
__WEAK_INLINE void 
__softboundcets_memset_check(void* dest, size_t size,
                             __v2di dest_base_bound) {

  void* dest_base = (void*)__softboundcets_extract_base(dest_base_bound);
  void* dest_bound = (void*)__softboundcets_extract_bound(dest_base_bound);

#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_memcpy_checks++;
#endif

  if(size >= LONG_MAX)
    __softboundcets_abort();
  
  if(dest < dest_base || dest + size > dest_bound)
    __softboundcets_abort();

  if(src < src_base || src + size > src_bound)
    __softboundcets_abort();

}
#elif __SOFTBOUNDCETS_TEMPORAL

__WEAK_INLINE void 
__softboundcets_memset_check(void* dest, size_t size,
                             __v2di dest_key_lock){

  size_t dest_key = __softboundcets_extract_key(dest_key_lock);
  void* dest_lock = (void*)__softboundcets_extract_lock(dest_key_lock);

#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_memcpy_checks++;
#endif

  if(size >= LONG_MAX)
    __softboundcets_abort();


  if(size >= LONG_MAX)
    __softboundcets_abort();


  if(dest_key != *((size_t*)(dest_lock))){
    __softboundcets_abort();
  }

}

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

__WEAK_INLINE void 
__softboundcets_memset_check(void* dest, size_t size,
                             __v2di dest_base_bound, __v2di dest_key_lock){

  
  void* dest_base = (void*)__softboundcets_extract_base(dest_base_bound);
  void* dest_bound = (void*)__softboundcets_extract_bound(dest_base_bound);
  size_t dest_key = __softboundcets_extract_key(dest_key_lock);
  void* dest_lock = (void*)__softboundcets_extract_lock(dest_key_lock);

#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_memcpy_checks++;
#endif

#ifndef __NOSIM_CHECKS

  if(size >= LONG_MAX)
    __softboundcets_abort();

  if(dest < dest_base || dest + size > dest_bound)
    __softboundcets_abort();

  if(dest_key != *((size_t*)(dest_lock))){
    __softboundcets_abort();
  }
#endif

}
#else

__WEAK_INLINE void 
__softboundcets_memset_check(void* dest, size_t size,
                             __v2di dest_base_bound, 
                             __v2di dest_key_lock){

  
#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_memcpy_checks++;
#endif
  
  printf("not handled\n");
  __softboundcets_abort();

}
#endif



/* Metadata store parameterized by the mode of checking */

#ifdef __SOFTBOUNDCETS_SPATIAL

__METADATA_INLINE void __softboundcets_metadata_store(void* addr_of_ptr, 
                                                      __v2di base_bound) {

#elif __SOFTBOUNDCETS_TEMPORAL

__METADATA_INLINE void __softboundcets_metadata_store(void* addr_of_ptr, 
                                                      __v2di key_lock) {

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

__METADATA_INLINE void __softboundcets_metadata_store(void* addr_of_ptr, 
                                                      __v2di base_bound, 
                                                      __v2di key_lock) {  
  
#else

__METADATA_INLINE void __softboundcets_metadata_store(void* addr_of_ptr, 
                                                      __v2di base_bound, 
                                                      __v2di key_lock) {  

#endif 

#ifdef __SBCETS_STATS_MODE
  __sbcets_stats_metadata_stores++;
#endif

#ifdef __SBCETS_XMM_ASM_FULL_MODE

#if 0
  void* map_addr;


  __asm__("icmap %1, %0\n\t"
          :"=r"(map_addr)
          : "r" (addr_of_ptr)
          );
#endif

  __asm__("icmdstbb %0, %1\n\t"
          :
          : "r"(addr_of_ptr), "x"(base_bound)
          : "memory"
          );

  __asm__("icmdstkl %0, %1\n\t"
          :
          :"r"(addr_of_ptr), "x"(key_lock)
          : "memory"
          );

  return;


#endif


  size_t ptr = (size_t) addr_of_ptr;
  size_t primary_index;
  __softboundcets_trie_entry_t* trie_secondary_table;
  //  __softboundcets_trie_entry_t** trie_primary_table = __softboundcets_trie_primary_table;
  
  
  primary_index = (ptr >> 25);
  trie_secondary_table = __softboundcets_trie_primary_table[primary_index];
 
 
  if(!__SOFTBOUNDCETS_PREALLOCATE_TRIE) {
    if(trie_secondary_table == NULL){
      trie_secondary_table =  __softboundcets_trie_allocate();
      __softboundcets_trie_primary_table[primary_index] = trie_secondary_table;
    }    
    assert(trie_secondary_table != NULL);
  }
  
  size_t secondary_index = ((ptr >> 3) & 0x3fffff);
  __softboundcets_trie_entry_t* entry_ptr =&trie_secondary_table[secondary_index];

  //__builtin_ia32_storedqu seems to work so leaving it for now
  
#ifdef __SOFTBOUNDCETS_SPATIAL
  
  __builtin_ia32_storedqu((char*)(&entry_ptr->base), base_bound);
  
#elif __SOFTBOUNDCETS_TEMPORAL

  __builtin_ia32_storedqu((char*)(&entry_ptr->key), key_lock);

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

  __builtin_ia32_storedqu((char*)(&entry_ptr->base), base_bound);
  __builtin_ia32_storedqu((char*)(&entry_ptr->key), key_lock);

#else

  __builtin_ia32_storedqu((char*)(&entry_ptr->base), base_bound);
  __builtin_ia32_storedqu((char*)(&entry_ptr->key), key_lock);

#endif

  return;
}
// 

#ifdef __SOFTBOUNDCETS_SPATIAL_TEMPORAL

 __WEAK_INLINE void* 
   __softboundcets_metadata_map(void* addr_of_ptr){

#ifdef __SBCETS_XMM_ASM_FULL_MODE
#if 0
  void* map_addr;
  __asm__("icmap %1, %0\n\t"
          : "=r"(map_addr)
          : "r"(addr_of_ptr)
          );
  return map_addr;
#endif

  return addr_of_ptr;

  
#endif

   size_t ptr = (size_t) addr_of_ptr;
   __softboundcets_trie_entry_t* trie_secondary_table;
   size_t primary_index = (ptr >> 25);
   trie_secondary_table = __softboundcets_trie_primary_table[primary_index];
   
   if(trie_secondary_table == NULL){
     trie_secondary_table = __softboundcets_trie_allocate();
     __softboundcets_trie_primary_table[primary_index] = trie_secondary_table;
   }

    size_t secondary_index = ((ptr >> 3) & 0x3fffff);
    __softboundcets_trie_entry_t*
      entry_ptr =&trie_secondary_table[secondary_index];
    return (void*) entry_ptr;    

 }
 
__WEAK_INLINE __v2di 
  __softboundcets_metadata_load_base_bound(void* address) {

#ifdef __SBCETS_XMM_ASM_FULL_MODE

  __v2di temp_base_bound;
  __asm__("icmdldbb %1, %0\n\t"
          : "=x"(temp_base_bound)
          : "r"(address)
          : "memory"
          );
  return temp_base_bound;

#endif

  __softboundcets_trie_entry_t* 
    entry_ptr = (__softboundcets_trie_entry_t*) address;  
  __m128 base_bound = *((__m128*)(&(entry_ptr->base)));  
  return (__v2di) base_bound;
}

 __WEAK_INLINE __v2di 
   __softboundcets_metadata_load_key_lock(void* address) {

#ifdef __SBCETS_XMM_ASM_FULL_MODE

  __v2di temp_key_lock;
  __asm__("icmdldkl %1, %0\n\t"
          : "=x"(temp_key_lock)
          : "r"(address)
          : "memory"
          );
  return temp_key_lock;

#endif

  __softboundcets_trie_entry_t* 
    entry_ptr = (__softboundcets_trie_entry_t*) address;
  __m128 key_lock = *((__m128*)(&(entry_ptr->key)));
  return (__v2di)(key_lock);
 }

#endif // End of simple metadata mode of spatial-temporal checking

#ifdef __SOFTBOUNDCETS_SPATIAL

__METADATA_INLINE void __softboundcets_metadata_load(void* addr_of_ptr, __v2di* base_bound){   

#elif __SOFTBOUNDCETS_TEMPORAL

__METADATA_INLINE void __softboundcets_metadata_load(void* addr_of_ptr, __v2di* key_lock){   

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

__METADATA_INLINE void __softboundcets_metadata_load(void* addr_of_ptr, __v2di* base_bound, __v2di* key_lock){   

#else
 
__METADATA_INLINE void __softboundcets_metadata_load(void* addr_of_ptr, __v2di* base_bound, __v2di* key_lock){

#endif

  if (__SOFTBOUNDCETS_DISABLE) {
    return;
  }

  if(__SOFTBOUNDCETS_TRIE){

    size_t ptr = (size_t) addr_of_ptr;
    __softboundcets_trie_entry_t* trie_secondary_table;
    //    __softboundcets_trie_entry_t** trie_primary_table = __softboundcets_trie_primary_table;
    
    //assert(__softboundcetswithss_trie_primary_table[primary_index] == trie_secondary_table);

    size_t primary_index = ( ptr >> 25);
    trie_secondary_table = __softboundcets_trie_primary_table[primary_index];


    if(!__SOFTBOUNDCETS_PREALLOCATE_TRIE) {      
      if(trie_secondary_table == NULL) {  
#ifdef __SOFTBOUNDCETS_SPATIAL

        __v2di zero_base_bound = __softboundcets_construct_v2di(0,0);
        *((__m128*) base_bound) = zero_base_bound;

#elif __SOFTBOUNDCETS_TEMPORAL

        __v2di zero_key_lock = __softboundcets_construct_v2di(0,0);
        *((__m128*) key_lock) = zero_key_lock;

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

      __v2di zero_base_bound = __softboundcets_construct_v2di(0,0);
      
      *((__m128*) base_bound) = zero_base_bound;
      *((__m128*) key_lock) = zero_base_bound;
#else

      __v2di zero_base_bound = __softboundcets_construct_v2di(0,0);
      *((__m128*) base_bound) = zero_base_bound;
      *((__m128*) key_lock) = zero_base_bound;
  
#endif 
        return;
      }
    } /* PREALLOCATE_ENDS */

    /* MAIN SOFTBOUNDCETS LOAD WHICH RUNS ON THE NORMAL MACHINE */
    size_t secondary_index = ((ptr >> 3) & 0x3fffff);
    __softboundcets_trie_entry_t* entry_ptr = &trie_secondary_table[secondary_index];
    
#ifdef __SOFTBOUNDCETS_SPATIAL
    
    *((__v2di*)base_bound) = *((__m128*)(&(entry_ptr->base)));
    
#elif __SOFTBOUNDCETS_TEMPORAL
    *((__v2di*)key_lock) = *((__m128*)(&(entry_ptr->key)));

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

    *((__v2di*)base_bound) =  *((__m128*)(&(entry_ptr->base)));
    *((__v2di*)key_lock) = *((__m128*)(&(entry_ptr->key)));
      
#else
    *((__v2di*)base_bound) =  *((__m128*)(&(entry_ptr->base)));
    *((__v2di*)key_lock) = *((__m128*)(&(entry_ptr->key)));
#endif      

      return;
  }
}
/******************************************************************************/

extern size_t __softboundcets_key_id_counter;
extern size_t* __softboundcets_lock_next_location;
extern size_t* __softboundcets_lock_new_location;

#ifdef __SOFTBOUNDCETS_SPATIAL_TEMPORAL
__WEAK_INLINE void __softboundcets_temporal_load_dereference_check(__v2di key_lock,  __v2di base_bound) {
#else
__WEAK_INLINE void __softboundcets_temporal_load_dereference_check(__v2di key_lock) {  
#endif

#ifdef __SBCETS_XMM_ASM_MODE_TCHK
  __asm__("ictchkx %0\n\t"
          : 
          : "x"(key_lock)
          );
  return;

#endif


  void* pointer_lock = __softboundcets_extract_lock(key_lock);
  size_t key  = __softboundcets_extract_key(key_lock);
  
  /* URGENT: I should think about removing this condition check */
  if(!pointer_lock){
    if(__SOFTBOUNDCETS_DEBUG) {
      __softboundcets_printf("Temporal lock null\n");
    }
    //    __softboundcets_printf("Temporal lock null\n");
    __softboundcets_abort();
    return;
  }
  size_t temp = *((size_t*)pointer_lock);
  
  if(temp != key) {
    if(__SOFTBOUNDCETS_DEBUG) {
      __softboundcets_printf("[TLDC] key mismatch, key = %zx, *lock=%zx\n", 
                             key, temp );
    }
#ifdef __SOFTBOUNDCETS_MINIMAL_PRINT 
    __softboundcets_printf("[TLDC] Key mismatch key = %zx, *lock=%zx\n", 
                           key, temp );
#endif

    __softboundcets_abort();    
  }

}

#ifdef __SOFTBOUNDCETS_SPATIAL_TEMPORAL
__WEAK_INLINE void __softboundcets_temporal_store_dereference_check(__v2di key_lock, 
                                                                    __v2di base_bound) {
#else
__WEAK_INLINE void __softboundcets_temporal_store_dereference_check(__v2di key_lock){
#endif    


#ifdef __SBCETS_XMM_ASM_MODE_TCHK
  __asm__("ictchkx %0\n\t"
          : 
          : "x"(key_lock)
          );
  return;

#endif


  size_t key = __softboundcets_extract_key(key_lock);  
  void* pointer_lock = __softboundcets_extract_lock(key_lock);


#if 0
  if(!pointer_lock){
    __softboundcets_abort();    
  }
#endif

  size_t temp = *((size_t*)pointer_lock);
  
  if(temp != key) {

    if(__SOFTBOUNDCETS_DEBUG) {
      __softboundcets_printf("[TSDC] key mismatch, key = %zx, *lock=%zx\n", key, temp );
    }
#ifdef __SOFTBOUNDCETS_MINIMAL_PRINT 
      __softboundcets_printf("[TSDC] key mismatch, key = %zx, *lock=%zx\n", key, temp );
#endif
    __softboundcets_abort();    
  }

}


__WEAK_INLINE void __softboundcets_stack_memory_deallocation(__v2di key_lock){
  
#ifndef __SOFTBOUNDCETS_CONSTANT_STACK_KEY_LOCK

  __softboundcets_stack_temporal_space_begin--;
  *(__softboundcets_stack_temporal_space_begin) = 0;

#endif

  return;

}

__WEAK_INLINE void __softboundcets_memory_deallocation(__v2di key_lock) {

  
  void* ptr_lock = __softboundcets_extract_lock(key_lock);

  if(__SOFTBOUNDCETS_DEBUG){
    __softboundcets_printf("[__softboundcets_deallocateKeyAddrLocation] pointer_lock = %p, *pointer_lock=%zx\n", ptr_lock, *((size_t*) ptr_lock));
  }
  
  *((size_t*)ptr_lock) = 0;
  *((void**) ptr_lock) = __softboundcets_lock_next_location;
  __softboundcets_lock_next_location = ptr_lock;


}

__WEAK_INLINE void*  __softboundcets_allocate_lock_location() {

  
  void* temp= NULL;
  if(__softboundcets_lock_next_location == NULL) {
    if(__SOFTBOUNDCETS_DEBUG) {
      __softboundcets_printf("[__softboundcets_allocateKeyAddrLocation] returning softboundcets_lock_new_location=%p\n", __softboundcets_lock_new_location);
      
      if(__softboundcets_lock_new_location  > __softboundcets_temporal_space_begin + __SOFTBOUNDCETS_N_TEMPORAL_ENTRIES){
        __softboundcets_printf("[__softboundcets_allocateKeyAddrLocation] running out of temporal free entries \n");
        __softboundcets_abort();
      }
    }

    return __softboundcets_lock_new_location++;
  }
  else{

    temp = __softboundcets_lock_next_location;
    if(__SOFTBOUNDCETS_DEBUG){
      __softboundcets_printf("[__softboundcets_allocateKeyAddrLocation] returning softboundcetswithss_lock_next_location=%p\n", temp);
    }

    __softboundcets_lock_next_location = *((void**)__softboundcets_lock_next_location);
    return temp;
  }
}

__WEAK_INLINE void __softboundcets_allocation_secondary_trie_allocate_range(void* initial_ptr, size_t size) {

  if(!__SOFTBOUNDCETS_TRIE)
    return;

  if(!__SOFTBOUNDCETS_PREALLOCATE_TRIE)
    return;

  void* addr_of_ptr = initial_ptr;
  size_t start_addr_of_ptr = (size_t) addr_of_ptr;
  size_t start_primary_index = start_addr_of_ptr >> 25;
  
  size_t end_addr_of_ptr = (size_t)((char*) initial_ptr + size);
  size_t end_primary_index = end_addr_of_ptr >> 25;
  
  for(; start_primary_index <= end_primary_index; start_primary_index++){
    
    __softboundcets_trie_entry_t* trie_secondary_table = __softboundcets_trie_primary_table[start_primary_index];    
    if(trie_secondary_table == NULL) {
      trie_secondary_table =  __softboundcets_trie_allocate();
      __softboundcets_trie_primary_table[start_primary_index] = trie_secondary_table;
    }
  }
}

__WEAK_INLINE void __softboundcets_allocation_secondary_trie_allocate(void* addr_of_ptr) {
  
  /* URGENT: THIS FUNCTION REQUIRES REWRITE */

  if(!__SOFTBOUNDCETS_PREALLOCATE_TRIE)
    return;


  size_t ptr = (size_t) addr_of_ptr;
  size_t primary_index = ( ptr >> 25);
  //  size_t secondary_index = ((ptr >> 3) & 0x3fffff);
  
  __softboundcets_trie_entry_t* trie_secondary_table = __softboundcets_trie_primary_table[primary_index];

  if(trie_secondary_table == NULL) {
    trie_secondary_table =  __softboundcets_trie_allocate();
    __softboundcets_trie_primary_table[primary_index] = trie_secondary_table;
  }

  __softboundcets_trie_entry_t* trie_secondary_table_second_entry = __softboundcets_trie_primary_table[primary_index +1];

  if(trie_secondary_table_second_entry == NULL) {
    __softboundcets_trie_primary_table[primary_index+1] = __softboundcets_trie_allocate();
  }

  if(primary_index != 0 && (__softboundcets_trie_primary_table[primary_index -1] == NULL)){
    __softboundcets_trie_primary_table[primary_index-1] = __softboundcets_trie_allocate();    

  }

  return;
}


__WEAK_INLINE void __softboundcets_stack_memory_allocation(__v2di* key_lock) {


#ifdef __SOFTBOUNDCETS_CONSTANT_STACK_KEY_LOCK
  
  __v2di temp_key_lock = __softboundcets_construct_v2di(1, __softboundcets_global_lock);

  *((__m128*)key_lock) = temp_key_lock;

#else
  size_t* temp_lock = (size_t*)__softboundcets_stack_temporal_space_begin++;
  size_t temp_id = __softboundcets_key_id_counter++;
  *(temp_lock) = temp_id;
  
  __v2di temp_key_lock = __softboundcets_construct_v2di(temp_id, (size_t)temp_lock);
  
  *((__m128*)key_lock) = temp_key_lock;
  
  //  printf("done with softboundcets_stack_memory_allocation\n");
  //  __softboundcets_allocation_secondary_trie_allocate(ptr);
#endif

}



__WEAK_INLINE void __softboundcets_memory_allocation(void* ptr, __v2di* key_lock){

  size_t temp_key = __softboundcets_key_id_counter++;
  size_t* temp_lock = (size_t*)__softboundcets_allocate_lock_location();  
  
  *temp_lock = temp_key;
  
  __softboundcets_add_to_free_map(temp_key, ptr);
  __v2di temp_key_lock  = __softboundcets_construct_v2di(temp_key, (size_t)temp_lock);
  
  *((__m128*)key_lock) = temp_key_lock;
  __softboundcets_allocation_secondary_trie_allocate(ptr);

  if(__SOFTBOUNDCETS_DEBUG) {    
    //    __softboundcets_printf("[__softboundcets_memoryAllocation] location_ptr = %p, ptr_key = %p, key = %zx\n", ptr_lock, ptr_key, temp_id);
  }
}




__WEAK_INLINE void __softboundcets_add_to_free_map(size_t ptr_key, void* ptr) {

  if(!__SOFTBOUNDCETS_FREE_MAP)
    return;

  size_t counter  = 0;
  while(1){
    size_t index = (ptr_key + counter) % __SOFTBOUNDCETS_N_FREE_MAP_ENTRIES;
    size_t* entry_ptr = &__softboundcets_free_map_table[index];
    size_t tag = *entry_ptr;

    if(tag == 0 || tag == 2) {
      *entry_ptr = (size_t)(ptr);
      return;
    }
    if(counter >= (__SOFTBOUNDCETS_N_FREE_MAP_ENTRIES)) {
#ifndef __NOSIM_CHECKS      
      __softboundcets_abort();
#else
      break;
#endif
    }
    counter++;
  }
  return;
}


__WEAK_INLINE void __softboundcets_check_remove_from_free_map(size_t ptr_key, void* ptr) {

  if(! __SOFTBOUNDCETS_FREE_MAP){
    return;
  }

  size_t counter = 0;
  while(1) {
    size_t index = (ptr_key + counter) % __SOFTBOUNDCETS_N_FREE_MAP_ENTRIES;
    size_t* entry_ptr = &__softboundcets_free_map_table[index];
    size_t tag = *entry_ptr;

    if(tag == 0) {
#ifndef __NOSIM_CHECKS      
      __softboundcets_abort();
#else
      break;
#endif
    }

    if(tag == (size_t) ptr) {      
      *entry_ptr = 2;
      return;
    }

    if(counter >= __SOFTBOUNDCETS_N_FREE_MAP_ENTRIES) {
#ifndef __NOSIM_CHECKS      
      __softboundcets_abort();
#else
      break;
#endif
    }
    counter++;
  }
  return;
}

#endif

