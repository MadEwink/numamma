/* -*- c-file-style: "GNU" -*- */
#define _GNU_SOURCE

/* intercept a set of memory/pthread related functions
 * and modify their behavior
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <numaif.h>
#include <numa.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include "numamma.h"
#include "mem_intercept.h"
#include "mem_tools.h"
#include "mem_bind.h"

//#define INTERCEPT_MALLOC 1
//#define CHECK_PLACEMENT 1

int _dump = 0;
FILE* dump_file = NULL; // useless
int _verbose = 0;
__thread int is_recurse_unsafe = 0;

/* set to 1 if thread binding is activated */
int bind_threads=0;

/* array describing the binding of each thread */
int thread_bindings[MAX_THREADS];
/* number of valid entries in the array */
int nb_thread_max=0;

/* set to 1 when all the hooks are set.
 * This is useful in order to avoid recursive calls
 */
static int __memory_initialized = 0;

void* (*libcalloc)(size_t nmemb, size_t size) = NULL;
void* (*libmalloc)(size_t size) = NULL;
void (*libfree)(void *ptr) = NULL;
void* (*librealloc)(void *ptr, size_t size) = NULL;
int  (*libpthread_create) (pthread_t * thread, const pthread_attr_t * attr,
			   void *(*start_routine) (void *), void *arg) = NULL;
void (*libpthread_exit) (void *thread_return) = NULL;

/* Custom malloc function. It is used when libmalloc=NULL (e.g. during startup)
 * This function is not thread-safe and is very likely to be bogus, so use with
 * caution
 */
static void* hand_made_malloc(size_t size) {
  /* allocate a 1MB buffer */
#define POOL_SIZE (1024 * 1024 * 10)
  static char mem[POOL_SIZE] = {'\0'};

  /* since this function is only used before we found libmalloc, there's no
   * fancy memory management mechanism (block reuse, etc.)
   */
  static char* next_slot = &mem[0];
  static int total_alloc = 0;

  if (libmalloc)
    /* let's use the real malloc */
    return malloc(size);

  debug_printf("%s(size=%lu)\n", __FUNCTION__, size);
  struct mem_block_info *p_block = NULL;
  INIT_MEM_INFO(p_block, next_slot, size, 1);
  p_block->mem_type = MEM_TYPE_HAND_MADE_MALLOC;

  /* if you want to make this function thread-safe, these instructions should be protected
   * by a mutex:
   */
  p_block->mem_type = MEM_TYPE_HAND_MADE_MALLOC;
  total_alloc += size;
  next_slot = next_slot + p_block->total_size;
  debug_printf("%s returns: --> %p (p_block=%p)\n", __FUNCTION__, p_block->u_ptr, p_block);
  return p_block->u_ptr;
}

static int nb_malloc=0;
static int nb_free=0;
static int nb_realloc=0;
static int nb_calloc=0;

#if INTERCEPT_MALLOC

void* malloc(size_t size) {
  nb_malloc++;
  static int total_alloced=0;
  /* if memory_init hasn't been called yet, we need to get libc's malloc
   * address
   */
  if (!libmalloc) {
    if( !IS_RECURSE_SAFE) {
      /* protection flag says that malloc is already trying to retrieve the
       * address of malloc.
       * If we call dlsym now, there will be an infinite recursion, so let's
       * allocate memory 'by hand'
       */
      return hand_made_malloc(size);
    }

    /* set the protection flag and retrieve the address of malloc.
     * If dlsym calls malloc, memory will be allocated 'by hand'
     */
    PROTECT_FROM_RECURSION;
    {
      libmalloc = dlsym(RTLD_NEXT, "malloc");
      char* error;
      if ((error = dlerror()) != NULL) {
	fputs(error, stderr);
	exit(1);
      }
    }
    /* it is now safe to call libmalloc */
    UNPROTECT_FROM_RECURSION;
  }

  /* allocate a buffer */
  debug_printf("%s(size=%lu) \n", __FUNCTION__, size);
  void* pptr = libmalloc(size + HEADER_SIZE + TAIL_SIZE);
  total_alloced+=size + HEADER_SIZE + TAIL_SIZE;

  if(!pptr){
    return NULL;
  }
  struct mem_block_info *p_block = NULL;
  INIT_MEM_INFO(p_block, pptr, size, 1);

  if(__memory_initialized && IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    p_block->mem_type = MEM_TYPE_MALLOC;
    /* TODO: use the callsite to generate a buffer_id */
    bind_malloced_buffer(p_block->u_ptr, size, NULL);
    UNPROTECT_FROM_RECURSION;
    //    return p_block->u_ptr;
  } else {
    /* we are already processing a malloc/free function, so don't try to record information,
     * just call the function
     */
    p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;
  }
  debug_printf("%s returns: --> %p (p_block=%p)\n", __FUNCTION__, p_block->u_ptr, p_block);

  return p_block->u_ptr;
}

void* realloc(void *ptr, size_t size) {
  nb_realloc++;
  /* if ptr is NULL, realloc behaves like malloc */
  if (!ptr)
    return malloc(size);

  /* if size=0 and ptr isn't NULL, realloc behaves like free */
  if (!size && ptr) {
    free(ptr);
    return NULL;
  }

  //  FUNCTION_ENTRY;
  if (!librealloc) {
    librealloc = dlsym(RTLD_NEXT, "realloc");
    char* error;
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      exit(1);
    }
  }

  debug_printf("%s(ptr=%p, size=%lu)\n", __FUNCTION__, ptr, size);
  if (!CANARY_OK(ptr)) {
    /* we didn't malloc'ed this buffer */
    fprintf(stderr,"%s(%p). I can't find this pointer !\n", __FUNCTION__, ptr);
    abort();
    void* retval = librealloc(ptr, size);
    debug_printf("%s returns --> %p\n", retval, __FUNCTION__);
    return retval;
  }

  struct mem_block_info *p_block;
  USER_PTR_TO_BLOCK_INFO(ptr, p_block);
  size_t old_size = p_block->size;
  size_t header_size = p_block->total_size - p_block->size;

  if (p_block->mem_type != MEM_TYPE_MALLOC) {
    fprintf(stderr, "Warning: realloc a ptr that was allocated by hand_made_malloc\n");
  }
  void *old_addr= p_block->u_ptr;
  void *pptr = librealloc(p_block->p_ptr, size + header_size);
  INIT_MEM_INFO(p_block, pptr, size, 1);

  if(__memory_initialized && IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    /* retrieve the malloc information from the pointer */
    if (!pptr) {
      /* realloc failed */
      UNPROTECT_FROM_RECURSION;
      debug_printf("%s returns --> %p\n", __FUNCTION__, NULL);
      return NULL;
    }

    p_block->mem_type = MEM_TYPE_MALLOC;
    UNPROTECT_FROM_RECURSION;
  } else {
    /* it is not safe to record information */
    p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;
  }

  debug_printf("%s returns --> %p (p_block=%p)\n", __FUNCTION__, p_block->u_ptr, p_block);
  return p_block->u_ptr;
}

void* calloc(size_t nmemb, size_t size) {
  nb_calloc++;
  if (!libcalloc) {
    void* ret = hand_made_malloc(nmemb * size);
    if (ret) {
      memset(ret, 0, nmemb * size);
    }
    return ret;
  }

  debug_printf("calloc(nmemb=%zu, size=%zu)\n", nmemb, size);

  /* compute the number of blocks for header */
  int nb_memb_header = (HEADER_SIZE  + TAIL_SIZE)/ size;
  if (size * nb_memb_header < HEADER_SIZE + TAIL_SIZE)
    nb_memb_header++;

    /* allocate buffer + header */
  void* p_ptr = libcalloc(nmemb + nb_memb_header, size);

  struct mem_block_info *p_block = NULL;
  INIT_MEM_INFO(p_block, p_ptr, nmemb, size);


  if(__memory_initialized && IS_RECURSE_SAFE) {
    PROTECT_FROM_RECURSION;
    p_block->mem_type = MEM_TYPE_MALLOC;
    /* todo: call mbind ? */
    bind_malloced_buffer(p_block->u_ptr, size*nmemb, NULL);
    UNPROTECT_FROM_RECURSION;
  } else {
    p_block->mem_type = MEM_TYPE_INTERNAL_MALLOC;
  }
  debug_printf("%s returns --> %p (p_block=%p)\n", __FUNCTION__, p_block->u_ptr, p_block);
  return p_block->u_ptr;
}

void free(void* ptr) {
  nb_free++;
  if (!libfree) {
    libfree = dlsym(RTLD_NEXT, "free");
    char* error;
    if ((error = dlerror()) != NULL) {
      fputs(error, stderr);
      exit(1);
    }
  }
  if (!ptr) {
    libfree(ptr);
    return;
  }

  debug_printf("%s(%p)\n", __FUNCTION__, ptr);
  /* first, check wether we malloc'ed the buffer */
  if (!CANARY_OK(ptr)) {
    /* we didn't malloc this buffer */
    fprintf(stderr, "%s(%p). I don't know this malloc !\n", __FUNCTION__, ptr);
    abort();
    libfree(ptr);
    return;
  }

  struct mem_block_info *p_block;
  USER_PTR_TO_BLOCK_INFO(ptr, p_block);

  void* start_ptr = p_block->p_ptr;
  ERASE_CANARY(ptr);
  //  memset(start_ptr, 0x00, p_block->total_size);
  libfree(start_ptr);
}
#endif	/* INTERCEPT_MALLOC */

/* Internal structure used for transmitting the function and argument
 * during pthread_create.
 */
struct __pthread_create_info_t {
  void *(*func)(void *);
  void *arg;
  int thread_rank;
};

enum thread_status_t {
  thread_status_none,
  thread_status_created,
  thread_status_finalized
};

struct thread_info {
  pthread_t tid;
  enum thread_status_t status;
};
struct thread_info thread_array[MAX_THREADS];
int nb_threads = 0;

static int __get_thread_rank(pthread_t thread_id) {
  int i;
  for(i=0; i< nb_threads; i++) {
    if(thread_array[i].tid == thread_id)
      return i;
  }
  return -1;
}

static void __thread_cleanup_function(void* arg);
/* Invoked by pthread_create on the new thread */
static void *
__pthread_new_thread(void *arg) {
  PROTECT_FROM_RECURSION;
  void* res = NULL;
  struct __pthread_create_info_t *p_arg = (struct __pthread_create_info_t*) arg;
  void *(*f)(void *) = p_arg->func;
  void *__arg = p_arg->arg;
  int thread_rank = p_arg->thread_rank;
  free(p_arg);

  UNPROTECT_FROM_RECURSION;
  int oldtype;
  pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, &oldtype);

  pthread_cleanup_push(__thread_cleanup_function,
		       &thread_array[thread_rank]);

  FUNCTION_ENTRY;
  if(_verbose) {
    pid_t tid = syscall(__NR_gettid);
    printf("I'm thread %d (tid=%d) bound on cpu %d\n", thread_rank, tid, thread_bindings[thread_rank]);
  }

  res = (*f)(__arg);

  pthread_cleanup_pop(0);
  if(_verbose)
    fprintf(stderr, "End of thread %lu\n", thread_array[thread_rank].tid);
  __thread_cleanup_function(&thread_array[thread_rank]);
  return res;
}


static void __thread_cleanup_function(void* arg) {
  struct thread_info* me = arg;
  PROTECT_FROM_RECURSION;
  me->status = thread_status_finalized;
  UNPROTECT_FROM_RECURSION;
}

int
pthread_create (pthread_t *__restrict thread,
		const pthread_attr_t *__restrict attr,
		void *(*start_routine) (void *),
		void *__restrict arg) {
  FUNCTION_ENTRY;
  PROTECT_FROM_RECURSION;
  int thread_rank = __sync_fetch_and_add( &nb_threads, 1 );
  thread_array[thread_rank].status = thread_status_created;
  struct __pthread_create_info_t * __args =
    (struct __pthread_create_info_t*) malloc(sizeof(struct __pthread_create_info_t));
  __args->func = start_routine;
  __args->arg = arg;
  __args->thread_rank= thread_rank;

  if (!libpthread_create) {
    libpthread_create = dlsym(RTLD_NEXT, "pthread_create");
  }

  pthread_attr_t local_attr;
  if(attr) {
    memcpy(&local_attr, attr, sizeof(local_attr));
  } else {
    pthread_attr_init(&local_attr);
  }
  if(bind_threads && thread_rank < nb_thread_max) {
    if(thread_bindings[thread_rank] >= 0) {
      cpu_set_t cpuset;
      CPU_ZERO(&cpuset);
      CPU_SET(thread_bindings[thread_rank], &cpuset);
#if 0
      if(_verbose)
	printf("[MemRun] Binding %d to %d\n", thread_rank, thread_bindings[thread_rank]);
#endif
      int ret = pthread_attr_setaffinity_np(&local_attr,
					    sizeof(cpuset),
					    &cpuset);
      if(ret != 0){
	perror("pthread_attr_setaffinity_np failed");
	abort();
      }
    }
  }
  UNPROTECT_FROM_RECURSION;

  /* We do not call directly start_routine since we want to initialize stuff at the thread startup.
   * Instead, let's invoke __pthread_new_thread that initialize the thread-specific things and call
   * start_routine.
   */
  int retval = libpthread_create(&thread_array[thread_rank].tid, &local_attr,
				 __pthread_new_thread, __args);
  memcpy(thread, &thread_array[thread_rank].tid, sizeof(pthread_t));
  return retval;
}

void pthread_exit(void *thread_return) {
  FUNCTION_ENTRY;

  libpthread_exit(thread_return);
  __builtin_unreachable();
}

/* bind the current thread on a cpu */
static void bind_current_thread(int cpu) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);

  pthread_t current_thread = pthread_self();
  pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
}

static void get_thread_binding() {
  char* str=getenv("NUMAMMA_THREAD_BIND");
  if(str) {
    printf("[MemRun] Thread binding activated: %s\n", str);

    if(getenv("GOMP_CPU_AFFINITY")) {
      fprintf(stderr, "Error: NUMAMMA_THREAD_BIND conflicts with GOMP_CPU_AFFINITY\n");
      fprintf(stderr, "  Please unset GOMP_CPU_AFFINITY\n");
      abort();
    }

    for(int i = 0; i<MAX_THREADS; i++) {
      thread_bindings[i] = -1;
    }
    char bindings[10*MAX_THREADS];
    strncpy(bindings, str, 10*MAX_THREADS);
    char* token = strtok(bindings, ",");
    while(token) {
      thread_bindings[nb_thread_max] = atoi(token);
      nb_thread_max++;
      token = strtok(NULL, ",");
    }

    bind_threads=1;
    if(_verbose) {
      for(int i=0; i<nb_thread_max; i++) {
	printf("[MemRun] Thread %d is bound to %d\n", i, thread_bindings[i]);
      }
    }

    int thread_rank = nb_threads++;
    thread_array[thread_rank].status = thread_status_created;

#if 0
    if(_verbose)
      printf("[MemRun] Binding %d to %d\n", thread_rank, thread_bindings[thread_rank]);
#endif
    bind_current_thread(thread_bindings[thread_rank]);
  } else {
    printf("[MemRun] No thread binding policy selected.\n");
    printf("[MemRun] \tYou can use NUMAMMA_THREAD_BIND\n");
  }
}

static void read_options() {
  char* verbose_str = getenv("NUMAMMA_VERBOSE");
  if(verbose_str) {
    if(strcmp(verbose_str, "0")!=0) {
      _verbose = 1;
      printf("Verbose mode enabled\n");
    }
  }

  char* mbind_policy_str = getenv("NUMAMMA_MBIND_POLICY");
  set_mbind_policy(mbind_policy_str);
  get_thread_binding();
}

extern char**environ;
char ld_preload_value[4096];

/* unset LD_PRELOAD
 * this makes sure that forked processes will not be analyzed
 */
void unset_ld_preload() {
  /* unset LD_PRELOAD */
  char* ld_preload = getenv("LD_PRELOAD");
  if(!ld_preload) {
    ld_preload_value[0]='\0';
    return;
  }

  /* save the value of ld_preload so that we can set it back later */
  strncpy(ld_preload_value, ld_preload, 4096);
  int ret = unsetenv("LD_PRELOAD");
  if(ret != 0 ){
    fprintf(stderr, "unsetenv failed ! %s\n", strerror(errno));
    abort();
  }

  /* also change the environ variable since exec* function
   * rely on it.
   */
  for (int i=0; environ[i]; i++) {
    if (strstr(environ[i],"LD_PRELOAD=")) {
      printf("hacking out LD_PRELOAD from environ[%d]\n",i);
      environ[i][0] = '\0';
    }
  }
  char*plop=getenv("LD_PRELOAD");
  if(plop) {
    fprintf(stderr, "Warning: cannot unset LD_PRELOAD\n");
    fprintf(stderr, "This is likely to cause problems later.\n");
  }
}

/* set LD_PRELOAD so that future forked processes are analyzed
 *  you need to call unset_ld_preload before calling this function
 */
void reset_ld_preload() {
  if(strlen(ld_preload_value)>0) {
    debug_printf("Setting back ld_preload to %s\n", ld_preload_value);
    setenv("LD_PRELOAD", ld_preload_value, 1);
  }
}

static void __memory_init(void) __attribute__ ((constructor));
static void __memory_init(void) {
  PROTECT_FROM_RECURSION;
  /* TODO: there's a race condition here: if I remove the printf, then mem_run
   * fails while loading the custom mbind policy file. This should be investigated !
   */
  printf("[Mem_run] initializing stuff\n");
#if INTERCEPT_MALLOC
  printf("[Mem_run] malloc interception is enabled\n");
#else
    printf("[Mem_run] malloc interception is disabled\n");
#endif
  libmalloc = dlsym(RTLD_NEXT, "malloc");
  libcalloc = dlsym(RTLD_NEXT, "calloc");
  librealloc = dlsym(RTLD_NEXT, "realloc");
  libfree = dlsym(RTLD_NEXT, "free");
  libpthread_create = dlsym(RTLD_NEXT, "pthread_create");
  libpthread_exit = dlsym(RTLD_NEXT, "pthread_exit");

  set_nb_nodes();
  read_options();

  bind_global_variables();

  __memory_initialized = 1;
  printf("[Mem_run] initialization done\n");
  UNPROTECT_FROM_RECURSION;
}

static void __memory_conclude(void) __attribute__ ((destructor));
static void __memory_conclude(void) {
  check_placement();
  __memory_initialized = 0;
  printf("Nb malloc: %d\n", nb_malloc);
  printf("Nb realloc: %d\n", nb_realloc);
  printf("Nb calloc: %d\n", nb_calloc);
  printf("Nb free: %d\n", nb_free);
}
