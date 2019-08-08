/* -*- c-file-style: "GNU" -*- */
#define _GNU_SOURCE

/* all bind related functions that were previously in mem_run.c
 * except for thread bind functions that could be left there
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

int page_size=4096;		/* todo: detect this using sysconf */
enum mbind_policy _mbind_policy;
struct mbind_directive *directives = NULL;;
int nb_nodes=-1;

/* unset LD_PRELOAD
 * this makes sure that forked processes will not be analyzed
 */
extern void unset_ld_preload();

/* set LD_PRELOAD so that future forked processes are analyzed
 *  you need to call unset_ld_preload before calling this function
 */
extern void reset_ld_preload();
  
uintptr_t align_ptr(uintptr_t ptr, int align) {
  uintptr_t mask = ~(uintptr_t)(align - 1);
  uintptr_t res = ptr & mask;
  return ptr & mask;
}

int get_numa_node(void* address) {
  void * ptr_to_check = address;
  /*here you should align ptr_to_check to page boundary */
  int status=-1;
  int ret_code;
  ret_code = move_pages(0 /*self memory */, 1, &ptr_to_check,
			NULL, &status, 0);
  if(ret_code != 0) {
    perror("move_pages failed");
    abort();
  }
  if(status < 0){
    printf("move_pages failed: %s\n", strerror(-status));
  }
  return status;
}

static void bind_buffer_blocks(void*buffer, size_t len,
			       int n_blocks, struct block_bind* blocks) {
  if(n_blocks*page_size > len+page_size) {
    /* too many blocks ! */
    abort();
  }

  uintptr_t base_addr=align_ptr((uintptr_t)buffer, page_size);

  if(_verbose)
    printf("[MemRun] Binding %d blocks. starting at %p\n", n_blocks, base_addr);


  for(int i=0; i<n_blocks; i++) {
    uintptr_t start_addr=base_addr + ((uintptr_t)blocks[i].start_page*page_size);
    start_addr+=page_size;
    size_t block_len=((blocks[i].end_page+1 - blocks[i].start_page))*page_size;
    const uint64_t nodeMask = 1UL << blocks[i].numa_node;

    if(blocks[i].numa_node>nb_nodes) {
      fprintf(stderr, "Bad binding: binding on node %d requested, but only %d nodes are available\n", blocks[i].numa_node, nb_nodes);
      abort();
    }
    if(_verbose)
      printf("\t[MemRun] Binding pages %d-%d to node %d\n", blocks[i].start_page, blocks[i].end_page, blocks[i].numa_node);

    if(start_addr+block_len > (uintptr_t)buffer+len) {
      /* make sure there's no overflow */
      block_len=(uintptr_t)buffer+len-start_addr;
    }

    int ret = mbind((void*)start_addr, block_len, MPOL_BIND, &nodeMask, sizeof(nodeMask)*8, MPOL_MF_MOVE | MPOL_MF_STRICT);
    if(ret < 0) {
      perror("mbind failed");
      abort();
    }
    
#if CHECK_PLACEMENT
    int effective_node=get_numa_node((void*)start_addr);
    if(effective_node != blocks[i].numa_node ){
      printf("Warning: when binding %p to node %d: page is actually on node %d\n",
	     start_addr, blocks[i].numa_node, effective_node);
    } else {
      printf("When binding %p to node %d: page is indeed on node %d\n",
	     start_addr, blocks[i].numa_node, effective_node);
    }
#endif
  }
}

static void bind_interleaved(void* buffer, size_t len) {
  if(_mbind_policy != POLICY_INTERLEAVED)
    return;
  int nblocks=(len/page_size)+1;
  struct block_bind blocks[nblocks];
  for(int i=0; i<nblocks; i++){
    blocks[i].start_page=i;
    blocks[i].end_page=i+1;
    blocks[i].numa_node = i%nb_nodes;
  }
  bind_buffer_blocks(buffer, len, nblocks, blocks);
}

static void bind_block(void*buffer, size_t len) {
  if(_mbind_policy != POLICY_BLOCK)
    return;
  int nb_pages=((len/page_size));
  int nb_pages_per_node=1;
  if(nb_pages > nb_nodes) {
    nb_pages_per_node=nb_pages/nb_nodes;
  }

  int nb_blocks=0;
  struct block_bind blocks[nb_nodes];
  for(int i=0; i<nb_nodes; i++){
    blocks[i].start_page = i * nb_pages_per_node;
    blocks[i].end_page   = (i+1) * nb_pages_per_node;
    blocks[i].numa_node = i;
    nb_blocks++;
    if(blocks[i].end_page > nb_pages) {
      /* the last node gets all the remaining blocks */
      blocks[i].end_page = nb_pages;
      break;
    }
  }

  bind_buffer_blocks(buffer, len, nb_blocks, blocks);
}

static void bind_custom(void* buffer, size_t len, char* buffer_id) {
  if(_mbind_policy != POLICY_CUSTOM || buffer_id == NULL)
    return;

  printf("Trying to bind %s\n", buffer_id);
  /* search for buffer_id in the list of mbind directives */
  struct mbind_directive *dir = directives;
  while(dir) {
    if(strcmp(dir->block_identifier, buffer_id)==0) {

      if(dir->buffer_len != len) {
	fprintf(stderr, "Warning: I found variable %s, but its length (%zu) is different from the specified length (%zu)\n",
		buffer_id, len, dir->buffer_len);
      } else {
	printf("Binding %s\n", buffer_id);
	dir->base_addr = buffer;
	bind_buffer_blocks(buffer, len, dir->nb_blocks, dir->blocks);
      }
      return;
    }
    dir = dir->next;
  }
  printf("\t%s not found\n", buffer_id);
}

void bind_buffer(void* buffer, size_t len, char* buffer_id) {

  if(len > page_size) {
    switch(_mbind_policy) {
    case POLICY_INTERLEAVED:
      bind_interleaved(buffer, len);
      break;
    case POLICY_BLOCK:
      bind_block(buffer, len);
      break;
    case POLICY_CUSTOM:
      bind_custom(buffer, len, buffer_id);
      break;
      /* else: nothing to do */
    }
  }
}

static void load_custom_block(FILE*f) {
  char block_identifier[4096];
  size_t buffer_len=-1;
  size_t nb_blocks=0;

  struct mbind_directive *dir=malloc(sizeof(struct mbind_directive));
  
  int nread=fscanf(f, "%s\t%zu\t%d", dir->block_identifier, &dir->buffer_len, &dir->nb_blocks);
  assert(nread==3);
  if(_verbose)
    printf("New custom block(id=%s, len=%d, nblocks=%d)\n", dir->block_identifier, dir->buffer_len, dir->nb_blocks);

  if(strcmp(dir->block_identifier, "malloc") == 0) {
    dir->buffer_type=type_malloc;
  } else {
    dir->buffer_type=type_global;
  }
  dir->blocks = malloc(sizeof(struct block_bind)* dir->nb_blocks);
  char* line_buffer=NULL;
  size_t line_size;
  int block_id=0;
  dir->next = directives;
  directives = dir;

  while((nread=getline(&line_buffer, &line_size, f)) != -1) {
    if(strncmp(line_buffer, "end_block", 9) == 0)  {     
      dir->nb_blocks=block_id;
      return;
    }
    struct block_bind*block = &dir->blocks[block_id];
    int numa_node, start_page, end_page;
    nread=sscanf(line_buffer, "%d\t%d\t%d", &block->numa_node, &block->start_page, &block->end_page);
    if(nread == 3) {
      if(block->numa_node > nb_nodes-1) {
	fprintf(stderr, "Warning: trying to bind %s[page %d] on node %d, but there are only %d nodes on this machine\n",
		dir->block_identifier, block->start_page, block->numa_node, nb_nodes);
      }
      block_id++;
      if(block_id > dir->nb_blocks)
	break;
    }
  }
}

static void load_custom_mbind(const char*fname) {
  FILE*f = fopen(fname, "r");
  if(!f) {
    perror("Cannot open mbind file");
    exit(1);
  }
  char *line_buffer=NULL;
  size_t line_size;
  int nread=0;
  while((nread=getline(&line_buffer, &line_size, f)) != -1) {
    if(strncmp(line_buffer, "begin_block", 11) == 0) {
      load_custom_block(f);
    } else {
      /* Something else */
    }
  }
  
  fclose(f);
}

void set_mbind_policy(char* mbind_policy_str) {
  if(mbind_policy_str) {
    if(strcmp(mbind_policy_str, "interleaved")==0) {
      _mbind_policy= POLICY_INTERLEAVED;
      printf("Memory binding (interleaved) enabled\n");
    } else if(strcmp(mbind_policy_str, "block")==0) {
      _mbind_policy= POLICY_BLOCK;
      printf("Memory binding (block) enabled\n");
    } else if(strcmp(mbind_policy_str, "none")==0) {
      _mbind_policy= POLICY_NONE;
      printf("Memory binding (none) enabled\n");
    } else if(strcmp(mbind_policy_str, "custom")==0) {
      _mbind_policy= POLICY_CUSTOM;
      char* mbind_file=getenv("NUMAMMA_MBIND_FILE");
      if(!mbind_file) {
	fprintf(stderr, "Please set the NUMAMMA_MBIND_FILE variable\n");
	exit(1);
      }
      load_custom_mbind(mbind_file);
      printf("Memory binding (custom) enabled\n");
    } 
  } else {
    printf("[MemRun] No memory binding policy selected.\n");
    printf("[MemRun] \tYou can use NUMAMMA_MBIND_POLICY=interleaved|block|custom\n");
  }
}

static void check_buffer_placement(struct mbind_directive *dir) {
  assert(dir->base_addr);
  uintptr_t base_addr=align_ptr((uintptr_t)dir->base_addr, page_size);

  for(int i=0; i<dir->nb_blocks; i++) {
    uintptr_t start_addr=base_addr + dir->blocks[i].start_page*page_size;
    start_addr+=page_size;
    size_t block_len=((dir->blocks[i].end_page - dir->blocks[i].start_page))*page_size;
    const uint64_t nodeMask = 1UL << dir->blocks[i].numa_node;

    if(start_addr+block_len > (uintptr_t)dir->base_addr+dir->buffer_len) {
      /* make sure there's no overflow */
      block_len=(uintptr_t)dir->base_addr+dir->buffer_len-start_addr;
    }

#if CHECK_PLACEMENT
    int effective_node=get_numa_node((void*)start_addr);
    if(effective_node != dir->blocks[i].numa_node ){
      printf("Warning: %p/%d should be on node %d: page is actually on node %d\n",
	     start_addr, dir->blocks[i].start_page, dir->blocks[i].numa_node, effective_node);
    }
#endif
  }
}

void check_placement() {
  struct mbind_directive *dir = directives;
  while(dir) {
    if( dir->base_addr)
      check_buffer_placement(dir);
    dir = dir->next;
  }
}

void bind_malloced_buffer(void* buffer, size_t len, char* buffer_id) {
  struct mbind_directive* dir = directives;
  while(dir) {
    /* search for the directive corresponding to this malloc */

    /* todo:
     * - take the buffer_id into account
     * - don't apply a directive several times
     */
    if(dir->buffer_type == type_malloc &&
       dir->buffer_len == len) {

      dir->base_addr = buffer;
      if(_verbose) {
	printf("Binding malloced buffer(len=%d)\n", len);
      }
      bind_buffer_blocks(buffer, len, dir->nb_blocks, dir->blocks);
      return;
    }

    dir = dir->next;
  }
}

static char null_str[]="";

/* get the list of global/static variables with their address and size, and bind them
 * according to _mbind_policy
 */
void bind_global_variables() {
  if(_mbind_policy == POLICY_NONE) {
    /* nothing to do */
    return;
  }

  /* TODO: this function, share a lot of code with the ma_get_global_variables defined
   * in mem_analyzer.c
   * Maybe we should merge them ?
   */

  /* make sure forked processes (eg nm, readlink, etc.) won't be analyzed */
  unset_ld_preload();
  FILE *f;
  char program_file[4096];
  char line[4096];

  debug_printf("Looking for global variables\n");

  /* get the filename of the program being run */
  get_program_file(program_file, 4096);
  debug_printf("  The program file is %s\n", program_file);

  /* get the address at which the program is mapped in memory */
  void *base_addr = NULL;
  void *end_addr = NULL;
  get_map_address(program_file, &base_addr, &end_addr);

  /* get the list of global variables in the current binary */
  char nm_cmd[1024];
  sprintf(nm_cmd, "nm -fs --defined-only -l -S %s", program_file);
  //sprintf(nm_cmd, "nm --defined-only -l -S %s", program_file);
  f = popen(nm_cmd, "r");

  while(!feof(f)) {
    if( ! fgets(line, 4096, f) ) {
      goto out;
    }

    char *addr = null_str;
    char *size_str = null_str;
    char *section = null_str;
    char *symbol = null_str;
    char *file = null_str;
    char *type = null_str;

    int nb_found;
    /* line is in the form:
symbol_name |addr| section | type |symbol_size| [line]    |section    [file:line]
    */
    const char* delim="| \t\n";

    symbol = strtok(line, delim);
    if(!symbol|| strcmp(symbol, "_end")==0) {
      /* nothing to read */
      continue;
    }
    
    addr = strtok(NULL, delim);
    if(!addr) {
      /* nothing to read */
      continue;
    }

    section = strtok(NULL, delim);
    if(!section) {
      /* nothing to read */
      continue;
    }
    type = strtok(NULL, delim);
    if(!type) {
      /* nothing to read */
      continue;
    }

    size_str = strtok(NULL, " \t\n");
    if(!size_str) {
      /* nothing to read */
      continue;
    }

    if(!symbol) {
      /* only 3 fields (addr section symbol) */
      nb_found = 3;
      symbol = section;
      section = size_str;
      size_str = null_str;
      /* this is not enough (we need the size), skip this one */
      continue;
    } else {
      nb_found = 4;
      /*  fields */
      file = strtok(NULL, " \t\n");
      if(!file) {
	file = null_str;
      } else {
	nb_found = 5;
      }
    }

    if(section[0]== 'b' || section[0]=='B' || /* BSS (uninitialized global vars) section */
       section[0]== 'd' || section[0]=='D' || /* initialized data section */
       section[0]== 'g' || section[0]=='G') { /* initialized data section for small objects */

      if(strcmp(type, "TLS") == 0) {
	continue;
      }
      size_t size;
      sscanf(size_str, "%lx", &size);
      if(size) {

	
#if 0
	struct memory_info * mem_info = NULL;
#ifdef USE_HASHTABLE
	mem_info = mem_allocator_alloc(mem_info_allocator);
#else
	struct memory_info_list * p_node = mem_allocator_alloc(mem_info_allocator);
	mem_info = &p_node->mem_info;
#endif

	mem_info->alloc_date = 0;
	mem_info->free_date = 0;
	mem_info->initial_buffer_size = size;
	mem_info->buffer_size = mem_info->initial_buffer_size;
#endif
	
	/* addr is the offset within the binary. The actual address of the variable is located at
	 *  addr+base_addr
	 */
	size_t offset;
	sscanf(addr, "%lx", &offset);
	void* buffer_addr = offset + (uint8_t*)base_addr;
	size_t buffer_size = size;
	char caller[1024];
	snprintf(caller, 1024, "%s in %s", symbol, file);

	debug_printf("Found a global variable: %s (defined at %s). base addr=%p, size=%zu\n",
		     symbol, file, buffer_addr, buffer_size);
	bind_buffer(buffer_addr, buffer_size, symbol);
      }
    }
  }
 out:
  /* Restore LD_PRELOAD.
   * This is usefull when the program is run with gdb. gdb creates a process than runs bash -e prog arg1
   * Thus, the ld_preload affects bash. bash then calls execvp to execute the program.
   * If we unset ld_preload, the ld_preload will only affect bash (and not the programà
   * Hence, we need to restore ld_preload here.
   */
  reset_ld_preload();
}

void set_nb_nodes() {
  nb_nodes = numa_num_configured_nodes();
}
