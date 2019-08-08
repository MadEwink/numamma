#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h>
#include <sys/types.h>
#include <unistd.h>

#include "numamma.h"
#include "mem_tools.h"
#include "mem_intercept.h"
#include "hash.h"

#define HAVE_LIBBACKTRACE 1
#if HAVE_LIBBACKTRACE
#include <libbacktrace/backtrace.h>
#include <libbacktrace/backtrace-supported.h>
#endif


struct ht_node* symbols=NULL;

void print_backtrace(int backtrace_max_depth) {
  if(!IS_RECURSE_SAFE)
    return;

  PROTECT_FROM_RECURSION;
  int j, nptrs;
  void *buffer[backtrace_max_depth];
  char **strings;

  nptrs = backtrace(buffer, backtrace_max_depth);
  printf("backtrace() returned %d addresses\n", nptrs);
  printf("-------------------\n");
  /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
     would produce similar output to the following: */

  strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL) {
    perror("backtrace_symbols");
    exit(EXIT_FAILURE);
  }

  for (j = 0; j < nptrs; j++)
    printf("%s\n", strings[j]);
  printf("-------------------\n");

  free(strings);
  UNPROTECT_FROM_RECURSION;
}


#if HAVE_LIBBACKTRACE
__thread char current_frame[4096];

static void error_callback(void *data, const char *msg, int errnum)
{
  fprintf(stderr, "ERROR: %s (%d)", msg, errnum);
}

static int backtrace_callback (void *data, uintptr_t pc,
			       const char *filename, int lineno,
			       const char *function) {
  if(!function) {
    /* symbol can't be resolved */
    current_frame[0]='\0';
  } else {
    snprintf(current_frame, 4096, "%s:%d(%s)", filename, lineno, function);
  }
  return 0;
}
#endif /* HAVE_LIBBACKTRACE */


void* get_caller_rip(int depth) {
  int backtrace_depth=depth+1;
  void* buffer[backtrace_depth];

  /* TODO: calling backtrace seems to be very expensive (~7.5 usec)
   * maybe we should implement it to make it faster
   */
  int nb_calls = backtrace(buffer, backtrace_depth);
  if(nb_calls < depth) {
    return NULL;
  }
  return buffer[depth];
}

char* get_caller_function_from_rip(void* rip) {
  char* retval = NULL;

  /* check if the function corresponding to rip is already known */
  retval = ht_get_value(symbols, (uint64_t) rip);
  if(retval)
    return retval;

  if(!rip) {
    retval = libmalloc(sizeof(char)*16);
    sprintf(retval, "???");
    symbols = ht_insert(symbols, (uint64_t) rip, retval);
    return retval;
  }

#if HAVE_LIBBACKTRACE
  struct backtrace_state *state = backtrace_create_state (NULL, BACKTRACE_SUPPORTS_THREADS,
							  error_callback, NULL);

#endif
#if HAVE_LIBBACKTRACE
  backtrace_pcinfo (state, (uintptr_t) rip,
		    backtrace_callback,
		    error_callback,
		    NULL);
  if(current_frame[0] != '\0') {
    retval = libmalloc(sizeof(char)*4096);
    sprintf(retval, "%s", current_frame);
    symbols = ht_insert(symbols, (uint64_t) rip, retval);
    return retval;
  }
#endif
  /* symbol can't be resolved by libbacktrace, use the symbol name */
  char **functions;
  functions = backtrace_symbols(&rip, 1);
  retval = libmalloc(sizeof(char)*4096);
  sprintf(retval, "%s", functions[0]);
  free(functions);
  symbols = ht_insert(symbols, (uint64_t) rip, retval);
  return retval;
}

char* get_caller_function(int depth) {
  int backtrace_depth=depth+1;
  void* buffer[backtrace_depth];
  /* get pointers to functions */

  int nb_calls = backtrace(buffer, backtrace_depth);

#if HAVE_LIBBACKTRACE
  struct backtrace_state *state = backtrace_create_state (NULL, BACKTRACE_SUPPORTS_THREADS,
							  error_callback, NULL);
#endif

  char* retval = NULL;
  if(nb_calls < depth) {
    retval = libmalloc(sizeof(char)*16);
    sprintf(retval, "???");
    return retval;
  }

#if HAVE_LIBBACKTRACE
  backtrace_pcinfo (state, (uintptr_t) buffer[depth],
		    backtrace_callback,
		    error_callback,
		    NULL);
  if(current_frame[0] != '\0') {
    retval = libmalloc(sizeof(char)*4096);
    sprintf(retval, "%s", current_frame);
    return retval;
  }
#endif
  /* symbol can't be resolved by libbacktrace, use the symbol name */
  char **functions;
  functions = backtrace_symbols(buffer, nb_calls);
  retval = libmalloc(sizeof(char)*4096);
  sprintf(retval, "%s", functions[depth]);
  free(functions);

    return retval;
}

void get_program_file(char* program_file, size_t size) {
  char link_path[size];
  sprintf(link_path, "/proc/%d/exe", getpid());
  readlink(link_path, program_file, size);
}

void get_map_address(char* program_file, void** base_addr, void** end_addr) {
  FILE *f;
  char cmd[4069];
  char line[4096];
  sprintf(cmd, "file \"%s\" |grep \"shared object\\|pie executable\" > plop", program_file);
  int ret = system(cmd);
  if(WIFEXITED(ret)) {
    /* find address range of the heap */
    int exit_status= WEXITSTATUS(ret);
    if(exit_status == EXIT_SUCCESS) {
      /* process is compiled with -fPIE, thus, the addresses in the ELF are to be relocated */
      sprintf(cmd, "cat /proc/%d/maps |grep \"[heap]\"", getpid());
      f = popen(cmd, "r");
      fgets(line, 4096, f);
      pclose(f);
      sscanf(line, "%p-%p", base_addr, end_addr);
      printf("[NumaMMA]  This program was compiled with -fPIE. It is mapped at address %p\n", *base_addr);
    } else {
      /* process is not compiled with -fPIE, thus, the addresses in the ELF are the addresses in the binary */
      *base_addr= NULL;
      *end_addr= NULL;
      printf("[NumaMMA]  This program was not compiled with -fPIE. It is mapped at address %p\n", *base_addr);
    }
  }
}
