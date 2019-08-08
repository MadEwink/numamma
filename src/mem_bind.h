#ifndef MEM_BIND_H
#define MEM_BIND_H

enum mbind_policy{
  POLICY_NONE,
  POLICY_INTERLEAVED,
  POLICY_BLOCK,
  POLICY_CUSTOM,
  POLICY_MAX
};

struct mbind_directive {
  char block_identifier[4096]; // name of the variable to move
  size_t buffer_len;
  size_t nb_blocks;
  void* base_addr;
  enum {type_global, type_malloc} buffer_type;
  struct block_bind *blocks;
  struct mbind_directive *next;
};

struct block_bind {
  int start_page;
  int end_page;
  int numa_node;
};

void bind_buffer(void* buffer, size_t len, char* buffer_id);
void set_mbind_policy(char* mbind_policy_str);
void check_placement();
void bind_malloced_buffer(void* buffer, size_t len, char* buffer_id);
void bind_global_variables();
void set_nb_nodes();

#endif //MEM_BIND_H
