/*
 * OS-CFI: Origin-sensitive Control Flow Integrity
 * Authors: Mustakimur Khandaker (Florida State University)
 * Wenqing Liu (Florida State University)
 * Abu Naser (Florida State University)
 * Zhi Wang (Florida State University)
 * Jie Yang (Florida State University)
 */

#define HASH_KEY_RANGE 1000000

// hash table for SUPA failure call-points
// build from STATIC_TABLE
typedef struct STATIC_ITEM {
  unsigned long ref_id;
  unsigned long target;
  struct STATIC_ITEM *next;
} staticItem;

// hash table for call-site sensitive call-points
// build from PCALL_D0, PCALL_D1, PCALL_D2, PCALL_D3
typedef struct PCALL_ITEM {
  int depth;
  unsigned long call_site[3];
  unsigned long ref_id;
  unsigned long target;
  struct PCALL_ITEM *next;
} pcallItem;

// hash table for origin sensitive call-points
// build from PCALL_OSCFI and VCALL_OSCFI
typedef struct OSCFI_ITEM {
  unsigned long origin;
  unsigned long originCtx;
  unsigned long ref_id;
  unsigned long target;
  struct OSCFI_ITEM *next;
} oscfiItem;

typedef struct MPX_ENTRY {
  unsigned long origin;
  unsigned long originCtx;
} mEntry;

// (pointer_addr, pointer_val, origin, origin_ctx)
void update_mpx_table(unsigned long, unsigned long, unsigned long,
                      unsigned long);
// (pointer_addr, pointer_val)
mEntry get_entry_mpx_table(unsigned long, unsigned long);

// (ref_id, pointer_addr, pointer_val)
void pcall_reference_monitor(unsigned long, unsigned long, unsigned long);
// (ref_id, vptr_addr, vtable_addr, vtarget)
void vcall_reference_monitor(unsigned long, unsigned long, unsigned long,
                             unsigned long);

// (ref_id, pointer_addr, pointer_val)
void oscfi_pcall_reference_monitor(unsigned long, unsigned long, unsigned long);
// (ref_id, pointer_addr, pointer_val)
void oscfi_pcall_reference_monitor_d0(unsigned long, unsigned long,
                                      unsigned long);
// (ref_id, pointer_addr, pointer_val)
void oscfi_pcall_reference_monitor_d1(unsigned long, unsigned long,
                                      unsigned long);
// (ref_id, pointer_addr, pointer_val)
void oscfi_pcall_reference_monitor_d2(unsigned long, unsigned long,
                                      unsigned long);
// (ref_id, pointer_addr, pointer_val)
void oscfi_pcall_reference_monitor_d3(unsigned long, unsigned long,
                                      unsigned long);

// (ref_id, vptr_addr, vtable_addr, vtarget)
void oscfi_vcall_reference_monitor(unsigned long, unsigned long, unsigned long,
                                   unsigned long);

// (ref_id, pointer_addr, pointer_val)
void static_pcall_reference_monitor(unsigned long, unsigned long,
                                    unsigned long);
// (ref_id, vptr_addr, vtable_addr, vtarget)
void static_vcall_reference_monitor(unsigned long, unsigned long, unsigned long,
                                    unsigned long);

void oscfi_init();
void oscfi_end();