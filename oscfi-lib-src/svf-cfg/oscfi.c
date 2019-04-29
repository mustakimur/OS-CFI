/*
 * OS-CFI: Origin-sensitive Control Flow Integrity
 * Authors: Mustakimur Khandaker (Florida State University)
 * Wenqing Liu (Florida State University)
 * Abu Naser (Florida State University)
 * Zhi Wang (Florida State University)
 * Jie Yang (Florida State University)
 */

#include "mpxrt.h"
#include <stdio.h>
#include <stdlib.h>

// will be used for statistical purpose
unsigned long stats[12] = {0};
char *stats_name[12] = {
    "update_mpx: ",      "get_entry: ",     "oscfi_vcall: ",
    "oscfi_pcall: ",     "oscfi_pcall_0: ", "oscfi_pcall_1: ",
    "oscfi_pcall_2: ",   "oscfi_pcall_3",   "oscfi_pcall_fix: ",
    "oscfi_vcall_fix: ", "ref_pcall",       "ref_vcall"};

// the fixer for SUPA, a address-taken type check CFG
// Format: ref_id, target
__attribute__((__used__)) __attribute__((section("cfg_label_data")))
const int *STATIC_TABLE[] = {};
__attribute__((__used__)) unsigned int STATIC_TABLE_LENGTH = 0;

// SUPE works fine but the call-points are call-site sensitive
// Format: ref_id, target
__attribute__((__used__)) __attribute__((section("cfg_label_data")))
const int *PCALL_D0[] = {};
__attribute__((__used__)) unsigned int PCALL_D0_C = 0;
// Format: ref_id, target, site1
__attribute__((__used__)) __attribute__((section("cfg_label_data")))
const int *PCALL_D1[] = {};
__attribute__((__used__)) unsigned int PCALL_D1_C = 0;
// Format: ref_id, target, site1, site2
__attribute__((__used__)) __attribute__((section("cfg_label_data")))
const int *PCALL_D2[] = {};
__attribute__((__used__)) unsigned int PCALL_D2_C = 0;
// Format: ref_id, target, site1, site2, site3
__attribute__((__used__)) __attribute__((section("cfg_label_data")))
const int *PCALL_D3[] = {};
__attribute__((__used__)) unsigned int PCALL_D3_C = 0;

// SUPA works fine and the call-points are origin sensitive
// Format: ref_id, target, origin, originCtx
__attribute__((__used__)) __attribute__((section("cfg_label_data")))
const int *PCALL_OSCFI[] = {};
__attribute__((__used__)) unsigned int PCALL_OSCFI_C = 0;
// Format: ref_id, target, origin, originCtx
__attribute__((__used__)) __attribute__((section("cfg_label_data")))
const int *VCALL_OSCFI[] = {};
__attribute__((__used__)) unsigned int VCALL_OSCFI_C = 0;

oscfiItem *OSCFI_HASH_TABLE[HASH_KEY_RANGE] = {NULL};

pcallItem *PCALL_HASH_TABLE[HASH_KEY_RANGE] = {NULL};

staticItem *STATIC_HASH_TABLE[HASH_KEY_RANGE] = {NULL};

// update mpx table
void __attribute__((__used__))
update_mpx_table(unsigned long ptr_addr, unsigned long ptr_val,
                 unsigned long origin, unsigned long originCtx) {
  __asm__ __volatile__("bndmk (%0,%1), %%bnd0;\
      bndstx %%bnd0, (%2,%3);"
                       :
                       : "r"(origin), "r"(originCtx), "r"(ptr_addr),
                         "r"(ptr_val)
                       : "%bnd0");
  stats[0]++;
}

// get entry from mpx table
mEntry __attribute__((__used__))
get_entry_mpx_table(unsigned long ptr_addr, unsigned long ptr_val) {
  mEntry entry;
  unsigned long bnds[2];
  __asm__ __volatile__("bndldx (%1,%2), %%bnd0;\
      bndmov %%bnd0, %0;"
                       : "=m"(bnds)
                       : "r"(ptr_addr), "r"(ptr_val)
                       : "%bnd0");
  entry.origin = bnds[0];
  entry.originCtx = (~bnds[1] - bnds[0]);

  stats[1]++;

  return entry;
}

// add new oscfiItem in the OSCFI_HASH_TABLE
void __attribute__((__used__))
oscfi_hash_insert(unsigned long ref_id, unsigned long target,
                  unsigned long origin, unsigned long originCtx) {
  unsigned long hash_key =
      (ref_id ^ target ^ origin ^ originCtx) % HASH_KEY_RANGE;
  oscfiItem *item = (oscfiItem *)malloc(sizeof(oscfiItem));
  item->ref_id = ref_id;
  item->origin = origin;
  item->originCtx = originCtx;
  item->target = target;
  item->next = NULL;

  if (OSCFI_HASH_TABLE[hash_key] == NULL) {
    OSCFI_HASH_TABLE[hash_key] = item;
  } else {
    oscfiItem *temp = OSCFI_HASH_TABLE[hash_key];
    while (temp->next != NULL) {
      temp = temp->next;
    }
    temp->next = item;
  }
}

// add new pcallItem in the PCALL_HASH_TABLE
void __attribute__((__used__))
pcall_D0_hash_insert(unsigned long ref_id, unsigned long target) {
  unsigned long hash_key = (ref_id ^ target) % HASH_KEY_RANGE;
  pcallItem *item = (pcallItem *)malloc(sizeof(pcallItem));
  item->depth = 0;
  item->ref_id = ref_id;
  item->target = target;
  item->next = NULL;

  if (PCALL_HASH_TABLE[hash_key] == NULL) {
    PCALL_HASH_TABLE[hash_key] = item;
  } else {
    pcallItem *temp = PCALL_HASH_TABLE[hash_key];
    while (temp->next != NULL) {
      temp = temp->next;
    }
    temp->next = item;
  }
}

void __attribute__((__used__))
pcall_D1_hash_insert(unsigned long ref_id, unsigned long target,
                     unsigned long site1) {
  unsigned long hash_key = (ref_id ^ target ^ site1) % HASH_KEY_RANGE;
  pcallItem *item = (pcallItem *)malloc(sizeof(pcallItem));
  item->depth = 1;
  item->ref_id = ref_id;
  item->call_site[0] = site1;
  item->target = target;
  item->next = NULL;

  if (PCALL_HASH_TABLE[hash_key] == NULL) {
    PCALL_HASH_TABLE[hash_key] = item;
  } else {
    pcallItem *temp = PCALL_HASH_TABLE[hash_key];
    while (temp->next != NULL) {
      temp = temp->next;
    }
    temp->next = item;
  }
}

void __attribute__((__used__))
pcall_D2_hash_insert(unsigned long ref_id, unsigned long target,
                     unsigned long site1, unsigned long site2) {
  unsigned long hash_key = (ref_id ^ target ^ site1 ^ site2) % HASH_KEY_RANGE;
  pcallItem *item = (pcallItem *)malloc(sizeof(pcallItem));
  item->depth = 2;
  item->ref_id = ref_id;
  item->call_site[0] = site1;
  item->call_site[1] = site2;
  item->target = target;
  item->next = NULL;

  if (PCALL_HASH_TABLE[hash_key] == NULL) {
    PCALL_HASH_TABLE[hash_key] = item;
  } else {
    pcallItem *temp = PCALL_HASH_TABLE[hash_key];
    while (temp->next != NULL) {
      temp = temp->next;
    }
    temp->next = item;
  }
}

void __attribute__((__used__))
pcall_D3_hash_insert(unsigned long ref_id, unsigned long target,
                     unsigned long site1, unsigned long site2,
                     unsigned long site3) {
  unsigned long hash_key =
      (ref_id ^ target ^ site1 ^ site2 ^ site3) % HASH_KEY_RANGE;
  pcallItem *item = (pcallItem *)malloc(sizeof(pcallItem));
  item->depth = 3;
  item->ref_id = ref_id;
  item->call_site[0] = site1;
  item->call_site[1] = site2;
  item->call_site[2] = site3;
  item->target = target;
  item->next = NULL;

  if (PCALL_HASH_TABLE[hash_key] == NULL) {
    PCALL_HASH_TABLE[hash_key] = item;
  } else {
    pcallItem *temp = PCALL_HASH_TABLE[hash_key];
    while (temp->next != NULL) {
      temp = temp->next;
    }
    temp->next = item;
  }
}

// add new staticItem in the STATIC_HASH_TABLE
void __attribute__((__used__))
static_hash_insert(unsigned long ref_id, unsigned long target) {
  unsigned long hash_key = (ref_id ^ target) % HASH_KEY_RANGE;
  staticItem *item = (staticItem *)malloc(sizeof(staticItem));
  item->ref_id = ref_id;
  item->target = target;
  item->next = NULL;

  if (STATIC_HASH_TABLE[hash_key] == NULL) {
    STATIC_HASH_TABLE[hash_key] = item;
  } else {
    staticItem *temp = STATIC_HASH_TABLE[hash_key];
    while (temp->next != NULL) {
      temp = temp->next;
    }
    temp->next = item;
  }
}

void __attribute__((__used__))
pcall_reference_monitor(unsigned long ref_id, unsigned long ptr_addr,
                        unsigned long ptr_val) {
  stats[10]++;
}
void __attribute__((__used__))
vcall_reference_monitor(unsigned long ref_id, unsigned long vptr_addr,
                        unsigned long vtable_addr, unsigned long vtarget) {
  stats[11]++;
}

void __attribute__((__used__))
oscfi_vcall_reference_monitor(unsigned long ref_id, unsigned long vptr_addr,
                              unsigned long vtable_addr, unsigned long target) {
  mEntry entry = get_entry_mpx_table(vptr_addr, vtable_addr);

  if (entry.origin == 0) {
    fprintf(stderr, "[OSCFI-LOG] Something wrong with mpx metadata table\n");
  }

  unsigned long long hash_key =
      ((ref_id ^ vtable_addr ^ entry.origin ^ entry.origin) % HASH_KEY_RANGE);

  if (OSCFI_HASH_TABLE[hash_key] != NULL) {
    oscfiItem *temp = OSCFI_HASH_TABLE[hash_key];
    while (temp != NULL) {
      if (temp->ref_id == ref_id && temp->target == vtable_addr &&
          temp->origin == entry.origin && temp->originCtx == entry.originCtx) {
        stats[2]++;
        return;
      }
      temp = temp->next;
    }
  }

  fprintf(stderr,
          "[OSCFI-LOG] Failed validation for <vcall origin sensitivity> {%lu "
          "=> %lx}\n",
          ref_id, target);
}

void __attribute__((__used__))
oscfi_pcall_reference_monitor(unsigned long ref_id, unsigned long ptr_addr,
                              unsigned long ptr_val) {
  mEntry entry = get_entry_mpx_table(ptr_addr, ptr_val);

  if (entry.origin == 0) {
    fprintf(stderr, "[OSCFI-LOG] Something wrong with mpx metadata table\n");
  }

  unsigned long long hash_key =
      ((ref_id ^ ptr_val ^ entry.origin ^ entry.origin) % HASH_KEY_RANGE);

  if (OSCFI_HASH_TABLE[hash_key] != NULL) {
    oscfiItem *temp = OSCFI_HASH_TABLE[hash_key];
    while (temp != NULL) {
      if (temp->ref_id == ref_id && temp->target == ptr_val &&
          temp->origin == entry.origin && temp->originCtx == entry.originCtx) {
        stats[3]++;
        return;
      }
      temp = temp->next;
    }
  }

  fprintf(stderr,
          "[OSCFI-LOG] Failed validation for <pcall origin sensitivity> {%lu "
          "=> %lx}\n",
          ref_id, ptr_val);
}

void __attribute__((__used__))
oscfi_pcall_reference_monitor_d0(unsigned long ref_id, unsigned long ptr_addr,
                                 unsigned long ptr_val) {
  unsigned long long hash_key = ((ref_id ^ ptr_val) % HASH_KEY_RANGE);

  if (PCALL_HASH_TABLE[hash_key] != NULL) {
    pcallItem *temp = PCALL_HASH_TABLE[hash_key];
    while (temp != NULL) {
      if (temp->depth == 0 && temp->ref_id == ref_id &&
          temp->target == ptr_val) {
        stats[4]++;
        return;
      }
      temp = temp->next;
    }
  }

  fprintf(stderr,
          "[OSCFI-LOG] Failed validation for <pcall call-site sensitivity "
          "depth 0> {%lu "
          "=> %lx}\n",
          ref_id, ptr_val);
}

void __attribute__((__used__))
oscfi_pcall_reference_monitor_d1(unsigned long ref_id, unsigned long ptr_addr,
                                 unsigned long ptr_val) {
  unsigned long long site1 = (unsigned long long)__builtin_return_address(1);
  unsigned long long hash_key = ((ref_id ^ ptr_val ^ site1) % HASH_KEY_RANGE);

  if (PCALL_HASH_TABLE[hash_key] != NULL) {
    pcallItem *temp = PCALL_HASH_TABLE[hash_key];
    while (temp != NULL) {
      if (temp->depth == 1 && temp->ref_id == ref_id &&
          temp->target == ptr_val && temp->call_site[0] == site1) {
        stats[5]++;
        return;
      }
      temp = temp->next;
    }
  }

  fprintf(stderr, "%lu, %lx, %lx\n", ref_id, ptr_val, site1);

  /* fprintf(stderr,
          "[OSCFI-LOG] Failed validation for <pcall call-site sensitivity "
          "depth 1> {%lu "
          "=> %lx}\n",
          ref_id, ptr_val); */
}

void __attribute__((__used__))
oscfi_pcall_reference_monitor_d2(unsigned long ref_id, unsigned long ptr_addr,
                                 unsigned long ptr_val) {
  unsigned long long site1 = (unsigned long long)__builtin_return_address(1);
  unsigned long long site2 = (unsigned long long)__builtin_return_address(2);
  unsigned long long hash_key =
      ((ref_id ^ ptr_val ^ site1 ^ site2) % HASH_KEY_RANGE);

  if (PCALL_HASH_TABLE[hash_key] != NULL) {
    pcallItem *temp = PCALL_HASH_TABLE[hash_key];
    while (temp != NULL) {
      if (temp->depth == 2 && temp->ref_id == ref_id &&
          temp->target == ptr_val && temp->call_site[0] == site1 &&
          temp->call_site[1] == site2) {
        stats[6]++;
        return;
      }
      temp = temp->next;
    }
  }

  fprintf(stderr,
          "[OSCFI-LOG] Failed validation for <pcall call-site sensitivity "
          "depth 2> {%lu "
          "=> %lx}\n",
          ref_id, ptr_val);
}

void __attribute__((__used__))
oscfi_pcall_reference_monitor_d3(unsigned long ref_id, unsigned long ptr_addr,
                                 unsigned long ptr_val) {
  unsigned long long site1 = (unsigned long long)__builtin_return_address(1);
  unsigned long long site2 = (unsigned long long)__builtin_return_address(2);
  unsigned long long site3 = (unsigned long long)__builtin_return_address(3);
  unsigned long long hash_key =
      ((ref_id ^ ptr_val ^ site1 ^ site2 ^ site3) % HASH_KEY_RANGE);

  if (PCALL_HASH_TABLE[hash_key] != NULL) {
    pcallItem *temp = PCALL_HASH_TABLE[hash_key];
    while (temp != NULL) {
      if (temp->depth == 3 && temp->ref_id == ref_id &&
          temp->target == ptr_val && temp->call_site[0] == site1 &&
          temp->call_site[1] == site2 && temp->call_site[2] == site3) {
        stats[7]++;
        return;
      }
      temp = temp->next;
    }
  }

  fprintf(stderr,
          "[OSCFI-LOG] Failed validation for <pcall call-site sensitivity "
          "depth 3> {%lu "
          "=> %lx}\n",
          ref_id, ptr_val);
}

void __attribute__((__used__))
static_vcall_reference_monitor(unsigned long ref_id, unsigned long vptr_addr,
                               unsigned long vtable_addr,
                               unsigned long target) {
  unsigned long hash_key = (ref_id ^ target) % HASH_KEY_RANGE;
  if (STATIC_HASH_TABLE[hash_key] != NULL) {
    staticItem *temp = STATIC_HASH_TABLE[hash_key];
    while (temp != NULL) {
      if (temp->ref_id == ref_id && temp->target == target) {
        stats[9]++;
        return;
      }
      temp = temp->next;
    }
  }

  fprintf(stderr,
          "[OSCFI-LOG] Failed validation for <vcall supa fixer> {%lu => %lx}\n",
          ref_id, target);
}

// initialize the hash table at the beginning of the program execution
void __attribute__((__used__)) oscfi_init() {
  int i;

  for (i = 0; i < STATIC_TABLE_LENGTH; i += 2) {
    static_hash_insert((unsigned long)STATIC_TABLE[i],
                       (unsigned long)STATIC_TABLE[i + 1]);
  }

  for (i = 0; i < PCALL_D0_C; i += 2) {
    pcall_D0_hash_insert((unsigned long)PCALL_D0[i],
                         (unsigned long)PCALL_D0[i + 1]);
  }
  for (i = 0; i < PCALL_D1_C; i += 3) {
    pcall_D1_hash_insert((unsigned long)PCALL_D1[i],
                         (unsigned long)PCALL_D1[i + 1],
                         (unsigned long)PCALL_D1[i + 2]);
  }
  for (i = 0; i < PCALL_D2_C; i += 4) {
    pcall_D2_hash_insert(
        (unsigned long)PCALL_D2[i], (unsigned long)PCALL_D2[i + 1],
        (unsigned long)PCALL_D2[i + 2], (unsigned long)PCALL_D2[i + 3]);
  }
  for (i = 0; i < PCALL_D3_C; i += 5) {
    pcall_D3_hash_insert(
        (unsigned long)PCALL_D3[i], (unsigned long)PCALL_D3[i + 1],
        (unsigned long)PCALL_D3[i + 2], (unsigned long)PCALL_D3[i + 3],
        (unsigned long)PCALL_D3[i + 4]);
  }

  for (i = 0; i < PCALL_OSCFI_C; i += 4) {
    oscfi_hash_insert(
        (unsigned long)PCALL_OSCFI[i], (unsigned long)PCALL_OSCFI[i + 1],
        (unsigned long)PCALL_OSCFI[i + 2], (unsigned long)PCALL_OSCFI[i + 3]);
  }
  for (i = 0; i < VCALL_OSCFI_C; i += 4) {
    oscfi_hash_insert(
        (unsigned long)VCALL_OSCFI[i], (unsigned long)VCALL_OSCFI[i + 1],
        (unsigned long)VCALL_OSCFI[i + 2], (unsigned long)VCALL_OSCFI[i + 3]);
  }
}

void __attribute__((__used__)) oscfi_end() {
  unsigned long i;
  fprintf(stderr, "PRINT END DATA\n");
  fprintf(
      stderr,
      "-----------------------------------------------------------------\n");
  for (i = 0; i < 12; i++) {
    fprintf(stderr, "%-20s%20lu\n", stats_name[i], stats[i]);
  }
  fprintf(
      stderr,
      "-----------------------------------------------------------------\n");
}

__attribute__((section(".preinit_array"),
               used)) void (*_ocscfi_preinit)(void) = oscfi_init;

__attribute__((section(".fini_array"),
               used)) void (*_ocscfi_fini)(void) = oscfi_end;