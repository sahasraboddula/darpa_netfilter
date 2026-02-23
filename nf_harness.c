/*
 * KLEE Symbolic Execution Harness — v3
 * Target: Linux Kernel Netfilter — nf_bpf_link.c & nf_conntrack_extend.c
 *
 * WMI Classes:
 *   WMI-1: Stale Reference       — entity freed while trigger holds pointer
 *   WMI-2: Leak via Type Confusion — funcptr read through stale reference
 *   WMI-3: Arbitrary Free        — fake entity used to free arbitrary address
 *   WMI-4: Write-What-Where      — reclaimed slab, controlled index/value write
 *
 * THE ONE RULE FOR klee_make_symbolic:
 *   klee_make_symbolic(ptr, size, tag) is ONLY valid when ptr points to
 *   stack-allocated memory or a global variable.  It is NEVER valid on
 *   heap memory (malloc/realloc), even for plain scalar fields within a
 *   heap struct.  KLEE's deterministic allocator tracks provenance per
 *   allocation region; heap objects are a separate region from the stack.
 *
 *   The universal pattern used throughout this file:
 *
 *     // declare on the stack
 *     SomeType sym;
 *     klee_make_symbolic(&sym, sizeof(sym), "tag");  // OK: stack
 *     heap_struct->field = sym;                      // assign in
 *
 *   Stack structs of plain integers (no pointer fields) can be symbolized
 *   all at once:
 *     struct Foo foo;   // stack
 *     klee_make_symbolic(&foo, sizeof(foo), "tag");  // OK: stack
 */

#include <assert.h>      /* needed: klee_assert expands to __assert_fail */
#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* =========================================================================
 * 1. KERNEL TYPE STUBS
 *    Function pointers and data pointers stored as uintptr_t so KLEE can
 *    reason over them as integers via the stack-proxy pattern.
 * ========================================================================= */

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;

struct net { u32 ns_id; };

struct nf_hook_ops {
    uintptr_t hook;        /* function pointer as integer */
    uintptr_t priv;
    u8        pf;
    u8        hooknum;
    int       priority;
    u8        hook_ops_type;
};

struct bpf_prog {
    u32       type;
    u32       jited;
    uintptr_t run_fn;
};

struct bpf_link {
    u32              refcnt;
    uintptr_t        ops;   /* pointer as integer */
    struct bpf_prog *prog;
};

struct nf_defrag_hook {
    uintptr_t enable_fn;   /* int  (*enable)(struct net *)  */
    uintptr_t disable_fn;  /* void (*disable)(struct net *) */
    uintptr_t owner;       /* struct module *                */
};

struct bpf_nf_link {
    struct bpf_link           link;
    struct nf_hook_ops        hook_ops;
    struct net               *net;
    u32                       dead;
    const struct nf_defrag_hook *defrag_hook;
};

/* conntrack extension stubs */
#define NF_CT_EXT_NUM      10
#define NF_CT_EXT_PREALLOC 128u

struct nf_ct_ext {
    u8  offset[NF_CT_EXT_NUM];
    u8  len;
    u32 gen_id;
};

struct nf_conn {
    struct nf_ct_ext *ext;
    u32               status;
};

/* =========================================================================
 * 2. HELPERS
 * ========================================================================= */

static void *must_malloc(size_t sz) {
    void *p = malloc(sz);
    klee_assume(p != NULL);
    return p;
}

/* =========================================================================
 * 3. WMI-1: STALE REFERENCE
 *
 *    Models the race between bpf_nf_link_release() and bpf_nf_link_detach()
 *    both reading `dead == 0` before the cmpxchg completes.
 *
 *    Fix for "invalid pointer: make_symbolic":
 *      `dead` lives inside a heap-allocated bpf_nf_link, so we CANNOT
 *      call klee_make_symbolic(&link->dead, ...).
 *      Instead: declare u32 sym_dead on the STACK, symbolize that, assign.
 * ========================================================================= */

static int g_unregister_count;

static void stub_unregister(struct net *net, struct nf_hook_ops *ops) {
    (void)net; (void)ops;
    g_unregister_count++;
    klee_assert(g_unregister_count <= 1 &&
                "WMI-1: stale ref -- double unregister of hook_ops");
}

static u32 sim_cmpxchg(u32 *ptr, u32 old, u32 newval) {
    u32 cur = *ptr;
    if (cur == old) *ptr = newval;
    return cur;
}

static void sim_release(struct bpf_nf_link *l) {
    if (l->dead) return;
    if (sim_cmpxchg(&l->dead, 0, 1) == 0)
        stub_unregister(l->net, &l->hook_ops);
}

void test_wmi1_stale_reference(void) {
    struct net         net  = { .ns_id = 1 };
    struct bpf_nf_link *link = must_malloc(sizeof(*link));
    memset(link, 0, sizeof(*link));
    link->net = &net;

    /* Stack proxy — symbolize on stack, assign into heap struct */
    u32 sym_dead;
    klee_make_symbolic(&sym_dead, sizeof(sym_dead), "wmi1_dead");
    klee_assume(sym_dead == 0 || sym_dead == 1);
    link->dead = sym_dead;

    g_unregister_count = 0;
    sim_release(link);
    sim_release(link);   /* second call must be a no-op */

    free(link);
}

/* =========================================================================
 * 4. WMI-2: TYPE CONFUSION
 *
 *    An attacker reclaims the freed bpf_nf_link slab and plants a fake
 *    enable_fn pointer.  The stale defrag_hook pointer then calls through
 *    an attacker-controlled address.
 *
 *    Pattern: stack uintptr_t proxy → assign into heap struct field.
 * ========================================================================= */

static int concrete_enable(struct net *net) { (void)net; return 0; }

static void sim_call_enable(const struct nf_defrag_hook *hook, struct net *net) {
    klee_assert(!klee_is_symbolic((unsigned int)hook->enable_fn) &&
                "WMI-2: type confusion -- funcptr is symbolic/attacker-controlled");
    if (hook->enable_fn) {
        int (*fn)(struct net *) = (int (*)(struct net *))hook->enable_fn;
        fn(net);
    }
}

void test_wmi2_type_confusion(void) {
    struct net             net  = { .ns_id = 1 };
    struct bpf_nf_link    *link = must_malloc(sizeof(*link));
    struct nf_defrag_hook *hook = must_malloc(sizeof(*hook));
    memset(link, 0, sizeof(*link));
    memset(hook, 0, sizeof(*hook));
    link->net         = &net;
    link->defrag_hook = hook;

    /* Scenario A: attacker-controlled funcptr (reclaimed slab) */
    {
        uintptr_t sym_fn;                                    /* STACK */
        klee_make_symbolic(&sym_fn, sizeof(sym_fn), "wmi2_enable_attacker");
        hook->enable_fn = sym_fn;                            /* assign in */
        sim_call_enable(hook, &net);                         /* trips assertion */
    }

    /* Scenario B: concrete funcptr — must NOT fire assertion */
    {
        hook->enable_fn = (uintptr_t)concrete_enable;
        sim_call_enable(hook, &net);
    }

    free(hook);
    free(link);
}

/* =========================================================================
 * 5. WMI-3: ARBITRARY FREE
 *
 *    bpf_nf_disable_defrag() calls module_put(hook->owner).  If hook is
 *    a reclaimed slab under attacker control, owner can be any address,
 *    giving an arbitrary decrement/free primitive.
 *
 *    Pattern: stack uintptr_t proxy → assign into heap struct field.
 * ========================================================================= */

static void stub_module_put(uintptr_t owner) {
    klee_assert(!klee_is_symbolic((unsigned int)owner) &&
                "WMI-3: arbitrary free -- module_put with symbolic/attacker owner");
    (void)owner;
}

static void sim_disable_defrag(struct bpf_nf_link *l) {
    const struct nf_defrag_hook *h = l->defrag_hook;
    if (!h) return;
    if (h->disable_fn) {
        void (*fn)(struct net *) = (void (*)(struct net *))h->disable_fn;
        fn(l->net);
    }
    stub_module_put(h->owner);
}

void test_wmi3_arbitrary_free(void) {
    struct net             net  = { .ns_id = 1 };
    struct bpf_nf_link    *link = must_malloc(sizeof(*link));
    struct nf_defrag_hook *hook = must_malloc(sizeof(*hook));
    memset(link, 0, sizeof(*link));
    memset(hook, 0, sizeof(*hook));
    link->net         = &net;
    link->defrag_hook = hook;
    hook->disable_fn  = 0;

    uintptr_t sym_owner;                                     /* STACK */
    klee_make_symbolic(&sym_owner, sizeof(sym_owner), "wmi3_owner");
    hook->owner = sym_owner;                                 /* assign in */

    sim_disable_defrag(link);

    free(hook);
    free(link);
}

/* =========================================================================
 * 6. WMI-4: WRITE-WHAT-WHERE via nf_ct_ext_add
 *
 *    nf_ct_ext_add() writes:
 *        new->offset[id] = newoff;
 *    If `id` or `len` (which drives newoff) are attacker-influenced via a
 *    reclaimed/stale nf_ct_ext slab, this is a controlled write-what-where.
 *
 *    ALL symbolic variables are stack-local; heap struct fields are set
 *    by assignment after the klee_make_symbolic call.
 * ========================================================================= */

static const u8 ext_type_len[NF_CT_EXT_NUM] = {
    32, 8, 16, 24, 12, 8, 8, 16, 8, 8
};

static void *sim_nf_ct_ext_add(struct nf_conn *ct, u8 id) {
    unsigned int newoff, newlen, oldlen;
    struct nf_ct_ext *new_ext;

    klee_assert(!klee_is_symbolic((unsigned int)id) &&
                "WMI-4a: id is symbolic -- attacker controls write index");
    klee_assert(id < NF_CT_EXT_NUM &&
                "WMI-4b: id >= NF_CT_EXT_NUM -- OOB write into offset array");

    if (ct->ext) {
        if (ct->ext->offset[id] != 0)
            return NULL;
        oldlen = ct->ext->len;
    } else {
        oldlen = (unsigned int)sizeof(struct nf_ct_ext);
    }

    newoff = (oldlen + 7u) & ~7u;
    newlen = newoff + ext_type_len[id];

    klee_assert(!klee_is_symbolic(newoff) &&
                "WMI-4c: newoff is symbolic -- write-what-where on ext blob");

    unsigned int alloc = (newlen > NF_CT_EXT_PREALLOC) ? newlen : NF_CT_EXT_PREALLOC;
    new_ext = (struct nf_ct_ext *)realloc(ct->ext, alloc);
    klee_assume(new_ext != NULL);

    if (!ct->ext) {
        memset(new_ext->offset, 0, sizeof(new_ext->offset));
        new_ext->gen_id = 1;
    }

    new_ext->offset[id] = (u8)newoff;
    new_ext->len        = (u8)newlen;
    ct->ext = new_ext;
    return (void *)new_ext + newoff;
}

void test_wmi4_write_what_where(void) {
    struct nf_conn ct;

    /*
     * Scenario A: symbolic id, no existing ext.
     * sym_id is on the STACK — valid for klee_make_symbolic.
     */
    {
        memset(&ct, 0, sizeof(ct));

        u8 sym_id;                                           /* STACK */
        klee_make_symbolic(&sym_id, sizeof(sym_id), "wmi4_id_fresh");
        /* unconstrained: KLEE explores full u8 range including OOB values */

        sim_nf_ct_ext_add(&ct, sym_id);
        if (ct.ext) { free(ct.ext); ct.ext = NULL; }
    }

    /*
     * Scenario B: corrupted len drives newoff out of expected range.
     * sym_len is on the STACK; assigned into the heap ext after allocation.
     */
    {
        memset(&ct, 0, sizeof(ct));
        ct.ext = (struct nf_ct_ext *)must_malloc(NF_CT_EXT_PREALLOC);
        memset(ct.ext, 0, NF_CT_EXT_PREALLOC);
        ct.ext->gen_id = 1;

        u8 sym_len;                                          /* STACK */
        klee_make_symbolic(&sym_len, sizeof(sym_len), "wmi4_len_corrupt");
        ct.ext->len = sym_len;                               /* assign in */

        sim_nf_ct_ext_add(&ct, 3);
        if (ct.ext) { free(ct.ext); ct.ext = NULL; }
    }

    /*
     * Scenario C: stale offset entry — can it bypass the "already exists"
     * guard and trigger a double-write to the same extension slot?
     * sym_offset on the STACK; assigned into heap ext->offset[2].
     */
    {
        memset(&ct, 0, sizeof(ct));
        ct.ext = (struct nf_ct_ext *)must_malloc(NF_CT_EXT_PREALLOC);
        memset(ct.ext, 0, NF_CT_EXT_PREALLOC);
        ct.ext->len    = (u8)sizeof(struct nf_ct_ext);
        ct.ext->gen_id = 1;

        u8 sym_offset;                                       /* STACK */
        klee_make_symbolic(&sym_offset, sizeof(sym_offset), "wmi4_offset2_stale");
        ct.ext->offset[2] = sym_offset;                      /* assign in */

        sim_nf_ct_ext_add(&ct, 2);
        if (ct.ext) { free(ct.ext); ct.ext = NULL; }
    }

    /*
     * Scenario D: symbolic gen_id — version confusion between a stale
     * ext pointer and the current generation counter.
     * sym_genid on the STACK; assigned into heap ext->gen_id.
     */
    {
        memset(&ct, 0, sizeof(ct));
        ct.ext = (struct nf_ct_ext *)must_malloc(NF_CT_EXT_PREALLOC);
        memset(ct.ext, 0, NF_CT_EXT_PREALLOC);
        ct.ext->len = (u8)sizeof(struct nf_ct_ext);

        u32 sym_genid;                                       /* STACK */
        klee_make_symbolic(&sym_genid, sizeof(sym_genid), "wmi4_genid");
        ct.ext->gen_id = sym_genid;                          /* assign in */

        sim_nf_ct_ext_add(&ct, 1);
        if (ct.ext) { free(ct.ext); ct.ext = NULL; }
    }
}

/* =========================================================================
 * 7. PRIORITY BYPASS — bpf_nf_check_pf_and_hooks
 *
 *    sym_nf_attr contains only plain integer fields (no pointers), and is
 *    stack-allocated — can be symbolized as a whole struct directly.
 * ========================================================================= */

#define NFPROTO_IPV4                2
#define NFPROTO_IPV6               10
#define NF_INET_NUMHOOKS            5
#define NF_IP_PRI_FIRST           (-2147483648)
#define NF_IP_PRI_LAST             2147483647
#define NF_IP_PRI_CONNTRACK_DEFRAG (-400)
#define BPF_F_NETFILTER_IP_DEFRAG  (1U << 0)

struct sym_nf_attr {
    u8   pf;
    u8   hooknum;
    int  priority;
    u32  flags;
    u32  link_flags;
};

static int sim_check_pf_and_hooks(const struct sym_nf_attr *a) {
    if (a->link_flags)
        return -22;  /* -EINVAL */

    switch (a->pf) {
    case NFPROTO_IPV4:
    case NFPROTO_IPV6:
        if (a->hooknum >= NF_INET_NUMHOOKS) return -71;  /* -EPROTO */
        break;
    default:
        return -97;  /* -EAFNOSUPPORT */
    }

    if (a->flags & ~BPF_F_NETFILTER_IP_DEFRAG)
        return -95;  /* -EOPNOTSUPP */

    int prio = a->priority;

    klee_assert(prio != NF_IP_PRI_FIRST &&
                "Priority bypass: NF_IP_PRI_FIRST not rejected -- sabotage_in risk");
    klee_assert(prio != NF_IP_PRI_LAST &&
                "Priority bypass: NF_IP_PRI_LAST not rejected -- conntrack confirm risk");

    if (prio == NF_IP_PRI_FIRST) return -34;
    if (prio == NF_IP_PRI_LAST)  return -34;
    if ((a->flags & BPF_F_NETFILTER_IP_DEFRAG) &&
        prio <= NF_IP_PRI_CONNTRACK_DEFRAG)      return -34;

    return 0;
}

void test_priority_bypass(void) {
    struct sym_nf_attr attr;          /* STACK struct, all plain integers */
    klee_make_symbolic(&attr, sizeof(attr), "nf_attr");

    klee_assume(attr.pf == NFPROTO_IPV4 || attr.pf == NFPROTO_IPV6);
    klee_assume(attr.hooknum < NF_INET_NUMHOOKS);
    klee_assume(attr.link_flags == 0);
    klee_assume(attr.flags == 0 || attr.flags == BPF_F_NETFILTER_IP_DEFRAG);

    sim_check_pf_and_hooks(&attr);
}

/* =========================================================================
 * 8. MAIN
 * ========================================================================= */

int main(void) {
    test_wmi1_stale_reference();
    test_wmi2_type_confusion();
    test_wmi3_arbitrary_free();
    test_wmi4_write_what_where();
    test_priority_bypass();
    return 0;
}

/*
 * ==========================================================================
 * BUILD AND RUN
 * ==========================================================================
 *
 * STEP 1 — Compile to LLVM bitcode
 *
 *   clang-14 -emit-llvm -c -g -O0 \
 *       -I /usr/local/include \
 *       -Wno-everything \
 *       klee_nf_harness.c \
 *       -o klee_nf_harness.bc
 *
 *   Common include paths for KLEE headers:
 *     /usr/local/include          (system-installed KLEE)
 *     /home/klee/klee_src/include (Docker klee/klee image)
 *     /path/to/klee/build/include (custom build)
 *
 *
 * STEP 2 — Run KLEE
 *
 *   klee \
 *       --solver-backend=z3 \
 *       --max-time=3600 \
 *       --max-memory=8192 \
 *       --emit-all-errors \
 *       --only-output-states-covering-new \
 *       --output-dir=klee-out-nf \
 *       klee_nf_harness.bc
 *
 *   If WMI-4 scenario A explodes (256 unconstrained id values):
 *       --max-forks=50000
 *   For breadth-first coverage of all tests before going deep:
 *       --search=bfs
 *
 *
 * STEP 3 — Inspect results
 *
 *   klee-stats klee-out-nf/
 *   ls klee-out-nf/           (look for .err files)
 *   ktest-tool klee-out-nf/testN.ktest
 *
 *
 * ASSERTION TO WMI MAPPING
 * ------------------------
 *   Assertion text                                         WMI
 *   ----------------------------------------------------- -------
 *   "stale ref -- double unregister of hook_ops"           WMI-1
 *   "funcptr is symbolic/attacker-controlled"              WMI-2
 *   "module_put with symbolic/attacker owner"              WMI-3
 *   "id is symbolic"                                       WMI-4a
 *   "id >= NF_CT_EXT_NUM"                                  WMI-4b
 *   "newoff is symbolic"                                   WMI-4c
 *   "NF_IP_PRI_FIRST not rejected"                         priority bypass
 *   "NF_IP_PRI_LAST not rejected"                          priority bypass
 *
 *
 * THE RULE: WHERE klee_make_symbolic IS VALID
 * -------------------------------------------
 *   VALID:   stack variables (any scalar or plain-integer struct)
 *   VALID:   global variables
 *   INVALID: any field inside a malloc/realloc'd object
 *   INVALID: any field that holds a pointer or function pointer
 *
 *   Every heap struct field in this harness is set by assignment from a
 *   stack-local symbolic variable, never by calling klee_make_symbolic
 *   with the address of a heap field directly.
 *
 * ==========================================================================
 */