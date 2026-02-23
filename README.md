# DARPA CHALLENGE - Netfilter
The netfilter framework allows for intercepting and manipulating network packets in the Linux kernel.

### LLM Prompt
The harness file `nf_harness.c` was generated using Claude's Sonnet 4.6 model. This was the initial prompt given along with files from the netfilter directory:
> Write a KLEE symbolic execution harness file to detect vulnerabilities in the linux kernel netfilter files. 
> The WMIs to focus on are: 
> 1. WMI-1 (Stale Reference): Entity freed while trigger maintains pointer
> 2. WMI-2 (Leak via Type Confusion): Reading funcptr as entity through stale reference
> 3. WMI-3 (Arbitrary Free): Using fake entity to free arbitrary address
> 4. WMI-4 (Write-What-Where): Reclaiming freed memory and overwriting

### Using KLEE Symbolic Execution
```
# Compile to LLVM bitcode
clang-14 -emit-llvm -c -g -O0 \
    -I /path/to/klee/include \
    nf_harness.c -o nf_harness.bc

# Run KLEE
klee --solver-backend=z3 --max-time=3600 \
    --emit-all-errors --output-dir=klee-out-nf \
    nf_harness.bc

# Inspect hits
klee-stats klee-out-nf
ktest-tool klee-out-nf/test000001.ktest
```

### KLEE Output
```
KLEE: output directory is "/root/demo3_linux-main/demo3_linux-main/net/netfilter/klee-out-nf"
KLEE: Using Z3 solver backend
KLEE: Deterministic allocator: Using quarantine queue size 8
KLEE: Deterministic allocator: globals (start-address=0x7dbb6c800000 size=10 GiB)
KLEE: Deterministic allocator: constants (start-address=0x7db8ec800000 size=10 GiB)
KLEE: Deterministic allocator: heap (start-address=0x7cb8ec800000 size=1024 GiB)
KLEE: Deterministic allocator: stack (start-address=0x7c98ec800000 size=128 GiB)
KLEE: WARNING ONCE: Alignment of memory from call "malloc" is not modelled. Using alignment of 8.
KLEE: ERROR: nf_harness.c:175: ASSERTION FAIL: !klee_is_symbolic((unsigned int)hook->enable_fn) && "WMI-2: type confusion -- funcptr is symbolic/attacker-controlled"
KLEE: ERROR: nf_harness.c:175: ASSERTION FAIL: !klee_is_symbolic((unsigned int)hook->enable_fn) && "WMI-2: type confusion -- funcptr is symbolic/attacker-controlled"
KLEE: done: total instructions = 4141
KLEE: done: completed paths = 0
KLEE: done: partially completed paths = 2
KLEE: done: generated tests = 2
```

### Interpretation
The harness models this scenario from `nf_bpf_link.c`: when a BPF netfilter program is attached with the `BPF_F_NETFILTER_IP_DEFRAG` flag, the kernel allocates a `bpf_nf_link` and stores a pointer to a `nf_defrag_hook` inside it.
The attack chain is: 
Step 1: normal attachment, where `bpf_nf_link` is allocated and `defrag_hook` is set to point at a legitimate `nf_defrag_hook` object
Step 2: `bpf_nf_link` struct is freed, but `nf_defraf_hook` object's lifetime may be mismanaged because `bpf_nf_disable_defrag()` may not fire correctly.
Step 3: the kernel's slab allocator recycles the freed memory. If an attacker triggers an allocation of the same size, the attacker controls the contents of this new allocation.

In the harness:
```
uintptr_t sym_fn;
klee_make_symbolic(&sym_fn, sizeof(sym_fn), "wmi2_enable_attacker");
hook->enable_fn = sym_fn;   // attacker controls this
sim_call_enable(hook, &net);

// ...

static void sim_call_enable(const struct nf_defrag_hook *hook, struct net *net) {
    klee_assert(!klee_is_symbolic((unsigned int)hook->enable_fn) ...);
    //                            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    //  KLEE evaluates this: is enable_fn symbolic? YES.
    //  So !klee_is_symbolic(...) = FALSE.
    //  Assertion fails → KLEE reports a bug.
```

Klee_make_symbolic models the attacker writing arbitrary bytes to the reclaimed slab slot. If the symbolic value reaches `sim_call_enable`, this evaluates to FALSE, modeling the real kernel which would jump to an attacker controlled address at this part of the code. 

### Concrete Examples
```
ktest file : 'klee-out-nf/test000001.ktest'
args       : ['nf_harness.bc']
num objects: 2
object 0: name: 'wmi1_dead'
object 0: size: 4
object 0: data: b'\x01\x00\x00\x00'
object 0: hex : 0x01000000
object 0: int : 1
object 0: uint: 1
object 0: text: ....
object 1: name: 'wmi2_enable_attacker'
object 1: size: 8
object 1: data: b'\x00\x00\x00\x00\x00\x00\x00\x00'
object 1: hex : 0x0000000000000000
object 1: int : 0
object 1: uint: 0
object 1: text: ........
```
```
ktest file : 'klee-out-nf/test000002.ktest'
args       : ['nf_harness.bc']
num objects: 2
object 0: name: 'wmi1_dead'
object 0: size: 4
object 0: data: b'\x00\x00\x00\x00'
object 0: hex : 0x00000000
object 0: int : 0
object 0: uint: 0
object 0: text: ....
object 1: name: 'wmi2_enable_attacker'
object 1: size: 8
object 1: data: b'\x00\x00\x00\x00\x00\x00\x00\x00'
object 1: hex : 0x0000000000000000
object 1: int : 0
object 1: uint: 0
object 1: text: ........
```
