# DARPA CHALLENGE - Netfilter
The netfilter framework allows for intercepting and manipulating network packets in the Linux kernel.

### LLM Prompt
The harness file `nf_harness.c` was generated using Claude's Sonnet 4.6 model. This was the initial prompt given:
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
