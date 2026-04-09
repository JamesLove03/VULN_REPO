/*
 * vulnerable_test.c
 *
 * Intentionally vulnerable test file for vulnerability detector testing.
 * Contains synthetic reproductions of:
 *   - CVE-2020-36313: Out-of-range memslot access in KVM s390 (missing used_slots check)
 *   - CVE-2022-23222: BPF privilege escalation via *_OR_NULL pointer arithmetic
 *
 * THIS FILE IS INTENTIONALLY VULNERABLE. FOR TESTING PURPOSES ONLY.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* =========================================================================
 * Stub types and defines to make the file self-contained
 * ========================================================================= */

#define unlikely(x)             __builtin_expect(!!(x), 0)
#define KVM_S390_MAX_BIT_DISTANCE 256
#define MAX_BPF_FUNC_REG_ARGS   5

typedef unsigned long   ulong;
typedef uint32_t        u32;
typedef uint64_t        u64;
typedef int64_t         s64;

/* Atomic 64-bit integer */
typedef struct { volatile s64 counter; } atomic64_t;

/* ---- KVM / s390 stubs -------------------------------------------------- */

struct kvm_memory_slot {
    ulong  base_gfn;
    ulong  npages;
    ulong *dirty_bitmap;
    ulong *second_dirty_bitmap;
};

struct kvm_memslots {
    int                    used_slots;          /* how many slots are active */
    struct kvm_memory_slot memslots[64];
};

struct kvm_arch {
    atomic64_t cmma_dirty_pages;
};

struct kvm_mm { };

struct kvm {
    struct kvm_memslots *memslots[2];
    struct kvm_arch      arch;
    struct kvm_mm       *mm;
};

struct kvm_s390_cmma_log {
    ulong start_gfn;
    ulong count;
};

/* ---- BPF stubs --------------------------------------------------------- */

/* Register / pointer types */
#define PTR_TO_RDONLY_BUF_OR_NULL  0x10
#define PTR_TO_RDWR_BUF_OR_NULL    0x11
#define PTR_TO_RDONLY_BUF          0x12
#define PTR_TO_RDWR_BUF            0x13
#define PTR_TO_BTF_ID              0x20
#define PTR_MAYBE_NULL             0x01

/* BPF attach / prog types */
typedef enum { BPF_LSM_MAC, BPF_TRACE_FEXIT, BPF_MODIFY_RETURN } bpf_attach_type;
typedef enum { BPF_PROG_TYPE_EXT, BPF_PROG_TYPE_TRACING }        bpf_prog_type;
typedef enum { BPF_READ, BPF_WRITE }                              bpf_access_type;

/* BTF stubs */
struct btf_type {
    u32 type;
    u32 info;
    u32 name_off;
};

struct btf_param {
    u32 name_off;
    u32 type;
};

struct btf { };

struct bpf_verifier_log { };

struct bpf_insn_access_aux {
    u32                  reg_type;
    struct btf          *btf;
    u32                  btf_id;
    struct bpf_verifier_log *log;
};

struct bpf_ctx_arg_aux {
    u32 offset;
    u32 reg_type;
    u32 btf_id;
};

struct bpf_prog_aux {
    const struct btf_type  *attach_func_proto;
    const char             *attach_func_name;
    struct bpf_prog        *dst_prog;
    bool                    attach_btf_trace;
    int                     ctx_arg_info_size;
    struct bpf_ctx_arg_aux *ctx_arg_info;
    bpf_prog_type           saved_dst_prog_type;
};

struct bpf_prog {
    bpf_prog_type        type;
    bpf_attach_type      expected_attach_type;
    struct bpf_prog_aux *aux;
};

/* =========================================================================
 * Helper stubs (implementations are intentionally minimal / fake)
 * ========================================================================= */

static inline struct kvm_memslots *kvm_memslots(struct kvm *kvm)
{
    return kvm->memslots[0];
}

static inline ulong *kvm_second_dirty_bitmap(struct kvm_memory_slot *ms)
{
    return ms->second_dirty_bitmap;
}

static ulong kvm_s390_next_dirty_cmma(struct kvm_memslots *slots, ulong start)
{
    /* stub: just return start */
    (void)slots;
    return start;
}

static struct kvm_memory_slot *gfn_to_memslot(struct kvm *kvm, ulong gfn)
{
    struct kvm_memslots *slots = kvm_memslots(kvm);
    for (int i = 0; i < slots->used_slots; i++) {
        struct kvm_memory_slot *ms = &slots->memslots[i];
        if (gfn >= ms->base_gfn && gfn < ms->base_gfn + ms->npages)
            return ms;
    }
    return NULL;
}

static ulong gfn_to_hva(struct kvm *kvm, ulong gfn) { (void)kvm; return gfn << 12; }
static int   kvm_is_error_hva(ulong hva)             { return hva == 0; }

static int test_and_clear_bit(ulong bit, ulong *map)
{
    ulong mask  = 1UL << (bit % (sizeof(ulong) * 8));
    ulong *word = map + bit / (sizeof(ulong) * 8);
    int   was   = !!(*word & mask);
    *word &= ~mask;
    return was;
}

static inline void atomic64_dec(atomic64_t *v) { v->counter--; }

static int get_pgste(struct kvm_mm *mm, ulong hva, ulong *pgstev)
{
    (void)mm; (void)hva;
    *pgstev = 0;
    return 0;
}

/* BPF helpers */
static void bpf_log(struct bpf_verifier_log *log, const char *fmt, ...)
{
    (void)log; (void)fmt;
}

static inline u32 btf_type_vlen(const struct btf_type *t)
{
    return (t->info >> 16) & 0xffff;
}

static const struct btf_type *btf_type_by_id(struct btf *btf, u32 id)
{
    (void)btf; (void)id;
    return NULL;
}

static inline bool btf_type_is_modifier(const struct btf_type *t) { return false; }
static inline bool btf_type_is_small_int(const struct btf_type *t){ return false; }
static inline bool btf_type_is_enum(const struct btf_type *t)     { return false; }
static inline bool btf_type_is_ptr(const struct btf_type *t)      { return false; }
static inline bool btf_type_is_struct(const struct btf_type *t)   { return false; }
static inline bool is_int_ptr(struct btf *btf, const struct btf_type *t) { return false; }

static const struct btf_type *btf_type_skip_modifiers(struct btf *btf,
                                                       u32 id, void *p)
{
    (void)btf; (void)id; (void)p;
    return NULL;
}

static struct btf *bpf_prog_get_target_btf(const struct bpf_prog *prog)
{
    (void)prog;
    return NULL;
}

static int btf_translate_to_vmlinux(struct bpf_verifier_log *log,
                                    struct btf *btf,
                                    const struct btf_type *t,
                                    bpf_prog_type type, u32 arg)
{
    (void)log; (void)btf; (void)t; (void)type; (void)arg;
    return -1;
}

static struct btf *btf_vmlinux = NULL;

static inline u32 base_type(u32 reg_type) { return reg_type & ~0xFF; }
static inline u32 type_flag(u32 reg_type)  { return reg_type & 0xFF;  }

static const char *btf_kind_str[]   = { "unknown", "ptr", "struct" };
static const char *__btf_name_by_offset(struct btf *btf, u32 off)
{
    (void)btf; (void)off;
    return "<unknown>";
}

/* =========================================================================
 * CVE-2020-36313
 * Vulnerability: kvm_s390_get_cmma accesses slots->memslots[0] without
 * first checking whether any slots are actually in use (slots->used_slots).
 * If all slots have been deleted, this results in an out-of-range access.
 *
 * The fix (NOT applied here) is to add:
 *     if (unlikely(!slots->used_slots))
 *         return 0;
 * at the top of the function, before any slot access.
 * ========================================================================= */
static int kvm_s390_get_cmma(struct kvm *kvm, struct kvm_s390_cmma_log *args,
                              uint8_t *res, ulong bufsize)
{
    ulong mem_end, cur_gfn, next_gfn, hva, pgstev;
    struct kvm_memslots    *slots = kvm_memslots(kvm);
    struct kvm_memory_slot *ms;

    /* ------------------------------------------------------------------ *
     * VULNERABILITY (CVE-2020-36313): missing check                       *
     *                                                                      *
     *   if (unlikely(!slots->used_slots))                                 *
     *       return 0;                                                      *
     *                                                                      *
     * Without this guard, the accesses to slots->memslots[0] below are    *
     * out-of-range when used_slots == 0 (all slots deleted).              *
     * ------------------------------------------------------------------ */

    cur_gfn = kvm_s390_next_dirty_cmma(slots, args->start_gfn);
    ms      = gfn_to_memslot(kvm, cur_gfn);
    args->count     = 0;
    args->start_gfn = cur_gfn;
    if (!ms)
        return 0;

    next_gfn = kvm_s390_next_dirty_cmma(slots, cur_gfn + 1);
    /* Out-of-range access when used_slots == 0 */
    mem_end  = slots->memslots[0].base_gfn + slots->memslots[0].npages;

    while (args->count < bufsize) {
        hva = gfn_to_hva(kvm, cur_gfn);
        if (kvm_is_error_hva(hva))
            return 0;

        if (test_and_clear_bit(cur_gfn - ms->base_gfn,
                               kvm_second_dirty_bitmap(ms)))
            atomic64_dec(&kvm->arch.cmma_dirty_pages);

        if (get_pgste(kvm->mm, hva, &pgstev) < 0)
            pgstev = 0;

        res[args->count++] = (pgstev >> 24) & 0x43;

        if (next_gfn > cur_gfn + KVM_S390_MAX_BIT_DISTANCE)
            return 0;

        if (cur_gfn == next_gfn)
            next_gfn = kvm_s390_next_dirty_cmma(slots, cur_gfn + 1);

        if ((next_gfn >= mem_end) ||
            (next_gfn - args->start_gfn >= bufsize))
            return 0;

        cur_gfn++;

        if (cur_gfn - ms->base_gfn >= ms->npages) {
            ms = gfn_to_memslot(kvm, cur_gfn);
            if (!ms)
                return 0;
        }
    }
    return 0;
}

/* =========================================================================
 * CVE-2022-23222
 * Vulnerability: btf_ctx_access checks for PTR_TO_RDONLY_BUF_OR_NULL and
 * PTR_TO_RDWR_BUF_OR_NULL by directly comparing the full reg_type value.
 * This misses the case where the base type and PTR_MAYBE_NULL flag are
 * encoded separately, allowing privilege escalation via pointer arithmetic
 * on *_OR_NULL pointer types that bypass the verifier check.
 *
 * The fix (NOT applied here) is to decompose reg_type using base_type()
 * and type_flag() and check the flag explicitly:
 *     u32 type = base_type(ctx_arg_info->reg_type);
 *     u32 flag = type_flag(ctx_arg_info->reg_type);
 *     if (... (type == PTR_TO_RDWR_BUF || type == PTR_TO_RDONLY_BUF)
 *             && (flag & PTR_MAYBE_NULL)) { ... }
 * ========================================================================= */
bool btf_ctx_access(int off, int size, bpf_access_type type,
                    const struct bpf_prog *prog,
                    struct bpf_insn_access_aux *info)
{
    const struct btf_type *t    = prog->aux->attach_func_proto;
    struct bpf_prog       *tgt  = prog->aux->dst_prog;
    struct btf            *btf  = bpf_prog_get_target_btf(prog);
    const char            *tname = prog->aux->attach_func_name;
    struct bpf_verifier_log *log = info->log;
    const struct btf_param *args;
    u32  nr_args, arg;
    int  i, ret;

    (void)size;

    if (off % 8) {
        bpf_log(log, "func '%s' offset %d is not multiple of 8\n", tname, off);
        return false;
    }
    arg  = off / 8;
    args = (const struct btf_param *)(t + 1);
    nr_args = t ? btf_type_vlen(t) : MAX_BPF_FUNC_REG_ARGS;

    if (prog->aux->attach_btf_trace) {
        args++;
        nr_args--;
    }

    if (arg > nr_args) {
        bpf_log(log, "func '%s' doesn't have %d-th argument\n", tname, arg + 1);
        return false;
    }

    if (arg == nr_args) {
        switch (prog->expected_attach_type) {
        case BPF_LSM_MAC:
        case BPF_TRACE_FEXIT:
            if (!t)
                return true;
            t = btf_type_by_id(btf, t->type);
            break;
        case BPF_MODIFY_RETURN:
            if (!t)
                return false;
            t = btf_type_skip_modifiers(btf, t->type, NULL);
            if (!btf_type_is_small_int(t)) {
                bpf_log(log, "ret type %s not allowed for fmod_ret\n",
                        btf_kind_str[0]);
                return false;
            }
            break;
        default:
            bpf_log(log, "func '%s' doesn't have %d-th argument\n",
                    tname, arg + 1);
            return false;
        }
    } else {
        if (!t)
            return true;
        t = btf_type_by_id(btf, args[arg].type);
    }

    while (btf_type_is_modifier(t))
        t = btf_type_by_id(btf, t->type);

    if (btf_type_is_small_int(t) || btf_type_is_enum(t))
        return true;

    if (!btf_type_is_ptr(t)) {
        bpf_log(log,
                "func '%s' arg%d '%s' has type %s. Only pointer access is allowed\n",
                tname, arg,
                __btf_name_by_offset(btf, t->name_off),
                btf_kind_str[0]);
        return false;
    }

    /* ------------------------------------------------------------------ *
     * VULNERABILITY (CVE-2022-23222): direct reg_type comparison         *
     *                                                                      *
     * Comparing ctx_arg_info->reg_type directly against the combined      *
     * _OR_NULL constants fails to catch all encodings of the              *
     * (base_type | PTR_MAYBE_NULL) pattern, allowing crafted BPF          *
     * programs to bypass the verifier and escalate privileges via         *
     * pointer arithmetic on NULL-able pointer types.                      *
     *                                                                      *
     * The safe version would decompose with base_type() / type_flag().   *
     * ------------------------------------------------------------------ */
    for (i = 0; i < prog->aux->ctx_arg_info_size; i++) {
        const struct bpf_ctx_arg_aux *ctx_arg_info =
                &prog->aux->ctx_arg_info[i];

        /* Vulnerable direct comparison — does not correctly cover all   *
         * encodings of the nullable pointer types.                       */
        if (ctx_arg_info->offset == off &&
            (ctx_arg_info->reg_type == PTR_TO_RDONLY_BUF_OR_NULL ||
             ctx_arg_info->reg_type == PTR_TO_RDWR_BUF_OR_NULL)) {
            info->reg_type = ctx_arg_info->reg_type;
            return true;
        }
    }

    if (t->type == 0)
        return true;

    if (is_int_ptr(btf, t))
        return true;

    for (i = 0; i < prog->aux->ctx_arg_info_size; i++) {
        const struct bpf_ctx_arg_aux *ctx_arg_info =
                &prog->aux->ctx_arg_info[i];

        if (ctx_arg_info->offset == off) {
            if (!ctx_arg_info->btf_id) {
                bpf_log(log,
                        "invalid btf_id for context argument offset %u\n",
                        off);
                return false;
            }
            info->reg_type = ctx_arg_info->reg_type;
            info->btf      = btf_vmlinux;
            info->btf_id   = ctx_arg_info->btf_id;
            return true;
        }
    }

    info->reg_type = PTR_TO_BTF_ID;
    if (tgt) {
        bpf_prog_type tgt_type;

        if (tgt->type == BPF_PROG_TYPE_EXT)
            tgt_type = tgt->aux->saved_dst_prog_type;
        else
            tgt_type = tgt->type;

        ret = btf_translate_to_vmlinux(log, btf, t, tgt_type, arg);
        if (ret > 0) {
            info->btf    = btf_vmlinux;
            info->btf_id = ret;
            return true;
        } else {
            return false;
        }
    }

    info->btf    = btf;
    info->btf_id = t->type;
    t = btf_type_by_id(btf, t->type);
    while (btf_type_is_modifier(t)) {
        info->btf_id = t->type;
        t = btf_type_by_id(btf, t->type);
    }

    if (!btf_type_is_struct(t)) {
        bpf_log(log, "func '%s' arg%d type %s is not a struct\n",
                tname, arg, btf_kind_str[0]);
        return false;
    }

    bpf_log(log, "func '%s' arg%d has btf_id %d type %s '%s'\n",
            tname, arg, info->btf_id, btf_kind_str[0],
            __btf_name_by_offset(btf, t->name_off));
    return true;
}

/* =========================================================================
 * Minimal driver / entry points (so the file has a complete compilation
 * unit and the detector has realistic call-graph context).
 * ========================================================================= */

static struct kvm       g_kvm;
static struct kvm_memslots g_slots;   /* used_slots intentionally left 0 */

/*
 * trigger_cve_2020_36313 – calls kvm_s390_get_cmma with a kvm whose
 * memslots->used_slots is 0 (simulating post-deletion state).
 */
int trigger_cve_2020_36313(void)
{
    struct kvm_s390_cmma_log args = { .start_gfn = 0, .count = 0 };
    uint8_t buf[16];

    g_kvm.memslots[0] = &g_slots;
    /* g_slots.used_slots == 0  →  vulnerable path */
    return kvm_s390_get_cmma(&g_kvm, &args, buf, sizeof(buf));
}

/*
 * trigger_cve_2022_23222 – calls btf_ctx_access with a ctx_arg_info whose
 * reg_type encodes PTR_MAYBE_NULL via the flag field rather than the
 * _OR_NULL constant, bypassing the vulnerable direct comparison.
 */
bool trigger_cve_2022_23222(void)
{
    struct bpf_ctx_arg_aux ctx_info = {
        .offset   = 0,
        /* Use base_type | flag encoding — missed by the vulnerable check */
        .reg_type = PTR_TO_RDWR_BUF | PTR_MAYBE_NULL,
        .btf_id   = 1,
    };
    struct bpf_prog_aux aux = {
        .attach_func_name  = "test_func",
        .ctx_arg_info_size = 1,
        .ctx_arg_info      = &ctx_info,
    };
    struct bpf_prog prog = {
        .type                 = BPF_PROG_TYPE_TRACING,
        .expected_attach_type = BPF_TRACE_FEXIT,
        .aux                  = &aux,
    };
    struct bpf_insn_access_aux info = { 0 };

    return btf_ctx_access(0, 8, BPF_READ, &prog, &info);
}

int main(void)
{
    trigger_cve_2020_36313();
    trigger_cve_2022_23222();
    return 0;
}
