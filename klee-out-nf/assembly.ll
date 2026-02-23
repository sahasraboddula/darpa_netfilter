; ModuleID = 'nf_harness.bc'
source_filename = "nf_harness.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.net = type { i32 }
%struct.bpf_nf_link = type { %struct.bpf_link, %struct.nf_hook_ops, %struct.net*, i32, %struct.nf_defrag_hook* }
%struct.bpf_link = type { i32, i64, %struct.bpf_prog* }
%struct.bpf_prog = type { i32, i32, i64 }
%struct.nf_hook_ops = type { i64, i64, i8, i8, i32, i8 }
%struct.nf_defrag_hook = type { i64, i64, i64 }
%struct.nf_conn = type { %struct.nf_ct_ext*, i32 }
%struct.nf_ct_ext = type { [10 x i8], i8, i32 }
%struct.sym_nf_attr = type { i8, i8, i32, i32, i32 }

@__const.test_wmi1_stale_reference.net = private unnamed_addr constant %struct.net { i32 1 }, align 4
@.str = private unnamed_addr constant [10 x i8] c"wmi1_dead\00", align 1
@g_unregister_count = internal global i32 0, align 4, !dbg !0
@__const.test_wmi2_type_confusion.net = private unnamed_addr constant %struct.net { i32 1 }, align 4
@.str.1 = private unnamed_addr constant [21 x i8] c"wmi2_enable_attacker\00", align 1
@__const.test_wmi3_arbitrary_free.net = private unnamed_addr constant %struct.net { i32 1 }, align 4
@.str.2 = private unnamed_addr constant [11 x i8] c"wmi3_owner\00", align 1
@.str.3 = private unnamed_addr constant [14 x i8] c"wmi4_id_fresh\00", align 1
@.str.4 = private unnamed_addr constant [17 x i8] c"wmi4_len_corrupt\00", align 1
@.str.5 = private unnamed_addr constant [19 x i8] c"wmi4_offset2_stale\00", align 1
@.str.6 = private unnamed_addr constant [11 x i8] c"wmi4_genid\00", align 1
@.str.7 = private unnamed_addr constant [8 x i8] c"nf_attr\00", align 1
@.str.8 = private unnamed_addr constant [50 x i8] c"WMI-1: stale ref -- double unregister of hook_ops\00", align 1
@.str.9 = private unnamed_addr constant [79 x i8] c"g_unregister_count <= 1 && \22WMI-1: stale ref -- double unregister of hook_ops\22\00", align 1
@.str.10 = private unnamed_addr constant [13 x i8] c"nf_harness.c\00", align 1
@__PRETTY_FUNCTION__.stub_unregister = private unnamed_addr constant [57 x i8] c"void stub_unregister(struct net *, struct nf_hook_ops *)\00", align 1
@.str.11 = private unnamed_addr constant [65 x i8] c"WMI-2: type confusion -- funcptr is symbolic/attacker-controlled\00", align 1
@.str.12 = private unnamed_addr constant [119 x i8] c"!klee_is_symbolic((unsigned int)hook->enable_fn) && \22WMI-2: type confusion -- funcptr is symbolic/attacker-controlled\22\00", align 1
@__PRETTY_FUNCTION__.sim_call_enable = private unnamed_addr constant [66 x i8] c"void sim_call_enable(const struct nf_defrag_hook *, struct net *)\00", align 1
@.str.13 = private unnamed_addr constant [65 x i8] c"WMI-3: arbitrary free -- module_put with symbolic/attacker owner\00", align 1
@.str.14 = private unnamed_addr constant [109 x i8] c"!klee_is_symbolic((unsigned int)owner) && \22WMI-3: arbitrary free -- module_put with symbolic/attacker owner\22\00", align 1
@__PRETTY_FUNCTION__.stub_module_put = private unnamed_addr constant [32 x i8] c"void stub_module_put(uintptr_t)\00", align 1
@.str.15 = private unnamed_addr constant [56 x i8] c"WMI-4a: id is symbolic -- attacker controls write index\00", align 1
@.str.16 = private unnamed_addr constant [97 x i8] c"!klee_is_symbolic((unsigned int)id) && \22WMI-4a: id is symbolic -- attacker controls write index\22\00", align 1
@__PRETTY_FUNCTION__.sim_nf_ct_ext_add = private unnamed_addr constant [46 x i8] c"void *sim_nf_ct_ext_add(struct nf_conn *, u8)\00", align 1
@.str.17 = private unnamed_addr constant [59 x i8] c"WMI-4b: id >= NF_CT_EXT_NUM -- OOB write into offset array\00", align 1
@.str.18 = private unnamed_addr constant [83 x i8] c"id < NF_CT_EXT_NUM && \22WMI-4b: id >= NF_CT_EXT_NUM -- OOB write into offset array\22\00", align 1
@ext_type_len = internal constant [10 x i8] c" \08\10\18\0C\08\08\10\08\08", align 1, !dbg !40
@.str.19 = private unnamed_addr constant [59 x i8] c"WMI-4c: newoff is symbolic -- write-what-where on ext blob\00", align 1
@.str.20 = private unnamed_addr constant [90 x i8] c"!klee_is_symbolic(newoff) && \22WMI-4c: newoff is symbolic -- write-what-where on ext blob\22\00", align 1
@.str.21 = private unnamed_addr constant [66 x i8] c"Priority bypass: NF_IP_PRI_FIRST not rejected -- sabotage_in risk\00", align 1
@.str.22 = private unnamed_addr constant [95 x i8] c"prio != NF_IP_PRI_FIRST && \22Priority bypass: NF_IP_PRI_FIRST not rejected -- sabotage_in risk\22\00", align 1
@__PRETTY_FUNCTION__.sim_check_pf_and_hooks = private unnamed_addr constant [55 x i8] c"int sim_check_pf_and_hooks(const struct sym_nf_attr *)\00", align 1
@.str.23 = private unnamed_addr constant [71 x i8] c"Priority bypass: NF_IP_PRI_LAST not rejected -- conntrack confirm risk\00", align 1
@.str.24 = private unnamed_addr constant [99 x i8] c"prio != NF_IP_PRI_LAST && \22Priority bypass: NF_IP_PRI_LAST not rejected -- conntrack confirm risk\22\00", align 1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test_wmi1_stale_reference() #0 !dbg !56 {
  %1 = alloca %struct.net, align 4
  %2 = alloca %struct.bpf_nf_link*, align 8
  %3 = alloca i32, align 4
  call void @llvm.dbg.declare(metadata %struct.net* %1, metadata !60, metadata !DIExpression()), !dbg !61
  %4 = bitcast %struct.net* %1 to i8*, !dbg !61
  %5 = call i8* @memcpy(i8* %4, i8* bitcast (%struct.net* @__const.test_wmi1_stale_reference.net to i8*), i64 4), !dbg !61
  call void @llvm.dbg.declare(metadata %struct.bpf_nf_link** %2, metadata !62, metadata !DIExpression()), !dbg !97
  %6 = call i8* @must_malloc(i64 noundef 80), !dbg !98
  %7 = bitcast i8* %6 to %struct.bpf_nf_link*, !dbg !98
  store %struct.bpf_nf_link* %7, %struct.bpf_nf_link** %2, align 8, !dbg !97
  %8 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !99
  %9 = bitcast %struct.bpf_nf_link* %8 to i8*, !dbg !100
  %10 = call i8* @memset(i8* %9, i32 0, i64 80), !dbg !100
  %11 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !101
  %12 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %11, i32 0, i32 2, !dbg !102
  store %struct.net* %1, %struct.net** %12, align 8, !dbg !103
  call void @llvm.dbg.declare(metadata i32* %3, metadata !104, metadata !DIExpression()), !dbg !105
  %13 = bitcast i32* %3 to i8*, !dbg !106
  call void @klee_make_symbolic(i8* noundef %13, i64 noundef 4, i8* noundef getelementptr inbounds ([10 x i8], [10 x i8]* @.str, i64 0, i64 0)), !dbg !107
  %14 = load i32, i32* %3, align 4, !dbg !108
  %15 = icmp eq i32 %14, 0, !dbg !109
  br i1 %15, label %19, label %16, !dbg !110

16:                                               ; preds = %0
  %17 = load i32, i32* %3, align 4, !dbg !111
  %18 = icmp eq i32 %17, 1, !dbg !112
  br label %19, !dbg !110

19:                                               ; preds = %16, %0
  %20 = phi i1 [ true, %0 ], [ %18, %16 ]
  %21 = zext i1 %20 to i32, !dbg !110
  %22 = sext i32 %21 to i64, !dbg !108
  call void @klee_assume(i64 noundef %22), !dbg !113
  %23 = load i32, i32* %3, align 4, !dbg !114
  %24 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !115
  %25 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %24, i32 0, i32 3, !dbg !116
  store i32 %23, i32* %25, align 8, !dbg !117
  store i32 0, i32* @g_unregister_count, align 4, !dbg !118
  %26 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !119
  call void @sim_release(%struct.bpf_nf_link* noundef %26), !dbg !120
  %27 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !121
  call void @sim_release(%struct.bpf_nf_link* noundef %27), !dbg !122
  %28 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !123
  %29 = bitcast %struct.bpf_nf_link* %28 to i8*, !dbg !123
  call void @free(i8* noundef %29) #8, !dbg !124
  ret void, !dbg !125
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: argmemonly nofree nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly, i8* noalias nocapture readonly, i64, i1 immarg) #2

; Function Attrs: noinline nounwind optnone uwtable
define internal i8* @must_malloc(i64 noundef %0) #0 !dbg !126 {
  %2 = alloca i64, align 8
  %3 = alloca i8*, align 8
  store i64 %0, i64* %2, align 8
  call void @llvm.dbg.declare(metadata i64* %2, metadata !131, metadata !DIExpression()), !dbg !132
  call void @llvm.dbg.declare(metadata i8** %3, metadata !133, metadata !DIExpression()), !dbg !134
  %4 = load i64, i64* %2, align 8, !dbg !135
  %5 = call noalias i8* @malloc(i64 noundef %4) #8, !dbg !136
  store i8* %5, i8** %3, align 8, !dbg !134
  %6 = load i8*, i8** %3, align 8, !dbg !137
  %7 = icmp ne i8* %6, null, !dbg !138
  %8 = zext i1 %7 to i32, !dbg !138
  %9 = sext i32 %8 to i64, !dbg !137
  call void @klee_assume(i64 noundef %9), !dbg !139
  %10 = load i8*, i8** %3, align 8, !dbg !140
  ret i8* %10, !dbg !141
}

; Function Attrs: argmemonly nofree nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #3

declare void @klee_make_symbolic(i8* noundef, i64 noundef, i8* noundef) #4

declare void @klee_assume(i64 noundef) #4

; Function Attrs: noinline nounwind optnone uwtable
define internal void @sim_release(%struct.bpf_nf_link* noundef %0) #0 !dbg !142 {
  %2 = alloca %struct.bpf_nf_link*, align 8
  store %struct.bpf_nf_link* %0, %struct.bpf_nf_link** %2, align 8
  call void @llvm.dbg.declare(metadata %struct.bpf_nf_link** %2, metadata !145, metadata !DIExpression()), !dbg !146
  %3 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !147
  %4 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %3, i32 0, i32 3, !dbg !149
  %5 = load i32, i32* %4, align 8, !dbg !149
  %6 = icmp ne i32 %5, 0, !dbg !147
  br i1 %6, label %7, label %8, !dbg !150

7:                                                ; preds = %1
  br label %19, !dbg !151

8:                                                ; preds = %1
  %9 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !152
  %10 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %9, i32 0, i32 3, !dbg !154
  %11 = call i32 @sim_cmpxchg(i32* noundef %10, i32 noundef 0, i32 noundef 1), !dbg !155
  %12 = icmp eq i32 %11, 0, !dbg !156
  br i1 %12, label %13, label %19, !dbg !157

13:                                               ; preds = %8
  %14 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !158
  %15 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %14, i32 0, i32 2, !dbg !159
  %16 = load %struct.net*, %struct.net** %15, align 8, !dbg !159
  %17 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !160
  %18 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %17, i32 0, i32 1, !dbg !161
  call void @stub_unregister(%struct.net* noundef %16, %struct.nf_hook_ops* noundef %18), !dbg !162
  br label %19, !dbg !162

19:                                               ; preds = %7, %13, %8
  ret void, !dbg !163
}

; Function Attrs: nounwind
declare void @free(i8* noundef) #5

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test_wmi2_type_confusion() #0 !dbg !164 {
  %1 = alloca %struct.net, align 4
  %2 = alloca %struct.bpf_nf_link*, align 8
  %3 = alloca %struct.nf_defrag_hook*, align 8
  %4 = alloca i64, align 8
  call void @llvm.dbg.declare(metadata %struct.net* %1, metadata !165, metadata !DIExpression()), !dbg !166
  %5 = bitcast %struct.net* %1 to i8*, !dbg !166
  %6 = call i8* @memcpy(i8* %5, i8* bitcast (%struct.net* @__const.test_wmi2_type_confusion.net to i8*), i64 4), !dbg !166
  call void @llvm.dbg.declare(metadata %struct.bpf_nf_link** %2, metadata !167, metadata !DIExpression()), !dbg !168
  %7 = call i8* @must_malloc(i64 noundef 80), !dbg !169
  %8 = bitcast i8* %7 to %struct.bpf_nf_link*, !dbg !169
  store %struct.bpf_nf_link* %8, %struct.bpf_nf_link** %2, align 8, !dbg !168
  call void @llvm.dbg.declare(metadata %struct.nf_defrag_hook** %3, metadata !170, metadata !DIExpression()), !dbg !172
  %9 = call i8* @must_malloc(i64 noundef 24), !dbg !173
  %10 = bitcast i8* %9 to %struct.nf_defrag_hook*, !dbg !173
  store %struct.nf_defrag_hook* %10, %struct.nf_defrag_hook** %3, align 8, !dbg !172
  %11 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !174
  %12 = bitcast %struct.bpf_nf_link* %11 to i8*, !dbg !175
  %13 = call i8* @memset(i8* %12, i32 0, i64 80), !dbg !175
  %14 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !176
  %15 = bitcast %struct.nf_defrag_hook* %14 to i8*, !dbg !177
  %16 = call i8* @memset(i8* %15, i32 0, i64 24), !dbg !177
  %17 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !178
  %18 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %17, i32 0, i32 2, !dbg !179
  store %struct.net* %1, %struct.net** %18, align 8, !dbg !180
  %19 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !181
  %20 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !182
  %21 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %20, i32 0, i32 4, !dbg !183
  store %struct.nf_defrag_hook* %19, %struct.nf_defrag_hook** %21, align 8, !dbg !184
  call void @llvm.dbg.declare(metadata i64* %4, metadata !185, metadata !DIExpression()), !dbg !187
  %22 = bitcast i64* %4 to i8*, !dbg !188
  call void @klee_make_symbolic(i8* noundef %22, i64 noundef 8, i8* noundef getelementptr inbounds ([21 x i8], [21 x i8]* @.str.1, i64 0, i64 0)), !dbg !189
  %23 = load i64, i64* %4, align 8, !dbg !190
  %24 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !191
  %25 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %24, i32 0, i32 0, !dbg !192
  store i64 %23, i64* %25, align 8, !dbg !193
  %26 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !194
  call void @sim_call_enable(%struct.nf_defrag_hook* noundef %26, %struct.net* noundef %1), !dbg !195
  %27 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !196
  %28 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %27, i32 0, i32 0, !dbg !198
  store i64 ptrtoint (i32 (%struct.net*)* @concrete_enable to i64), i64* %28, align 8, !dbg !199
  %29 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !200
  call void @sim_call_enable(%struct.nf_defrag_hook* noundef %29, %struct.net* noundef %1), !dbg !201
  %30 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !202
  %31 = bitcast %struct.nf_defrag_hook* %30 to i8*, !dbg !202
  call void @free(i8* noundef %31) #8, !dbg !203
  %32 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !204
  %33 = bitcast %struct.bpf_nf_link* %32 to i8*, !dbg !204
  call void @free(i8* noundef %33) #8, !dbg !205
  ret void, !dbg !206
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @sim_call_enable(%struct.nf_defrag_hook* noundef %0, %struct.net* noundef %1) #0 !dbg !207 {
  %3 = alloca %struct.nf_defrag_hook*, align 8
  %4 = alloca %struct.net*, align 8
  %5 = alloca i32 (%struct.net*)*, align 8
  store %struct.nf_defrag_hook* %0, %struct.nf_defrag_hook** %3, align 8
  call void @llvm.dbg.declare(metadata %struct.nf_defrag_hook** %3, metadata !210, metadata !DIExpression()), !dbg !211
  store %struct.net* %1, %struct.net** %4, align 8
  call void @llvm.dbg.declare(metadata %struct.net** %4, metadata !212, metadata !DIExpression()), !dbg !213
  %6 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !214
  %7 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %6, i32 0, i32 0, !dbg !214
  %8 = load i64, i64* %7, align 8, !dbg !214
  %9 = trunc i64 %8 to i32, !dbg !214
  %10 = zext i32 %9 to i64, !dbg !214
  %11 = call i32 @klee_is_symbolic(i64 noundef %10), !dbg !214
  %12 = icmp ne i32 %11, 0, !dbg !214
  br i1 %12, label %15, label %13, !dbg !214

13:                                               ; preds = %2
  br i1 true, label %14, label %15, !dbg !214

14:                                               ; preds = %13
  br label %17, !dbg !214

15:                                               ; preds = %13, %2
  call void @__assert_fail(i8* noundef getelementptr inbounds ([119 x i8], [119 x i8]* @.str.12, i64 0, i64 0), i8* noundef getelementptr inbounds ([13 x i8], [13 x i8]* @.str.10, i64 0, i64 0), i32 noundef 176, i8* noundef getelementptr inbounds ([66 x i8], [66 x i8]* @__PRETTY_FUNCTION__.sim_call_enable, i64 0, i64 0)) #9, !dbg !214
  unreachable, !dbg !214

16:                                               ; No predecessors!
  br label %17, !dbg !214

17:                                               ; preds = %16, %14
  %18 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !215
  %19 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %18, i32 0, i32 0, !dbg !217
  %20 = load i64, i64* %19, align 8, !dbg !217
  %21 = icmp ne i64 %20, 0, !dbg !215
  br i1 %21, label %22, label %30, !dbg !218

22:                                               ; preds = %17
  call void @llvm.dbg.declare(metadata i32 (%struct.net*)** %5, metadata !219, metadata !DIExpression()), !dbg !221
  %23 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !222
  %24 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %23, i32 0, i32 0, !dbg !223
  %25 = load i64, i64* %24, align 8, !dbg !223
  %26 = inttoptr i64 %25 to i32 (%struct.net*)*, !dbg !224
  store i32 (%struct.net*)* %26, i32 (%struct.net*)** %5, align 8, !dbg !221
  %27 = load i32 (%struct.net*)*, i32 (%struct.net*)** %5, align 8, !dbg !225
  %28 = load %struct.net*, %struct.net** %4, align 8, !dbg !226
  %29 = call i32 %27(%struct.net* noundef %28), !dbg !225
  br label %30, !dbg !227

30:                                               ; preds = %22, %17
  ret void, !dbg !228
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @concrete_enable(%struct.net* noundef %0) #0 !dbg !229 {
  %2 = alloca %struct.net*, align 8
  store %struct.net* %0, %struct.net** %2, align 8
  call void @llvm.dbg.declare(metadata %struct.net** %2, metadata !230, metadata !DIExpression()), !dbg !231
  %3 = load %struct.net*, %struct.net** %2, align 8, !dbg !232
  ret i32 0, !dbg !233
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test_wmi3_arbitrary_free() #0 !dbg !234 {
  %1 = alloca %struct.net, align 4
  %2 = alloca %struct.bpf_nf_link*, align 8
  %3 = alloca %struct.nf_defrag_hook*, align 8
  %4 = alloca i64, align 8
  call void @llvm.dbg.declare(metadata %struct.net* %1, metadata !235, metadata !DIExpression()), !dbg !236
  %5 = bitcast %struct.net* %1 to i8*, !dbg !236
  %6 = call i8* @memcpy(i8* %5, i8* bitcast (%struct.net* @__const.test_wmi3_arbitrary_free.net to i8*), i64 4), !dbg !236
  call void @llvm.dbg.declare(metadata %struct.bpf_nf_link** %2, metadata !237, metadata !DIExpression()), !dbg !238
  %7 = call i8* @must_malloc(i64 noundef 80), !dbg !239
  %8 = bitcast i8* %7 to %struct.bpf_nf_link*, !dbg !239
  store %struct.bpf_nf_link* %8, %struct.bpf_nf_link** %2, align 8, !dbg !238
  call void @llvm.dbg.declare(metadata %struct.nf_defrag_hook** %3, metadata !240, metadata !DIExpression()), !dbg !241
  %9 = call i8* @must_malloc(i64 noundef 24), !dbg !242
  %10 = bitcast i8* %9 to %struct.nf_defrag_hook*, !dbg !242
  store %struct.nf_defrag_hook* %10, %struct.nf_defrag_hook** %3, align 8, !dbg !241
  %11 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !243
  %12 = bitcast %struct.bpf_nf_link* %11 to i8*, !dbg !244
  %13 = call i8* @memset(i8* %12, i32 0, i64 80), !dbg !244
  %14 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !245
  %15 = bitcast %struct.nf_defrag_hook* %14 to i8*, !dbg !246
  %16 = call i8* @memset(i8* %15, i32 0, i64 24), !dbg !246
  %17 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !247
  %18 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %17, i32 0, i32 2, !dbg !248
  store %struct.net* %1, %struct.net** %18, align 8, !dbg !249
  %19 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !250
  %20 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !251
  %21 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %20, i32 0, i32 4, !dbg !252
  store %struct.nf_defrag_hook* %19, %struct.nf_defrag_hook** %21, align 8, !dbg !253
  %22 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !254
  %23 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %22, i32 0, i32 1, !dbg !255
  store i64 0, i64* %23, align 8, !dbg !256
  call void @llvm.dbg.declare(metadata i64* %4, metadata !257, metadata !DIExpression()), !dbg !258
  %24 = bitcast i64* %4 to i8*, !dbg !259
  call void @klee_make_symbolic(i8* noundef %24, i64 noundef 8, i8* noundef getelementptr inbounds ([11 x i8], [11 x i8]* @.str.2, i64 0, i64 0)), !dbg !260
  %25 = load i64, i64* %4, align 8, !dbg !261
  %26 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !262
  %27 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %26, i32 0, i32 2, !dbg !263
  store i64 %25, i64* %27, align 8, !dbg !264
  %28 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !265
  call void @sim_disable_defrag(%struct.bpf_nf_link* noundef %28), !dbg !266
  %29 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !267
  %30 = bitcast %struct.nf_defrag_hook* %29 to i8*, !dbg !267
  call void @free(i8* noundef %30) #8, !dbg !268
  %31 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !269
  %32 = bitcast %struct.bpf_nf_link* %31 to i8*, !dbg !269
  call void @free(i8* noundef %32) #8, !dbg !270
  ret void, !dbg !271
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @sim_disable_defrag(%struct.bpf_nf_link* noundef %0) #0 !dbg !272 {
  %2 = alloca %struct.bpf_nf_link*, align 8
  %3 = alloca %struct.nf_defrag_hook*, align 8
  %4 = alloca void (%struct.net*)*, align 8
  store %struct.bpf_nf_link* %0, %struct.bpf_nf_link** %2, align 8
  call void @llvm.dbg.declare(metadata %struct.bpf_nf_link** %2, metadata !273, metadata !DIExpression()), !dbg !274
  call void @llvm.dbg.declare(metadata %struct.nf_defrag_hook** %3, metadata !275, metadata !DIExpression()), !dbg !276
  %5 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !277
  %6 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %5, i32 0, i32 4, !dbg !278
  %7 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %6, align 8, !dbg !278
  store %struct.nf_defrag_hook* %7, %struct.nf_defrag_hook** %3, align 8, !dbg !276
  %8 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !279
  %9 = icmp ne %struct.nf_defrag_hook* %8, null, !dbg !279
  br i1 %9, label %11, label %10, !dbg !281

10:                                               ; preds = %1
  br label %29, !dbg !282

11:                                               ; preds = %1
  %12 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !283
  %13 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %12, i32 0, i32 1, !dbg !285
  %14 = load i64, i64* %13, align 8, !dbg !285
  %15 = icmp ne i64 %14, 0, !dbg !283
  br i1 %15, label %16, label %25, !dbg !286

16:                                               ; preds = %11
  call void @llvm.dbg.declare(metadata void (%struct.net*)** %4, metadata !287, metadata !DIExpression()), !dbg !289
  %17 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !290
  %18 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %17, i32 0, i32 1, !dbg !291
  %19 = load i64, i64* %18, align 8, !dbg !291
  %20 = inttoptr i64 %19 to void (%struct.net*)*, !dbg !292
  store void (%struct.net*)* %20, void (%struct.net*)** %4, align 8, !dbg !289
  %21 = load void (%struct.net*)*, void (%struct.net*)** %4, align 8, !dbg !293
  %22 = load %struct.bpf_nf_link*, %struct.bpf_nf_link** %2, align 8, !dbg !294
  %23 = getelementptr inbounds %struct.bpf_nf_link, %struct.bpf_nf_link* %22, i32 0, i32 2, !dbg !295
  %24 = load %struct.net*, %struct.net** %23, align 8, !dbg !295
  call void %21(%struct.net* noundef %24), !dbg !293
  br label %25, !dbg !296

25:                                               ; preds = %16, %11
  %26 = load %struct.nf_defrag_hook*, %struct.nf_defrag_hook** %3, align 8, !dbg !297
  %27 = getelementptr inbounds %struct.nf_defrag_hook, %struct.nf_defrag_hook* %26, i32 0, i32 2, !dbg !298
  %28 = load i64, i64* %27, align 8, !dbg !298
  call void @stub_module_put(i64 noundef %28), !dbg !299
  br label %29, !dbg !300

29:                                               ; preds = %25, %10
  ret void, !dbg !300
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test_wmi4_write_what_where() #0 !dbg !301 {
  %1 = alloca %struct.nf_conn, align 8
  %2 = alloca i8, align 1
  %3 = alloca i8, align 1
  %4 = alloca i8, align 1
  %5 = alloca i32, align 4
  call void @llvm.dbg.declare(metadata %struct.nf_conn* %1, metadata !302, metadata !DIExpression()), !dbg !307
  %6 = bitcast %struct.nf_conn* %1 to i8*, !dbg !308
  %7 = call i8* @memset(i8* %6, i32 0, i64 16), !dbg !308
  call void @llvm.dbg.declare(metadata i8* %2, metadata !310, metadata !DIExpression()), !dbg !311
  call void @klee_make_symbolic(i8* noundef %2, i64 noundef 1, i8* noundef getelementptr inbounds ([14 x i8], [14 x i8]* @.str.3, i64 0, i64 0)), !dbg !312
  %8 = load i8, i8* %2, align 1, !dbg !313
  %9 = call i8* @sim_nf_ct_ext_add(%struct.nf_conn* noundef %1, i8 noundef zeroext %8), !dbg !314
  %10 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !315
  %11 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %10, align 8, !dbg !315
  %12 = icmp ne %struct.nf_ct_ext* %11, null, !dbg !317
  br i1 %12, label %13, label %18, !dbg !318

13:                                               ; preds = %0
  %14 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !319
  %15 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %14, align 8, !dbg !319
  %16 = bitcast %struct.nf_ct_ext* %15 to i8*, !dbg !321
  call void @free(i8* noundef %16) #8, !dbg !322
  %17 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !323
  store %struct.nf_ct_ext* null, %struct.nf_ct_ext** %17, align 8, !dbg !324
  br label %18, !dbg !325

18:                                               ; preds = %13, %0
  %19 = bitcast %struct.nf_conn* %1 to i8*, !dbg !326
  %20 = call i8* @memset(i8* %19, i32 0, i64 16), !dbg !326
  %21 = call i8* @must_malloc(i64 noundef 128), !dbg !328
  %22 = bitcast i8* %21 to %struct.nf_ct_ext*, !dbg !329
  %23 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !330
  store %struct.nf_ct_ext* %22, %struct.nf_ct_ext** %23, align 8, !dbg !331
  %24 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !332
  %25 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %24, align 8, !dbg !332
  %26 = bitcast %struct.nf_ct_ext* %25 to i8*, !dbg !333
  %27 = call i8* @memset(i8* %26, i32 0, i64 128), !dbg !333
  %28 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !334
  %29 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %28, align 8, !dbg !334
  %30 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %29, i32 0, i32 2, !dbg !335
  store i32 1, i32* %30, align 4, !dbg !336
  call void @llvm.dbg.declare(metadata i8* %3, metadata !337, metadata !DIExpression()), !dbg !338
  call void @klee_make_symbolic(i8* noundef %3, i64 noundef 1, i8* noundef getelementptr inbounds ([17 x i8], [17 x i8]* @.str.4, i64 0, i64 0)), !dbg !339
  %31 = load i8, i8* %3, align 1, !dbg !340
  %32 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !341
  %33 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %32, align 8, !dbg !341
  %34 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %33, i32 0, i32 1, !dbg !342
  store i8 %31, i8* %34, align 2, !dbg !343
  %35 = call i8* @sim_nf_ct_ext_add(%struct.nf_conn* noundef %1, i8 noundef zeroext 3), !dbg !344
  %36 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !345
  %37 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %36, align 8, !dbg !345
  %38 = icmp ne %struct.nf_ct_ext* %37, null, !dbg !347
  br i1 %38, label %39, label %44, !dbg !348

39:                                               ; preds = %18
  %40 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !349
  %41 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %40, align 8, !dbg !349
  %42 = bitcast %struct.nf_ct_ext* %41 to i8*, !dbg !351
  call void @free(i8* noundef %42) #8, !dbg !352
  %43 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !353
  store %struct.nf_ct_ext* null, %struct.nf_ct_ext** %43, align 8, !dbg !354
  br label %44, !dbg !355

44:                                               ; preds = %39, %18
  %45 = bitcast %struct.nf_conn* %1 to i8*, !dbg !356
  %46 = call i8* @memset(i8* %45, i32 0, i64 16), !dbg !356
  %47 = call i8* @must_malloc(i64 noundef 128), !dbg !358
  %48 = bitcast i8* %47 to %struct.nf_ct_ext*, !dbg !359
  %49 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !360
  store %struct.nf_ct_ext* %48, %struct.nf_ct_ext** %49, align 8, !dbg !361
  %50 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !362
  %51 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %50, align 8, !dbg !362
  %52 = bitcast %struct.nf_ct_ext* %51 to i8*, !dbg !363
  %53 = call i8* @memset(i8* %52, i32 0, i64 128), !dbg !363
  %54 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !364
  %55 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %54, align 8, !dbg !364
  %56 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %55, i32 0, i32 1, !dbg !365
  store i8 16, i8* %56, align 2, !dbg !366
  %57 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !367
  %58 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %57, align 8, !dbg !367
  %59 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %58, i32 0, i32 2, !dbg !368
  store i32 1, i32* %59, align 4, !dbg !369
  call void @llvm.dbg.declare(metadata i8* %4, metadata !370, metadata !DIExpression()), !dbg !371
  call void @klee_make_symbolic(i8* noundef %4, i64 noundef 1, i8* noundef getelementptr inbounds ([19 x i8], [19 x i8]* @.str.5, i64 0, i64 0)), !dbg !372
  %60 = load i8, i8* %4, align 1, !dbg !373
  %61 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !374
  %62 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %61, align 8, !dbg !374
  %63 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %62, i32 0, i32 0, !dbg !375
  %64 = getelementptr inbounds [10 x i8], [10 x i8]* %63, i64 0, i64 2, !dbg !376
  store i8 %60, i8* %64, align 2, !dbg !377
  %65 = call i8* @sim_nf_ct_ext_add(%struct.nf_conn* noundef %1, i8 noundef zeroext 2), !dbg !378
  %66 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !379
  %67 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %66, align 8, !dbg !379
  %68 = icmp ne %struct.nf_ct_ext* %67, null, !dbg !381
  br i1 %68, label %69, label %74, !dbg !382

69:                                               ; preds = %44
  %70 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !383
  %71 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %70, align 8, !dbg !383
  %72 = bitcast %struct.nf_ct_ext* %71 to i8*, !dbg !385
  call void @free(i8* noundef %72) #8, !dbg !386
  %73 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !387
  store %struct.nf_ct_ext* null, %struct.nf_ct_ext** %73, align 8, !dbg !388
  br label %74, !dbg !389

74:                                               ; preds = %69, %44
  %75 = bitcast %struct.nf_conn* %1 to i8*, !dbg !390
  %76 = call i8* @memset(i8* %75, i32 0, i64 16), !dbg !390
  %77 = call i8* @must_malloc(i64 noundef 128), !dbg !392
  %78 = bitcast i8* %77 to %struct.nf_ct_ext*, !dbg !393
  %79 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !394
  store %struct.nf_ct_ext* %78, %struct.nf_ct_ext** %79, align 8, !dbg !395
  %80 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !396
  %81 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %80, align 8, !dbg !396
  %82 = bitcast %struct.nf_ct_ext* %81 to i8*, !dbg !397
  %83 = call i8* @memset(i8* %82, i32 0, i64 128), !dbg !397
  %84 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !398
  %85 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %84, align 8, !dbg !398
  %86 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %85, i32 0, i32 1, !dbg !399
  store i8 16, i8* %86, align 2, !dbg !400
  call void @llvm.dbg.declare(metadata i32* %5, metadata !401, metadata !DIExpression()), !dbg !402
  %87 = bitcast i32* %5 to i8*, !dbg !403
  call void @klee_make_symbolic(i8* noundef %87, i64 noundef 4, i8* noundef getelementptr inbounds ([11 x i8], [11 x i8]* @.str.6, i64 0, i64 0)), !dbg !404
  %88 = load i32, i32* %5, align 4, !dbg !405
  %89 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !406
  %90 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %89, align 8, !dbg !406
  %91 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %90, i32 0, i32 2, !dbg !407
  store i32 %88, i32* %91, align 4, !dbg !408
  %92 = call i8* @sim_nf_ct_ext_add(%struct.nf_conn* noundef %1, i8 noundef zeroext 1), !dbg !409
  %93 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !410
  %94 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %93, align 8, !dbg !410
  %95 = icmp ne %struct.nf_ct_ext* %94, null, !dbg !412
  br i1 %95, label %96, label %101, !dbg !413

96:                                               ; preds = %74
  %97 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !414
  %98 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %97, align 8, !dbg !414
  %99 = bitcast %struct.nf_ct_ext* %98 to i8*, !dbg !416
  call void @free(i8* noundef %99) #8, !dbg !417
  %100 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %1, i32 0, i32 0, !dbg !418
  store %struct.nf_ct_ext* null, %struct.nf_ct_ext** %100, align 8, !dbg !419
  br label %101, !dbg !420

101:                                              ; preds = %96, %74
  ret void, !dbg !421
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i8* @sim_nf_ct_ext_add(%struct.nf_conn* noundef %0, i8 noundef zeroext %1) #0 !dbg !422 {
  %3 = alloca i8*, align 8
  %4 = alloca %struct.nf_conn*, align 8
  %5 = alloca i8, align 1
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  %8 = alloca i32, align 4
  %9 = alloca %struct.nf_ct_ext*, align 8
  %10 = alloca i32, align 4
  store %struct.nf_conn* %0, %struct.nf_conn** %4, align 8
  call void @llvm.dbg.declare(metadata %struct.nf_conn** %4, metadata !426, metadata !DIExpression()), !dbg !427
  store i8 %1, i8* %5, align 1
  call void @llvm.dbg.declare(metadata i8* %5, metadata !428, metadata !DIExpression()), !dbg !429
  call void @llvm.dbg.declare(metadata i32* %6, metadata !430, metadata !DIExpression()), !dbg !431
  call void @llvm.dbg.declare(metadata i32* %7, metadata !432, metadata !DIExpression()), !dbg !433
  call void @llvm.dbg.declare(metadata i32* %8, metadata !434, metadata !DIExpression()), !dbg !435
  call void @llvm.dbg.declare(metadata %struct.nf_ct_ext** %9, metadata !436, metadata !DIExpression()), !dbg !437
  %11 = load i8, i8* %5, align 1, !dbg !438
  %12 = zext i8 %11 to i32, !dbg !438
  %13 = zext i32 %12 to i64, !dbg !438
  %14 = call i32 @klee_is_symbolic(i64 noundef %13), !dbg !438
  %15 = icmp ne i32 %14, 0, !dbg !438
  br i1 %15, label %18, label %16, !dbg !438

16:                                               ; preds = %2
  br i1 true, label %17, label %18, !dbg !438

17:                                               ; preds = %16
  br label %20, !dbg !438

18:                                               ; preds = %16, %2
  call void @__assert_fail(i8* noundef getelementptr inbounds ([97 x i8], [97 x i8]* @.str.16, i64 0, i64 0), i8* noundef getelementptr inbounds ([13 x i8], [13 x i8]* @.str.10, i64 0, i64 0), i32 noundef 277, i8* noundef getelementptr inbounds ([46 x i8], [46 x i8]* @__PRETTY_FUNCTION__.sim_nf_ct_ext_add, i64 0, i64 0)) #9, !dbg !438
  unreachable, !dbg !438

19:                                               ; No predecessors!
  br label %20, !dbg !438

20:                                               ; preds = %19, %17
  %21 = load i8, i8* %5, align 1, !dbg !439
  %22 = zext i8 %21 to i32, !dbg !439
  %23 = icmp slt i32 %22, 10, !dbg !439
  br i1 %23, label %24, label %26, !dbg !439

24:                                               ; preds = %20
  br i1 true, label %25, label %26, !dbg !439

25:                                               ; preds = %24
  br label %28, !dbg !439

26:                                               ; preds = %24, %20
  call void @__assert_fail(i8* noundef getelementptr inbounds ([83 x i8], [83 x i8]* @.str.18, i64 0, i64 0), i8* noundef getelementptr inbounds ([13 x i8], [13 x i8]* @.str.10, i64 0, i64 0), i32 noundef 279, i8* noundef getelementptr inbounds ([46 x i8], [46 x i8]* @__PRETTY_FUNCTION__.sim_nf_ct_ext_add, i64 0, i64 0)) #9, !dbg !439
  unreachable, !dbg !439

27:                                               ; No predecessors!
  br label %28, !dbg !439

28:                                               ; preds = %27, %25
  %29 = load %struct.nf_conn*, %struct.nf_conn** %4, align 8, !dbg !440
  %30 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %29, i32 0, i32 0, !dbg !442
  %31 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %30, align 8, !dbg !442
  %32 = icmp ne %struct.nf_ct_ext* %31, null, !dbg !440
  br i1 %32, label %33, label %52, !dbg !443

33:                                               ; preds = %28
  %34 = load %struct.nf_conn*, %struct.nf_conn** %4, align 8, !dbg !444
  %35 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %34, i32 0, i32 0, !dbg !447
  %36 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %35, align 8, !dbg !447
  %37 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %36, i32 0, i32 0, !dbg !448
  %38 = load i8, i8* %5, align 1, !dbg !449
  %39 = zext i8 %38 to i64, !dbg !444
  %40 = getelementptr inbounds [10 x i8], [10 x i8]* %37, i64 0, i64 %39, !dbg !444
  %41 = load i8, i8* %40, align 1, !dbg !444
  %42 = zext i8 %41 to i32, !dbg !444
  %43 = icmp ne i32 %42, 0, !dbg !450
  br i1 %43, label %44, label %45, !dbg !451

44:                                               ; preds = %33
  store i8* null, i8** %3, align 8, !dbg !452
  br label %123, !dbg !452

45:                                               ; preds = %33
  %46 = load %struct.nf_conn*, %struct.nf_conn** %4, align 8, !dbg !453
  %47 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %46, i32 0, i32 0, !dbg !454
  %48 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %47, align 8, !dbg !454
  %49 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %48, i32 0, i32 1, !dbg !455
  %50 = load i8, i8* %49, align 2, !dbg !455
  %51 = zext i8 %50 to i32, !dbg !453
  store i32 %51, i32* %8, align 4, !dbg !456
  br label %53, !dbg !457

52:                                               ; preds = %28
  store i32 16, i32* %8, align 4, !dbg !458
  br label %53

53:                                               ; preds = %52, %45
  %54 = load i32, i32* %8, align 4, !dbg !460
  %55 = add i32 %54, 7, !dbg !461
  %56 = and i32 %55, -8, !dbg !462
  store i32 %56, i32* %6, align 4, !dbg !463
  %57 = load i32, i32* %6, align 4, !dbg !464
  %58 = load i8, i8* %5, align 1, !dbg !465
  %59 = zext i8 %58 to i64, !dbg !466
  %60 = getelementptr inbounds [10 x i8], [10 x i8]* @ext_type_len, i64 0, i64 %59, !dbg !466
  %61 = load i8, i8* %60, align 1, !dbg !466
  %62 = zext i8 %61 to i32, !dbg !466
  %63 = add i32 %57, %62, !dbg !467
  store i32 %63, i32* %7, align 4, !dbg !468
  %64 = load i32, i32* %6, align 4, !dbg !469
  %65 = zext i32 %64 to i64, !dbg !469
  %66 = call i32 @klee_is_symbolic(i64 noundef %65), !dbg !469
  %67 = icmp ne i32 %66, 0, !dbg !469
  br i1 %67, label %70, label %68, !dbg !469

68:                                               ; preds = %53
  br i1 true, label %69, label %70, !dbg !469

69:                                               ; preds = %68
  br label %72, !dbg !469

70:                                               ; preds = %68, %53
  call void @__assert_fail(i8* noundef getelementptr inbounds ([90 x i8], [90 x i8]* @.str.20, i64 0, i64 0), i8* noundef getelementptr inbounds ([13 x i8], [13 x i8]* @.str.10, i64 0, i64 0), i32 noundef 293, i8* noundef getelementptr inbounds ([46 x i8], [46 x i8]* @__PRETTY_FUNCTION__.sim_nf_ct_ext_add, i64 0, i64 0)) #9, !dbg !469
  unreachable, !dbg !469

71:                                               ; No predecessors!
  br label %72, !dbg !469

72:                                               ; preds = %71, %69
  call void @llvm.dbg.declare(metadata i32* %10, metadata !470, metadata !DIExpression()), !dbg !471
  %73 = load i32, i32* %7, align 4, !dbg !472
  %74 = icmp ugt i32 %73, 128, !dbg !473
  br i1 %74, label %75, label %77, !dbg !474

75:                                               ; preds = %72
  %76 = load i32, i32* %7, align 4, !dbg !475
  br label %78, !dbg !474

77:                                               ; preds = %72
  br label %78, !dbg !474

78:                                               ; preds = %77, %75
  %79 = phi i32 [ %76, %75 ], [ 128, %77 ], !dbg !474
  store i32 %79, i32* %10, align 4, !dbg !471
  %80 = load %struct.nf_conn*, %struct.nf_conn** %4, align 8, !dbg !476
  %81 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %80, i32 0, i32 0, !dbg !477
  %82 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %81, align 8, !dbg !477
  %83 = bitcast %struct.nf_ct_ext* %82 to i8*, !dbg !476
  %84 = load i32, i32* %10, align 4, !dbg !478
  %85 = zext i32 %84 to i64, !dbg !478
  %86 = call i8* @realloc(i8* noundef %83, i64 noundef %85) #8, !dbg !479
  %87 = bitcast i8* %86 to %struct.nf_ct_ext*, !dbg !480
  store %struct.nf_ct_ext* %87, %struct.nf_ct_ext** %9, align 8, !dbg !481
  %88 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %9, align 8, !dbg !482
  %89 = icmp ne %struct.nf_ct_ext* %88, null, !dbg !483
  %90 = zext i1 %89 to i32, !dbg !483
  %91 = sext i32 %90 to i64, !dbg !482
  call void @klee_assume(i64 noundef %91), !dbg !484
  %92 = load %struct.nf_conn*, %struct.nf_conn** %4, align 8, !dbg !485
  %93 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %92, i32 0, i32 0, !dbg !487
  %94 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %93, align 8, !dbg !487
  %95 = icmp ne %struct.nf_ct_ext* %94, null, !dbg !485
  br i1 %95, label %103, label %96, !dbg !488

96:                                               ; preds = %78
  %97 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %9, align 8, !dbg !489
  %98 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %97, i32 0, i32 0, !dbg !491
  %99 = getelementptr inbounds [10 x i8], [10 x i8]* %98, i64 0, i64 0, !dbg !492
  %100 = call i8* @memset(i8* %99, i32 0, i64 10), !dbg !492
  %101 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %9, align 8, !dbg !493
  %102 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %101, i32 0, i32 2, !dbg !494
  store i32 1, i32* %102, align 4, !dbg !495
  br label %103, !dbg !496

103:                                              ; preds = %96, %78
  %104 = load i32, i32* %6, align 4, !dbg !497
  %105 = trunc i32 %104 to i8, !dbg !498
  %106 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %9, align 8, !dbg !499
  %107 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %106, i32 0, i32 0, !dbg !500
  %108 = load i8, i8* %5, align 1, !dbg !501
  %109 = zext i8 %108 to i64, !dbg !499
  %110 = getelementptr inbounds [10 x i8], [10 x i8]* %107, i64 0, i64 %109, !dbg !499
  store i8 %105, i8* %110, align 1, !dbg !502
  %111 = load i32, i32* %7, align 4, !dbg !503
  %112 = trunc i32 %111 to i8, !dbg !504
  %113 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %9, align 8, !dbg !505
  %114 = getelementptr inbounds %struct.nf_ct_ext, %struct.nf_ct_ext* %113, i32 0, i32 1, !dbg !506
  store i8 %112, i8* %114, align 2, !dbg !507
  %115 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %9, align 8, !dbg !508
  %116 = load %struct.nf_conn*, %struct.nf_conn** %4, align 8, !dbg !509
  %117 = getelementptr inbounds %struct.nf_conn, %struct.nf_conn* %116, i32 0, i32 0, !dbg !510
  store %struct.nf_ct_ext* %115, %struct.nf_ct_ext** %117, align 8, !dbg !511
  %118 = load %struct.nf_ct_ext*, %struct.nf_ct_ext** %9, align 8, !dbg !512
  %119 = bitcast %struct.nf_ct_ext* %118 to i8*, !dbg !513
  %120 = load i32, i32* %6, align 4, !dbg !514
  %121 = zext i32 %120 to i64, !dbg !515
  %122 = getelementptr i8, i8* %119, i64 %121, !dbg !515
  store i8* %122, i8** %3, align 8, !dbg !516
  br label %123, !dbg !516

123:                                              ; preds = %103, %44
  %124 = load i8*, i8** %3, align 8, !dbg !517
  ret i8* %124, !dbg !517
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @test_priority_bypass() #0 !dbg !518 {
  %1 = alloca %struct.sym_nf_attr, align 4
  call void @llvm.dbg.declare(metadata %struct.sym_nf_attr* %1, metadata !519, metadata !DIExpression()), !dbg !527
  %2 = bitcast %struct.sym_nf_attr* %1 to i8*, !dbg !528
  call void @klee_make_symbolic(i8* noundef %2, i64 noundef 16, i8* noundef getelementptr inbounds ([8 x i8], [8 x i8]* @.str.7, i64 0, i64 0)), !dbg !529
  %3 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %1, i32 0, i32 0, !dbg !530
  %4 = load i8, i8* %3, align 4, !dbg !530
  %5 = zext i8 %4 to i32, !dbg !531
  %6 = icmp eq i32 %5, 2, !dbg !532
  br i1 %6, label %12, label %7, !dbg !533

7:                                                ; preds = %0
  %8 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %1, i32 0, i32 0, !dbg !534
  %9 = load i8, i8* %8, align 4, !dbg !534
  %10 = zext i8 %9 to i32, !dbg !535
  %11 = icmp eq i32 %10, 10, !dbg !536
  br label %12, !dbg !533

12:                                               ; preds = %7, %0
  %13 = phi i1 [ true, %0 ], [ %11, %7 ]
  %14 = zext i1 %13 to i32, !dbg !533
  %15 = sext i32 %14 to i64, !dbg !531
  call void @klee_assume(i64 noundef %15), !dbg !537
  %16 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %1, i32 0, i32 1, !dbg !538
  %17 = load i8, i8* %16, align 1, !dbg !538
  %18 = zext i8 %17 to i32, !dbg !539
  %19 = icmp slt i32 %18, 5, !dbg !540
  %20 = zext i1 %19 to i32, !dbg !540
  %21 = sext i32 %20 to i64, !dbg !539
  call void @klee_assume(i64 noundef %21), !dbg !541
  %22 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %1, i32 0, i32 4, !dbg !542
  %23 = load i32, i32* %22, align 4, !dbg !542
  %24 = icmp eq i32 %23, 0, !dbg !543
  %25 = zext i1 %24 to i32, !dbg !543
  %26 = sext i32 %25 to i64, !dbg !544
  call void @klee_assume(i64 noundef %26), !dbg !545
  %27 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %1, i32 0, i32 3, !dbg !546
  %28 = load i32, i32* %27, align 4, !dbg !546
  %29 = icmp eq i32 %28, 0, !dbg !547
  br i1 %29, label %34, label %30, !dbg !548

30:                                               ; preds = %12
  %31 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %1, i32 0, i32 3, !dbg !549
  %32 = load i32, i32* %31, align 4, !dbg !549
  %33 = icmp eq i32 %32, 1, !dbg !550
  br label %34, !dbg !548

34:                                               ; preds = %30, %12
  %35 = phi i1 [ true, %12 ], [ %33, %30 ]
  %36 = zext i1 %35 to i32, !dbg !548
  %37 = sext i32 %36 to i64, !dbg !551
  call void @klee_assume(i64 noundef %37), !dbg !552
  %38 = call i32 @sim_check_pf_and_hooks(%struct.sym_nf_attr* noundef %1), !dbg !553
  ret void, !dbg !554
}

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @sim_check_pf_and_hooks(%struct.sym_nf_attr* noundef %0) #0 !dbg !555 {
  %2 = alloca i32, align 4
  %3 = alloca %struct.sym_nf_attr*, align 8
  %4 = alloca i32, align 4
  store %struct.sym_nf_attr* %0, %struct.sym_nf_attr** %3, align 8
  call void @llvm.dbg.declare(metadata %struct.sym_nf_attr** %3, metadata !560, metadata !DIExpression()), !dbg !561
  %5 = load %struct.sym_nf_attr*, %struct.sym_nf_attr** %3, align 8, !dbg !562
  %6 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %5, i32 0, i32 4, !dbg !564
  %7 = load i32, i32* %6, align 4, !dbg !564
  %8 = icmp ne i32 %7, 0, !dbg !562
  br i1 %8, label %9, label %10, !dbg !565

9:                                                ; preds = %1
  store i32 -22, i32* %2, align 4, !dbg !566
  br label %69, !dbg !566

10:                                               ; preds = %1
  %11 = load %struct.sym_nf_attr*, %struct.sym_nf_attr** %3, align 8, !dbg !567
  %12 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %11, i32 0, i32 0, !dbg !568
  %13 = load i8, i8* %12, align 4, !dbg !568
  %14 = zext i8 %13 to i32, !dbg !567
  switch i32 %14, label %23 [
    i32 2, label %15
    i32 10, label %15
  ], !dbg !569

15:                                               ; preds = %10, %10
  %16 = load %struct.sym_nf_attr*, %struct.sym_nf_attr** %3, align 8, !dbg !570
  %17 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %16, i32 0, i32 1, !dbg !573
  %18 = load i8, i8* %17, align 1, !dbg !573
  %19 = zext i8 %18 to i32, !dbg !570
  %20 = icmp sge i32 %19, 5, !dbg !574
  br i1 %20, label %21, label %22, !dbg !575

21:                                               ; preds = %15
  store i32 -71, i32* %2, align 4, !dbg !576
  br label %69, !dbg !576

22:                                               ; preds = %15
  br label %24, !dbg !577

23:                                               ; preds = %10
  store i32 -97, i32* %2, align 4, !dbg !578
  br label %69, !dbg !578

24:                                               ; preds = %22
  %25 = load %struct.sym_nf_attr*, %struct.sym_nf_attr** %3, align 8, !dbg !579
  %26 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %25, i32 0, i32 3, !dbg !581
  %27 = load i32, i32* %26, align 4, !dbg !581
  %28 = and i32 %27, -2, !dbg !582
  %29 = icmp ne i32 %28, 0, !dbg !582
  br i1 %29, label %30, label %31, !dbg !583

30:                                               ; preds = %24
  store i32 -95, i32* %2, align 4, !dbg !584
  br label %69, !dbg !584

31:                                               ; preds = %24
  call void @llvm.dbg.declare(metadata i32* %4, metadata !585, metadata !DIExpression()), !dbg !586
  %32 = load %struct.sym_nf_attr*, %struct.sym_nf_attr** %3, align 8, !dbg !587
  %33 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %32, i32 0, i32 2, !dbg !588
  %34 = load i32, i32* %33, align 4, !dbg !588
  store i32 %34, i32* %4, align 4, !dbg !586
  %35 = load i32, i32* %4, align 4, !dbg !589
  %36 = sext i32 %35 to i64, !dbg !589
  %37 = icmp ne i64 %36, -2147483648, !dbg !589
  br i1 %37, label %38, label %40, !dbg !589

38:                                               ; preds = %31
  br i1 true, label %39, label %40, !dbg !589

39:                                               ; preds = %38
  br label %42, !dbg !589

40:                                               ; preds = %38, %31
  call void @__assert_fail(i8* noundef getelementptr inbounds ([95 x i8], [95 x i8]* @.str.22, i64 0, i64 0), i8* noundef getelementptr inbounds ([13 x i8], [13 x i8]* @.str.10, i64 0, i64 0), i32 noundef 428, i8* noundef getelementptr inbounds ([55 x i8], [55 x i8]* @__PRETTY_FUNCTION__.sim_check_pf_and_hooks, i64 0, i64 0)) #9, !dbg !589
  unreachable, !dbg !589

41:                                               ; No predecessors!
  br label %42, !dbg !589

42:                                               ; preds = %41, %39
  %43 = load i32, i32* %4, align 4, !dbg !590
  %44 = icmp ne i32 %43, 2147483647, !dbg !590
  br i1 %44, label %45, label %47, !dbg !590

45:                                               ; preds = %42
  br i1 true, label %46, label %47, !dbg !590

46:                                               ; preds = %45
  br label %49, !dbg !590

47:                                               ; preds = %45, %42
  call void @__assert_fail(i8* noundef getelementptr inbounds ([99 x i8], [99 x i8]* @.str.24, i64 0, i64 0), i8* noundef getelementptr inbounds ([13 x i8], [13 x i8]* @.str.10, i64 0, i64 0), i32 noundef 430, i8* noundef getelementptr inbounds ([55 x i8], [55 x i8]* @__PRETTY_FUNCTION__.sim_check_pf_and_hooks, i64 0, i64 0)) #9, !dbg !590
  unreachable, !dbg !590

48:                                               ; No predecessors!
  br label %49, !dbg !590

49:                                               ; preds = %48, %46
  %50 = load i32, i32* %4, align 4, !dbg !591
  %51 = sext i32 %50 to i64, !dbg !591
  %52 = icmp eq i64 %51, -2147483648, !dbg !593
  br i1 %52, label %53, label %54, !dbg !594

53:                                               ; preds = %49
  store i32 -34, i32* %2, align 4, !dbg !595
  br label %69, !dbg !595

54:                                               ; preds = %49
  %55 = load i32, i32* %4, align 4, !dbg !596
  %56 = icmp eq i32 %55, 2147483647, !dbg !598
  br i1 %56, label %57, label %58, !dbg !599

57:                                               ; preds = %54
  store i32 -34, i32* %2, align 4, !dbg !600
  br label %69, !dbg !600

58:                                               ; preds = %54
  %59 = load %struct.sym_nf_attr*, %struct.sym_nf_attr** %3, align 8, !dbg !601
  %60 = getelementptr inbounds %struct.sym_nf_attr, %struct.sym_nf_attr* %59, i32 0, i32 3, !dbg !603
  %61 = load i32, i32* %60, align 4, !dbg !603
  %62 = and i32 %61, 1, !dbg !604
  %63 = icmp ne i32 %62, 0, !dbg !604
  br i1 %63, label %64, label %68, !dbg !605

64:                                               ; preds = %58
  %65 = load i32, i32* %4, align 4, !dbg !606
  %66 = icmp sle i32 %65, -400, !dbg !607
  br i1 %66, label %67, label %68, !dbg !608

67:                                               ; preds = %64
  store i32 -34, i32* %2, align 4, !dbg !609
  br label %69, !dbg !609

68:                                               ; preds = %64, %58
  store i32 0, i32* %2, align 4, !dbg !610
  br label %69, !dbg !610

69:                                               ; preds = %68, %67, %57, %53, %30, %23, %21, %9
  %70 = load i32, i32* %2, align 4, !dbg !611
  ret i32 %70, !dbg !611
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 !dbg !612 {
  %1 = alloca i32, align 4
  store i32 0, i32* %1, align 4
  call void @test_wmi1_stale_reference(), !dbg !615
  call void @test_wmi2_type_confusion(), !dbg !616
  call void @test_wmi3_arbitrary_free(), !dbg !617
  call void @test_wmi4_write_what_where(), !dbg !618
  call void @test_priority_bypass(), !dbg !619
  ret i32 0, !dbg !620
}

; Function Attrs: nounwind
declare noalias i8* @malloc(i64 noundef) #5

; Function Attrs: noinline nounwind optnone uwtable
define internal i32 @sim_cmpxchg(i32* noundef %0, i32 noundef %1, i32 noundef %2) #0 !dbg !621 {
  %4 = alloca i32*, align 8
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  store i32* %0, i32** %4, align 8
  call void @llvm.dbg.declare(metadata i32** %4, metadata !625, metadata !DIExpression()), !dbg !626
  store i32 %1, i32* %5, align 4
  call void @llvm.dbg.declare(metadata i32* %5, metadata !627, metadata !DIExpression()), !dbg !628
  store i32 %2, i32* %6, align 4
  call void @llvm.dbg.declare(metadata i32* %6, metadata !629, metadata !DIExpression()), !dbg !630
  call void @llvm.dbg.declare(metadata i32* %7, metadata !631, metadata !DIExpression()), !dbg !632
  %8 = load i32*, i32** %4, align 8, !dbg !633
  %9 = load i32, i32* %8, align 4, !dbg !634
  store i32 %9, i32* %7, align 4, !dbg !632
  %10 = load i32, i32* %7, align 4, !dbg !635
  %11 = load i32, i32* %5, align 4, !dbg !637
  %12 = icmp eq i32 %10, %11, !dbg !638
  br i1 %12, label %13, label %16, !dbg !639

13:                                               ; preds = %3
  %14 = load i32, i32* %6, align 4, !dbg !640
  %15 = load i32*, i32** %4, align 8, !dbg !641
  store i32 %14, i32* %15, align 4, !dbg !642
  br label %16, !dbg !643

16:                                               ; preds = %13, %3
  %17 = load i32, i32* %7, align 4, !dbg !644
  ret i32 %17, !dbg !645
}

; Function Attrs: noinline nounwind optnone uwtable
define internal void @stub_unregister(%struct.net* noundef %0, %struct.nf_hook_ops* noundef %1) #0 !dbg !646 {
  %3 = alloca %struct.net*, align 8
  %4 = alloca %struct.nf_hook_ops*, align 8
  store %struct.net* %0, %struct.net** %3, align 8
  call void @llvm.dbg.declare(metadata %struct.net** %3, metadata !650, metadata !DIExpression()), !dbg !651
  store %struct.nf_hook_ops* %1, %struct.nf_hook_ops** %4, align 8
  call void @llvm.dbg.declare(metadata %struct.nf_hook_ops** %4, metadata !652, metadata !DIExpression()), !dbg !653
  %5 = load %struct.net*, %struct.net** %3, align 8, !dbg !654
  %6 = load %struct.nf_hook_ops*, %struct.nf_hook_ops** %4, align 8, !dbg !655
  %7 = load i32, i32* @g_unregister_count, align 4, !dbg !656
  %8 = add nsw i32 %7, 1, !dbg !656
  store i32 %8, i32* @g_unregister_count, align 4, !dbg !656
  %9 = load i32, i32* @g_unregister_count, align 4, !dbg !657
  %10 = icmp sle i32 %9, 1, !dbg !657
  br i1 %10, label %11, label %13, !dbg !657

11:                                               ; preds = %2
  br i1 true, label %12, label %13, !dbg !657

12:                                               ; preds = %11
  br label %15, !dbg !657

13:                                               ; preds = %11, %2
  call void @__assert_fail(i8* noundef getelementptr inbounds ([79 x i8], [79 x i8]* @.str.9, i64 0, i64 0), i8* noundef getelementptr inbounds ([13 x i8], [13 x i8]* @.str.10, i64 0, i64 0), i32 noundef 128, i8* noundef getelementptr inbounds ([57 x i8], [57 x i8]* @__PRETTY_FUNCTION__.stub_unregister, i64 0, i64 0)) #9, !dbg !657
  unreachable, !dbg !657

14:                                               ; No predecessors!
  br label %15, !dbg !657

15:                                               ; preds = %14, %12
  ret void, !dbg !658
}

; Function Attrs: noreturn nounwind
declare void @__assert_fail(i8* noundef, i8* noundef, i32 noundef, i8* noundef) #6

declare i32 @klee_is_symbolic(i64 noundef) #4

; Function Attrs: noinline nounwind optnone uwtable
define internal void @stub_module_put(i64 noundef %0) #0 !dbg !659 {
  %2 = alloca i64, align 8
  store i64 %0, i64* %2, align 8
  call void @llvm.dbg.declare(metadata i64* %2, metadata !662, metadata !DIExpression()), !dbg !663
  %3 = load i64, i64* %2, align 8, !dbg !664
  %4 = trunc i64 %3 to i32, !dbg !664
  %5 = zext i32 %4 to i64, !dbg !664
  %6 = call i32 @klee_is_symbolic(i64 noundef %5), !dbg !664
  %7 = icmp ne i32 %6, 0, !dbg !664
  br i1 %7, label %10, label %8, !dbg !664

8:                                                ; preds = %1
  br i1 true, label %9, label %10, !dbg !664

9:                                                ; preds = %8
  br label %12, !dbg !664

10:                                               ; preds = %8, %1
  call void @__assert_fail(i8* noundef getelementptr inbounds ([109 x i8], [109 x i8]* @.str.14, i64 0, i64 0), i8* noundef getelementptr inbounds ([13 x i8], [13 x i8]* @.str.10, i64 0, i64 0), i32 noundef 222, i8* noundef getelementptr inbounds ([32 x i8], [32 x i8]* @__PRETTY_FUNCTION__.stub_module_put, i64 0, i64 0)) #9, !dbg !664
  unreachable, !dbg !664

11:                                               ; No predecessors!
  br label %12, !dbg !664

12:                                               ; preds = %11, %9
  %13 = load i64, i64* %2, align 8, !dbg !665
  ret void, !dbg !666
}

; Function Attrs: nounwind
declare i8* @realloc(i8* noundef, i64 noundef) #5

; Function Attrs: noinline nounwind uwtable
define dso_local i8* @memcpy(i8* noundef %0, i8* noundef %1, i64 noundef %2) #7 !dbg !667 {
  %4 = alloca i8*, align 8
  %5 = alloca i8*, align 8
  %6 = alloca i64, align 8
  %7 = alloca i8*, align 8
  %8 = alloca i8*, align 8
  store i8* %0, i8** %4, align 8
  call void @llvm.dbg.declare(metadata i8** %4, metadata !673, metadata !DIExpression()), !dbg !674
  store i8* %1, i8** %5, align 8
  call void @llvm.dbg.declare(metadata i8** %5, metadata !675, metadata !DIExpression()), !dbg !676
  store i64 %2, i64* %6, align 8
  call void @llvm.dbg.declare(metadata i64* %6, metadata !677, metadata !DIExpression()), !dbg !678
  call void @llvm.dbg.declare(metadata i8** %7, metadata !679, metadata !DIExpression()), !dbg !682
  %9 = load i8*, i8** %4, align 8, !dbg !683
  store i8* %9, i8** %7, align 8, !dbg !682
  call void @llvm.dbg.declare(metadata i8** %8, metadata !684, metadata !DIExpression()), !dbg !687
  %10 = load i8*, i8** %5, align 8, !dbg !688
  store i8* %10, i8** %8, align 8, !dbg !687
  br label %11, !dbg !689

11:                                               ; preds = %15, %3
  %12 = load i64, i64* %6, align 8, !dbg !690
  %13 = add i64 %12, -1, !dbg !690
  store i64 %13, i64* %6, align 8, !dbg !690
  %14 = icmp ugt i64 %12, 0, !dbg !691
  br i1 %14, label %15, label %21, !dbg !689

15:                                               ; preds = %11
  %16 = load i8*, i8** %8, align 8, !dbg !692
  %17 = getelementptr inbounds i8, i8* %16, i32 1, !dbg !692
  store i8* %17, i8** %8, align 8, !dbg !692
  %18 = load i8, i8* %16, align 1, !dbg !693
  %19 = load i8*, i8** %7, align 8, !dbg !694
  %20 = getelementptr inbounds i8, i8* %19, i32 1, !dbg !694
  store i8* %20, i8** %7, align 8, !dbg !694
  store i8 %18, i8* %19, align 1, !dbg !695
  br label %11, !dbg !689, !llvm.loop !696

21:                                               ; preds = %11
  %22 = load i8*, i8** %4, align 8, !dbg !698
  ret i8* %22, !dbg !699
}

; Function Attrs: noinline nounwind uwtable
define dso_local i8* @memset(i8* noundef %0, i32 noundef %1, i64 noundef %2) #7 !dbg !700 {
  %4 = alloca i8*, align 8
  %5 = alloca i32, align 4
  %6 = alloca i64, align 8
  %7 = alloca i8*, align 8
  store i8* %0, i8** %4, align 8
  call void @llvm.dbg.declare(metadata i8** %4, metadata !704, metadata !DIExpression()), !dbg !705
  store i32 %1, i32* %5, align 4
  call void @llvm.dbg.declare(metadata i32* %5, metadata !706, metadata !DIExpression()), !dbg !707
  store i64 %2, i64* %6, align 8
  call void @llvm.dbg.declare(metadata i64* %6, metadata !708, metadata !DIExpression()), !dbg !709
  call void @llvm.dbg.declare(metadata i8** %7, metadata !710, metadata !DIExpression()), !dbg !711
  %8 = load i8*, i8** %4, align 8, !dbg !712
  store i8* %8, i8** %7, align 8, !dbg !711
  br label %9, !dbg !713

9:                                                ; preds = %13, %3
  %10 = load i64, i64* %6, align 8, !dbg !714
  %11 = add i64 %10, -1, !dbg !714
  store i64 %11, i64* %6, align 8, !dbg !714
  %12 = icmp ugt i64 %10, 0, !dbg !715
  br i1 %12, label %13, label %18, !dbg !713

13:                                               ; preds = %9
  %14 = load i32, i32* %5, align 4, !dbg !716
  %15 = trunc i32 %14 to i8, !dbg !716
  %16 = load i8*, i8** %7, align 8, !dbg !717
  %17 = getelementptr inbounds i8, i8* %16, i32 1, !dbg !717
  store i8* %17, i8** %7, align 8, !dbg !717
  store i8 %15, i8* %16, align 1, !dbg !718
  br label %9, !dbg !713, !llvm.loop !719

18:                                               ; preds = %9
  %19 = load i8*, i8** %4, align 8, !dbg !720
  ret i8* %19, !dbg !721
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { argmemonly nofree nounwind willreturn }
attributes #3 = { argmemonly nofree nounwind willreturn writeonly }
attributes #4 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #5 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #6 = { noreturn nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #7 = { noinline nounwind uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #8 = { nounwind }
attributes #9 = { noreturn nounwind }

!llvm.dbg.cu = !{!2, !44, !46}
!llvm.module.flags = !{!48, !49, !50, !51, !52, !53, !54}
!llvm.ident = !{!55, !55, !55}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "g_unregister_count", scope: !2, file: !3, line: 122, type: !31, isLocal: true, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.6", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !4, globals: !39, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "nf_harness.c", directory: "/root/demo3_linux-main/demo3_linux-main/net/netfilter", checksumkind: CSK_MD5, checksum: "e7e3f2203948bd1d81b60f872244024f")
!4 = !{!5, !8, !13, !27, !26, !28, !36}
!5 = !DIDerivedType(tag: DW_TAG_typedef, name: "uintptr_t", file: !6, line: 79, baseType: !7)
!6 = !DIFile(filename: "/usr/include/stdint.h", directory: "", checksumkind: CSK_MD5, checksum: "bfb03fa9c46a839e35c32b929fbdbb8e")
!7 = !DIBasicType(name: "unsigned long", size: 64, encoding: DW_ATE_unsigned)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "nf_ct_ext", file: !3, line: 89, size: 128, elements: !10)
!10 = !{!11, !21, !22}
!11 = !DIDerivedType(tag: DW_TAG_member, name: "offset", scope: !9, file: !3, line: 90, baseType: !12, size: 80)
!12 = !DICompositeType(tag: DW_TAG_array_type, baseType: !13, size: 80, elements: !19)
!13 = !DIDerivedType(tag: DW_TAG_typedef, name: "u8", file: !3, line: 44, baseType: !14)
!14 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint8_t", file: !15, line: 24, baseType: !16)
!15 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/stdint-uintn.h", directory: "", checksumkind: CSK_MD5, checksum: "256fcabbefa27ca8cf5e6d37525e6e16")
!16 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint8_t", file: !17, line: 38, baseType: !18)
!17 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types.h", directory: "", checksumkind: CSK_MD5, checksum: "e1865d9fe29fe1b5ced550b7ba458f9e")
!18 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!19 = !{!20}
!20 = !DISubrange(count: 10)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "len", scope: !9, file: !3, line: 91, baseType: !13, size: 8, offset: 80)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "gen_id", scope: !9, file: !3, line: 92, baseType: !23, size: 32, offset: 96)
!23 = !DIDerivedType(tag: DW_TAG_typedef, name: "u32", file: !3, line: 46, baseType: !24)
!24 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint32_t", file: !15, line: 26, baseType: !25)
!25 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint32_t", file: !17, line: 42, baseType: !26)
!26 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!27 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!28 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !29, size: 64)
!29 = !DISubroutineType(types: !30)
!30 = !{!31, !32}
!31 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "net", file: !3, line: 48, size: 32, elements: !34)
!34 = !{!35}
!35 = !DIDerivedType(tag: DW_TAG_member, name: "ns_id", scope: !33, file: !3, line: 48, baseType: !23, size: 32)
!36 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !37, size: 64)
!37 = !DISubroutineType(types: !38)
!38 = !{null, !32}
!39 = !{!0, !40}
!40 = !DIGlobalVariableExpression(var: !41, expr: !DIExpression())
!41 = distinct !DIGlobalVariable(name: "ext_type_len", scope: !2, file: !3, line: 268, type: !42, isLocal: true, isDefinition: true)
!42 = !DICompositeType(tag: DW_TAG_array_type, baseType: !43, size: 80, elements: !19)
!43 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !13)
!44 = distinct !DICompileUnit(language: DW_LANG_C99, file: !45, producer: "Ubuntu clang version 14.0.6", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!45 = !DIFile(filename: "/root/klee/runtime/Freestanding/memcpy.c", directory: "/root/klee/build/runtime/Freestanding", checksumkind: CSK_MD5, checksum: "c636d77d986b2156da8c1ff12af1c5cd")
!46 = distinct !DICompileUnit(language: DW_LANG_C99, file: !47, producer: "Ubuntu clang version 14.0.6", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, splitDebugInlining: false, nameTableKind: None)
!47 = !DIFile(filename: "/root/klee/runtime/Freestanding/memset.c", directory: "/root/klee/build/runtime/Freestanding", checksumkind: CSK_MD5, checksum: "f66ef9ef9131ab198e93a41b1a9ae1fc")
!48 = !{i32 7, !"Dwarf Version", i32 5}
!49 = !{i32 2, !"Debug Info Version", i32 3}
!50 = !{i32 1, !"wchar_size", i32 4}
!51 = !{i32 7, !"PIC Level", i32 2}
!52 = !{i32 7, !"PIE Level", i32 2}
!53 = !{i32 7, !"uwtable", i32 1}
!54 = !{i32 7, !"frame-pointer", i32 2}
!55 = !{!"Ubuntu clang version 14.0.6"}
!56 = distinct !DISubprogram(name: "test_wmi1_stale_reference", scope: !3, file: !3, line: 143, type: !57, scopeLine: 143, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !59)
!57 = !DISubroutineType(types: !58)
!58 = !{null}
!59 = !{}
!60 = !DILocalVariable(name: "net", scope: !56, file: !3, line: 144, type: !33)
!61 = !DILocation(line: 144, column: 24, scope: !56)
!62 = !DILocalVariable(name: "link", scope: !56, file: !3, line: 145, type: !63)
!63 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !64, size: 64)
!64 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_nf_link", file: !3, line: 77, size: 640, elements: !65)
!65 = !{!66, !78, !87, !88, !89}
!66 = !DIDerivedType(tag: DW_TAG_member, name: "link", scope: !64, file: !3, line: 78, baseType: !67, size: 192)
!67 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_link", file: !3, line: 65, size: 192, elements: !68)
!68 = !{!69, !70, !71}
!69 = !DIDerivedType(tag: DW_TAG_member, name: "refcnt", scope: !67, file: !3, line: 66, baseType: !23, size: 32)
!70 = !DIDerivedType(tag: DW_TAG_member, name: "ops", scope: !67, file: !3, line: 67, baseType: !5, size: 64, offset: 64)
!71 = !DIDerivedType(tag: DW_TAG_member, name: "prog", scope: !67, file: !3, line: 68, baseType: !72, size: 64, offset: 128)
!72 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !73, size: 64)
!73 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_prog", file: !3, line: 59, size: 128, elements: !74)
!74 = !{!75, !76, !77}
!75 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !73, file: !3, line: 60, baseType: !23, size: 32)
!76 = !DIDerivedType(tag: DW_TAG_member, name: "jited", scope: !73, file: !3, line: 61, baseType: !23, size: 32, offset: 32)
!77 = !DIDerivedType(tag: DW_TAG_member, name: "run_fn", scope: !73, file: !3, line: 62, baseType: !5, size: 64, offset: 64)
!78 = !DIDerivedType(tag: DW_TAG_member, name: "hook_ops", scope: !64, file: !3, line: 79, baseType: !79, size: 256, offset: 192)
!79 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "nf_hook_ops", file: !3, line: 50, size: 256, elements: !80)
!80 = !{!81, !82, !83, !84, !85, !86}
!81 = !DIDerivedType(tag: DW_TAG_member, name: "hook", scope: !79, file: !3, line: 51, baseType: !5, size: 64)
!82 = !DIDerivedType(tag: DW_TAG_member, name: "priv", scope: !79, file: !3, line: 52, baseType: !5, size: 64, offset: 64)
!83 = !DIDerivedType(tag: DW_TAG_member, name: "pf", scope: !79, file: !3, line: 53, baseType: !13, size: 8, offset: 128)
!84 = !DIDerivedType(tag: DW_TAG_member, name: "hooknum", scope: !79, file: !3, line: 54, baseType: !13, size: 8, offset: 136)
!85 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !79, file: !3, line: 55, baseType: !31, size: 32, offset: 160)
!86 = !DIDerivedType(tag: DW_TAG_member, name: "hook_ops_type", scope: !79, file: !3, line: 56, baseType: !13, size: 8, offset: 192)
!87 = !DIDerivedType(tag: DW_TAG_member, name: "net", scope: !64, file: !3, line: 80, baseType: !32, size: 64, offset: 448)
!88 = !DIDerivedType(tag: DW_TAG_member, name: "dead", scope: !64, file: !3, line: 81, baseType: !23, size: 32, offset: 512)
!89 = !DIDerivedType(tag: DW_TAG_member, name: "defrag_hook", scope: !64, file: !3, line: 82, baseType: !90, size: 64, offset: 576)
!90 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !91, size: 64)
!91 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !92)
!92 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "nf_defrag_hook", file: !3, line: 71, size: 192, elements: !93)
!93 = !{!94, !95, !96}
!94 = !DIDerivedType(tag: DW_TAG_member, name: "enable_fn", scope: !92, file: !3, line: 72, baseType: !5, size: 64)
!95 = !DIDerivedType(tag: DW_TAG_member, name: "disable_fn", scope: !92, file: !3, line: 73, baseType: !5, size: 64, offset: 64)
!96 = !DIDerivedType(tag: DW_TAG_member, name: "owner", scope: !92, file: !3, line: 74, baseType: !5, size: 64, offset: 128)
!97 = !DILocation(line: 145, column: 25, scope: !56)
!98 = !DILocation(line: 145, column: 32, scope: !56)
!99 = !DILocation(line: 146, column: 12, scope: !56)
!100 = !DILocation(line: 146, column: 5, scope: !56)
!101 = !DILocation(line: 147, column: 5, scope: !56)
!102 = !DILocation(line: 147, column: 11, scope: !56)
!103 = !DILocation(line: 147, column: 15, scope: !56)
!104 = !DILocalVariable(name: "sym_dead", scope: !56, file: !3, line: 150, type: !23)
!105 = !DILocation(line: 150, column: 9, scope: !56)
!106 = !DILocation(line: 151, column: 24, scope: !56)
!107 = !DILocation(line: 151, column: 5, scope: !56)
!108 = !DILocation(line: 152, column: 17, scope: !56)
!109 = !DILocation(line: 152, column: 26, scope: !56)
!110 = !DILocation(line: 152, column: 31, scope: !56)
!111 = !DILocation(line: 152, column: 34, scope: !56)
!112 = !DILocation(line: 152, column: 43, scope: !56)
!113 = !DILocation(line: 152, column: 5, scope: !56)
!114 = !DILocation(line: 153, column: 18, scope: !56)
!115 = !DILocation(line: 153, column: 5, scope: !56)
!116 = !DILocation(line: 153, column: 11, scope: !56)
!117 = !DILocation(line: 153, column: 16, scope: !56)
!118 = !DILocation(line: 155, column: 24, scope: !56)
!119 = !DILocation(line: 156, column: 17, scope: !56)
!120 = !DILocation(line: 156, column: 5, scope: !56)
!121 = !DILocation(line: 157, column: 17, scope: !56)
!122 = !DILocation(line: 157, column: 5, scope: !56)
!123 = !DILocation(line: 159, column: 10, scope: !56)
!124 = !DILocation(line: 159, column: 5, scope: !56)
!125 = !DILocation(line: 160, column: 1, scope: !56)
!126 = distinct !DISubprogram(name: "must_malloc", scope: !3, file: !3, line: 104, type: !127, scopeLine: 104, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!127 = !DISubroutineType(types: !128)
!128 = !{!27, !129}
!129 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_t", file: !130, line: 46, baseType: !7)
!130 = !DIFile(filename: "/usr/lib/llvm-14/lib/clang/14.0.6/include/stddef.h", directory: "", checksumkind: CSK_MD5, checksum: "2499dd2361b915724b073282bea3a7bc")
!131 = !DILocalVariable(name: "sz", arg: 1, scope: !126, file: !3, line: 104, type: !129)
!132 = !DILocation(line: 104, column: 33, scope: !126)
!133 = !DILocalVariable(name: "p", scope: !126, file: !3, line: 105, type: !27)
!134 = !DILocation(line: 105, column: 11, scope: !126)
!135 = !DILocation(line: 105, column: 22, scope: !126)
!136 = !DILocation(line: 105, column: 15, scope: !126)
!137 = !DILocation(line: 106, column: 17, scope: !126)
!138 = !DILocation(line: 106, column: 19, scope: !126)
!139 = !DILocation(line: 106, column: 5, scope: !126)
!140 = !DILocation(line: 107, column: 12, scope: !126)
!141 = !DILocation(line: 107, column: 5, scope: !126)
!142 = distinct !DISubprogram(name: "sim_release", scope: !3, file: !3, line: 137, type: !143, scopeLine: 137, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!143 = !DISubroutineType(types: !144)
!144 = !{null, !63}
!145 = !DILocalVariable(name: "l", arg: 1, scope: !142, file: !3, line: 137, type: !63)
!146 = !DILocation(line: 137, column: 45, scope: !142)
!147 = !DILocation(line: 138, column: 9, scope: !148)
!148 = distinct !DILexicalBlock(scope: !142, file: !3, line: 138, column: 9)
!149 = !DILocation(line: 138, column: 12, scope: !148)
!150 = !DILocation(line: 138, column: 9, scope: !142)
!151 = !DILocation(line: 138, column: 18, scope: !148)
!152 = !DILocation(line: 139, column: 22, scope: !153)
!153 = distinct !DILexicalBlock(scope: !142, file: !3, line: 139, column: 9)
!154 = !DILocation(line: 139, column: 25, scope: !153)
!155 = !DILocation(line: 139, column: 9, scope: !153)
!156 = !DILocation(line: 139, column: 37, scope: !153)
!157 = !DILocation(line: 139, column: 9, scope: !142)
!158 = !DILocation(line: 140, column: 25, scope: !153)
!159 = !DILocation(line: 140, column: 28, scope: !153)
!160 = !DILocation(line: 140, column: 34, scope: !153)
!161 = !DILocation(line: 140, column: 37, scope: !153)
!162 = !DILocation(line: 140, column: 9, scope: !153)
!163 = !DILocation(line: 141, column: 1, scope: !142)
!164 = distinct !DISubprogram(name: "test_wmi2_type_confusion", scope: !3, file: !3, line: 183, type: !57, scopeLine: 183, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !59)
!165 = !DILocalVariable(name: "net", scope: !164, file: !3, line: 184, type: !33)
!166 = !DILocation(line: 184, column: 28, scope: !164)
!167 = !DILocalVariable(name: "link", scope: !164, file: !3, line: 185, type: !63)
!168 = !DILocation(line: 185, column: 28, scope: !164)
!169 = !DILocation(line: 185, column: 35, scope: !164)
!170 = !DILocalVariable(name: "hook", scope: !164, file: !3, line: 186, type: !171)
!171 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !92, size: 64)
!172 = !DILocation(line: 186, column: 28, scope: !164)
!173 = !DILocation(line: 186, column: 35, scope: !164)
!174 = !DILocation(line: 187, column: 12, scope: !164)
!175 = !DILocation(line: 187, column: 5, scope: !164)
!176 = !DILocation(line: 188, column: 12, scope: !164)
!177 = !DILocation(line: 188, column: 5, scope: !164)
!178 = !DILocation(line: 189, column: 5, scope: !164)
!179 = !DILocation(line: 189, column: 11, scope: !164)
!180 = !DILocation(line: 189, column: 23, scope: !164)
!181 = !DILocation(line: 190, column: 25, scope: !164)
!182 = !DILocation(line: 190, column: 5, scope: !164)
!183 = !DILocation(line: 190, column: 11, scope: !164)
!184 = !DILocation(line: 190, column: 23, scope: !164)
!185 = !DILocalVariable(name: "sym_fn", scope: !186, file: !3, line: 194, type: !5)
!186 = distinct !DILexicalBlock(scope: !164, file: !3, line: 193, column: 5)
!187 = !DILocation(line: 194, column: 19, scope: !186)
!188 = !DILocation(line: 195, column: 28, scope: !186)
!189 = !DILocation(line: 195, column: 9, scope: !186)
!190 = !DILocation(line: 196, column: 27, scope: !186)
!191 = !DILocation(line: 196, column: 9, scope: !186)
!192 = !DILocation(line: 196, column: 15, scope: !186)
!193 = !DILocation(line: 196, column: 25, scope: !186)
!194 = !DILocation(line: 197, column: 25, scope: !186)
!195 = !DILocation(line: 197, column: 9, scope: !186)
!196 = !DILocation(line: 202, column: 9, scope: !197)
!197 = distinct !DILexicalBlock(scope: !164, file: !3, line: 201, column: 5)
!198 = !DILocation(line: 202, column: 15, scope: !197)
!199 = !DILocation(line: 202, column: 25, scope: !197)
!200 = !DILocation(line: 203, column: 25, scope: !197)
!201 = !DILocation(line: 203, column: 9, scope: !197)
!202 = !DILocation(line: 206, column: 10, scope: !164)
!203 = !DILocation(line: 206, column: 5, scope: !164)
!204 = !DILocation(line: 207, column: 10, scope: !164)
!205 = !DILocation(line: 207, column: 5, scope: !164)
!206 = !DILocation(line: 208, column: 1, scope: !164)
!207 = distinct !DISubprogram(name: "sim_call_enable", scope: !3, file: !3, line: 174, type: !208, scopeLine: 174, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!208 = !DISubroutineType(types: !209)
!209 = !{null, !90, !32}
!210 = !DILocalVariable(name: "hook", arg: 1, scope: !207, file: !3, line: 174, type: !90)
!211 = !DILocation(line: 174, column: 58, scope: !207)
!212 = !DILocalVariable(name: "net", arg: 2, scope: !207, file: !3, line: 174, type: !32)
!213 = !DILocation(line: 174, column: 76, scope: !207)
!214 = !DILocation(line: 175, column: 5, scope: !207)
!215 = !DILocation(line: 177, column: 9, scope: !216)
!216 = distinct !DILexicalBlock(scope: !207, file: !3, line: 177, column: 9)
!217 = !DILocation(line: 177, column: 15, scope: !216)
!218 = !DILocation(line: 177, column: 9, scope: !207)
!219 = !DILocalVariable(name: "fn", scope: !220, file: !3, line: 178, type: !28)
!220 = distinct !DILexicalBlock(scope: !216, file: !3, line: 177, column: 26)
!221 = !DILocation(line: 178, column: 15, scope: !220)
!222 = !DILocation(line: 178, column: 58, scope: !220)
!223 = !DILocation(line: 178, column: 64, scope: !220)
!224 = !DILocation(line: 178, column: 35, scope: !220)
!225 = !DILocation(line: 179, column: 9, scope: !220)
!226 = !DILocation(line: 179, column: 12, scope: !220)
!227 = !DILocation(line: 180, column: 5, scope: !220)
!228 = !DILocation(line: 181, column: 1, scope: !207)
!229 = distinct !DISubprogram(name: "concrete_enable", scope: !3, file: !3, line: 172, type: !29, scopeLine: 172, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!230 = !DILocalVariable(name: "net", arg: 1, scope: !229, file: !3, line: 172, type: !32)
!231 = !DILocation(line: 172, column: 40, scope: !229)
!232 = !DILocation(line: 172, column: 53, scope: !229)
!233 = !DILocation(line: 172, column: 58, scope: !229)
!234 = distinct !DISubprogram(name: "test_wmi3_arbitrary_free", scope: !3, file: !3, line: 236, type: !57, scopeLine: 236, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !59)
!235 = !DILocalVariable(name: "net", scope: !234, file: !3, line: 237, type: !33)
!236 = !DILocation(line: 237, column: 28, scope: !234)
!237 = !DILocalVariable(name: "link", scope: !234, file: !3, line: 238, type: !63)
!238 = !DILocation(line: 238, column: 28, scope: !234)
!239 = !DILocation(line: 238, column: 35, scope: !234)
!240 = !DILocalVariable(name: "hook", scope: !234, file: !3, line: 239, type: !171)
!241 = !DILocation(line: 239, column: 28, scope: !234)
!242 = !DILocation(line: 239, column: 35, scope: !234)
!243 = !DILocation(line: 240, column: 12, scope: !234)
!244 = !DILocation(line: 240, column: 5, scope: !234)
!245 = !DILocation(line: 241, column: 12, scope: !234)
!246 = !DILocation(line: 241, column: 5, scope: !234)
!247 = !DILocation(line: 242, column: 5, scope: !234)
!248 = !DILocation(line: 242, column: 11, scope: !234)
!249 = !DILocation(line: 242, column: 23, scope: !234)
!250 = !DILocation(line: 243, column: 25, scope: !234)
!251 = !DILocation(line: 243, column: 5, scope: !234)
!252 = !DILocation(line: 243, column: 11, scope: !234)
!253 = !DILocation(line: 243, column: 23, scope: !234)
!254 = !DILocation(line: 244, column: 5, scope: !234)
!255 = !DILocation(line: 244, column: 11, scope: !234)
!256 = !DILocation(line: 244, column: 23, scope: !234)
!257 = !DILocalVariable(name: "sym_owner", scope: !234, file: !3, line: 246, type: !5)
!258 = !DILocation(line: 246, column: 15, scope: !234)
!259 = !DILocation(line: 247, column: 24, scope: !234)
!260 = !DILocation(line: 247, column: 5, scope: !234)
!261 = !DILocation(line: 248, column: 19, scope: !234)
!262 = !DILocation(line: 248, column: 5, scope: !234)
!263 = !DILocation(line: 248, column: 11, scope: !234)
!264 = !DILocation(line: 248, column: 17, scope: !234)
!265 = !DILocation(line: 250, column: 24, scope: !234)
!266 = !DILocation(line: 250, column: 5, scope: !234)
!267 = !DILocation(line: 252, column: 10, scope: !234)
!268 = !DILocation(line: 252, column: 5, scope: !234)
!269 = !DILocation(line: 253, column: 10, scope: !234)
!270 = !DILocation(line: 253, column: 5, scope: !234)
!271 = !DILocation(line: 254, column: 1, scope: !234)
!272 = distinct !DISubprogram(name: "sim_disable_defrag", scope: !3, file: !3, line: 226, type: !143, scopeLine: 226, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!273 = !DILocalVariable(name: "l", arg: 1, scope: !272, file: !3, line: 226, type: !63)
!274 = !DILocation(line: 226, column: 52, scope: !272)
!275 = !DILocalVariable(name: "h", scope: !272, file: !3, line: 227, type: !90)
!276 = !DILocation(line: 227, column: 34, scope: !272)
!277 = !DILocation(line: 227, column: 38, scope: !272)
!278 = !DILocation(line: 227, column: 41, scope: !272)
!279 = !DILocation(line: 228, column: 10, scope: !280)
!280 = distinct !DILexicalBlock(scope: !272, file: !3, line: 228, column: 9)
!281 = !DILocation(line: 228, column: 9, scope: !272)
!282 = !DILocation(line: 228, column: 13, scope: !280)
!283 = !DILocation(line: 229, column: 9, scope: !284)
!284 = distinct !DILexicalBlock(scope: !272, file: !3, line: 229, column: 9)
!285 = !DILocation(line: 229, column: 12, scope: !284)
!286 = !DILocation(line: 229, column: 9, scope: !272)
!287 = !DILocalVariable(name: "fn", scope: !288, file: !3, line: 230, type: !36)
!288 = distinct !DILexicalBlock(scope: !284, file: !3, line: 229, column: 24)
!289 = !DILocation(line: 230, column: 16, scope: !288)
!290 = !DILocation(line: 230, column: 60, scope: !288)
!291 = !DILocation(line: 230, column: 63, scope: !288)
!292 = !DILocation(line: 230, column: 36, scope: !288)
!293 = !DILocation(line: 231, column: 9, scope: !288)
!294 = !DILocation(line: 231, column: 12, scope: !288)
!295 = !DILocation(line: 231, column: 15, scope: !288)
!296 = !DILocation(line: 232, column: 5, scope: !288)
!297 = !DILocation(line: 233, column: 21, scope: !272)
!298 = !DILocation(line: 233, column: 24, scope: !272)
!299 = !DILocation(line: 233, column: 5, scope: !272)
!300 = !DILocation(line: 234, column: 1, scope: !272)
!301 = distinct !DISubprogram(name: "test_wmi4_write_what_where", scope: !3, file: !3, line: 310, type: !57, scopeLine: 310, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !59)
!302 = !DILocalVariable(name: "ct", scope: !301, file: !3, line: 311, type: !303)
!303 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "nf_conn", file: !3, line: 95, size: 128, elements: !304)
!304 = !{!305, !306}
!305 = !DIDerivedType(tag: DW_TAG_member, name: "ext", scope: !303, file: !3, line: 96, baseType: !8, size: 64)
!306 = !DIDerivedType(tag: DW_TAG_member, name: "status", scope: !303, file: !3, line: 97, baseType: !23, size: 32, offset: 64)
!307 = !DILocation(line: 311, column: 20, scope: !301)
!308 = !DILocation(line: 318, column: 9, scope: !309)
!309 = distinct !DILexicalBlock(scope: !301, file: !3, line: 317, column: 5)
!310 = !DILocalVariable(name: "sym_id", scope: !309, file: !3, line: 320, type: !13)
!311 = !DILocation(line: 320, column: 12, scope: !309)
!312 = !DILocation(line: 321, column: 9, scope: !309)
!313 = !DILocation(line: 324, column: 32, scope: !309)
!314 = !DILocation(line: 324, column: 9, scope: !309)
!315 = !DILocation(line: 325, column: 16, scope: !316)
!316 = distinct !DILexicalBlock(scope: !309, file: !3, line: 325, column: 13)
!317 = !DILocation(line: 325, column: 13, scope: !316)
!318 = !DILocation(line: 325, column: 13, scope: !309)
!319 = !DILocation(line: 325, column: 31, scope: !320)
!320 = distinct !DILexicalBlock(scope: !316, file: !3, line: 325, column: 21)
!321 = !DILocation(line: 325, column: 28, scope: !320)
!322 = !DILocation(line: 325, column: 23, scope: !320)
!323 = !DILocation(line: 325, column: 40, scope: !320)
!324 = !DILocation(line: 325, column: 44, scope: !320)
!325 = !DILocation(line: 325, column: 52, scope: !320)
!326 = !DILocation(line: 333, column: 9, scope: !327)
!327 = distinct !DILexicalBlock(scope: !301, file: !3, line: 332, column: 5)
!328 = !DILocation(line: 334, column: 38, scope: !327)
!329 = !DILocation(line: 334, column: 18, scope: !327)
!330 = !DILocation(line: 334, column: 12, scope: !327)
!331 = !DILocation(line: 334, column: 16, scope: !327)
!332 = !DILocation(line: 335, column: 19, scope: !327)
!333 = !DILocation(line: 335, column: 9, scope: !327)
!334 = !DILocation(line: 336, column: 12, scope: !327)
!335 = !DILocation(line: 336, column: 17, scope: !327)
!336 = !DILocation(line: 336, column: 24, scope: !327)
!337 = !DILocalVariable(name: "sym_len", scope: !327, file: !3, line: 338, type: !13)
!338 = !DILocation(line: 338, column: 12, scope: !327)
!339 = !DILocation(line: 339, column: 9, scope: !327)
!340 = !DILocation(line: 340, column: 23, scope: !327)
!341 = !DILocation(line: 340, column: 12, scope: !327)
!342 = !DILocation(line: 340, column: 17, scope: !327)
!343 = !DILocation(line: 340, column: 21, scope: !327)
!344 = !DILocation(line: 342, column: 9, scope: !327)
!345 = !DILocation(line: 343, column: 16, scope: !346)
!346 = distinct !DILexicalBlock(scope: !327, file: !3, line: 343, column: 13)
!347 = !DILocation(line: 343, column: 13, scope: !346)
!348 = !DILocation(line: 343, column: 13, scope: !327)
!349 = !DILocation(line: 343, column: 31, scope: !350)
!350 = distinct !DILexicalBlock(scope: !346, file: !3, line: 343, column: 21)
!351 = !DILocation(line: 343, column: 28, scope: !350)
!352 = !DILocation(line: 343, column: 23, scope: !350)
!353 = !DILocation(line: 343, column: 40, scope: !350)
!354 = !DILocation(line: 343, column: 44, scope: !350)
!355 = !DILocation(line: 343, column: 52, scope: !350)
!356 = !DILocation(line: 352, column: 9, scope: !357)
!357 = distinct !DILexicalBlock(scope: !301, file: !3, line: 351, column: 5)
!358 = !DILocation(line: 353, column: 38, scope: !357)
!359 = !DILocation(line: 353, column: 18, scope: !357)
!360 = !DILocation(line: 353, column: 12, scope: !357)
!361 = !DILocation(line: 353, column: 16, scope: !357)
!362 = !DILocation(line: 354, column: 19, scope: !357)
!363 = !DILocation(line: 354, column: 9, scope: !357)
!364 = !DILocation(line: 355, column: 12, scope: !357)
!365 = !DILocation(line: 355, column: 17, scope: !357)
!366 = !DILocation(line: 355, column: 24, scope: !357)
!367 = !DILocation(line: 356, column: 12, scope: !357)
!368 = !DILocation(line: 356, column: 17, scope: !357)
!369 = !DILocation(line: 356, column: 24, scope: !357)
!370 = !DILocalVariable(name: "sym_offset", scope: !357, file: !3, line: 358, type: !13)
!371 = !DILocation(line: 358, column: 12, scope: !357)
!372 = !DILocation(line: 359, column: 9, scope: !357)
!373 = !DILocation(line: 360, column: 29, scope: !357)
!374 = !DILocation(line: 360, column: 12, scope: !357)
!375 = !DILocation(line: 360, column: 17, scope: !357)
!376 = !DILocation(line: 360, column: 9, scope: !357)
!377 = !DILocation(line: 360, column: 27, scope: !357)
!378 = !DILocation(line: 362, column: 9, scope: !357)
!379 = !DILocation(line: 363, column: 16, scope: !380)
!380 = distinct !DILexicalBlock(scope: !357, file: !3, line: 363, column: 13)
!381 = !DILocation(line: 363, column: 13, scope: !380)
!382 = !DILocation(line: 363, column: 13, scope: !357)
!383 = !DILocation(line: 363, column: 31, scope: !384)
!384 = distinct !DILexicalBlock(scope: !380, file: !3, line: 363, column: 21)
!385 = !DILocation(line: 363, column: 28, scope: !384)
!386 = !DILocation(line: 363, column: 23, scope: !384)
!387 = !DILocation(line: 363, column: 40, scope: !384)
!388 = !DILocation(line: 363, column: 44, scope: !384)
!389 = !DILocation(line: 363, column: 52, scope: !384)
!390 = !DILocation(line: 372, column: 9, scope: !391)
!391 = distinct !DILexicalBlock(scope: !301, file: !3, line: 371, column: 5)
!392 = !DILocation(line: 373, column: 38, scope: !391)
!393 = !DILocation(line: 373, column: 18, scope: !391)
!394 = !DILocation(line: 373, column: 12, scope: !391)
!395 = !DILocation(line: 373, column: 16, scope: !391)
!396 = !DILocation(line: 374, column: 19, scope: !391)
!397 = !DILocation(line: 374, column: 9, scope: !391)
!398 = !DILocation(line: 375, column: 12, scope: !391)
!399 = !DILocation(line: 375, column: 17, scope: !391)
!400 = !DILocation(line: 375, column: 21, scope: !391)
!401 = !DILocalVariable(name: "sym_genid", scope: !391, file: !3, line: 377, type: !23)
!402 = !DILocation(line: 377, column: 13, scope: !391)
!403 = !DILocation(line: 378, column: 28, scope: !391)
!404 = !DILocation(line: 378, column: 9, scope: !391)
!405 = !DILocation(line: 379, column: 26, scope: !391)
!406 = !DILocation(line: 379, column: 12, scope: !391)
!407 = !DILocation(line: 379, column: 17, scope: !391)
!408 = !DILocation(line: 379, column: 24, scope: !391)
!409 = !DILocation(line: 381, column: 9, scope: !391)
!410 = !DILocation(line: 382, column: 16, scope: !411)
!411 = distinct !DILexicalBlock(scope: !391, file: !3, line: 382, column: 13)
!412 = !DILocation(line: 382, column: 13, scope: !411)
!413 = !DILocation(line: 382, column: 13, scope: !391)
!414 = !DILocation(line: 382, column: 31, scope: !415)
!415 = distinct !DILexicalBlock(scope: !411, file: !3, line: 382, column: 21)
!416 = !DILocation(line: 382, column: 28, scope: !415)
!417 = !DILocation(line: 382, column: 23, scope: !415)
!418 = !DILocation(line: 382, column: 40, scope: !415)
!419 = !DILocation(line: 382, column: 44, scope: !415)
!420 = !DILocation(line: 382, column: 52, scope: !415)
!421 = !DILocation(line: 384, column: 1, scope: !301)
!422 = distinct !DISubprogram(name: "sim_nf_ct_ext_add", scope: !3, file: !3, line: 272, type: !423, scopeLine: 272, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!423 = !DISubroutineType(types: !424)
!424 = !{!27, !425, !13}
!425 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !303, size: 64)
!426 = !DILocalVariable(name: "ct", arg: 1, scope: !422, file: !3, line: 272, type: !425)
!427 = !DILocation(line: 272, column: 48, scope: !422)
!428 = !DILocalVariable(name: "id", arg: 2, scope: !422, file: !3, line: 272, type: !13)
!429 = !DILocation(line: 272, column: 55, scope: !422)
!430 = !DILocalVariable(name: "newoff", scope: !422, file: !3, line: 273, type: !26)
!431 = !DILocation(line: 273, column: 18, scope: !422)
!432 = !DILocalVariable(name: "newlen", scope: !422, file: !3, line: 273, type: !26)
!433 = !DILocation(line: 273, column: 26, scope: !422)
!434 = !DILocalVariable(name: "oldlen", scope: !422, file: !3, line: 273, type: !26)
!435 = !DILocation(line: 273, column: 34, scope: !422)
!436 = !DILocalVariable(name: "new_ext", scope: !422, file: !3, line: 274, type: !8)
!437 = !DILocation(line: 274, column: 23, scope: !422)
!438 = !DILocation(line: 276, column: 5, scope: !422)
!439 = !DILocation(line: 278, column: 5, scope: !422)
!440 = !DILocation(line: 281, column: 9, scope: !441)
!441 = distinct !DILexicalBlock(scope: !422, file: !3, line: 281, column: 9)
!442 = !DILocation(line: 281, column: 13, scope: !441)
!443 = !DILocation(line: 281, column: 9, scope: !422)
!444 = !DILocation(line: 282, column: 13, scope: !445)
!445 = distinct !DILexicalBlock(scope: !446, file: !3, line: 282, column: 13)
!446 = distinct !DILexicalBlock(scope: !441, file: !3, line: 281, column: 18)
!447 = !DILocation(line: 282, column: 17, scope: !445)
!448 = !DILocation(line: 282, column: 22, scope: !445)
!449 = !DILocation(line: 282, column: 29, scope: !445)
!450 = !DILocation(line: 282, column: 33, scope: !445)
!451 = !DILocation(line: 282, column: 13, scope: !446)
!452 = !DILocation(line: 283, column: 13, scope: !445)
!453 = !DILocation(line: 284, column: 18, scope: !446)
!454 = !DILocation(line: 284, column: 22, scope: !446)
!455 = !DILocation(line: 284, column: 27, scope: !446)
!456 = !DILocation(line: 284, column: 16, scope: !446)
!457 = !DILocation(line: 285, column: 5, scope: !446)
!458 = !DILocation(line: 286, column: 16, scope: !459)
!459 = distinct !DILexicalBlock(scope: !441, file: !3, line: 285, column: 12)
!460 = !DILocation(line: 289, column: 15, scope: !422)
!461 = !DILocation(line: 289, column: 22, scope: !422)
!462 = !DILocation(line: 289, column: 28, scope: !422)
!463 = !DILocation(line: 289, column: 12, scope: !422)
!464 = !DILocation(line: 290, column: 14, scope: !422)
!465 = !DILocation(line: 290, column: 36, scope: !422)
!466 = !DILocation(line: 290, column: 23, scope: !422)
!467 = !DILocation(line: 290, column: 21, scope: !422)
!468 = !DILocation(line: 290, column: 12, scope: !422)
!469 = !DILocation(line: 292, column: 5, scope: !422)
!470 = !DILocalVariable(name: "alloc", scope: !422, file: !3, line: 295, type: !26)
!471 = !DILocation(line: 295, column: 18, scope: !422)
!472 = !DILocation(line: 295, column: 27, scope: !422)
!473 = !DILocation(line: 295, column: 34, scope: !422)
!474 = !DILocation(line: 295, column: 26, scope: !422)
!475 = !DILocation(line: 295, column: 58, scope: !422)
!476 = !DILocation(line: 296, column: 43, scope: !422)
!477 = !DILocation(line: 296, column: 47, scope: !422)
!478 = !DILocation(line: 296, column: 52, scope: !422)
!479 = !DILocation(line: 296, column: 35, scope: !422)
!480 = !DILocation(line: 296, column: 15, scope: !422)
!481 = !DILocation(line: 296, column: 13, scope: !422)
!482 = !DILocation(line: 297, column: 17, scope: !422)
!483 = !DILocation(line: 297, column: 25, scope: !422)
!484 = !DILocation(line: 297, column: 5, scope: !422)
!485 = !DILocation(line: 299, column: 10, scope: !486)
!486 = distinct !DILexicalBlock(scope: !422, file: !3, line: 299, column: 9)
!487 = !DILocation(line: 299, column: 14, scope: !486)
!488 = !DILocation(line: 299, column: 9, scope: !422)
!489 = !DILocation(line: 300, column: 16, scope: !490)
!490 = distinct !DILexicalBlock(scope: !486, file: !3, line: 299, column: 19)
!491 = !DILocation(line: 300, column: 25, scope: !490)
!492 = !DILocation(line: 300, column: 9, scope: !490)
!493 = !DILocation(line: 301, column: 9, scope: !490)
!494 = !DILocation(line: 301, column: 18, scope: !490)
!495 = !DILocation(line: 301, column: 25, scope: !490)
!496 = !DILocation(line: 302, column: 5, scope: !490)
!497 = !DILocation(line: 304, column: 31, scope: !422)
!498 = !DILocation(line: 304, column: 27, scope: !422)
!499 = !DILocation(line: 304, column: 5, scope: !422)
!500 = !DILocation(line: 304, column: 14, scope: !422)
!501 = !DILocation(line: 304, column: 21, scope: !422)
!502 = !DILocation(line: 304, column: 25, scope: !422)
!503 = !DILocation(line: 305, column: 31, scope: !422)
!504 = !DILocation(line: 305, column: 27, scope: !422)
!505 = !DILocation(line: 305, column: 5, scope: !422)
!506 = !DILocation(line: 305, column: 14, scope: !422)
!507 = !DILocation(line: 305, column: 25, scope: !422)
!508 = !DILocation(line: 306, column: 15, scope: !422)
!509 = !DILocation(line: 306, column: 5, scope: !422)
!510 = !DILocation(line: 306, column: 9, scope: !422)
!511 = !DILocation(line: 306, column: 13, scope: !422)
!512 = !DILocation(line: 307, column: 20, scope: !422)
!513 = !DILocation(line: 307, column: 12, scope: !422)
!514 = !DILocation(line: 307, column: 30, scope: !422)
!515 = !DILocation(line: 307, column: 28, scope: !422)
!516 = !DILocation(line: 307, column: 5, scope: !422)
!517 = !DILocation(line: 308, column: 1, scope: !422)
!518 = distinct !DISubprogram(name: "test_priority_bypass", scope: !3, file: !3, line: 440, type: !57, scopeLine: 440, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !59)
!519 = !DILocalVariable(name: "attr", scope: !518, file: !3, line: 441, type: !520)
!520 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "sym_nf_attr", file: !3, line: 401, size: 128, elements: !521)
!521 = !{!522, !523, !524, !525, !526}
!522 = !DIDerivedType(tag: DW_TAG_member, name: "pf", scope: !520, file: !3, line: 402, baseType: !13, size: 8)
!523 = !DIDerivedType(tag: DW_TAG_member, name: "hooknum", scope: !520, file: !3, line: 403, baseType: !13, size: 8, offset: 8)
!524 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !520, file: !3, line: 404, baseType: !31, size: 32, offset: 32)
!525 = !DIDerivedType(tag: DW_TAG_member, name: "flags", scope: !520, file: !3, line: 405, baseType: !23, size: 32, offset: 64)
!526 = !DIDerivedType(tag: DW_TAG_member, name: "link_flags", scope: !520, file: !3, line: 406, baseType: !23, size: 32, offset: 96)
!527 = !DILocation(line: 441, column: 24, scope: !518)
!528 = !DILocation(line: 442, column: 24, scope: !518)
!529 = !DILocation(line: 442, column: 5, scope: !518)
!530 = !DILocation(line: 444, column: 22, scope: !518)
!531 = !DILocation(line: 444, column: 17, scope: !518)
!532 = !DILocation(line: 444, column: 25, scope: !518)
!533 = !DILocation(line: 444, column: 41, scope: !518)
!534 = !DILocation(line: 444, column: 49, scope: !518)
!535 = !DILocation(line: 444, column: 44, scope: !518)
!536 = !DILocation(line: 444, column: 52, scope: !518)
!537 = !DILocation(line: 444, column: 5, scope: !518)
!538 = !DILocation(line: 445, column: 22, scope: !518)
!539 = !DILocation(line: 445, column: 17, scope: !518)
!540 = !DILocation(line: 445, column: 30, scope: !518)
!541 = !DILocation(line: 445, column: 5, scope: !518)
!542 = !DILocation(line: 446, column: 22, scope: !518)
!543 = !DILocation(line: 446, column: 33, scope: !518)
!544 = !DILocation(line: 446, column: 17, scope: !518)
!545 = !DILocation(line: 446, column: 5, scope: !518)
!546 = !DILocation(line: 447, column: 22, scope: !518)
!547 = !DILocation(line: 447, column: 28, scope: !518)
!548 = !DILocation(line: 447, column: 33, scope: !518)
!549 = !DILocation(line: 447, column: 41, scope: !518)
!550 = !DILocation(line: 447, column: 47, scope: !518)
!551 = !DILocation(line: 447, column: 17, scope: !518)
!552 = !DILocation(line: 447, column: 5, scope: !518)
!553 = !DILocation(line: 449, column: 5, scope: !518)
!554 = !DILocation(line: 450, column: 1, scope: !518)
!555 = distinct !DISubprogram(name: "sim_check_pf_and_hooks", scope: !3, file: !3, line: 409, type: !556, scopeLine: 409, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!556 = !DISubroutineType(types: !557)
!557 = !{!31, !558}
!558 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !559, size: 64)
!559 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !520)
!560 = !DILocalVariable(name: "a", arg: 1, scope: !555, file: !3, line: 409, type: !558)
!561 = !DILocation(line: 409, column: 61, scope: !555)
!562 = !DILocation(line: 410, column: 9, scope: !563)
!563 = distinct !DILexicalBlock(scope: !555, file: !3, line: 410, column: 9)
!564 = !DILocation(line: 410, column: 12, scope: !563)
!565 = !DILocation(line: 410, column: 9, scope: !555)
!566 = !DILocation(line: 411, column: 9, scope: !563)
!567 = !DILocation(line: 413, column: 13, scope: !555)
!568 = !DILocation(line: 413, column: 16, scope: !555)
!569 = !DILocation(line: 413, column: 5, scope: !555)
!570 = !DILocation(line: 416, column: 13, scope: !571)
!571 = distinct !DILexicalBlock(scope: !572, file: !3, line: 416, column: 13)
!572 = distinct !DILexicalBlock(scope: !555, file: !3, line: 413, column: 20)
!573 = !DILocation(line: 416, column: 16, scope: !571)
!574 = !DILocation(line: 416, column: 24, scope: !571)
!575 = !DILocation(line: 416, column: 13, scope: !572)
!576 = !DILocation(line: 416, column: 45, scope: !571)
!577 = !DILocation(line: 417, column: 9, scope: !572)
!578 = !DILocation(line: 419, column: 9, scope: !572)
!579 = !DILocation(line: 422, column: 9, scope: !580)
!580 = distinct !DILexicalBlock(scope: !555, file: !3, line: 422, column: 9)
!581 = !DILocation(line: 422, column: 12, scope: !580)
!582 = !DILocation(line: 422, column: 18, scope: !580)
!583 = !DILocation(line: 422, column: 9, scope: !555)
!584 = !DILocation(line: 423, column: 9, scope: !580)
!585 = !DILocalVariable(name: "prio", scope: !555, file: !3, line: 425, type: !31)
!586 = !DILocation(line: 425, column: 9, scope: !555)
!587 = !DILocation(line: 425, column: 16, scope: !555)
!588 = !DILocation(line: 425, column: 19, scope: !555)
!589 = !DILocation(line: 427, column: 5, scope: !555)
!590 = !DILocation(line: 429, column: 5, scope: !555)
!591 = !DILocation(line: 432, column: 9, scope: !592)
!592 = distinct !DILexicalBlock(scope: !555, file: !3, line: 432, column: 9)
!593 = !DILocation(line: 432, column: 14, scope: !592)
!594 = !DILocation(line: 432, column: 9, scope: !555)
!595 = !DILocation(line: 432, column: 34, scope: !592)
!596 = !DILocation(line: 433, column: 9, scope: !597)
!597 = distinct !DILexicalBlock(scope: !555, file: !3, line: 433, column: 9)
!598 = !DILocation(line: 433, column: 14, scope: !597)
!599 = !DILocation(line: 433, column: 9, scope: !555)
!600 = !DILocation(line: 433, column: 34, scope: !597)
!601 = !DILocation(line: 434, column: 10, scope: !602)
!602 = distinct !DILexicalBlock(scope: !555, file: !3, line: 434, column: 9)
!603 = !DILocation(line: 434, column: 13, scope: !602)
!604 = !DILocation(line: 434, column: 19, scope: !602)
!605 = !DILocation(line: 434, column: 48, scope: !602)
!606 = !DILocation(line: 435, column: 9, scope: !602)
!607 = !DILocation(line: 435, column: 14, scope: !602)
!608 = !DILocation(line: 434, column: 9, scope: !555)
!609 = !DILocation(line: 435, column: 50, scope: !602)
!610 = !DILocation(line: 437, column: 5, scope: !555)
!611 = !DILocation(line: 438, column: 1, scope: !555)
!612 = distinct !DISubprogram(name: "main", scope: !3, file: !3, line: 456, type: !613, scopeLine: 456, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !2, retainedNodes: !59)
!613 = !DISubroutineType(types: !614)
!614 = !{!31}
!615 = !DILocation(line: 457, column: 5, scope: !612)
!616 = !DILocation(line: 458, column: 5, scope: !612)
!617 = !DILocation(line: 459, column: 5, scope: !612)
!618 = !DILocation(line: 460, column: 5, scope: !612)
!619 = !DILocation(line: 461, column: 5, scope: !612)
!620 = !DILocation(line: 462, column: 5, scope: !612)
!621 = distinct !DISubprogram(name: "sim_cmpxchg", scope: !3, file: !3, line: 131, type: !622, scopeLine: 131, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!622 = !DISubroutineType(types: !623)
!623 = !{!23, !624, !23, !23}
!624 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !23, size: 64)
!625 = !DILocalVariable(name: "ptr", arg: 1, scope: !621, file: !3, line: 131, type: !624)
!626 = !DILocation(line: 131, column: 29, scope: !621)
!627 = !DILocalVariable(name: "old", arg: 2, scope: !621, file: !3, line: 131, type: !23)
!628 = !DILocation(line: 131, column: 38, scope: !621)
!629 = !DILocalVariable(name: "newval", arg: 3, scope: !621, file: !3, line: 131, type: !23)
!630 = !DILocation(line: 131, column: 47, scope: !621)
!631 = !DILocalVariable(name: "cur", scope: !621, file: !3, line: 132, type: !23)
!632 = !DILocation(line: 132, column: 9, scope: !621)
!633 = !DILocation(line: 132, column: 16, scope: !621)
!634 = !DILocation(line: 132, column: 15, scope: !621)
!635 = !DILocation(line: 133, column: 9, scope: !636)
!636 = distinct !DILexicalBlock(scope: !621, file: !3, line: 133, column: 9)
!637 = !DILocation(line: 133, column: 16, scope: !636)
!638 = !DILocation(line: 133, column: 13, scope: !636)
!639 = !DILocation(line: 133, column: 9, scope: !621)
!640 = !DILocation(line: 133, column: 28, scope: !636)
!641 = !DILocation(line: 133, column: 22, scope: !636)
!642 = !DILocation(line: 133, column: 26, scope: !636)
!643 = !DILocation(line: 133, column: 21, scope: !636)
!644 = !DILocation(line: 134, column: 12, scope: !621)
!645 = !DILocation(line: 134, column: 5, scope: !621)
!646 = distinct !DISubprogram(name: "stub_unregister", scope: !3, file: !3, line: 124, type: !647, scopeLine: 124, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!647 = !DISubroutineType(types: !648)
!648 = !{null, !32, !649}
!649 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !79, size: 64)
!650 = !DILocalVariable(name: "net", arg: 1, scope: !646, file: !3, line: 124, type: !32)
!651 = !DILocation(line: 124, column: 41, scope: !646)
!652 = !DILocalVariable(name: "ops", arg: 2, scope: !646, file: !3, line: 124, type: !649)
!653 = !DILocation(line: 124, column: 66, scope: !646)
!654 = !DILocation(line: 125, column: 11, scope: !646)
!655 = !DILocation(line: 125, column: 22, scope: !646)
!656 = !DILocation(line: 126, column: 23, scope: !646)
!657 = !DILocation(line: 127, column: 5, scope: !646)
!658 = !DILocation(line: 129, column: 1, scope: !646)
!659 = distinct !DISubprogram(name: "stub_module_put", scope: !3, file: !3, line: 220, type: !660, scopeLine: 220, flags: DIFlagPrototyped, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition, unit: !2, retainedNodes: !59)
!660 = !DISubroutineType(types: !661)
!661 = !{null, !5}
!662 = !DILocalVariable(name: "owner", arg: 1, scope: !659, file: !3, line: 220, type: !5)
!663 = !DILocation(line: 220, column: 39, scope: !659)
!664 = !DILocation(line: 221, column: 5, scope: !659)
!665 = !DILocation(line: 223, column: 11, scope: !659)
!666 = !DILocation(line: 224, column: 1, scope: !659)
!667 = distinct !DISubprogram(name: "memcpy", scope: !668, file: !668, line: 12, type: !669, scopeLine: 12, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !44, retainedNodes: !59)
!668 = !DIFile(filename: "runtime/Freestanding/memcpy.c", directory: "/root/klee", checksumkind: CSK_MD5, checksum: "c636d77d986b2156da8c1ff12af1c5cd")
!669 = !DISubroutineType(types: !670)
!670 = !{!27, !27, !671, !129}
!671 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !672, size: 64)
!672 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!673 = !DILocalVariable(name: "destaddr", arg: 1, scope: !667, file: !668, line: 12, type: !27)
!674 = !DILocation(line: 12, column: 20, scope: !667)
!675 = !DILocalVariable(name: "srcaddr", arg: 2, scope: !667, file: !668, line: 12, type: !671)
!676 = !DILocation(line: 12, column: 42, scope: !667)
!677 = !DILocalVariable(name: "len", arg: 3, scope: !667, file: !668, line: 12, type: !129)
!678 = !DILocation(line: 12, column: 58, scope: !667)
!679 = !DILocalVariable(name: "dest", scope: !667, file: !668, line: 13, type: !680)
!680 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !681, size: 64)
!681 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!682 = !DILocation(line: 13, column: 9, scope: !667)
!683 = !DILocation(line: 13, column: 16, scope: !667)
!684 = !DILocalVariable(name: "src", scope: !667, file: !668, line: 14, type: !685)
!685 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !686, size: 64)
!686 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !681)
!687 = !DILocation(line: 14, column: 15, scope: !667)
!688 = !DILocation(line: 14, column: 21, scope: !667)
!689 = !DILocation(line: 16, column: 3, scope: !667)
!690 = !DILocation(line: 16, column: 13, scope: !667)
!691 = !DILocation(line: 16, column: 16, scope: !667)
!692 = !DILocation(line: 17, column: 19, scope: !667)
!693 = !DILocation(line: 17, column: 15, scope: !667)
!694 = !DILocation(line: 17, column: 10, scope: !667)
!695 = !DILocation(line: 17, column: 13, scope: !667)
!696 = distinct !{!696, !689, !692, !697}
!697 = !{!"llvm.loop.mustprogress"}
!698 = !DILocation(line: 18, column: 10, scope: !667)
!699 = !DILocation(line: 18, column: 3, scope: !667)
!700 = distinct !DISubprogram(name: "memset", scope: !701, file: !701, line: 12, type: !702, scopeLine: 12, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !46, retainedNodes: !59)
!701 = !DIFile(filename: "runtime/Freestanding/memset.c", directory: "/root/klee", checksumkind: CSK_MD5, checksum: "f66ef9ef9131ab198e93a41b1a9ae1fc")
!702 = !DISubroutineType(types: !703)
!703 = !{!27, !27, !31, !129}
!704 = !DILocalVariable(name: "dst", arg: 1, scope: !700, file: !701, line: 12, type: !27)
!705 = !DILocation(line: 12, column: 20, scope: !700)
!706 = !DILocalVariable(name: "s", arg: 2, scope: !700, file: !701, line: 12, type: !31)
!707 = !DILocation(line: 12, column: 29, scope: !700)
!708 = !DILocalVariable(name: "count", arg: 3, scope: !700, file: !701, line: 12, type: !129)
!709 = !DILocation(line: 12, column: 39, scope: !700)
!710 = !DILocalVariable(name: "a", scope: !700, file: !701, line: 13, type: !680)
!711 = !DILocation(line: 13, column: 9, scope: !700)
!712 = !DILocation(line: 13, column: 13, scope: !700)
!713 = !DILocation(line: 14, column: 3, scope: !700)
!714 = !DILocation(line: 14, column: 15, scope: !700)
!715 = !DILocation(line: 14, column: 18, scope: !700)
!716 = !DILocation(line: 15, column: 12, scope: !700)
!717 = !DILocation(line: 15, column: 7, scope: !700)
!718 = !DILocation(line: 15, column: 10, scope: !700)
!719 = distinct !{!719, !713, !716, !697}
!720 = !DILocation(line: 16, column: 10, scope: !700)
!721 = !DILocation(line: 16, column: 3, scope: !700)
