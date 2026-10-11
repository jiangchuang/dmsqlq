// dmsqlq —— DM8 dmsql_*.log 解析 / 参数还原 / 可执行 SQL 导出工具
//
// 单文件、零第三方依赖（仅 Go 标准库）、跨平台（Linux/Windows/macOS 交叉编译单二进制）。
//
// 设计要点（对应《DM8 SQL日志内容解析学习笔记》）：
//  1. 一条记录 = 以 "yyyy-MM-dd HH:mm:ss.SSS" 开头的一行 + 其后所有非时间戳行（多行 SQL 续行）；
//  2. 参数行 PARAMS(SEQNO, TYPE, DATA)={...} 与执行行按「会话块(去 trxid) + stmt 句柄」关联，不看 trxid；
//  3. 参数取值用「引号感知 + 括号深度」扫描，**不按逗号切分**（规避官方切分法 10.5% 的静默错误）；
//  4. '?' 的定位与替换用「字面量/注释感知」扫描，**不用 replaceFirst**（规避官方把值里的 ? 再当占位符）；
//  5. 空值输出 NULL，而不是空串（官方会拼出 `,,` 这种非法 SQL）；
//  6. 全程按 []byte 处理、不解码 —— GBK/GB18030 日志原样透传，不产生乱码，也无解码开销。
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	chunkSize  = 8 << 20 // 读取块 8MB
	zipReadBuf = 4 << 20 // 压缩流底层读缓冲 4MB
	// 🩸 必须给 gzip.NewReader 套 bufio：
	// flate 默认每次只向底层要 512B，107GB 会触发约 2 亿次
	// syscall，实测把 5.44GB tgz 的解压从 60s 拖到 162s（2.7x）。
	ver          = "2.22"
	reportTopMax = 20      // 报告里各排行榜的显示上限（-p 更大时也只显示这么多）
	adviceLimit  = 8       // 「优先优化推荐」条数上限（推荐要精不要多，8 条足够排完收益）
	maxKeys      = 1 << 18 // 参数缓存键上限（防大日志吃内存）
	perKeyLimit  = 8       // 单键参数队列上限
)

// paramsTag PARAMS 行的固定前缀（内容段起始）
var paramsTag = []byte("PARAMS(SEQNO")

// ---------------------------------------------------------------- 配置

type Options struct {
	from, to    string
	out         string
	minMS       float64
	maxMS       float64
	ops         string
	excludeOps  string
	user        string
	trx         string
	objMapFile  string
	fullSQL     string
	sqlLike     string
	limit       int
	jobs        int
	noParams    bool
	noMeta      bool
	stats       bool
	statsOut    string
	excelOut    string // -e：Excel 交付件路径（定期交付给开发商做 SQL 优化用）
	excelTop    int    // Excel 交付件的行数上限（与报告的 -p 分开，默认 50）
	statsOnly   bool
	autoReport  bool // -s 未配 -r 时自动落默认报告文件
	explicitOut bool // 用户显式给了 -o（否则 out=="" 表示默认 stdout）
	noOpen      bool // -Q：生成 HTML 报告后不要自动弹浏览器
	top         int
	topMS       int
	term        string
	loose       bool
	allFiles    bool
	allOps      bool
	looseKey    bool
	skipMissing bool
	dangerOnly  bool
	maxSQL      int
	quiet       bool
	version     bool

	fromB, toB []byte
	// fromTimeOnly / toTimeOnly：用户只给了「时刻」（如 09:00），没给日期。
	// 🩸 不能简单补一个假日期：日志跨天时那样会让筛选结果全空。
	// 正确语义是「每天的这个时刻」——比较时只取记录的 HH:mm:ss 部分。
	fromTimeOnly, toTimeOnly bool
	opSet                    map[string]bool
	exclSet                  map[string]bool
	exclLike                 []string
	trxSet                   map[string]bool   // -x 支持多个事务号（逗号分隔）
	objMap                   map[string]string // 对象 ID → 表名（--obj-map，用于锁等待翻译）
	trxGroup                 *trxGroup         // 二次扫描时按事务号分组收集语句（生成配套 .sql 用）
}

// wantSQL 是否要把还原后的 SQL 输出到 stdout / -o 文件。
//
// 决定原则：用户此刻的目标是什么。
//   - 默认（只有日志路径）：核心目标就是拿 SQL → 输出。
//   - -S：只要命令行简要统计 → 不输出。
//   - 只要了报告（-s / -r，但**没给 -o**）：核心目标是报告，不把几十万条 SQL 刷到屏幕 ——
//     那会把报告路径和判读结论冲散，也没法接管道 grep。想要 SQL 就显式 -o 文件名。
//
// 注意这里判的是**有没有给 SQL 的去处（-o）**，而不是"有没有给报告路径"：
// `-s -r 报告.html` 同样是"只要报告"，此时 stdout 也必须干净（V1.9 曾把条件写成
// `statsOut == ""`，结果一给 -r 就把 140 万行 SQL 全刷出来了）。
func (o *Options) wantSQL() bool {
	if o.statsOnly {
		return false
	}
	if o.stats && !o.explicitOut {
		return false
	}
	// -e / -r *.xlsx 同理：此刻的目标是「拿到交付文件」，不是「把几十万条 SQL 刷满屏幕」。
	// 确实想连 SQL 一起导，显式给 -o 即可（与 -s 的处理完全一致）。
	if o.excelWanted() && !o.explicitOut {
		return false
	}
	return true
}

// rowCap 明细行的实际上限：报告用 -p，交付件可能更大，取两者较大值。
// 用于「扫描期就要定容量」的两处 —— 最慢语句榜（setSlowN）与锁等待明细（addLockWait），
// 它们必须在读日志前定好，不能事后补。
func (o *Options) rowCap() int {
	if o.excelTop > o.top {
		return o.excelTop
	}
	return o.top
}

// lockKeepCap 锁等待明细的保留上限（V2.8 起与显示上限解耦）。
//
// 🩸 与「最慢语句」不同：锁等待天然稀疏（实测 1 GB 现网日志仅 120 次），
// 但每一条都是能单独动手的线索，而且用户明确要「双方 SQL 覆盖全部等待」。
// 早先沿用 rowCap()（= -p，默认 20），等于报告只覆盖了 1/6 的锁等待 ——
// 更糟的是统计句里用截断后的值当分母，会写出「20/20 但没有一条 SQL」这种自相矛盾的话。
// 5000 条足够覆盖任何真实锁竞争场面，同时给病态日志留了内存上限。
func lockKeepCap(o *Options) int {
	const n = 5000
	if o.rowCap() > n {
		return o.rowCap()
	}
	return n
}

// excelWanted 本次是否要产出 Excel 交付件（-e，或 -r 落到 .xlsx）。
// 「要不要刷 SQL」「要不要打简要版」两处都靠它判断 —— 集中一处，免得规则打架。
func (o *Options) excelWanted() bool {
	return o.excelOut != "" || strings.HasSuffix(strings.ToLower(o.statsOut), ".xlsx")
}

// defaultOps 默认输出的语句类型：只保留「能拿去执行」的
// （[ORA] 只解析未执行、[LGN] 是登录事件，默认不出）
var defaultOps = map[string]bool{
	"SEL": true, "INS": true, "UPD": true, "DEL": true, "DML": true,
	"DDL": true, "CAL": true, "ERR": true,
}

func usage(fs *flag.FlagSet) func() {
	return func() {
		fmt.Fprintf(os.Stdout, `dmsqlq %s ── 达梦 DM8 SQL 日志解析 · 参数还原 · 可执行 SQL 导出

  把 dmsql_*.log 里带 ? 的语句，按日志中的 PARAMS 行还原成真实参数值，
  输出可直接复制到 disql 执行的 SQL；可另出性能统计报告。
  不连库、不建表、不落库；单个可执行文件，GB 级日志秒级扫完。

用法
  dmsqlq [选项] <日志文件|目录> [更多文件或目录...]
  dmsqlq                       显示本帮助（与 -h 相同）
  dmsqlq .                     处理当前目录（= dmsqlq 后跟一个点）

  · 路径可绝对可相对，支持通配符（"dmsql_*.log"），目录会递归查找；
  · 默认收 dmsql_*.log、dmsql_*.log.gz、dmsql_*.log.zip，以及文件名含 log 的
    .zip / .tar.gz（自动就地解压，不必先解包）；开了 -A 则收所有 .log。

快速上手（七个最常用）
  1) dmsqlq .                     扫当前目录，输出全部可执行 SQL
  2) dmsqlq . -m 1000             只要执行超过 1 秒的（慢 SQL 定位）
  3) dmsqlq . -s                  出统计报告：落一份 HTML 并自动用浏览器打开
  4) dmsqlq . -S                  只在屏幕上看统计，不生成文件、也不导 SQL
  5) dmsqlq . -B 20 -o slow.sql   导出最慢 20 条的完整 SQL
  6) dmsqlq x.log -x 10130765548  按事务号抽一条事务的全部语句（问题复现）
  7) dmsqlq . -e 交付.xlsx       出一份 Excel 交付件（定期交付给开发商做 SQL 优化）

  实时监视（独立子命令，与上面的批处理模式互不影响）
  8) dmsqlq watch -a manager.exe      （日志目录会自动找，不用记路径）
                                  实时跟随 SQL 日志，打印指定客户端执行的 SQL。
                                  想知道「点一下 DM 管理工具，它到底跑了什么 SQL」就用它。
                                  参数与上面完全不同，看 dmsqlq watch -h。

选项（每个都有短写与长写；大写多是同类里的“增强/反向”，方便记）
  筛选
    -f, --from TIME     起始时间；"2026-09-09" / "2026-09-09 23:52" / 完整时间均可
                        ⭐ 也可只给时刻（"09:00"）—— 表示「每天的 9 点起」，
                        用于「只看业务高峰、排除夜间跑批」，需与 -t 成对使用：
                          dmsqlq dmsql1001_all.tgz -f 09:00 -t 18:00 -s
    -t, --to   TIME     结束时间（同样支持纯时刻）
    -m, --min-ms N      只保留耗时 ≥ N 毫秒        -M, --max-ms N   只保留 ≤ N 毫秒
    -k, --op   LIST     只保留这些类型（默认 SEL,INS,UPD,DEL,DML,DDL,CAL,ERR）
    -E, --exclude-op LIST  排除指定语句。两种写法自动识别：
                            ① 事件类型码：CAL / DDL / SEL / INS / UPD / DEL …
                            ② 任意 SQL 子串（忽略大小写）：ANALYZE、DBMS_STATS、TMP_ …
                            例：-E CAL,ANALYZE,DBMS_STATS   剔除调用与统计信息收集
                            注意：被 -E 排除的语句**连统计一起排除**（它表达"这类语句
                            不是有效负载"）；而 -k/-m/-u 等只影响输出，统计仍反映全貌。
    -K, --all-ops       不做类型过滤（含 ORA 只解析、LGN 登录等全部）
    -u, --user NAME     只保留该用户
    -x, --trx ID        只保留该事务号（支持逗号分隔多个，如 -x 101,102）
    -l, --sql-like STR  SQL 文本包含该子串（忽略大小写，按表名过滤很好用）
    -n, --limit N       最多输出 N 条
  -O, --obj-map FILE  对象 ID → 表名 映射。DM 的 SQL 日志只记对象 ID 不记表名，
                      锁等待里显示的就是 ID；把库上查出来的结果存成此文件（UTF-8，
                      每行「ID=表名」或直接粘贴 ID 与表名两列）即可自动显示表名。

  统计
    -s, --stats         生成统计报告（推荐，这是核心产物）。默认落一份 HTML 到当前目录，
                        文件名取输入日志名 +「_报告.html」，**生成后自动用浏览器打开**，
                        报告可交互可打印。内容：概览 / 语句类型分布(含耗时占比) /
                        执行耗时分布(含分位数) / 热表(含读写比) / 吞吐(QPS·TPS) /
                        最慢语句 / 最耗时模板 / 用户与客户端 / 长事务(含利用率) /
                        锁等待 / 审计与恢复定位(危险操作·结构变更·LSN) /
                        采集配置体检 / 判读提示 —— 共十五节。
                          默认同时把**简要版**打到屏幕（结论 + 最慢 TOP5，看个大概）；
                          只想安静出文件就加 -q；不想弹浏览器就加 -Q。
                          想自定义文件名/格式用 -r；想连 SQL 一起导就再加 -o。
    -S, --stats-only    只在命令行打**完整文本版统计**（终端排版的十五节），不生成报告
                        文件、也不导出 SQL —— 适合 SSH 里看全貌。不能与 -r 同用
                        （两者互相矛盾，同时给会直接报错，不再静默忽略）。
    -r, --stats-out FILE  指定报告文件名与格式（配合 -s 使用，单独给也行）：
                          .html/.htm → 单文件 HTML（带图形图表与交互，浏览器直接看，
                                        生成后会自动打开；不想弹出加 -Q）
                          .md/.markdown → Markdown 表格（可贴文档/工单）
                          .xlsx → Excel 交付件（多张工作表，给开发商做 SQL 优化用）
                          其他 → 纯文本（等宽对齐）
                          不能与 -S 同用。
    -e, --excel FILE    Excel 交付件（.xlsx），用于定期交付给开发商做 SQL 优化。
                        可与 -s 并用：一次扫描同时出「自己看的 HTML」+「发出去的 Excel」；
                        也可单独给（等于 .xlsx 版的 -r），此时不生成 HTML、不弹浏览器。
                        工作表：概览 / SQL优化清单 / 慢SQL明细 / 热表 / 语句类型分布 /
                                锁等待 / 长事务 / 时段分布 / 用户与客户端 / 结构变更与高危操作。
                        其中「SQL优化清单」按累计耗时降序、标出优先级，开发商从第一行往下改即可。
                        -e auto 用输入日志名自动命名（<日志名>_交付.xlsx）。
                        行数 = -p（默认 20）；**调大 -p 即可导出完整清单**，而报告仍只显示前 20 条。
                        生成后不自动打开 —— 它是发出去的文件，路径已打印在屏幕上。
                        屏幕只给简要结论（与 -s 同一版式），**不会**把 SQL 刷到 stdout；
                        确实想连 SQL 一起导，再加 -o all.sql。不能与 -S 同用。
    -p, --top N         交付件（Excel）的行数，默认 20 —— **调大即可导出完整清单**。
                        报告（HTML/Markdown/终端）各排行榜**一律最多显示 20 条**：
                        报告是给人看结论的，榜单/时段一长就没人读（-p 更小时按 -p 走）。
    -F, --full-sql FILE 完整 SQL 附件。报告（HTML）里的语句本身已可点击展开、
                        悬停预览、一键复制，无需再翻文件；附件的作用是**整批导出**，
                        方便一次拿去 disql 执行。含：最慢语句 TopN、最耗时模板 TopN，
                        以及长事务与锁等待涉及事务的**全部语句**（按事务号分组）。
                        默认与 -r 报告同名 +「.full.sql」；写 off 表示不生成。
                          统计口径：-k/-m/-u/-x/-l/-f/-t 只影响"输出哪些 SQL"，统计仍
                          反映日志全貌；只有 -E 的排除会同时把该批语句剔出统计。
  输出
    -o, --out FILE      输出到文件（默认 stdout）
    -B, --top-ms N      导出“最慢的 N 条”完整 SQL（按耗时降序）
    -T, --term S        语句结束符，默认 ";"；none 表示不加
    -N, --no-meta       不输出 -- 注释头（得到纯 SQL）
    -P, --no-params     不还原参数（输出仍是带 ? 的原始 SQL）
    -X, --skip-missing  只输出参数已还原成功的语句
    -d, --danger        只输出审计命中的语句（高危操作 / 结构变更 / 大批量 DML），
                        用来单独导出"可能出事的语句"清单
    -C, --max-sql N     单条 SQL 超过 N 字符时截断（默认 0 不截断）
  其他
    -A, --all-files     目录下所有 .log 都处理（不限 dmsql_ 前缀）
    -L, --loose         兼容 SVR_LOG=3 简单模式（此类日志没有会话块）
    -Y, --loose-key     参数关联放宽为 sess+stmt（忽略 thrd 线程漂移）
    -j, --jobs N        并发处理文件数（默认 CPU 核数）
    -q, --quiet         不打印进度与警告
    -Q, --no-open       生成 HTML 报告后**不要**自动打开浏览器
                        （默认会自动打开；批处理里连跑多份日志时用这个关掉）
    -h, --help          显示本帮助              -V, --version  显示版本

TAB 补全（bash/zsh；首次以交互方式运行 dmsqlq 时自动安装，无需手工执行）
  自动: 首次交互运行即装好（提示走 stderr，不污染管道；只触发一次）
  手工: dmsqlq --completion-install        # 显式安装（幂等，可重复执行）
        dmsqlq --completion-install-dry-run # 只预览将做什么，不写盘
        dmsqlq --completion-uninstall      # 撤销（幂等）
        dmsqlq --completion-bash           # 只打印补全脚本（供 source <(...) 用）
  装后: dmsqlq -<TAB> → 全部选项 · dmsqlq watch -<TAB> → watch 专属选项
        位置参数（日志文件/目录）自动补文件名
  机制: 与 dmkit 一致 —— 写 ~/.dmsqlq/completion.bash + 在 ~/.bashrc 维护带标记的
        自动同步区块（二进制更新后新终端自动刷新；幂等，不产生重复配置）

输出长这样（每条语句之间空一行；-N 去掉注释头后是纯 SQL）
  -- 2026-09-09 23:52:51 · [INS] · 0ms · 1行 · COSMIC_FI · trxid:10130765548 · KD1_20260909_235252
  INSERT INTO t_rim_vouch_relation (...) VALUES ('2026-08-25 00:00:00.000000', ...);

  · 注释头字段：时间 · 类型 · 耗时 · 行数 · 用户 · 事务号 · 来源日志（已省略 dmsql_ 前缀与后缀）
  · 行数显示 "-" 表示该语句在日志里没有 ROWCOUNT（[DDL]/[CAL] 一律不带行数，不是 0 行）
  · 多行 PL/SQL 块原样保留，不追加多余结束符（块尾已是 end;，可直接 / 执行）

详尽用例（可直接复制，把路径换成自己的）
  ① 先看全局：哪类语句最耗时间、哪条最慢
     dmsqlq /dmdata/log -s                          # 出 HTML 报告并自动打开浏览器
     dmsqlq /dmdata/log -s -r 报告.txt              # 想要纯文本版就指定 .txt
     dmsqlq /dmdata/log -S                          # 只扫一眼，什么都不生成
  ② 导出慢 SQL 去复现
     dmsqlq /dmdata/log -m 2000 -o slow.sql         # 超过 2 秒的全部语句
     dmsqlq /dmdata/log -B 20 -N -o slow20.sql      # 最慢的 20 条，纯 SQL
  ③ 按表名 / 用户 / 时间段挑语句
     dmsqlq . -l t_rim_invoice -n 50                # 涉及某张表的语句
     dmsqlq . -u COSMIC_SYS -m 1000                 # 某用户的慢语句
     dmsqlq . -f "2026-09-09 23:52" -t "2026-09-09 23:55" -k SEL,UPD
  ④ 排除干扰项，只看业务慢 SQL
     dmsqlq . -m 1000 -E CAL,DDL                    # 排除调用/DDL 造成的假慢
     dmsqlq . -s -E CAL                             # 统计里也剔除调用类语句
  ⑤ 复现某个事务（业务侧排查）
     dmsqlq x.log -x 10130765548 -N                 # 该事务的全部语句，按时间序
     dmsqlq x.log -x 10130765548 -o trx.sql         # 存文件看
  ⑥ 压缩包直接喂（先解包再分析也行）
     dmsqlq dm_log_20260910.tar.gz -B 10 -o slow.sql
     dmsqlq dmsql_KD1_20260909_235252.log.gz -s
  ⑦ 多个目录 / 通配符一起处理
     dmsqlq D:/dmdbms/log D:/dmsql_log -o all.sql -s
     dmsqlq "dmsql_*.log" -m 500
  ⑧ 日志只有“时间+语句”（SVR_LOG=3 简单模式）
     dmsqlq . -L                                    # 需要 -L 才能解析
  ⑨ 只按类型抽 DDL，或用管道接给别的工具
     dmsqlq . -k DDL -N | head -100
  ⑩ 长事务里到底在干什么（利用率低 = 占着事务不干活）
     dmsqlq . -s -p 10                              # 长事务一节有「SQL 耗时 / 利用率」
     dmsqlq . -x 10131019540 -N                     # 抽出该事务的全部语句
  ⑪ 定期交付给开发商做 SQL 优化（Excel 交付件）
     dmsqlq . -e 交付.xlsx                          # 只要 Excel（清单 200 行）
     dmsqlq . -e 交付.xlsx -p 500                   # 清单要 500 行
     dmsqlq . -s -e 交付.xlsx                       # HTML 自己看 + Excel 发出去
     dmsqlq . -e auto                              # 自动命名 <日志名>_交付.xlsx

日志里能有什么，取决于采集配置（不是解析器的问题）
  没有 PARAMS 参数行  → sqllog.ini 的 SQL_TRACE_MASK 缺 28
  没有耗时/行数       → 缺 24、25        没有锁等待/事务事件 → 缺 29
  没有 [ORA] 原始语句 → 缺 27            没有 [LGN] 登录事件  → 缺 31
  接手陌生库先查：SELECT MODE_NAME,PARA_NAME,PARA_VALUE FROM V$DM_SQLLOG_CONFIG
                   WHERE PARA_NAME IN ('SQL_TRACE_MASK','EXECTIME_PREC_FLAG');
  · 报告里的「采集配置体检」一节会把上面这些一次性列出来（据日志实际内容反推），
    不用自己去对掩码。
  · 耗时单位自动识别：EXECTIME 是 (ms) 还是 (us) 由 EXECTIME_PREC_FLAG 决定，
    本工具读单位并统一换算成毫秒 —— EXECTIME_PREC_FLAG=1 的库不会差 1000 倍。
  · 支持 6 位微秒时间戳（yyyy-MM-dd HH:mm:ss.SSSSSS）与三种锁等待行格式。

退出码
  0 成功   1 未找到日志文件   2 参数或路径错误
`, ver)
	}
}

// regroup 把「选项」与「位置参数」分离，允许 `dmsqlq . -o out.sql -m 100` 这种自然写法
// （Go 标准 flag 包遇到第一个位置参数就停止解析）
func regroup(args []string) (flagArgs, posArgs []string) {
	boolNames := map[string]bool{
		// 长名
		"no-params": true, "no-meta": true, "stats": true, "stats-only": true,
		"loose": true, "all-files": true, "all-ops": true, "loose-key": true,
		"quiet": true, "skip-missing": true, "version": true, "help": true,
		"no-open": true,
		// 短名（漏一个就会把下一个参数当成它的值吞掉）
		"N": true, "P": true, "s": true, "S": true, "L": true, "A": true,
		"K": true, "Y": true, "X": true, "q": true, "V": true, "h": true,
		"d": true, "danger": true, "Q": true,
	}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			posArgs = append(posArgs, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") || boolNames[name] {
				i++
				continue
			}
			if i+1 < len(args) { // 值型选项：连值一起搬过去
				flagArgs = append(flagArgs, args[i+1])
				i += 2
				continue
			}
			i++
			continue
		}
		posArgs = append(posArgs, a)
		i++
	}
	return flagArgs, posArgs
}

func parseArgs(args []string) (*Options, []string, error) {
	o := &Options{}
	fs := flag.NewFlagSet("dmsqlq", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = usage(fs)

	strF := func(p, s, def, usage string) *string {
		v := fs.String(p, def, usage)
		if s != "" {
			fs.StringVar(v, s, def, usage)
		}
		return v
	}
	intF := func(p, s string, def int, usage string) *int {
		v := fs.Int(p, def, usage)
		if s != "" {
			fs.IntVar(v, s, def, usage)
		}
		return v
	}
	floatF := func(p string, def float64, usage string) *float64 {
		return fs.Float64(p, def, usage)
	}
	boolF := func(p, s string, def bool, usage string) *bool {
		v := fs.Bool(p, def, usage)
		if s != "" {
			fs.BoolVar(v, s, def, usage)
		}
		return v
	}

	// 每个选项都带短写；短名尽量取首字母，同类用大小写配对（-m/-M、-k/-K、-s/-S）
	pFrom := strF("from", "f", "", "起始时间")
	pTo := strF("to", "t", "", "结束时间")
	pMin := floatF("min-ms", 0, "")
	fs.Float64Var(pMin, "m", 0, "")
	pMax := floatF("max-ms", 0, "")
	fs.Float64Var(pMax, "M", 0, "")
	pOp := strF("op", "k", "", "")
	pExclOp := strF("exclude-op", "E", "", "")
	pUser := strF("user", "u", "", "")
	pTrx := strF("trx", "x", "", "")
	pObjMap := strF("obj-map", "O", "", "")
	pFull := strF("full-sql", "F", "", "")
	pLike := strF("sql-like", "l", "", "")
	pLimit := intF("limit", "n", 0, "")
	pJobs := intF("jobs", "j", runtime.NumCPU(), "")
	pOut := strF("out", "o", "", "")
	pTerm := strF("term", "T", ";", "")
	pNoParams := boolF("no-params", "P", false, "")
	pNoMeta := boolF("no-meta", "N", false, "")
	pStats := boolF("stats", "s", false, "")
	pStatsOut := strF("stats-out", "r", "", "")
	pStatsOnly := boolF("stats-only", "S", false, "")
	pExcel := strF("excel", "e", "", "")
	pNoOpen := boolF("no-open", "Q", false, "")
	pTop := intF("top", "p", 20, "")
	pTopMS := intF("top-ms", "B", 0, "")
	pVersion := boolF("version", "V", false, "")
	pLoose := boolF("loose", "L", false, "")
	pAll := boolF("all-files", "A", false, "")
	pAllOps := boolF("all-ops", "K", false, "")
	pSkipMissing := boolF("skip-missing", "X", false, "")
	pDanger := boolF("danger", "d", false, "")
	pLooseKey := boolF("loose-key", "Y", false, "")
	pMaxSQL := intF("max-sql", "C", 0, "")
	pQuiet := boolF("quiet", "q", false, "")

	flagArgs, posArgs := regroup(args)
	// 记录"用户显式给了哪些选项"——Excel 交付件想把 -p 默认提到 200 行，
	// 但用户写了 -p 就必须尊重他的数字，不能悄悄改大。
	explicit := map[string]bool{}
	_ = explicit

	if err := fs.Parse(flagArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// 不要再调一次 usage —— flag 包遇到未定义的 -h/--help 时，
			// 已经先调过 f.usage()（把帮助完整打了一遍）才返回 ErrHelp。
			// 这里再打一次就会整篇重复（V2.0 实测 `dmsqlq -h` 输出 328 行 = 164×2）。
			os.Exit(0)
		}
		return nil, nil, err
	}

	o.from, o.to = *pFrom, *pTo
	o.minMS, o.maxMS = *pMin, *pMax
	o.ops, o.user, o.trx, o.sqlLike = *pOp, *pUser, *pTrx, *pLike
	o.objMapFile, o.fullSQL = *pObjMap, *pFull
	o.excludeOps = *pExclOp
	o.limit, o.jobs = *pLimit, *pJobs
	o.out, o.term = *pOut, *pTerm
	o.explicitOut = *pOut != ""
	o.noParams, o.noMeta, o.stats = *pNoParams, *pNoMeta, *pStats
	o.statsOut, o.statsOnly, o.top, o.topMS = *pStatsOut, *pStatsOnly, *pTop, *pTopMS
	o.excelOut = *pExcel
	o.version = *pVersion
	o.loose, o.allFiles, o.looseKey = *pLoose, *pAll, *pLooseKey
	o.allOps = *pAllOps
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	if o.version {
		fmt.Printf("dmsqlq %s (%s %s/%s, %s)\n", ver, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.Compiler)
		os.Exit(0)
	}
	if o.top < 1 {
		o.top = 20
	}
	// -s 与 -S 的分工（2026-09-20 按"高频场景优先"重新划定）：
	//
	//   报告是核心产物 —— 用户明确指定要报告时，大概率就是准备看报告，
	//   不该再逼他补一个 -r 路径才拿到文件。所以 -s 直接生成 HTML 报告。
	//
	//   -S 留给"只想在命令行扫一眼"的简要统计：不写文件、不导 SQL，
	//   适合 SSH 里快速判断"这份日志有没有问题"。
	if o.statsOnly { // -S：命令行简要统计（不出文件、不导 SQL）
		// -S 与 -r 语义互斥：前者说「不生成文件」，后者说「写到这个文件」。
		// 以前是静默把 -r 丢掉（帮助里甚至有个 `-s -S -r 报告.html` 的错例），
		// 用户以为文件生成了、其实没有 —— 这种「静默不生效」必须改成明确报错。
		if o.statsOut != "" || o.excelOut != "" {
			return nil, nil, fmt.Errorf("-S 与 -r/-e 互相矛盾：-S 是「只在屏幕上看统计、不生成任何文件」，" +
				"-r/-e 是「把报告写到文件」。\n" +
				"  要报告文件：用 -s（自动落 HTML）、-s -r 报告.html，或用 -e 交付.xlsx\n" +
				"  只看屏幕：  用 -S（不要带 -r 或 -e）")
		}
		o.stats = true
		o.statsOut = ""
		o.autoReport = false
	} else if o.stats {
		// 未显式给 -r 文件名的纯 -s：自动落一份默认 HTML 报告。
		// 显式给了 -r 就尊重用户的选择，不再额外生成。
		o.autoReport = o.statsOut == ""
	}
	// 行数规则（2026-09-28 定）：
	//   报告（HTML / Markdown / 终端）→ **一律最多 reportTopMax(20) 条**：报告是给人看结论的，
	//                                    时段/排行榜一长就没人读（-p 更小时按 -p 走）。
	//   交付件（-e / -r *.xlsx）      → 行数 = -p（默认 20），调大即导出**完整清单**。
	// ⚠️ V2.1 曾把 -e 的默认行数写进 o.top（200），结果 HTML 也被撑到 200 行，非常臃肿。
	o.excelTop = o.top
	_ = explicit
	if o.topMS > 0 {
		o.jobs = 1 // 全局 Top-N 需要统一视图，关掉多文件并发
	}
	o.skipMissing = *pSkipMissing
	o.dangerOnly = *pDanger
	o.maxSQL, o.quiet = *pMaxSQL, *pQuiet
	o.noOpen = *pNoOpen

	if o.jobs < 1 {
		o.jobs = 1
	}
	if o.term == "none" || o.term == "NONE" || o.term == "-" {
		o.term = ""
	}
	if o.from != "" {
		s, err := normTime(o.from)
		if err != nil {
			return nil, nil, fmt.Errorf("--from 时间格式无法识别: %s", o.from)
		}
		o.fromB = []byte(s)
		if _, isClock := normClock(strings.TrimSpace(o.from)); isClock {
			o.fromTimeOnly = true
		}
	}
	if o.to != "" {
		s, err := normTime(o.to)
		if err != nil {
			return nil, nil, fmt.Errorf("--to 时间格式无法识别: %s", o.to)
		}
		o.toB = []byte(s)
		if _, isClock := normClock(strings.TrimSpace(o.to)); isClock {
			o.toTimeOnly = true
		}
	}
	// 🩸 纯时刻的语义是「每天的这个时段」，必须成对给：
	// 只给起点会退化成「所有天 00:00 之后」这种无意义筛选。
	if o.fromTimeOnly != o.toTimeOnly {
		return nil, nil, fmt.Errorf(
			"--from/--to 请成对给纯时刻（如 -f 09:00 -t 18:00），或两边都带日期")
	}
	if o.ops != "" {
		o.opSet = parseOpList(o.ops)
	}
	if o.excludeOps != "" {
		// -E 同时支持两种写法，二义性由「是否已知事件类型码」自动消解：
		//   · 事件类型码（CAL/DDL/SEL…）    → 按 [类型] 排除
		//   · 其他任意字符串（DBMS_STATS、ANALYZE、T_STAT…）→ 按 SQL 文本子串排除
		// 这样"排除统计信息收集"可以写成 -E CAL,ANALYZE,DBMS_STATS，不必猜日志里的类型码。
		o.exclSet, o.exclLike = parseExcludeList(o.excludeOps)
	}
	// -x 支持多个事务号（逗号分隔）—— 长事务排查时常要一次看好几个
	if o.trx != "" {
		o.trxSet = map[string]bool{}
		for _, p := range strings.Split(o.trx, ",") {
			if p = strings.TrimSpace(p); p != "" {
				o.trxSet[p] = true
			}
		}
	}
	if o.objMapFile != "" {
		m, err := loadObjMap(o.objMapFile)
		if err != nil {
			return nil, nil, fmt.Errorf("读取 --obj-map 失败: %w", err)
		}
		o.objMap = m
	}
	return o, posArgs, nil
}

// tableNameOf 应用「对象 ID → 表名」映射；没有映射时返回空（渲染退化为只显示 ID）
func tableNameOf(id string, m map[string]string) string {
	if m == nil {
		return ""
	}
	return m[id]
}

// loadObjMap 读取「对象 ID → 表名」映射，用于把锁等待里的 table id 翻译成表名。
// 宽松解析：每行认「第一个纯数字」为 ID、「其后第一个非数字」为表名，
// 所以从库上查出来的结果可以直接粘贴（带表头、空格/制表符/竖线分隔都行）。
// 文件请存为 UTF-8（GBK 的中文表名会乱码）。
func loadObjMap(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "--") {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool {
			switch r {
			case '=', ' ', '\t', ',', '|', ':', ';', '"', '\'':
				return true
			}
			return false
		})
		var id, name string
		for _, f := range fields {
			if f == "" {
				continue
			}
			if id == "" {
				if isAllDigits(f) {
					id = f
				}
				continue
			}
			if !isAllDigits(f) {
				name = f
				break
			}
		}
		if id != "" && name != "" {
			m[id] = name
		}
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("没解析出任何映射（每行需要「对象ID 表名」，例如 10175=T_RIM_VOUCH_ORDER）")
	}
	return m, nil
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// parseOpList 把 "CAL, DDL" 解析成集合（统一大写）
func parseOpList(s string) map[string]bool {
	m := map[string]bool{}
	for _, p := range strings.Split(strings.ToUpper(s), ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			m[p] = true
		}
	}
	return m
}

// knownOps 日志里出现的 SQL 事件类型码（用于区分「类型」与「SQL 子串」）
var knownOps = map[string]bool{
	"SEL": true, "INS": true, "UPD": true, "DEL": true, "DML": true,
	"DDL": true, "CAL": true, "ERR": true, "ORA": true, "LGN": true,
}

// parseExcludeList 拆出类型码与 SQL 子串两种排除条件
func parseExcludeList(s string) (ops map[string]bool, likes []string) {
	ops = map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if up := strings.ToUpper(p); knownOps[up] {
			ops[up] = true
		} else {
			likes = append(likes, p) // 保留原大小写（匹配本身忽略大小写）
		}
	}
	return ops, likes
}

// normTime 把各种简写补全成 "yyyy-MM-dd HH:mm:ss"（19 字符，可字典序比较）
func normTime(s string) (string, error) {
	s = strings.TrimSpace(s)
	switch len(s) {
	case 10: // yyyy-MM-dd
		return s + " 00:00:00", nil
	case 13: // yyyy-MM-dd HH
		return s + ":00:00", nil
	case 16: // yyyy-MM-dd HH:mm
		return s + ":00", nil
	}
	if len(s) >= 19 {
		if s[10] == 'T' || s[10] == '_' { // ISO 8601 习惯的分隔符
			s = s[:10] + " " + s[11:]
		}
		return s[:19], nil
	}
	// ---- 纯时刻：HH / HH:mm / HH:mm:ss（用于「只看每天这个时段」）----
	if t, ok := normClock(s); ok {
		return t, nil
	}
	return "", fmt.Errorf("bad time")
}

// normClock 识别纯时刻写法并归一成 "HH:mm:ss"。ok=false 表示不是纯时刻。
func normClock(s string) (string, bool) {
	isD := func(b byte) bool { return b >= '0' && b <= '9' }
	switch len(s) {
	case 2: // HH
		if isD(s[0]) && isD(s[1]) {
			return s + ":00:00", true
		}
	case 5: // HH:mm
		if isD(s[0]) && isD(s[1]) && s[2] == ':' && isD(s[3]) && isD(s[4]) {
			return s + ":00", true
		}
	case 8: // HH:mm:ss
		if isD(s[0]) && isD(s[1]) && s[2] == ':' && isD(s[3]) && isD(s[4]) &&
			s[5] == ':' && isD(s[6]) && isD(s[7]) {
			return s, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------- 记录判定

// epTag 是"新记录"的强判据尾巴：DM 的会话块一定以 ` (EP[` 开头（EP = Execution Point，单机恒为 0）。
// 老版本 DM 日志没有 EP 段（会话块直接以 `sess:` 开头），那条路走宽松判据。
var epTag = []byte(" (EP[")

// tsLen 返回行首合法时间戳的长度（23 = 毫秒 / 26 = 微秒 / 19 = 无毫秒），0 表示不是时间戳。
//
// 判据与 DM 官方解析工具（Web 版 DateTimeUtils.detectTimestampEnd）逐条对齐：
//  1. 长度 >= 19，第 4/7/10/13/16/19 位必须是 '-' '-' ' ' ':' ':' '.'，其余为数字；
//  2. 小数位只接受 3 位或 6 位（DM 7.5GB 现网样本里 6 位为 0 条，但官方 v1.4.7 起支持）；
//  3. 第 19 位不是 '.' 的（如 `2026-09-09 23:54:09:009#1300`）直接拒掉 —— 那是
//     「参数值里带换行的续行」，宽松判据会把它当新记录，把一条 SQL 劈成两三条。
func tsLen(l []byte) int {
	if len(l) < 19 {
		return 0
	}
	if !(l[0] >= '0' && l[0] <= '9' && l[1] >= '0' && l[1] <= '9' &&
		l[2] >= '0' && l[2] <= '9' && l[3] >= '0' && l[3] <= '9' && l[4] == '-' &&
		l[5] >= '0' && l[5] <= '9' && l[6] >= '0' && l[6] <= '9' && l[7] == '-' &&
		l[8] >= '0' && l[8] <= '9' && l[9] >= '0' && l[9] <= '9' && l[10] == ' ' &&
		l[11] >= '0' && l[11] <= '9' && l[12] >= '0' && l[12] <= '9' && l[13] == ':' &&
		l[14] >= '0' && l[14] <= '9' && l[15] >= '0' && l[15] <= '9' && l[16] == ':' &&
		l[17] >= '0' && l[17] <= '9' && l[18] >= '0' && l[18] <= '9') {
		return 0
	}
	if len(l) == 19 {
		return 19
	}
	if l[19] == ' ' || l[19] == '\t' { // 无毫秒：SVR_LOG=3 简单模式 / 老格式
		return 19
	}
	if l[19] != '.' || len(l) < 23 {
		return 0
	}
	if !isDig3(l[20]) || !isDig3(l[21]) || !isDig3(l[22]) {
		return 0
	}
	if len(l) == 23 || l[23] == ' ' || l[23] == '\t' {
		return 23
	}
	// 6 位微秒（yyyy-MM-dd HH:mm:ss.SSSSSS）
	if len(l) >= 26 && isDig3(l[23]) && isDig3(l[24]) && isDig3(l[25]) &&
		(len(l) == 26 || l[26] == ' ' || l[26] == '\t') {
		return 26
	}
	return 0
}

func isDig3(c byte) bool { return c >= '0' && c <= '9' }

// newRecLen 判定"这一行是不是一条新记录"，返回其时间戳长度（0 = 不是）。
//
// strictEP=true 时要求时间戳后紧跟 ` (EP[` —— 这是官方 Web 版 detectNewLineBoundary 的做法：
// 本机 7.5GB / 26,799,837 条合法时间戳行里，"后随不是 ` (EP[`" 的有 **0 条**，
// 说明它在本机现网样本上既充分又必要。早期版本只认"时间戳 + 空格"，遇到
// `2026-09-10 00:03:07.007 xxx` 这类长字符串续行仍会误切，故收严。
// 若某文件压根没有 EP 段（老 DM / SVR_LOG=3），调用方会自动切到 strictEP=false。
func newRecLen(l []byte, strictEP bool) int {
	n := tsLen(l)
	if n == 0 {
		return 0
	}
	if n == len(l) { // 行里只有时间戳
		return n
	}
	if l[n] != ' ' && l[n] != '\t' {
		return 0
	}
	if bytes.HasPrefix(l[n:], epTag) {
		return n
	}
	if strictEP {
		return 0
	}
	return n
}

// isTS 兼容旧调用：按宽松判据判定（用于"是否以时间戳开头"的粗筛）
func isTS(l []byte) bool { return tsLen(l) > 0 }

// ---------------------------------------------------------------- 参数解析

type Param struct{ typ, val string }

// parseParams 解析 "{ (0, BIGINT, 1), (1, VARCHAR2, 'a,b'), (2, TEXT, ) }"
// 关键：值按「引号感知 + 括号深度」扫描，含逗号/括号/单引号的值不会被切断。
// countParams 只数参数个数，不构造 Param（惰性解析的快路径）。
//
// 🩸 必须与 parseParams 的计数口径完全一致，否则 pop 的 len(ps)==nth
// 匹配会错位、参数还原整体失效。这里的扫描逻辑与 parseParams 同构。
func countParams(s []byte) int {
	n := 0
	i, ln := 0, len(s)
	for i < ln {
		for i < ln && s[i] != '(' {
			i++
		}
		if i >= ln {
			break
		}
		i++ // '('
		j := i
		for j < ln && s[j] != ',' {
			j++
		}
		if j >= ln {
			break
		}
		i = j + 1 // 跳过 seqno
		for i < ln && s[i] == ' ' {
			i++
		}
		j = i
		for j < ln && s[j] != ',' {
			j++
		}
		if j >= ln {
			break
		}
		i = j + 1 // 跳过 type
		// ---- 值：直到深度 0 的 ')' 为止；单引号内 '' 为转义 ----
		depth := 0
		for i < ln {
			c := s[i]
			if c == '\'' {
				i++
				for i < ln {
					if s[i] == '\'' {
						if i+1 < ln && s[i+1] == '\'' {
							i += 2
							continue
						}
						i++
						break
					}
					i++
				}
				continue
			}
			if c == '(' {
				depth++
				i++
				continue
			}
			if c == ')' {
				if depth == 0 {
					i++
					break
				}
				depth--
				i++
				continue
			}
			i++
		}
		n++
	}
	return n
}

func parseParams(s []byte) []Param {
	var out []Param
	i, n := 0, len(s)
	for i < n {
		for i < n && s[i] != '(' {
			i++
		}
		if i >= n {
			break
		}
		i++ // '('
		j := i
		for j < n && s[j] != ',' {
			j++
		}
		if j >= n {
			break
		}
		i = j + 1 // 跳过 seqno
		for i < n && s[i] == ' ' {
			i++
		}
		j = i
		for j < n && s[j] != ',' {
			j++
		}
		if j >= n {
			break
		}
		typ := strings.TrimSpace(string(s[i:j]))
		i = j + 1
		// ---- 值：直到深度 0 的 ')' 为止；单引号内 '' 为转义 ----
		vs, depth := i, 0
		for i < n {
			c := s[i]
			if c == '\'' {
				i++
				for i < n {
					if s[i] == '\'' {
						if i+1 < n && s[i+1] == '\'' {
							i += 2
							continue
						}
						i++
						break
					}
					i++
				}
				continue
			}
			if c == '(' {
				depth++
				i++
				continue
			}
			if c == ')' {
				if depth == 0 {
					break
				}
				depth--
				i++
				continue
			}
			i++
		}
		out = append(out, Param{typ, strings.TrimSpace(string(s[vs:i]))})
		if i < n {
			i++ // ')'
		}
	}
	return out
}

// formatVal 把参数值转成可直接嵌入 SQL 的字面量
func formatVal(p Param) string {
	v := strings.TrimSpace(p.val)
	if v == "" {
		return "NULL" // 空值 -> NULL（官方输出空串会拼出非法的 ",,"）
	}
	if v[0] == '\'' {
		return v // 已带引号的字符串/日期，原样
	}
	ut := strings.ToUpper(p.typ)
	if strings.Contains(ut, "DATE") || strings.Contains(ut, "TIME") {
		return "'" + strings.ReplaceAll(v, "'", "''") + "'" // 老格式无引号的时间值补引号
	}
	return v
}

// findPlaceholders 返回 SQL 中「字面量/注释之外」的 '?' 的下标。
// 官方用 replaceFirst 无差别替换，SQL 里的 '?' 字面量会占用参数名额，这里做了隔离。
func findPlaceholders(sql []byte) []int {
	var pos []int
	i, n := 0, len(sql)
	for i < n {
		switch sql[i] {
		case '\'':
			i++
			for i < n {
				if sql[i] == '\'' {
					if i+1 < n && sql[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case '"': // DM 里双引号是标识符引用
			i++
			for i < n {
				if sql[i] == '"' {
					i++
					break
				}
				i++
			}
		case '-':
			if i+1 < n && sql[i+1] == '-' {
				for i < n && sql[i] != '\n' {
					i++
				}
			} else {
				i++
			}
		case '/':
			if i+1 < n && sql[i+1] == '*' {
				i += 2
				for i+1 < n && !(sql[i] == '*' && sql[i+1] == '/') {
					i++
				}
				i += 2
				if i > n {
					i = n
				}
			} else {
				i++
			}
		case '?':
			pos = append(pos, i)
			i++
		default:
			i++
		}
	}
	return pos
}

// applyParams 按占位符下标逐位替换（不用 replaceFirst，避免把值里的 ? 也当占位符）
func applyParams(sql []byte, ph []int, vals []string) []byte {
	var b bytes.Buffer
	b.Grow(len(sql) + 64)
	last := 0
	for k, p := range ph {
		if k >= len(vals) || p < last || p >= len(sql) {
			break
		}
		b.Write(sql[last:p])
		b.WriteString(vals[k])
		last = p + 1
	}
	b.Write(sql[last:])
	return b.Bytes()
}

// ---------------------------------------------------------------- 参数缓存

// pgroup 是一组 PARAMS（对应一次 bind）。同一组会同时登记在**两个键**下：
//
//	① 严格键 = 会话块(到 trxid 前，含 thrd/user) + stmt 句柄 —— 精确，但线程漂移就找不到
//	② 句柄键 = 仅 stmt 句柄 —— 官方 Web 版默认策略，不含 thrd/user/trxid，抗线程漂移
//
// 取用时先试严格键、再退回句柄键；命中后从两个键里都摘掉，绝不重复消费。
// 官方桌面版只有 ①（线程一漂就留一堆 `?`），Web 版只有 ②（可能串到别的会话）——
// 两级匹配把两者的优点合起来，实测命中率只升不降。
type pgroup struct {
	ps   []Param // 惰性解析：pop 命中前为 nil
	keys []uint64
	// raw 参数的原始字节（形如 "(0, BIGINT, 123), (1, ...)"），延迟到 pop 时解析。
	// 🩸 必须独立于读取缓冲区：processStream 的 buf 会被反复复用，
	// 直接存切片会读到后续数据。所以 push 时复制一份。
	raw   []byte
	count int
}

type paramCache struct {
	m     map[uint64][]*pgroup // key -> 参数组队列（FIFO）
	ring  []uint64
	next  int
	count int
}

func newParamCache() *paramCache {
	return &paramCache{m: make(map[uint64][]*pgroup, 4096), ring: make([]uint64, maxKeys)}
}

// drop 把一组参数从它登记过的所有键里摘掉
func (c *paramCache) drop(g *pgroup) {
	for _, k := range g.keys {
		q := c.m[k]
		for i := range q {
			if q[i] == g {
				q = append(q[:i], q[i+1:]...)
				break
			}
		}
		if len(q) == 0 {
			if _, ok := c.m[k]; ok {
				delete(c.m, k)
				c.count--
			}
		} else {
			c.m[k] = q
		}
	}
}

// push 惰性登记一组参数。
//
// 🩸 raw 必须复制：调用方的字节来自 processStream 的复用缓冲区。
// 复制成本远低于 parseParams（一次 memmove vs 逐字段切割 + 堆分配）。
func (c *paramCache) pushRaw(key, altKey uint64, raw []byte, count int) {
	buf := make([]byte, len(raw))
	copy(buf, raw)
	c.pushGroup(&pgroup{raw: buf, count: count, keys: nil}, key, altKey)
}

func (c *paramCache) push(key, altKey uint64, ps []Param) {
	c.pushGroup(&pgroup{ps: ps, count: len(ps)}, key, altKey)
}

func (c *paramCache) pushGroup(g *pgroup, key, altKey uint64) {
	g.keys = []uint64{key}
	if altKey != 0 && altKey != key {
		g.keys = append(g.keys, altKey)
	}
	for _, k := range g.keys {
		q := c.m[k]
		if len(q) >= perKeyLimit { // 同键队列过长：丢最旧的一组
			c.drop(q[0])
			q = c.m[k]
		}
		if _, ok := c.m[k]; !ok {
			if c.count >= maxKeys { // 环形淘汰最旧的键
				old := c.ring[c.next]
				for _, g2 := range c.m[old] {
					for _, kk := range g2.keys {
						if qq := c.m[kk]; len(qq) > 0 {
							for j := range qq {
								if qq[j] == g2 {
									qq = append(qq[:j], qq[j+1:]...)
									break
								}
							}
							if len(qq) == 0 {
								delete(c.m, kk)
							} else {
								c.m[kk] = qq
							}
						}
					}
				}
				delete(c.m, old)
				c.count--
			}
			c.ring[c.next] = k
			c.next = (c.next + 1) % maxKeys
			c.count++
		}
		c.m[k] = append(c.m[k], g)
	}
}

// pop 取出占位符个数正好等于 nth 的最早一组参数；找不到就不动缓存
// （个数不等时强行替换必然错位，宁可标记未还原）
func (c *paramCache) pop(key uint64, nth int) ([]Param, bool) {
	q, ok := c.m[key]
	if !ok {
		return nil, false
	}
	for i := range q {
		if q[i].count != nth {
			continue
		}
		g := q[i]
		ps := g.ps
		if ps == nil && g.raw != nil { // 惰性解析：这是第一次真正需要它的内容
			ps = parseParams(g.raw)
		}
		c.drop(g)
		return ps, true
	}
	return nil, false
}

// countAllQ 统计 SQL 里所有 '?'（含字符串字面量内的）
// —— DM 会把 `like '?'` 这类字面量里的 ? 也算作一个参数槽位，
//
//	引号感知扫描会少算，此时用这个计数再试一次。
func countAllQ(sql []byte) int {
	n := 0
	for _, b := range sql {
		if b == '?' {
			n++
		}
	}
	return n
}

// allQPos 返回 SQL 中所有 '?' 的下标（不做引号隔离，对应 countAllQ 的语义）
func allQPos(sql []byte) []int {
	var pos []int
	for i, b := range sql {
		if b == '?' {
			pos = append(pos, i)
		}
	}
	return pos
}

// ---------------------------------------------------------------- 统计

// Agg 次数 / 累计耗时 / 最大耗时
type Agg struct {
	Count  int64
	SumMS  float64
	MaxMS  float64
	MinMS  float64  // 最快一次（配合平均看波动：最快≈平均=结构性问题；最快≪平均=计划/数据不稳）
	hasMin bool     // MinMS 是否已赋值（0ms 也是合法值，不能用 0 当"未初始化"）
	H      *logHist // 耗时分位直方图（只对类型/用户/客户端这类少量维度分配）
}

func (a *Agg) add(ms float64) {
	a.Count++
	a.SumMS += ms
	if ms > a.MaxMS {
		a.MaxMS = ms
	}
	if !a.hasMin || ms < a.MinMS {
		a.MinMS, a.hasMin = ms, true
	}
	if a.H != nil {
		a.H.add(ms)
	}
}

// newAgg 建一个带分位直方图的聚合
func newAgg() *Agg { return &Agg{H: &logHist{}} }

// lhBuckets：对数直方图档数。每档跨 10^(1/16) ≈ 1.155 倍，
// 160 档覆盖 1us ~ 1000s，桶内插值后的分位误差 < 2%。
const lhBuckets = 160

// logHist 对数分档的耗时直方图 —— 用来算 P50/P90/P95/P99。
//
// 为什么不用"排序取分位"：3 亿条记录不可能全留；也不用线性分档：
// 耗时跨 6 个数量级（0.01ms ~ 10min），线性档要么糊在低端要么撑爆内存。
// 160 个 int64 = 1.28KB，对类型/用户这种几十个的维度完全无压力。
type logHist struct {
	n     int64
	zero  int64 // 耗时为 0（或负数）的条数，单独记，否则对数桶放不下
	maxMS float64
	b     [lhBuckets]int64
}

func (h *logHist) add(ms float64) {
	h.n++
	if ms > h.maxMS {
		h.maxMS = ms
	}
	if ms <= 0 {
		h.zero++
		return
	}
	us := ms * 1000 // 以微秒为刻度，1us 起步
	if us < 1 {
		us = 1
	}
	i := int(math.Log10(us) * 16)
	if i < 0 {
		i = 0
	}
	if i >= lhBuckets {
		i = lhBuckets - 1
	}
	h.b[i]++
}

// minApprox 用「最低非空桶的下沿」近似最小耗时（毫秒）。
//
// 桶按 10^(i/16) 分档（每档约 1.155 倍），所以误差 ≤15% —— 对它的用途完全够：
// 判断「日志里最小 EXECTIME 是不是恰好卡在某个整数阈值上」，
// 从而识别采集侧的 MIN_EXEC_TIME（低于该值的语句根本不写日志）。
//
// 🩸 刻意不新增热路径字段：整份日志的最小值要么在桶里推、要么就得在每个 SQL 事件上
// 多写一个共享标量 —— 见「溯源缓冲别挂共享 Stats」那条教训（并发写共享字段会因
// 缓存行争用拖慢扫描）。这里纯靠报告期已有的桶算，零采集开销。
func (h *logHist) minApprox() float64 {
	if h.zero > 0 {
		return 0
	}
	for i := 0; i < lhBuckets; i++ {
		if h.b[i] > 0 {
			return math.Pow(10, float64(i)/16) / 1000 // µs → ms
		}
	}
	return 0
}

// quantile 返回 p 分位耗时（毫秒）。p ∈ (0,1]
func (h *logHist) quantile(p float64) float64 {
	if h == nil || h.n == 0 {
		return 0
	}
	target := int64(p*float64(h.n) + 0.999)
	if target < 1 {
		target = 1
	}
	if h.zero >= target {
		return 0
	}
	cum := h.zero
	for i := 0; i < lhBuckets; i++ {
		c := h.b[i]
		if c == 0 {
			continue
		}
		if cum+c >= target {
			frac := float64(target-cum) / float64(c)
			lo := math.Pow(10, float64(i)/16) // 档下界（us）
			hi := math.Pow(10, float64(i+1)/16)
			return (lo + (hi-lo)*frac) / 1000
		}
		cum += c
	}
	return math.Pow(10, float64(lhBuckets)/16) / 1000
}

// Mean 平均值（有直方图就能自算，不必依赖 SumMS）
func (h *logHist) Mean(sumMS float64) float64 {
	if h == nil || h.n == 0 {
		return 0
	}
	return sumMS / float64(h.n)
}

// TplAgg 语句模板聚合（同一模板按字面量归一化后合并）
type TplAgg struct {
	Agg
	Sample string
}

// slowRec 最慢语句（报告用摘要）
type slowRec struct {
	TS     string
	MS     float64
	Rows   string
	User   string
	Op     string
	File   string
	SQL    string
	ExecID string
}

// 耗时直方图分桶（毫秒）
var (
	histEdges = []float64{1, 10, 100, 1000, 10000, 60000}
	histNames = []string{"<1ms", "1-10ms", "10-100ms", "100ms-1s", "1-10s", "10-60s", ">=60s"}
)

const maxTpl = 60000 // 模板表上限，防超大日志吃内存

// maxFullSQL 单条"完整 SQL"缓存上限。
// 报告里要显示截断的摘要（好看），但溯源要能拿到全文 —— 所以 TopN 语句在内存里保留完整文本，
// 渲染时才截断。只对 TopN（几十条）生效，64KB × 几十条最多几 MB。
const maxFullSQL = 64 << 10

// maxInlineSQL 报告内嵌"完整 SQL"的总预算。
//
// 内嵌让报告真正做到「看到即拿到」（点击展开 / 悬停预览 / 一键复制），且仍是单文件、
// 零依赖。但报告要是被撑到几十 MB，浏览器打开和翻页都会明显卡；而审计命中在大日志上
// 可达上万条 —— 全部内嵌不可取。
//
// 2MB 是按实测定的：只嵌「最慢语句 + 最耗模板 + 审计 + 长事务」这些本来就在内存里的
// 集合时，1GB 日志的报告约 1MB 上下，浏览依然瞬时。超出预算的行自动退回
// 「摘要 + 悬停预览」，并提示去配套 .full.sql 附件拿全文。
const maxInlineSQL = 2 << 20

// inlineBudget 本次报告剩余可内嵌的字节数（渲染前由 resetInlineBudget 重置）。
// 单文件顺序渲染，用包级变量比到处传参更省事；不是并发安全的，也无需并发安全。
var inlineBudget = maxInlineSQL

func resetInlineBudget() { inlineBudget = maxInlineSQL }

// lockWait 一条真实的锁等待事件（掩码 29）
//
// 现网真实格式（官方 DMLOG 的判据 `] wait for LOCK_` 在 7.5GB 日志里命中 0 次，已失效）：
//
//	trx[10130794909] LOCK_TID (mode:X, table id:10175) wait for 1 trxs, trx[10130794908] used time:5(ms)
type lockWait struct {
	TS            string
	User          string
	File          string
	Waiter        string  // 等待方事务号
	Holder        string  // 持有方事务号（多个时逗号分隔）
	Mode          string  // 锁模式（X / S / IX …）
	TableID       string  // 表 ID
	Waiters       int64   // 声明被等事务数
	MS            float64 // 等待时长，统一换算成毫秒
	More          bool    // 持有方列表含 "...more"（日志侧截断）
	CountMismatch bool    // 声明个数 ≠ 实际列出个数（格式变体，值得关注）
}

// lockTableAgg 按表聚合的锁等待
type lockTableAgg struct {
	Count int64
	SumMS float64
	MaxMS float64
	Mode  string
	Users map[string]bool // 涉及的等待方用户（去重，控量）
	MaxAt string          // 最长一次等待的时间
}

// trxStmtRec 一条归属到具体事务的语句（锁等待溯源用，V2.8）。
//
// 为什么按事务存语句：锁等待行只给「等待方 trxid / 持有方 trxid」，
// 而现场真正想知道的是「到底哪条 SQL 在持锁、哪条 SQL 被卡住」。
// 实测执行行带真实 trxid（非 0），据此可反查。
//
// 🩸 但不能假设一定查得到：语句文本的采集受掩码 2~17 控制，
// 本批现网日志 80 次锁等待里只有 35% 的持有方能查到语句文本，
// 其余只留下 `TRX: START` / `PARAMS` / `alloc pseg`。取不到时必须**显式说明**，
// 而不是留空 —— 留空会被读成"这个事务没跑语句"，与"语句没记进日志"是两回事。
//
// 🩸 也**不能**改用语句句柄 `stmt:0x…` 关联：它是会话命令缓冲的地址，会被复用
// （实测同一个句柄 6 分钟后挂到另一条完全不同的语句上），拿它当键必然串错。
type trxStmtRec struct {
	TrxID string
	TS    string
	Op    string
	MS    float64
	Rows  string
	SQL   string
}

// trxEndRec 一次「带真实 trxid 的事务结束事件」（COMMIT / ROLLBACK）。
type trxEndRec struct {
	TrxID string
	TS    string
	Kind  string
}

// trxActivity 一个事务在日志里的可见活动（报告期按需归并出来的视图）。
//
// 🩸 采集期**不用** map[trxid]*trxActivity 逐事务建对象：现网执行行可达十万级，
// 每个事务建一个结构体 + 一条切片，实测让 2.0 GB 的扫描从 2.28s 涨到 2.66s（+14%）。
// 改成一根扁平数组追加（摊销 O(1)、无小对象），报告期只对**锁等待涉及的那几个
// 事务**做一次归并 —— 锁等待是百级，归并代价可忽略。
//
// 🩸 这里也刻意**不**记「PARAMS 行数」：PARAMS 行百万级，两种记账方式
// （string 键 / 零分配 uint64 键）都把扫描拖到 3.8~4.3s，不值得。
// 「语句文本没采到」用 Stmts 是否为空即可判：有=采到了，空=没进日志。
type trxActivity struct {
	Kind      string // 最后一次事件：START / COMMIT / ROLLBACK
	EndTS     string // 结束事件的时间（COMMIT/ROLLBACK 才有）
	Stmts     []trxStmtRec
	StmtTotal int64
}

// 锁等待行正则：锚点必须是 LOCK_TID + wait for 同时出现
// （不能只匹配 LOCK_ —— 日志里 LOCK_R3 / LOCK_MONITOR 之类表名会造成大量误判）
//
// 注意持有方可能是**多个事务**，日志写成 trx[10130987610, 10130987611]（逗号 + 空格分隔）。
// 早期版本只认单个数，导致等待 2 个以上事务的行（实测占 35%）被整条丢掉。
// 锁等待的三条正则（对应 DM 现网出现过的三种行格式）。
// 官方 Web 版 v1.5.3 也是这三条，实测 7.3GB 现网日志 1,375/1,375 = 100% 命中。
// 单位一律同时吃 (ms|us|ns) —— 老版本写死 "(ms)"，在 (us) 行上会越界。
var (
	// ① 单阻塞方，带 tid[]
	reLockSingle = regexp.MustCompile(`^trx\[(\d+)\]\s+LOCK_TID\s+\(mode:([^,)]+),\s*table\s+id:(\d+),\s*tid\[([\d,\s]+)\]\s*\)\s+wait\s+used\s+time:(\d+)\((ms|us|ns)\)`)
	// ② 多阻塞方（现网主流形态）
	reLockMulti = regexp.MustCompile(`^trx\[(\d+)\]\s+LOCK_TID\s+\(mode:([^,)]+),\s*table\s+id:(\d+)\)\s+wait\s+for\s+(\d+)\s+trxs?,\s*trx\[([^\]]+)\]\s+used\s+time:(\d+)\((ms|us|ns)\)`)
	// ③ 更老的格式（1.2.138 等）：判据串在 wait for 之后
	reLockOld = regexp.MustCompile(`^trx\[(\d+)\]\s+wait\s+for\s+LOCK_TID\s+\(mode:([^,)]+),\s*table\s+id:(\d+)\s*\)?\s*,?\s*tid\[([\d,\s]+)\]\s*\)\s+used\s+time:(\d+)\((ms|us|ns)\)`)
	// 内容段里出现这个串才值得去试上面三条（现网 115,380 条 `trx[..] alloc pseg page[...]`
	// 也以 trx[ 开头，靠它提前退出，省掉一次正则）
	lockTidTag = []byte("LOCK_TID")
	// TRX: COMMIT LSN[141832342617] —— 恢复定位要用的提交 LSN
	reLSN = regexp.MustCompile(`LSN\[(\d+)\]`)
)

// DLCK 行：锁操作符（执行计划节点）自身耗时，单位是 us，**不是锁等待**
var reDlck = regexp.MustCompile(`^DLCK used time:(\d+)\((us|ms)\)`)

// 锁等待时长分布（毫秒）
var (
	lockEdges = []float64{10, 100, 1000, 10000}
	lockNames = []string{"<10ms", "10-100ms", "100ms-1s", "1-10s", ">=10s"}
)

// tableAgg 单表聚合（热表统计）
type tableAgg struct {
	Count  int64 // 涉及该表的语句数
	Reads  int64 // 作为读取源（SEL/JOIN/FROM）
	Writes int64 // 作为写入目标（INS/UPD/DEL 的目标表）
	SumMS  float64
	MaxMS  float64
	ByOp   map[string]int64 // 各类语句对该表的操作次数
}

// secAgg 按秒聚合（QPS/TPS 与时间轴热点）
type secAgg struct {
	SQL      int64 // 该秒的 SQL 事件数
	Commit   int64
	Rollback int64
	SumMS    float64
}

type Stats struct {
	Files, Records, Exec, Skipped int64
	Out, NoParams, Matched        int64
	Mismatch, Missing, Filtered   int64
	Excluded                      int64 // 被 -E 排除（连统计也不计入）的语句数
	Bytes                         int64
	slowN                         int   // 最慢语句 Top-N 的 N
	execIDSeen                    int64 // 带 EXEC_ID 的执行行数（能否下钻 V$SQL_NODE_HISTORY）

	ByOp       map[string]*Agg
	ByUser     map[string]*Agg
	ByClient   map[string]*Agg // 按 appname/ip 聚合的客户端
	ByTable    map[string]*tableAgg
	Sec        map[int64]*secAgg // unix 秒 → 该秒的负载
	SpanFirst  string            // 日志时间跨度（首个/末个 SQL 事件时间）
	SpanLast   string
	Hist       [7]int64
	H          *logHist // 全局耗时分位直方图（P50/P90/P95/P99）
	Slow       []slowRec
	Tpl        map[string]*TplAgg
	TplFull    bool
	TrxFirst   map[string]string // trxid -> 首次事件时间（长事务跨度的依据）
	TrxLast    map[string]string
	TrxCount   map[string]int64
	TrxKind    map[string]string  // trxid -> 最后一次事件类型（START/COMMIT/ROLLBACK/SQL）
	TrxUser    map[string]string  // trxid -> 该事务的用户（用于回答"谁在持锁"）
	TrxExecMS  map[string]float64 // trxid -> 该事务内 SQL 累计执行耗时（算"事务利用率"用）
	TrxFirstMS map[string]float64 // trxid -> 该事务第一条 SQL 的耗时（利用率分母的修正项）
	// 锁等待溯源（V2.8）：扁平追加存放，报告期只对锁等待涉及的事务做归并。
	// 用扁平数组而不是 map[trxid]*trxActivity —— 后者每个事务一个对象 + 一条切片，
	// 十万级执行行下实测让扫描慢 14%（详见 trxActivity 注释）。
	trxStmts []trxStmtRec
	trxEnds  []trxEndRec
	trxFull  bool
	// V2.12：掩码 27 的 [ORA] 行（(sess,thrd,stmt) 键 → 原始 SQL）与「事务号 → 语句键」。
	// 二者配合，把"执行行被 MIN_EXEC_TIME 滤掉"的持有方 SQL 兜底找回来。
	// 只有日志开了位 27 才非空；没开时全程 nil（零额外内存）。
	oraSQL      map[uint64]string
	oraKeyByTrx map[uint64]uint64
	Commits     int64     // TRX: COMMIT 次数
	Rollbacks   int64     // TRX: ROLLBACK 次数
	agg         bool      // 是否需要做完整聚合（未要统计报告时全跳过）
	TopMSList   []topStmt // --top-ms 缓存

	// 锁（掩码 29）
	LockN        int64
	LockSumMS    float64
	LockMaxMS    float64
	LockHist     [5]int64
	Locks        []lockWait
	LockByTable  map[string]*lockTableAgg
	LockUnparsed int64 // 长得像锁行但没匹配上正则（格式变体告警）
	DlckN        int64 // DLCK 锁操作计时行
	DlckNonZero  int64 // 其中 used time > 0 的
	DlckMaxMS    float64
	LockBySec    map[int64]int64 // 秒 → 该秒的锁等待次数（用于和 QPS 峰值对齐）
	LockMoreN    int64           // 持有方列表被 "...more" 截断的次数
	LockCountMis int64           // 声明被等事务数 ≠ 实际列出数（格式变体告警）

	// 耗时单位计数（掩码 25 的 EXECTIME 单位由 EXECTIME_PREC_FLAG 决定）
	UnitMS, UnitUS, UnitNS, UnitNone int64

	// 审计（危险操作 / 结构变更 / 恢复定位）
	Dangers   []auditRec
	Changes   []auditRec
	changeN   int
	ChangeN   map[string]int64
	LastDDL   map[string]string
	LSNBucket map[int64]lsnRef
	auditFull bool
	pend      []pendRef
	BatchDML  int64            // 批量删除/更新（影响行数超阈值）命中数
	DDLVerb   map[string]int64 // DDL 的首词分布（STAT / CREATE / ALTER …）
	ddlVerbMu sync.Mutex

	// 采集配置体检（据日志内容反推 sqllog.ini 掩码开了哪些位）
	ParamsN      int64 // PARAMS 行数（掩码 28）
	TrxEventN    int64 // TRX: START 行数（掩码 29）
	TrxEndN      int64 // TRX: COMMIT/ROLLBACK 行数（掩码 29）
	OraN         int64 // [ORA] 行数（掩码 27）
	LgnN         int64 // [LGN] 行数（掩码 31）
	ErrN         int64 // [ERR(...)] 行数（掩码 23）
	ErrCodes     map[string]int64
	ErrMS        map[string]float64 // 错误码 → 累计执行耗时（-608 这类"每次卡 60s"的错误靠它现形）
	NoExecN      int64              // 有 SQL 文本但没有 EXECTIME 的执行行（掩码 24/25 未开）
	EPSeen       int64              // 见到 "(EP[" 会话块的行数（0 = 老格式日志）
	WinSkew      int64              // 落在 -f/-t 窗口之外、被排除出统计的语句数
	Ts26         int64              // 26 位（微秒）时间戳行数
	MatchedLoose int64              // 靠"句柄键"（不含 thrd）兜底匹配成功的次数

	seenNames map[string]bool // 已处理的日志名（查重：散装日志 + 压缩包内同名条目会重复计数）
	dupes     []string

	mu sync.Mutex
}

// noteSource 登记一个待处理日志名，发现重复则记下来
// （现场目录里常同时有散装 dmsql_*.log 和装着同一批日志的 tar.gz/zip，会把统计翻倍）
func (s *Stats) noteSource(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seenNames == nil {
		s.seenNames = map[string]bool{}
	}
	if s.seenNames[name] {
		if len(s.dupes) < 10 {
			s.dupes = append(s.dupes, name)
		}
		return
	}
	s.seenNames[name] = true
}

const maxTrx = 500000 // 事务表上限，防超大日志吃内存（实测 50 万条约占 200MB）

const (
	maxSecKeys = 2000000 // 秒桶上限（≈23 天），防超长跨度日志吃内存
	maxTables  = 200000  // 热表上限
)

func newStats() *Stats {
	return &Stats{
		ByOp:       map[string]*Agg{},
		ByUser:     map[string]*Agg{},
		ByClient:   map[string]*Agg{},
		ByTable:    map[string]*tableAgg{},
		Sec:        map[int64]*secAgg{},
		Tpl:        map[string]*TplAgg{},
		H:          &logHist{},
		ChangeN:    map[string]int64{},
		LastDDL:    map[string]string{},
		LSNBucket:  map[int64]lsnRef{},
		DDLVerb:    map[string]int64{},
		TrxFirst:   map[string]string{},
		TrxLast:    map[string]string{},
		TrxCount:   map[string]int64{},
		TrxKind:    map[string]string{},
		TrxExecMS:  map[string]float64{},
		TrxFirstMS: map[string]float64{},
		ErrCodes:   map[string]int64{},
		ErrMS:      map[string]float64{},
		TrxUser:    map[string]string{},
	}
}

// ---------------------------------------------------------------- 轻量聚合辅助

// tsUnix 把 "yyyy-MM-dd HH:mm:ss"（取前 19 字节）转成 Unix 秒。
// 不走 time.Parse：GB 级日志下每条语句都要算一次，直接算术快一个数量级。
func tsUnix(ts string) (int64, bool) {
	if len(ts) < 19 {
		return 0, false
	}
	two := func(a int) int {
		x, y := ts[a], ts[a+1]
		if x < '0' || x > '9' || y < '0' || y > '9' {
			return -1
		}
		return int(x-'0')*10 + int(y-'0')
	}
	if ts[4] != '-' || ts[7] != '-' || ts[10] != ' ' || ts[13] != ':' || ts[16] != ':' {
		return 0, false
	}
	y := two(0)*100 + two(2)
	mo, d := two(5), two(8)
	h, mi, se := two(11), two(14), two(17)
	if y < 0 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || mi < 0 || se < 0 {
		return 0, false
	}
	return daysFromCivil(y, mo, d)*86400 + int64(h)*3600 + int64(mi)*60 + int64(se), true
}

// daysFromCivil 公历年月日 → 距 1970-01-01 的天数（Howard Hinnant 算法）
func daysFromCivil(y, m, d int) int64 {
	yy := int64(y)
	if m <= 2 {
		yy--
	}
	era := yy / 400
	if yy < 0 && yy%400 != 0 {
		era--
	}
	yoe := yy - era*400
	mp := int64(m + 9)
	if m > 2 {
		mp = int64(m - 3)
	}
	doy := (153*mp+2)/5 + int64(d) - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}

// 表名提取时跳过的关键字（这些出现在 FROM/JOIN 后并非表名）
var nonTable = map[string]bool{
	"SELECT": true, "WHERE": true, "VALUES": true, "SET": true, "ON": true,
	"AS": true, "AND": true, "OR": true, "NOT": true, "NULL": true, "UNION": true,
	"ORDER": true, "GROUP": true, "HAVING": true, "LIMIT": true, "ROWNUM": true,
	"DUAL": true, "INTO": true, "FROM": true, "JOIN": true, "TABLE": true,
	"MERGE": true, "USING": true, "UPDATE": true, "DELETE": true, "INSERT": true,
	"ALL": true, "DISTINCT": true, "TOP": true, "WITH": true, "CASE": true,
	"WHEN": true, "THEN": true, "ELSE": true, "END": true, "LEFT": true,
	"RIGHT": true, "INNER": true, "OUTER": true, "CROSS": true, "FULL": true,
	"EXISTS": true, "UNKNOWN": true, "START": true, "CONNECT": true, "PRIOR": true,
}

// eachTable 从 SQL 文本里粗提表名（不做完整语法分析，只认常见位置）。
// 命中位置：FROM / JOIN / USING（读）、INSERT INTO / UPDATE / DELETE FROM / MERGE INTO / TABLE（写）。
// 同一语句内同名表只回调一次；DUAL 与关键字被过滤。
// cteNames 收集 `WITH x AS (...), y AS (...)` 里的 CTE 名。
//
// CTE 是查询内部定义的结果集、不是物理表；不过滤的话，"热表"排行里会冒出
// 一堆根本不是表的临时名字（官方 Web 版用 SqlTableExtractor 做了同样的过滤）。
// 判据：**出现过 WITH 之后**，形如 `名字 AS (` 的标识符才算 CTE —— 这样
// `CREATE VIEW v AS (...)` 这类不会被误收（它前面没有 WITH）。
func cteNames(sql []byte) []string {
	var out []string
	L := len(sql)
	sawWith := false
	i := 0
	for i < L {
		if !isAlpha(sql[i]) {
			i++
			continue
		}
		j := i
		for j < L && isIdentByte(sql[j]) {
			j++
		}
		word := sql[i:j]
		up := upperBytes(word)
		i = j
		if up == "WITH" {
			sawWith = true
			continue
		}
		if !sawWith {
			continue
		}
		// 跳过空白，看是不是 "AS ("
		k := i
		for k < L && (sql[k] == ' ' || sql[k] == '\t' || sql[k] == '\n' || sql[k] == '\r') {
			k++
		}
		if k+2 > L || (sql[k] != 'A' && sql[k] != 'a') || (sql[k+1] != 'S' && sql[k+1] != 's') {
			continue
		}
		m := k + 2
		for m < L && (sql[m] == ' ' || sql[m] == '\t' || sql[m] == '\n' || sql[m] == '\r') {
			m++
		}
		if m >= L || sql[m] != '(' {
			continue
		}
		nm := up
		if p := lastDot(nm); p >= 0 {
			nm = nm[p+1:]
		}
		if nm != "" && !nonTable[nm] && len(out) < 16 {
			out = append(out, nm)
		}
	}
	return out
}

func eachTable(sql []byte, op string, fn func(name string, write bool)) {
	var seen [16]string
	nSeen := 0
	dup := func(name string) bool {
		for i := 0; i < nSeen; i++ {
			if seen[i] == name {
				return true
			}
		}
		if nSeen < len(seen) {
			seen[nSeen] = name
			nSeen++
		}
		return false
	}
	isWriteOp := op == "INS" || op == "UPD" || op == "DEL" || op == "DDL" || op == "DML"
	// CTE 名过滤：只在 SQL 里确实有 WITH 时才扫一遍（含 CTE 的语句占比很低）
	var ctes []string
	if bytes.IndexByte(sql, '(') >= 0 && hasWordWith(sql) {
		ctes = cteNames(sql)
	}

	i := 0
	L := len(sql)
	prev := "" // 上一个词（大写），用于消歧：只有 `INSERT INTO` / `MERGE INTO` 的 INTO 才是表
	for i < L {
		c := sql[i]
		// 跳过字符串字面量与注释 —— 它们里面出现的 from / join 等词不是表引用。
		// 例：`where msg = 'delete from t_tmp'`、`-- from 旧表`、`/* from x */`
		switch c {
		case '\'':
			i++
			for i < L {
				if sql[i] == '\'' {
					if i+1 < L && sql[i+1] == '\'' { // '' 是转义
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
			continue
		case '-':
			if i+1 < L && sql[i+1] == '-' {
				for i < L && sql[i] != '\n' {
					i++
				}
			} else {
				i++
			}
			continue
		case '/':
			if i+1 < L && sql[i+1] == '*' {
				i += 2
				for i+1 < L && !(sql[i] == '*' && sql[i+1] == '/') {
					i++
				}
				i += 2
				if i > L {
					i = L
				}
			} else {
				i++
			}
			continue
		}
		if !isAlpha(c) {
			i++
			continue
		}
		// 读一个词（原样 + 大写折叠）
		j := i
		for j < L && isIdentByte(sql[j]) {
			j++
		}
		up := upperBytes(sql[i:j])
		i = j

		var write bool
		switch {
		case up == "FROM":
			write = op == "DEL" || op == "UPD" // DELETE FROM t / （DM 不常见）UPDATE ... FROM t
		case up == "JOIN" || up == "USING":
			write = false
		case up == "INTO":
			// 只有 INSERT INTO / MERGE INTO 的 INTO 后面是表；
			// `SELECT ... INTO 变量`（PL/SQL 赋值，如 DECLARE CNT ... INTO CNT）**不是表** ——
			// 早期版本见 INTO 就取名字，导致把变量名 CNT 当成热表。
			if prev != "INSERT" && prev != "MERGE" {
				prev = up
				continue
			}
			write = true
		case up == "UPDATE":
			// `FOR UPDATE` 是行锁子句，不是 UPDATE 语句
			if prev == "FOR" {
				prev = up
				continue
			}
			write = isWriteOp
		case up == "TABLE":
			write = isWriteOp
		default:
			prev = up
			continue
		}
		prev = up
		// 跳过空白、注释/提示块（如 `INSERT INTO /*+ append parallel(2)*/ TMP_X`）；
		// 遇到 '(' 说明是子查询，放弃本次
		k := i
		for k < L {
			switch ch := sql[k]; {
			case ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r':
				k++
			case ch == '(':
				k = -1
			case ch == '/' && k+1 < L && sql[k+1] == '*':
				e := bytes.Index(sql[k+2:], []byte("*/"))
				if e < 0 {
					k = -1
				} else {
					k = k + 2 + e + 2
				}
			}
			if k < 0 || k >= L || (sql[k] != ' ' && sql[k] != '\t' && sql[k] != '\n' && sql[k] != '\r') {
				break
			}
		}
		if k < 0 {
			continue
		}
		name, next := readIdent(sql, k)
		if next == k {
			continue
		}
		i = next
		// 去掉 schema 前缀，只留表名（同一表带不带 schema 才能合并）
		if p := lastDot(name); p >= 0 {
			name = name[p+1:]
		}
		if name == "" {
			continue
		}
		// 统一大写：日志里同一张表常有 T_CAL_X / t_cal_x 两种写法；
		// 注意 nonTable 的关键字表也是大写，所以必须先折叠再过滤
		name = upperStr(name)
		if name == "" || nonTable[name] {
			continue
		}
		if isCTE(ctes, name) {
			continue // CTE 不是物理表
		}
		if dup(name) {
			continue
		}
		fn(name, write)
	}
}

// hasWordWith 粗判 SQL 里是否出现独立单词 WITH（不区分大小写）
func hasWordWith(sql []byte) bool {
	L := len(sql)
	for i := 0; i+4 <= L; i++ {
		if (sql[i] == 'W' || sql[i] == 'w') && (sql[i+1] == 'I' || sql[i+1] == 'i') &&
			(sql[i+2] == 'T' || sql[i+2] == 't') && (sql[i+3] == 'H' || sql[i+3] == 'h') {
			if i > 0 && isIdentByte(sql[i-1]) {
				continue
			}
			if i+4 < L && isIdentByte(sql[i+4]) {
				continue
			}
			return true
		}
	}
	return false
}

// isCTE 判断名字是否是 CTE（名字已大写、已去 schema）
func isCTE(ctes []string, name string) bool {
	for _, c := range ctes {
		if c == name {
			return true
		}
	}
	return false
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'
}
func isIdentByte(c byte) bool {
	return isAlpha(c) || (c >= '0' && c <= '9') || c == '$' || c == '#'
}

// readIdent 读一个标识符（支持 "t" / `t` / [t] / a.b / a."b"），返回去引号后的文本与结束位置
func readIdent(s []byte, i int) (string, int) {
	start := i
	L := len(s)
loop:
	for i < L {
		c := s[i]
		switch {
		case isIdentByte(c) || c == '.':
			i++
		case c == '"' || c == '`':
			q := c
			i++
			for i < L && s[i] != q {
				i++
			}
			if i < L {
				i++
			}
		case c == '[':
			i++
			for i < L && s[i] != ']' {
				i++
			}
			if i < L {
				i++
			}
		default:
			break loop
		}
	}
	if i == start {
		return "", start
	}
	raw := s[start:i]
	out := make([]byte, 0, len(raw))
	for _, ch := range raw {
		if ch != '"' && ch != '`' && ch != '[' && ch != ']' {
			out = append(out, ch)
		}
	}
	return string(out), i
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

// upperBytes ASCII 大写折叠（表名都是 ASCII；中文/其他字节原样返回）
func upperBytes(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}

// upperStr 与 upperBytes 相同，只是入参是 string（表名归一用）
func upperStr(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		out[i] = c
	}
	return string(out)
}

// addOp 记录一条 SQL 事件（在筛选之前调用 → 统计始终反映日志全貌）
// addOp 记录一条 SQL 事件。返回"回填句柄"：调用方在参数还原成功后，
// 用 fillRestored 把最慢语句/模板里的 SQL 换成**还原后的版本** ——
// 报告与附件要的是能直接执行的语句，而不是带 ? 的原始文本。
func (s *Stats) addOp(op, user, client, trxid, ts string, ms float64, rows, file, execID string, sql []byte) (slowIdx int, tplK string, tplNew bool, needFill bool) {
	// 没要统计报告时不做任何聚合：省掉全局锁与大 map，
	// 这是"只导 SQL"路径上最大的一笔开销（GB 级日志下可达十倍差距）
	slowIdx = -1
	if !s.agg {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if a := s.ByOp[op]; a != nil {
		a.add(ms)
	} else {
		s.ByOp[op] = newAgg()
		s.ByOp[op].add(ms)
	}
	if user != "" {
		if a := s.ByUser[user]; a != nil {
			a.add(ms)
		} else {
			s.ByUser[user] = newAgg()
			s.ByUser[user].add(ms)
		}
	}
	// 客户端（appname/ip）：现场排查常要知道"是哪个应用在压库"
	if client != "" {
		if a := s.ByClient[client]; a != nil {
			a.add(ms)
		} else {
			s.ByClient[client] = newAgg()
			s.ByClient[client].add(ms)
		}
	}
	// 时间跨度 + 秒桶（QPS/TPS、时间轴热点）
	// 口径：排除 [ORA]（只解析未执行，不构成实际负载）—— 与"执行耗时分布"保持一致
	if ts != "" && op != "ORA" {
		if s.SpanFirst == "" || ts < s.SpanFirst {
			s.SpanFirst = ts
		}
		if ts > s.SpanLast {
			s.SpanLast = ts
		}
		if sec, ok := tsUnix(ts); ok {
			sa := s.Sec[sec]
			if sa == nil {
				if len(s.Sec) < maxSecKeys {
					sa = &secAgg{}
					s.Sec[sec] = sa
				}
			}
			if sa != nil {
				sa.SQL++
				sa.SumMS += ms
			}
		}
	}
	// 热表（按 SQL 文本粗提表名；只在统计模式下做）
	if len(sql) > 0 && op != "ORA" {
		eachTable(sql, op, func(name string, write bool) {
			t := s.ByTable[name]
			if t == nil {
				if len(s.ByTable) >= maxTables {
					return
				}
				t = &tableAgg{ByOp: map[string]int64{}}
				s.ByTable[name] = t
			}
			t.Count++
			if write {
				t.Writes++
			} else {
				t.Reads++
			}
			t.SumMS += ms
			if ms > t.MaxMS {
				t.MaxMS = ms
			}
			t.ByOp[op]++
		})
	}
	// 耗时直方图 + 对数分位直方图（只统计有耗时的事件）
	if ms > 0 || op != "ORA" {
		s.Hist[histBucket(ms)]++
		s.H.add(ms)
	}
	// 最慢语句 Top-N（小根堆式替换，N 很小，线性扫描足够）
	n := s.slowN
	if n > 0 && op != "ORA" {
		r := slowRec{TS: ts, MS: ms, Rows: rows, User: user, Op: op, File: file, ExecID: execID, SQL: sqlFull(sql)}
		if len(s.Slow) < n {
			s.Slow = append(s.Slow, r)
			slowIdx = len(s.Slow) - 1
		} else {
			mi := 0
			for i := range s.Slow {
				if s.Slow[i].MS < s.Slow[mi].MS {
					mi = i
				}
			}
			if r.MS > s.Slow[mi].MS {
				s.Slow[mi] = r
				slowIdx = mi
			}
		}
	}
	// 语句模板
	if len(sql) > 0 && op != "ORA" {
		k := tplKey(sql)
		tplK = k
		if t := s.Tpl[k]; t != nil {
			t.add(ms)
			// 该模板的样例仍带 ? → 说明那个样例当时没还原成功，后面遇到能还原的语句就替换它
			if strings.IndexByte(t.Sample, '?') >= 0 {
				needFill = true
			}
		} else if len(s.Tpl) < maxTpl {
			s.Tpl[k] = &TplAgg{Agg: Agg{Count: 1, SumMS: ms, MaxMS: ms, MinMS: ms, hasMin: true}, Sample: sqlFull(sql)}
			tplNew = true
		} else {
			s.TplFull = true
		}
	}
	// 事务跨度：同一 trxid 的首次事件 → 末次事件
	// （事件 = 该事务里的执行语句，以及掩码 29 的 TRX: START）
	s.touchTrx(trxid, ts, op)
	// 事务内 SQL 累计执行耗时 —— 用来算「事务利用率」：
	// 利用率 = 事务内 SQL 执行耗时 / 事务跨度。跨度长但利用率低 = 占着事务不干活
	// （长时间持锁、应用侧忘了 commit/rollback），这是长事务里最该先看的一类。
	if trxid != "" && trxid != "0" && trxid != "NULL" && len(s.TrxExecMS) < maxTrx {
		s.TrxExecMS[trxid] += ms
		// 记下第一条 SQL 的耗时：事务跨度的起点是首条 SQL 开始执行（并写下日志）的时刻，
		// 也就是这条 SQL 已经在跑了，所以分母要加上它的耗时 —— 官方 jar 里那个
		// 「事务的SQL」利用率模板就是这么修正的（BASE_DURATION_MS + FIRST_EXEC_MS）。
		if _, ok := s.TrxFirstMS[trxid]; !ok {
			s.TrxFirstMS[trxid] = ms
		}
	}
	// 顺便记住"事务 → 用户"：锁等待只带等待方的用户，
	// 有了这张表才能回答"持有方（谁在持锁）是谁"
	if user != "" && trxid != "" && trxid != "0" && trxid != "NULL" {
		if _, ok := s.TrxUser[trxid]; !ok && len(s.TrxUser) < maxTrx {
			s.TrxUser[trxid] = user
		}
	}
	// 进了最慢榜的语句也要回填（报告里要显示可执行 SQL）
	needFill = needFill || slowIdx >= 0
	return
}

// fillRestored 参数还原成功后，把最慢语句 / 模板样例里的 SQL 换成还原后的版本。
// 没回填的情况（语句被筛选掉、还原失败）会保留原始带 ? 的文本 —— 与 -o 导出的行为一致。
func (s *Stats) fillRestored(slowIdx int, key string, tplNew bool, outSQL []byte) {
	if len(outSQL) == 0 {
		return
	}
	full := sqlFull(outSQL)
	s.mu.Lock()
	defer s.mu.Unlock()
	if slowIdx >= 0 && slowIdx < len(s.Slow) {
		s.Slow[slowIdx].SQL = full
	}
	if key != "" && (tplNew || slowIdx >= 0) {
		if t := s.Tpl[key]; t != nil {
			// 只有在"首次样例"或"当前样例仍带 ?"时才覆盖：
			// 模板第一次出现时参数未必还原成功，后面总会出现能还原的样本
			if tplNew || strings.IndexByte(t.Sample, '?') >= 0 {
				t.Sample = full
			}
		}
	}
}

// touchTrx 记录事务时间点（调用方需持有 s.mu）
func (s *Stats) touchTrx(trxid, ts, kind string) { s.touchTrxN(trxid, ts, kind, true) }

// touchTrxN 记账一个事务事件。count=false 用于 `TRX: START` —— 它是**事件不是语句**，
// 若也计入，长事务表的"语句数"与"每事务语句数分布"都会整体 +1（实测会让
// "1 条语句的事务"这一档凭空消失）。
func (s *Stats) touchTrxN(trxid, ts, kind string, count bool) {
	if trxid == "" || trxid == "0" || trxid == "NULL" {
		return
	}
	if _, ok := s.TrxFirst[trxid]; !ok {
		if len(s.TrxFirst) >= maxTrx { // 保护：超大日志下不再新增事务键
			s.trxFull = true
			return
		}
		s.TrxFirst[trxid] = ts
	}
	s.TrxLast[trxid] = ts
	if count {
		s.TrxCount[trxid]++
	}
	s.TrxKind[trxid] = kind
}

// addTrxEvent 记录掩码 29 的事务 START 事件（带真实 trxid）
func (s *Stats) addTrxEvent(trxid, ts, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchTrxN(trxid, ts, kind, false)
}

// perTrxStmtCap 单个事务最多留存多少条语句（锁等待溯源）。
// 8 条足够看清「这个事务在持锁期间干了什么」；再多也读不完，还占内存。
const perTrxStmtCap = 8

// maxTrxActStmt 全局最多留存多少条「事务 → 语句」记录。
// 现网 execute 行通常稀疏（实测 1 GB 日志仅 1,332 条），但有的库会开满掩码，
// 那时 execute 行可到百万级 —— 设上限，超了只计数不再留存。
const maxTrxActStmt = 400000

// maxTrxEndRec 全局最多留存多少条「事务结束事件」记录。
// 现网 COMMIT/ROLLBACK 带真实 trxid 时可达百万级（本批 1008 日志 196 万条事务事件），
// 全留会吃内存 —— 只保前 maxTrxEndRec 条。
const maxTrxEndRec = 600000

// maxOraTrxKey 「事务号 → 语句键」映射最多存多少条（V2.12）。
// 只在 DLCK 行登记，量级 = 语句数（现网几十万）；设上限防极端日志把内存吃满。
const maxOraTrxKey = 300000

// addTrxEnd 记录事务结束事件（COMMIT / ROLLBACK）。
// 这些行的 trxid 常为 0，归属不到具体事务，但**次数与时间点**足以算 TPS 与回滚率。
func (s *Stats) addTrxEnd(ts, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	commit := kind == "COMMIT"
	if commit {
		s.Commits++
	} else {
		s.Rollbacks++
	}
	if sec, ok := tsUnix(ts); ok {
		sa := s.Sec[sec]
		if sa == nil && len(s.Sec) < maxSecKeys {
			sa = &secAgg{}
			s.Sec[sec] = sa
		}
		if sa != nil {
			if commit {
				sa.Commit++
			} else {
				sa.Rollback++
			}
		}
	}
}

// addLockWait 记录一条锁等待（真发生等待 = 有 wait for）
func (s *Stats) addLockWait(w lockWait, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w.More {
		s.LockMoreN++
	}
	if w.CountMismatch {
		s.LockCountMis++
	}
	s.LockN++
	s.LockSumMS += w.MS
	if w.MS > s.LockMaxMS {
		s.LockMaxMS = w.MS
	}
	s.LockHist[lockBucket(w.MS)]++
	if sec, ok := tsUnix(w.TS); ok {
		if s.LockBySec == nil {
			s.LockBySec = map[int64]int64{}
		}
		s.LockBySec[sec]++
	}
	if s.LockByTable == nil {
		s.LockByTable = map[string]*lockTableAgg{}
	}
	if a := s.LockByTable[w.TableID]; a != nil {
		a.Count++
		a.SumMS += w.MS
		if w.MS > a.MaxMS {
			a.MaxMS = w.MS
			a.MaxAt = w.TS
		}
		if w.User != "" && len(a.Users) < 8 {
			a.Users[w.User] = true
		}
	} else {
		us := map[string]bool{}
		if w.User != "" {
			us[w.User] = true
		}
		s.LockByTable[w.TableID] = &lockTableAgg{Count: 1, SumMS: w.MS, MaxMS: w.MS,
			Mode: w.Mode, Users: us, MaxAt: w.TS}
	}
	if n > 0 {
		if len(s.Locks) < n {
			s.Locks = append(s.Locks, w)
		} else {
			mi := 0
			for i := range s.Locks {
				if s.Locks[i].MS < s.Locks[mi].MS {
					mi = i
				}
			}
			if w.MS > s.Locks[mi].MS {
				s.Locks[mi] = w
			}
		}
	}
}

// addDlck 记录 DLCK 锁操作计时行（执行计划里锁节点的自身耗时，不是等待）
func (s *Stats) addDlck(ms float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DlckN++
	if ms > 0 {
		s.DlckNonZero++
	}
	if ms > s.DlckMaxMS {
		s.DlckMaxMS = ms
	}
}

func (s *Stats) addLockUnparsed() {
	s.mu.Lock()
	s.LockUnparsed++
	s.mu.Unlock()
}

// noteUnit 记录日志里的耗时单位出现次数 —— 用来在报告里回答
// "这份日志的 EXECTIME 是毫秒还是微秒"（对应 sqllog.ini 的 EXECTIME_PREC_FLAG）
func (s *Stats) noteUnit(u string) {
	switch u {
	case "ms":
		atomic.AddInt64(&s.UnitMS, 1)
	case "us":
		atomic.AddInt64(&s.UnitUS, 1)
	case "ns":
		atomic.AddInt64(&s.UnitNS, 1)
	default:
		atomic.AddInt64(&s.UnitNone, 1)
	}
}

// errCodeOf 从 `[ERR(-2111)]: ...` 里取错误码。
// 官方桌面版不提取错误码（只把整行存进 ERR 表），但"哪个错误码最多"是排查的
// 第一手线索，所以这里单独抽出来做分布统计。
func errCodeOf(rest []byte) string {
	l := bytes.IndexByte(rest, '(')
	if l < 0 {
		return ""
	}
	r := bytes.IndexByte(rest[l:], ')')
	if r <= 1 {
		return ""
	}
	code := strings.TrimSpace(string(rest[l+1 : l+r]))
	if code == "" {
		return ""
	}
	return code
}

// noteAudit 记一条审计记录。
//
// lvl==2（高危）会做 **[ORA] ↔ 执行行** 的配对：
//
//	· [ORA] 行先登记成"仅解析"的候选；
//	· 若随后同一语句句柄出现执行行（时间窗内），就把执行信息（行数/EXEC_ID/耗时/事务号）
//	  合并进那条候选 —— 于是一条危险操作既能看到"什么时候被发起"，
//	  也能看到"到底执行了没有、影响多少行"。
//	· 若始终没有执行行，记录保持 ORAOnly=true，表示"解析了但没执行成功"，这本身是证据。
func (s *Stats) noteAudit(lvl int, kind, obj, op, ts, user, client, trx, rows, execID, file string,
	ms float64, key, thrd string, isORA bool) int {
	if lvl <= 0 {
		return -1
	}
	sec := tsUnixOf(ts)
	s.mu.Lock()
	defer s.mu.Unlock()
	r := auditRec{TS: ts, Level: lvl, Kind: kind, Object: obj, User: user, Client: client,
		Op: op, Trx: trx, Rows: rows, ExecID: execID, File: file, MS: ms, key: key, Thrd: thrd}

	if lvl == 1 {
		// 结构变更：只记执行行（[ORA] 不重复登记），进环形时间线
		if isORA {
			return -1
		}
		if s.ChangeN == nil {
			s.ChangeN = map[string]int64{}
		}
		s.ChangeN[kind]++
		if s.LastDDL == nil {
			s.LastDDL = map[string]string{}
		}
		if obj != "" && len(s.LastDDL) < maxLastDDL {
			s.LastDDL[obj] = fmt.Sprintf("%s · %s · %s", shortTS(ts), kind, user)
		}
		if len(s.Changes) < maxChange {
			s.Changes = append(s.Changes, r)
			s.changeN = len(s.Changes)
			return -1
		}
		s.Changes[s.changeN%maxChange] = r // 环形覆盖最旧的
		s.changeN++
		return -1
	}

	// ---- 高危 ----
	if isORA {
		if len(s.Dangers) >= maxAudit {
			s.auditFull = true
			return -1
		}
		r.ORAOnly = true
		s.Dangers = append(s.Dangers, r)
		idx := len(s.Dangers) - 1
		if key != "" {
			if len(s.pend) > 5000 { // 清掉过老的候选，防堆积
				keep := s.pend[:0]
				for _, p := range s.pend {
					if sec-p.sec <= auditWinSec*2 {
						keep = append(keep, p)
					}
				}
				s.pend = keep
			}
			s.pend = append(s.pend, pendRef{key: key, idx: idx, sec: sec})
		}
		return idx
	}
	// 执行行：先找同句柄的 ORA 候选合并
	if key != "" {
		for i := len(s.pend) - 1; i >= 0; i-- {
			p := s.pend[i]
			if p.key != key || sec-p.sec > auditWinSec || sec < p.sec-auditWinSec {
				continue
			}
			d := &s.Dangers[p.idx]
			d.ORAOnly = false
			d.Rows, d.ExecID, d.MS, d.Trx, d.Op = rows, execID, ms, trx, op
			d.User, d.Client, d.Thrd = user, client, thrd
			s.pend = append(s.pend[:i], s.pend[i+1:]...)
			return p.idx
		}
	}
	if len(s.Dangers) >= maxAudit {
		s.auditFull = true
		return -1
	}
	s.Dangers = append(s.Dangers, r)
	return len(s.Dangers) - 1
}

// fillAuditSQL 参数还原成功后回填可执行 SQL（审计清单要能直接拿去执行/复核）
func (s *Stats) fillAuditSQL(idx int, sql []byte) {
	if idx < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx < len(s.Dangers) {
		s.Dangers[idx].SQL = sqlFull(sql)
	}
}

// fillTrxStmtSQL 参数还原后回填锁溯源里那条语句（按 trxid + 时间戳定位）。
//
// 位置改为：先把索引记下来再按索引回填，避免线性查找。
// 现在按「扁平数组 + 下标」实现（见 addTrxStmtLocked 的返回下标）。
func (s *Stats) fillTrxStmtSQLAt(idx int, sql []byte) {
	if idx < 0 || len(sql) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if idx < len(s.trxStmts) {
		s.trxStmts[idx].SQL = sqlFull(sql)
	}
}

// noteLSN 采样事务提交的 LSN：每 30 秒一桶。
//
// 用途是"恢复定位"：出了误删，DBA 需要知道出事前后最近的提交 LSN（配合归档日志做不完全恢复）。
// 现网 COMMIT 行是百万级，全留会吃内存，所以按桶降采样 —— 30 秒的分辨率对定位足够了。
func (s *Stats) noteLSN(ts, lsn string) {
	sec, ok := tsUnix(ts)
	if !ok {
		return
	}
	b := sec / 30
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.LSNBucket == nil {
		s.LSNBucket = map[int64]lsnRef{}
	}
	if _, exists := s.LSNBucket[b]; exists {
		return
	}
	if len(s.LSNBucket) >= maxLSNBucket {
		return
	}
	s.LSNBucket[b] = lsnRef{TS: ts, LSN: lsn}
}

// tsUnixOf 时间戳 → unix 秒（失败返回 0）
func tsUnixOf(ts string) int64 {
	if sec, ok := tsUnix(ts); ok {
		return sec
	}
	return 0
}

// noteErrCode 统计错误码分布
// noteErrCode 记一条错误码及其耗时。
//
// 为什么要连耗时一起记：DM 的 [ERR(-608)]（会话请求超时 / 锁超时）每次都要等满超时阈值，
// 实测某库 4,581 次就吃掉 79.7 小时 —— 只看次数（占 3.4%）完全看不出问题，看耗时占比（74.9%）才现形。
func (s *Stats) noteErrCode(code string, ms float64) {
	if code == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ErrCodes) < 500 {
		s.ErrCodes[code]++
	}
	isNew := false
	if _, ok := s.ErrMS[code]; !ok && len(s.ErrMS) < 500 {
		isNew = true
	}
	if isNew || len(s.ErrMS) <= 500 {
		s.ErrMS[code] += ms
	}
}

func (s *Stats) setSlowN(n int) {
	s.mu.Lock()
	s.slowN = n
	s.mu.Unlock()
}

// lockMS 把 used time 的数值与单位归一化成毫秒
func lockMS(num string, unit []byte) float64 {
	v, _ := strconv.ParseFloat(num, 64)
	switch unit[0] {
	case 'u':
		return v / 1000
	case 'n':
		return v / 1e6
	}
	return v
}

func lockBucket(ms float64) int {
	for i, e := range lockEdges {
		if ms < e {
			return i
		}
	}
	return len(lockEdges)
}

// ---------------------------------------------------------------- 锁等待展示辅助

// trxUserOf 事务对应用户；没有记录时给 "?"，避免显示空白让人误以为是解析漏了
func trxUserOf(v *statsView, trx string) string {
	if u := v.TrxUser[trx]; u != "" {
		return u
	}
	return "?"
}

// lockObj 锁对象显示：有表名（--obj-map 映射过）就给「表名 (ID)」，否则只给 ID
func lockObj(table, id string) string {
	if table != "" {
		return table + " (ID " + id + ")"
	}
	return "对象ID " + id
}

// lockParty 锁的参与方：trxid + 用户（日志里只有等待方的用户，持有方靠事务表反查）
func lockParty(trx, user string) string {
	if trx == "" {
		return "?"
	}
	if user == "" {
		user = "?"
	}
	t := trx
	if len(t) > 14 { // 多持有方（a,b,c）会很长，截断显示，否则表格列会错位
		t = t[:14] + "…"
	}
	return "trx[" + t + "] " + user
}

// splitTrxList 把日志里的持有方列表拆成事务号切片（保序）。
//
// 🩸 顺序有意义：清单是**累计排队**的，第一个才是真正持锁的事务，
// 后面那些是排在它身后的等待者（现网实测最长排到 18 个）。
// 所以"谁在持锁"永远取 [0]，不能把整条链都当成持有方。
// 日志在队列过长时会写成 `..., ...more]`，那种占位符要丢掉。
func splitTrxList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "...") {
			continue
		}
		out = append(out, p)
	}
	return out
}

// lockTraceCmd 该次锁等待的溯源命令（复制即可看等待方当时在跑什么 SQL）
func lockTraceCmd(lk lockRow) string {
	if lk.Waiter == "" {
		return ""
	}
	return "溯源：dmsqlq <同一路径> -x " + lk.Waiter + " -N"
}

// topStmt --top-ms 模式缓存的语句
type topStmt struct {
	MS   float64
	Info stmtInfo
	SQL  []byte
	File string
}

func (s *Stats) addTopMS(t topStmt, n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.TopMSList) < n {
		s.TopMSList = append(s.TopMSList, t)
		return
	}
	mi := 0
	for i := range s.TopMSList {
		if s.TopMSList[i].MS < s.TopMSList[mi].MS {
			mi = i
		}
	}
	if t.MS > s.TopMSList[mi].MS {
		s.TopMSList[mi] = t
	}
}

func histBucket(ms float64) int {
	for i, e := range histEdges {
		if ms < e {
			return i
		}
	}
	return len(histEdges)
}

// tplKey 把 SQL 归一化成模板键：字符串字面量 → '?'，数字 → #，压缩空白
func tplKey(sql []byte) string {
	const maxLen = 160
	buf := make([]byte, 0, maxLen)
	i, n := 0, len(sql)
	for i < n && len(buf) < maxLen {
		c := sql[i]
		switch {
		case c == '\'':
			buf = append(buf, '\'', '?', '\'')
			i++
			for i < n {
				if sql[i] == '\'' {
					if i+1 < n && sql[i+1] == '\'' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case c >= '0' && c <= '9':
			buf = append(buf, '#')
			for i < n && (sql[i] >= '0' && sql[i] <= '9' || sql[i] == '.') {
				i++
			}
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			if len(buf) > 0 && buf[len(buf)-1] != ' ' {
				buf = append(buf, ' ')
			}
			i++
		default:
			buf = append(buf, c)
			i++
		}
	}
	return string(bytes.TrimRight(buf, " "))
}

// sqlBrief 单行化 + 截断，用于报告摘要
func sqlBrief(sql []byte, max int) string {
	var b []byte
	for _, c := range sql {
		if c == '\n' || c == '\r' || c == '\t' {
			if len(b) > 0 && b[len(b)-1] != ' ' {
				b = append(b, ' ')
			}
			continue
		}
		b = append(b, c)
		if len(b) >= max {
			break
		}
	}
	s := strings.TrimSpace(string(b))
	if len(sql) > max {
		s += " …"
	}
	return s
}

// sqlFull 保留完整 SQL（供报告溯源 / 配套 .sql 文件）。超长时截断并标注原长度，
// 避免一条畸形超长语句把内存或报告撑爆。
func sqlFull(sql []byte) string {
	s := strings.TrimRight(string(sql), " \t\r\n")
	if len(s) > maxFullSQL {
		return s[:maxFullSQL] + "\n/*…已截断：原长 " + strconv.Itoa(len(s)) + " 字符，完整语句请用 -x 事务号或 -l 子串从日志中抽取*/"
	}
	return s
}

// briefSQL 报告里显示用的摘要。若语句里仍有未还原的占位符，前面加个标记 ——
// 这类语句在执行行前**没有 PARAMS 行**（采集侧就缺），不是解析失败，用户需要能分辨。
func briefSQL(s string, max int) string {
	b := briefOf(s, max)
	if strings.IndexByte(s, '?') >= 0 {
		return "[参数未还原] " + b
	}
	return b
}

// briefOf 对已存好的完整 SQL 做"单行摘要"（渲染报告用），换行/制表符折成空格
func briefOf(s string, max int) string {
	var b strings.Builder
	n := 0
	last := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\n' || c == '\r' || c == '\t' {
			if n > 0 && last != ' ' {
				b.WriteByte(' ')
				n++
			}
			last = ' '
			continue
		}
		b.WriteByte(c)
		n++
		last = c
		if n >= max {
			break
		}
	}
	out := strings.TrimSpace(b.String())
	if len(s) > n {
		out += " …"
	}
	return out
}

// ---------------------------------------------------------------- 数值/排版工具

// fmtInt 千分位整数
func fmtInt(v int64) string {
	s := strconv.FormatInt(v, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

// fmtDur 毫秒 → 人类可读（不足 0.01ms 的按微秒显示，锁行里 us 单位很常见）
func fmtDur(ms float64) string {
	switch {
	case ms <= 0:
		return "0"
	case ms < 0.01:
		return fmt.Sprintf("%.0fus", ms*1000)
	case ms < 1:
		return fmt.Sprintf("%.2fms", ms)
	case ms < 1000:
		return fmt.Sprintf("%.0fms", ms)
	case ms < 60000:
		return fmt.Sprintf("%.2fs", ms/1000)
	case ms < 3600000:
		return fmt.Sprintf("%.1fmin", ms/60000)
	default:
		return fmt.Sprintf("%.1fh", ms/3600000)
	}
}

// dispWidth 显示宽度：CJK/全角算 2 列
func dispWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r == 0x200B:
		case r >= 0x1100 && (r <= 0x115F || r == 0x2329 || r == 0x232A ||
			(r >= 0x2E80 && r <= 0xA4CF && r != 0x303F) ||
			(r >= 0xAC00 && r <= 0xD7A3) ||
			(r >= 0xF900 && r <= 0xFAFF) ||
			(r >= 0xFE30 && r <= 0xFE6F) ||
			(r >= 0xFF00 && r <= 0xFF60) ||
			(r >= 0xFFE0 && r <= 0xFFE6)):
			w += 2
		default:
			w++
		}
	}
	return w
}

// pad 按显示宽度右补空格
func pad(s string, w int) string {
	d := w - dispWidth(s)
	if d <= 0 {
		return s
	}
	return s + strings.Repeat(" ", d)
}

// lpad 按显示宽度左补空格
func lpad(s string, w int) string {
	d := w - dispWidth(s)
	if d <= 0 {
		return s
	}
	return strings.Repeat(" ", d) + s
}

// sec 打印分节标题（宽度 66）
func sec(w io.Writer, title string) {
	const total = 66
	fill := total - dispWidth(title) - 2
	if fill < 4 {
		fill = 4
	}
	left := fill / 2
	fmt.Fprintf(w, "%s %s %s\n", strings.Repeat("─", left), title, strings.Repeat("─", fill-left))
}

// ---------------------------------------------------------------- 解析主逻辑

type parser struct {
	opt  *Options
	pc   *paramCache
	st   *Stats
	buf  bytes.Buffer // 输出缓冲
	file string
	line int64

	// 锁等待溯源缓冲（V2.8）。🩸 刻意放在 parser 上而不是 Stats 上：
	// parser 是「一个文件一个」的，处理该文件时单线程，append 完全不需要加锁；
	// 而写 Stats 上那份共享切片要在 s.mu 下由 6 个 goroutine 抢着改切片头，
	// 实测让 2.0 GB 的扫描从 2.29s 退化到 2.71s（+18%）—— 纯粹是缓存行争用。
	// 文件处理完（含提前结束）在 defer 里一次性并入 Stats。
	trxStmts []trxStmtRec
	trxEnds  []trxEndRec

	// ---- V2.12：用掩码 27 的 [ORA] 行兜底补出「取不到的持有方 SQL」 ----
	//
	// 背景（133 构造实验实测）：`MIN_EXEC_TIME` **只过滤语句完成行（EXEC 行）**，
	// 不过滤 PARAMS/DLCK/alloc pseg/TRX 行。所以一条很快（< MIN_EXEC_TIME）的
	// INSERT/UPDATE，事务行都在、唯独没有 SQL 文本 —— 这就是现场"空壳事务"的成因。
	//
	// 而掩码 27（原始语句）的 `[ORA]: <SQL>` 行**不受 MIN_EXEC_TIME 影响**：
	// 实测 0.4ms 的 UPDATE 照样有 [ORA] 行。它虽不带 trxid（恒为 0），
	// 但带 sess + stmt 句柄 —— 而持有方事务的 PARAMS/DLCK 行带同样的 (sess, stmt)。
	// 于是可以用「(sess,stmt) → SQL」把 SQL 找回来。
	//
	// 🩸 为什么用 p.key(sess)（= sess|thrd|stmt 的混合哈希）当键：
	// 它就是参数还原用的那把键，不额外引入新的关联口径。
	oraSQL map[uint64]string
	// oraKeyByTrx 事务号(十进制→uint64) → 语句键。只在 **DLCK 行** 登记：
	// DLCK 是语句级的（与语句数同量级），而 PARAMS 是百万级 —— 挂 PARAMS 会把
	// 2GB 扫描从 2.1s 拖到 3.8s（见本文件上方 PARAMS 记账的教训）。
	oraKeyByTrx map[uint64]uint64
}

// addTrxStmt 记录「本文件里某事务执行了一条语句」。无锁（p 为单文件独占）。
// 返回在 p.trxStmts 里的下标，供参数还原后回填可执行版本。
func (p *parser) addTrxStmt(trxid, ts, op string, ms float64, rows string, sql []byte) int {
	if len(p.trxStmts) >= maxTrxActStmt {
		return -1
	}
	p.trxStmts = append(p.trxStmts, trxStmtRec{
		TrxID: trxid, TS: ts, Op: op, MS: ms, Rows: rows, SQL: string(sql)})
	return len(p.trxStmts) - 1
}

// fillTrxStmtSQLAt 参数还原后把那条记录换成可执行版本。无锁（同 addTrxStmt）。
func (p *parser) fillTrxStmtSQLAt(idx int, sql []byte) {
	if idx < 0 || idx >= len(p.trxStmts) || len(sql) == 0 {
		return
	}
	p.trxStmts[idx].SQL = sqlFull(sql)
}

// noteTrxEnd 记录带真实 trxid 的事务结束事件。无锁（同 addTrxStmt）。
func (p *parser) noteTrxEnd(trxid, ts, kind string) {
	if len(p.trxEnds) >= maxTrxEndRec {
		return
	}
	p.trxEnds = append(p.trxEnds, trxEndRec{TrxID: trxid, TS: ts, Kind: kind})
}

// mergeTrxTrace 把单个文件的溯源缓冲并入全局（文件结束时调用一次）。
func (s *Stats) mergeTrxTrace(p *parser) {
	if len(p.trxStmts) == 0 && len(p.trxEnds) == 0 &&
		len(p.oraSQL) == 0 && len(p.oraKeyByTrx) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if room := maxTrxActStmt - len(s.trxStmts); room > 0 {
		n := len(p.trxStmts)
		if n > room {
			n = room
			s.trxFull = true
		}
		s.trxStmts = append(s.trxStmts, p.trxStmts[:n]...)
	} else {
		s.trxFull = true
	}
	if room := maxTrxEndRec - len(s.trxEnds); room > 0 {
		n := len(p.trxEnds)
		if n > room {
			n = room
		}
		s.trxEnds = append(s.trxEnds, p.trxEnds[:n]...)
	}
	// V2.12：[ORA] 索引并入（只有日志开了掩码 27 才非空；没开时两个 map 全程 nil）。
	if len(p.oraSQL) > 0 {
		if s.oraSQL == nil {
			s.oraSQL = make(map[uint64]string, len(p.oraSQL))
		}
		for k, v := range p.oraSQL {
			if _, ok := s.oraSQL[k]; !ok {
				s.oraSQL[k] = v
			}
		}
	}
	if len(p.oraKeyByTrx) > 0 {
		if s.oraKeyByTrx == nil {
			s.oraKeyByTrx = make(map[uint64]uint64, len(p.oraKeyByTrx))
		}
		for k, v := range p.oraKeyByTrx {
			if _, ok := s.oraKeyByTrx[k]; !ok {
				s.oraKeyByTrx[k] = v
			}
		}
	}
}

// oraSQLOfTrx 从掩码 27 的 [ORA] 索引里取某事务的原始 SQL（V2.12）。
//
// 用途：语句执行很快（< MIN_EXEC_TIME）时**执行行不写日志**，于是"持有方 SQL 消失"，
// 只留下 PARAMS + alloc pseg（现场称之为空壳事务）。而 [ORA] 行（原始语句）**不受该阈值影响**，
// 靠 DLCK 行带下来的 (sess,thrd,stmt) 键就能把 SQL 归回这个事务。
//
// 返回空串 = 日志没开位 27，或该事务没能登记到语句键（此时按老口径"取不到"）。
func (s *Stats) oraSQLOfTrx(trxid string) string {
	if len(s.oraSQL) == 0 || len(s.oraKeyByTrx) == 0 {
		return ""
	}
	t := decID(trxid)
	if t == 0 {
		return ""
	}
	k, ok := s.oraKeyByTrx[t]
	if !ok {
		return ""
	}
	return s.oraSQL[k]
}

type stmtInfo struct {
	ts, op, user, trxid string
	exeMS               float64
	rows                string
	execID              string // 执行行尾部的 EXEC_ID（下钻 V$SQL_NODE_HISTORY 用）
	hasExec             bool
	note                string
}

// outOfWindow 记录是否落在 -f/-t 指定的时间窗口之外。
//
// 纯时刻写法（-f 09:00）只比较 [11:19] 的 HH:mm:ss，实现「每天的这个时段」。
func outOfWindow(rec []byte, o *Options) bool {
	if len(o.fromB) > 0 {
		if o.fromTimeOnly {
			if len(rec) >= 19 && bytes.Compare(rec[11:19], o.fromB) < 0 {
				return true
			}
		} else if bytes.Compare(rec[:19], o.fromB) < 0 {
			return true
		}
	}
	if len(o.toB) > 0 {
		if o.toTimeOnly {
			if len(rec) >= 19 && bytes.Compare(rec[11:19], o.toB) > 0 {
				return true
			}
		} else if bytes.Compare(rec[:19], o.toB) > 0 {
			return true
		}
	}
	return false
}

// handleRecord 处理一条完整记录（首行 + 已拼接的续行）
func (p *parser) handleRecord(rec []byte) {
	// Records 是「日志记录数」，始终按全量计（报告要能回答窗口内占全天多少）
	atomic.AddInt64(&p.st.Records, 1)
	o := p.opt
	if len(rec) < 19 {
		return
	}
	// ⭐ 时间窗口（-f/-t）在统计**之前**判定 —— 它表达「只看这个时段的负载」，
	// 属分析视角切换，故类型分布/最耗时模板/热表/事务/锁/审计全部只覆盖窗口内。
	// （-k/-m/-u 等仍只影响输出，统计保留全貌；-E 排除本就不入统计。）
	// 🩸 放在这里而非后面：既统一了口径，又省掉窗口外记录的解析开销。
	if outOfWindow(rec, o) {
		atomic.AddInt64(&p.st.WinSkew, 1)
		return
	}

	rest, sess := splitSession(rec)
	if sess == nil {
		if o.loose { // SVR_LOG=3：只有"时间 + 原始语句"
			p.emitLoose(rec)
			return
		}
		return
	}

	// ---- 参数行 ----
	// 快路径：内容段直接以 PARAMS(SEQNO 开头（现网格式即如此）。
	// 这里必须用前缀判定而不是全文查找 —— 现网非 SQL 事件行有百万级（TRX/PREPARE/ALLOC STMT…），
	// 对每条都做一次子串扫描会白白吃掉 10% 左右的时间。
	if len(rest) == 0 {
		return
	}
	if bytes.HasPrefix(rest, paramsTag) {
		p.handleParams(rest, sess, 0)
		return
	}

	// ---- SQL 事件行：内容段必须以 '[' 开头；否则交给非 SQL 事件处理 ----
	if rest[0] != '[' {
		if i := bytes.Index(rest, paramsTag); i > 0 { // 兜底：老格式/变体里 PARAMS 前还有别的内容
			p.handleParams(rest, sess, i)
			return
		}
		p.handleNonSQLEvent(rec, rest, sess)
		return
	}
	if len(rest) < 5 {
		return
	}
	// ---- SQL 事件行：取 [XXX] 之后的文本 ----
	op := string(rest[1:4])
	// 行格式体检：本行是否带 "(EP[" 会话块（老版本日志为 0）
	if bytes.Contains(rec, []byte("(EP[")) {
		atomic.AddInt64(&p.st.EPSeen, 1)
	}
	errCode := ""
	switch op { // 掩码体检：这些类型行出现与否，直接对应 SQL_TRACE_MASK 的位
	case "ORA":
		atomic.AddInt64(&p.st.OraN, 1)
	case "LGN":
		atomic.AddInt64(&p.st.LgnN, 1)
	case "ERR":
		atomic.AddInt64(&p.st.ErrN, 1)
		errCode = errCodeOf(rest) // 耗时还没解析出来，等下面 EXECTIME 解完再一起记
	}

	// SQL 文本范围
	cb := bytes.IndexByte(rest, ']')
	if cb < 0 {
		return
	}
	sqlStart := cb + 1
	for sqlStart < len(rest) && (rest[sqlStart] == ':' || rest[sqlStart] == ' ') {
		sqlStart++
	}
	sqlEnd := len(rest)
	var info stmtInfo
	info.op = op

	if ei := bytes.LastIndex(rest, []byte("EXECTIME")); ei > sqlStart {
		sqlEnd = ei
		info.hasExec = true
		var unit string
		info.exeMS, unit = parseExecTime(rest[ei:])
		info.rows = parseRowCount(rest[ei:])
		info.execID = parseExecID(rest[ei:])
		if info.execID != "" {
			atomic.AddInt64(&p.st.execIDSeen, 1)
		}
		if p.st.agg {
			p.st.noteUnit(unit)
		}
	} else if op != "ORA" && op != "LGN" && op != "ERR" {
		// 有 SQL 文本、却没有 EXECTIME —— 正常情况下不该出现
		//（实测 650,086 个执行行 100% 带 EXECTIME）；出现就说明掩码 24/25 没开全
		atomic.AddInt64(&p.st.NoExecN, 1)
	}
	if sqlEnd < sqlStart {
		sqlEnd = sqlStart
	}
	sql := bytes.TrimRight(rest[sqlStart:sqlEnd], " \t\r")

	// V2.12：[ORA] 行（掩码 27 = 原始语句）登记 (sess,thrd,stmt) → SQL，
	// 供报告期兜底补出"被 MIN_EXEC_TIME 滤掉执行行"的持有方 SQL。
	// 它 trxid 恒为 0（解析阶段事务还没开始，实测如此），只能靠这把键关联。
	if op == "ORA" && p.st.agg && len(sql) > 0 {
		if k := p.key(sess); k != 0 {
			if p.oraSQL == nil {
				p.oraSQL = make(map[uint64]string, 1024)
			}
			if _, ok := p.oraSQL[k]; !ok {
				p.oraSQL[k] = string(sql)
			}
		}
	}

	atomic.AddInt64(&p.st.Exec, 1)

	// ---- 排除（-E）：与 -k/-m/-u 等"输出筛选"不同，它表达的是"这类语句不是有效负载"，
	//      因此被排除的语句**连统计都不参与** —— 否则统计会被统计信息收集、调用类语句带偏。
	excluded := false
	if o.exclSet != nil && o.exclSet[op] {
		excluded = true
	}
	if !excluded && len(o.exclLike) > 0 {
		for _, s := range o.exclLike {
			if containsFold(sql, s) {
				excluded = true
				break
			}
		}
	}
	if excluded {
		atomic.AddInt64(&p.st.Excluded, 1)
		atomic.AddInt64(&p.st.Filtered, 1)
		return
	}

	// 时间窗口判定已提前到 handleRecord 入口（outOfWindow），这里不再重复。
	info.ts = string(rec[:19])
	info.user = field(sess, "user:", "trxid:")
	info.trxid = field(sess, "trxid:", "stmt:")
	slowIdx, tplK, tplNew, needFill := -1, "", false, false
	trxStmtIdx := -1
	auditIdx := -1
	if p.st.agg {
		if errCode != "" {
			p.st.noteErrCode(errCode, info.exeMS)
		}
		slowIdx, tplK, tplNew, needFill = p.st.addOp(op, info.user, clientOf(sess), info.trxid, info.ts, info.exeMS, info.rows, p.file, info.execID, sql)
		// 锁等待溯源：把语句挂到它所属的事务上（掩码 29 的锁行只给 trxid、不给 SQL）。
		// 写在 addOp 之外是刻意的 —— 缓冲在 parser 上（单文件独占），不需要 s.mu，
		// 也就不会和 6 个 goroutine 抢共享切片头（那样实测慢 18%）。
		// 先判 trxid 再取 string(sql)：实测 57% 的执行行 trxid 为 0，对它们做拷贝纯属浪费。
		if info.trxid != "" && info.trxid != "0" && info.trxid != "NULL" {
			trxStmtIdx = p.addTrxStmt(info.trxid, info.ts, op, info.exeMS, info.rows, sql)
		}
		if op == "DDL" {
			// DDL 的"首词"分布 —— 很多库的 [DDL] 其实是 STAT（更新统计信息）或
			// `create or replace index` 这类维护语句，不看清会误以为"业务在改表结构"。
			p.st.noteDDLVerb(firstWord(sql))
		}
		// ---- 审计：和统计一样，在筛选**之前**采集，否则一条被 -m/-k 过滤掉的
		//      DROP TABLE 就不会出现在审计清单里 —— 那正是最不该漏的。 ----
		lvl, kind, obj := dangerLevel(sql, op)
		if lvl == 0 && info.rows != "" {
			if bad, k := batchDanger(op, info.rows); bad {
				lvl, kind = 2, k
				atomic.AddInt64(&p.st.BatchDML, 1)
			}
		}
		if lvl > 0 {
			auditIdx = p.st.noteAudit(lvl, kind, obj, op, info.ts, info.user, clientOf(sess),
				info.trxid, info.rows, info.execID, p.file, info.exeMS, stmtKeyStr(sess),
				field(sess, "thrd:", "user:"), op == "ORA")
		}
	}

	// ---- 过滤 ----
	if o.opSet != nil {
		if !o.opSet[op] {
			atomic.AddInt64(&p.st.Filtered, 1)
			return
		}
	} else if !o.allOps && !defaultOps[op] {
		// 默认只输出「可作为可执行 SQL 使用」的语句类型：
		//   [ORA] 只解析未执行、[LGN] 是登录事件 —— 默认不输出（要就显式 --op ORA 或 --all-ops）
		if op == "ORA" {
			atomic.AddInt64(&p.st.Skipped, 1)
		} else {
			atomic.AddInt64(&p.st.Filtered, 1)
		}
		return
	}
	// 时间筛选已在「统计落点」之前判过（见 outOfWindow），这里不再重复。
	if o.user != "" && info.user != o.user {
		atomic.AddInt64(&p.st.Filtered, 1)
		return
	}
	if o.trxSet != nil && !o.trxSet[info.trxid] {
		atomic.AddInt64(&p.st.Filtered, 1)
		return
	}
	if o.minMS > 0 && info.exeMS < o.minMS {
		atomic.AddInt64(&p.st.Filtered, 1)
		return
	}
	if o.maxMS > 0 && (info.exeMS > o.maxMS || !info.hasExec) {
		atomic.AddInt64(&p.st.Filtered, 1)
		return
	}
	if o.sqlLike != "" && !containsFold(sql, o.sqlLike) {
		atomic.AddInt64(&p.st.Filtered, 1)
		return
	}
	if o.dangerOnly { // 只要审计命中的语句（高危 / 结构变更 / 大批量 DML）
		lvl, _, _ := dangerLevel(sql, op)
		if lvl == 0 {
			if bad, _ := batchDanger(op, info.rows); !bad {
				atomic.AddInt64(&p.st.Filtered, 1)
				return
			}
		}
	}
	if o.limit > 0 && atomic.LoadInt64(&p.st.Out) >= int64(o.limit) {
		atomic.AddInt64(&p.st.Filtered, 1)
		return
	}

	// ---- 参数还原 ----
	outSQL := sql
	if !o.noParams {
		ph := findPlaceholders(sql)
		if len(ph) > 0 {
			// 两级匹配：先严格键（会话块含 thrd/user + 句柄），再退到句柄键。
			// 线程漂移（解析与执行落在不同线程）时严格键失配，句柄键仍能命中 ——
			// 官方桌面版只做第一级，因此会留下一批本可还原的 `?`。
			key, alt := p.key(sess), stmtKey(sess)
			ps, ok := p.pc.pop(key, len(ph))
			if !ok && alt != 0 {
				if ps2, ok2 := p.pc.pop(alt, len(ph)); ok2 {
					ps, ok = ps2, true
					atomic.AddInt64(&p.st.MatchedLoose, 1)
				}
			}
			if !ok {
				// 字面量里也带 '?'（如 like '?'）时 DM 会把它算作参数槽位，
				// 引号感知扫描会少算 —— 用全部 '?' 的个数再试一次（两级键都试）
				if raw := countAllQ(sql); raw > len(ph) {
					if ps2, ok2 := p.pc.pop(key, raw); ok2 {
						ps, ok, ph = ps2, true, allQPos(sql)
					} else if alt != 0 {
						if ps3, ok3 := p.pc.pop(alt, raw); ok3 {
							ps, ok, ph = ps3, true, allQPos(sql)
						}
					}
				}
			}
			if ok {
				vals := make([]string, len(ps))
				for i := range ps {
					vals[i] = formatVal(ps[i])
				}
				outSQL = applyParams(sql, ph, vals)
				atomic.AddInt64(&p.st.Matched, 1)
			} else {
				atomic.AddInt64(&p.st.Missing, 1)
				if o.skipMissing { // 只导出"能直接执行"的语句
					return
				}
				info.note = fmt.Sprintf("/*未找到匹配参数: 占位符%d个*/", len(ph))
			}
		} else {
			atomic.AddInt64(&p.st.NoParams, 1)
		}
	}

	// 参数已还原 → 把最慢语句 / 模板样例里的 SQL 换成可执行版本。
	// 报告与配套附件都要能直接拿去执行，所以必须回填（而不是留着带 ? 的原始文本）。
	if p.st.agg && needFill {
		p.st.fillRestored(slowIdx, tplK, tplNew, outSQL)
	}
	if auditIdx >= 0 {
		p.st.fillAuditSQL(auditIdx, outSQL)
	}
	if trxStmtIdx >= 0 {
		// 参数还原后把锁溯源里那条记录也换成可执行版本（与最慢语句/模板同一份文本）
		p.fillTrxStmtSQLAt(trxStmtIdx, outSQL)
	}

	if o.maxSQL > 0 && len(outSQL) > o.maxSQL {
		outSQL = append(append([]byte{}, outSQL[:o.maxSQL]...), []byte("/*…已截断*/")...)
	}

	switch {
	case o.topMS > 0: // 收集最慢 N 条，最后统一按耗时降序输出
		p.st.addTopMS(topStmt{MS: info.exeMS, Info: info, SQL: append([]byte(nil), outSQL...), File: p.file}, o.topMS)
	case !o.wantSQL():
		// -S 只给统计；纯 -s 只出报告 —— 都不往 stdout 刷 SQL（见 wantSQL 注释）
	default:
		p.writeStmt(&info, outSQL, sess)
	}
	atomic.AddInt64(&p.st.Out, 1)
}

func (p *parser) emitLoose(rec []byte) {
	o := p.opt
	n := tsLen(rec)
	if n == 0 {
		n = 19
		if len(rec) < n {
			return
		}
	}
	if len(rec) <= n {
		return
	}
	sql := bytes.TrimRight(bytes.TrimLeft(rec[n:], " \t"), " \t\r")
	if len(sql) == 0 {
		return
	}
	if o.sqlLike != "" && !containsFold(sql, o.sqlLike) {
		atomic.AddInt64(&p.st.Filtered, 1)
		return
	}
	// 排除：简单模式没有事件类型码，只能按 SQL 子串排除（-E 同样连统计一起排除）
	if len(o.exclLike) > 0 {
		for _, s := range o.exclLike {
			if containsFold(sql, s) {
				atomic.AddInt64(&p.st.Excluded, 1)
				atomic.AddInt64(&p.st.Filtered, 1)
				return
			}
		}
	}
	if o.exclSet != nil { // 简单模式一律视为普通 SQL，-E 若点名类型则整类排除
		if o.exclSet["SQL"] || o.exclSet["SEL"] && o.exclSet["INS"] && o.exclSet["UPD"] && o.exclSet["DEL"] {
			atomic.AddInt64(&p.st.Excluded, 1)
			atomic.AddInt64(&p.st.Filtered, 1)
			return
		}
	}
	atomic.AddInt64(&p.st.Exec, 1)
	p.st.addOp("SQL", "", "", "", string(rec[:19]), 0, "", p.file, "", sql)
	info := &stmtInfo{ts: string(rec[:19]), op: "SQL", note: "/*简单模式(SVR_LOG=3): 无会话块*/"}
	if o.wantSQL() && o.topMS == 0 {
		p.writeStmt(info, sql, nil)
	}
	atomic.AddInt64(&p.st.Out, 1)
}

func (p *parser) writeStmt(info *stmtInfo, sql, sess []byte) {
	// 二次扫描（生成配套完整 SQL 文件）时按事务号分组，
	// 这样"一个事务里到底跑了哪些语句"是聚在一起的，不被别的会话插花
	if g := p.opt.trxGroup; g != nil {
		g.writeStmt(info, sql, p.file, p.opt)
		return
	}
	formatStmt(&p.buf, info, sql, p.file, p.opt)
	_ = sess
}

// ---------------------------------------------------------------- 事务分组收集
//
// 用于"报告保持简洁、全文另存"：报告里 SQL 只显示摘要（好看），
// 要看全文就打开配套 .sql（按事务号分组）。
// 长事务的 trxid 要等扫完排序才知道，所以配套文件用**二次扫描**生成 ——
// 零额外内存，代价是多读一遍日志（只在要报告时发生）。
type trxGroup struct {
	mu    sync.Mutex
	bufs  map[string]*bytes.Buffer
	n     map[string]int
	limit int // 每事务最多收集的语句条数（防巨型事务把文件撑爆）
}

// releaseStats 释放扫描期的聚合表。
//
// 为什么需要它：报告要的数据已经拷进 statsView，但 st 里还压着几百 MB 的 map
// （模板表、50 万条事务表、秒桶…）。二次扫描生成附件时，这些存活对象会让每次 GC 都要
// 重新标记它们 —— 实测同样的 1GB 文件，二次扫描从 1.7s 拖到 7.5s。
// 释放后 st 不可再用（渲染只依赖 statsView）。
func releaseStats(s *Stats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ByOp, s.ByUser, s.ByClient, s.ByTable = nil, nil, nil, nil
	s.Tpl = nil
	s.TrxFirst, s.TrxLast, s.TrxCount, s.TrxKind, s.TrxUser = nil, nil, nil, nil, nil
	s.Sec = nil
	s.Slow = nil
	s.Locks = nil
	s.LockByTable = nil
	s.LockBySec = nil
	s.TopMSList = nil
	s.seenNames = nil
}

func newTrxGroup(limit int) *trxGroup {
	return &trxGroup{bufs: map[string]*bytes.Buffer{}, n: map[string]int{}, limit: limit}
}

func (g *trxGroup) writeStmt(info *stmtInfo, sql []byte, file string, opt *Options) {
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.bufs[info.trxid]
	if b == nil {
		b = &bytes.Buffer{}
		g.bufs[info.trxid] = b
	}
	if g.n[info.trxid] >= g.limit {
		if g.n[info.trxid] == g.limit {
			fmt.Fprintf(b, "\n-- …该事务语句过多，仅列出前 %d 条（要全量请单独跑：dmsqlq <路径> -x %s -N -o trx.sql）\n", g.limit, info.trxid)
			g.n[info.trxid]++
		}
		return
	}
	formatStmt(b, info, sql, file, opt)
	g.n[info.trxid]++
}

// total 收集到的语句条数（判断有没有抽到东西）
func (g *trxGroup) total() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	t := 0
	for _, n := range g.n {
		if n > g.limit {
			n = g.limit
		}
		t += n
	}
	return t
}

// formatStmt 输出一条语句：-- 注释头 + SQL + 结束符 + 空行
//
// 注释头字段用 " · " 分隔（此前 "0ms 0rows" 挤在一起不好读）：
//
//	-- 2026-09-10 00:02:17 · [SEL] · 0ms · 0行 · COSMIC01_SYS · trxid:10130765548 · KD1_20260909_235252
func formatStmt(b *bytes.Buffer, info *stmtInfo, sql []byte, file string, o *Options) {
	if !o.noMeta {
		b.WriteString("-- ")
		b.WriteString(info.ts)
		b.WriteString(" · [")
		b.WriteString(info.op)
		b.WriteByte(']')
		if info.hasExec {
			b.WriteString(" · ")
			b.WriteString(fmtDur0(info.exeMS))
			if info.rows != "" {
				b.WriteString(" · ")
				b.WriteString(info.rows)
				b.WriteString("行")
			}
		}
		if info.user != "" {
			b.WriteString(" · ")
			b.WriteString(info.user)
		}
		if info.trxid != "" && info.trxid != "0" {
			b.WriteString(" · trxid:")
			b.WriteString(info.trxid)
		}
		if file != "" {
			b.WriteString(" · ")
			b.WriteString(file)
		}
		if info.note != "" {
			b.WriteString(" · ")
			b.WriteString(info.note)
		}
		b.WriteByte('\n')
	} else if info.note != "" {
		b.WriteString(info.note)
		b.WriteByte('\n')
	}
	b.Write(sql)
	// 结束符：已有 ';' 或 PL/SQL 块结尾的 'end;' / '/' 不再追加
	if o.term != "" {
		t := bytes.TrimRight(sql, " \t\r\n")
		if len(t) == 0 || (t[len(t)-1] != ';' && t[len(t)-1] != '/') {
			b.WriteString(o.term)
		}
	}
	// 语句之间留一空行，方便肉眼分条、也方便整段复制后逐条执行
	b.WriteString("\n\n")
}

// fmtDur0 注释头里的耗时（整数毫秒，保持紧凑）
func fmtDur0(ms float64) string {
	if ms == float64(int64(ms)) {
		return strconv.FormatInt(int64(ms), 10) + "ms"
	}
	return strconv.FormatFloat(ms, 'f', 1, 64) + "ms"
}

// shortSrc 来源日志的短名：去掉 dmsql_ 前缀与 .log/.gz/.zip 等后缀
//
//	dmsql_KD1_20260909_235252.log  →  KD1_20260909_235252
func shortSrc(name string) string {
	s := name
	for {
		l := strings.ToLower(s)
		switch {
		case strings.HasSuffix(l, ".gz"):
			s = s[:len(s)-3]
		case strings.HasSuffix(l, ".zip"):
			s = s[:len(s)-4]
		case strings.HasSuffix(l, ".tar"):
			s = s[:len(s)-4]
		case strings.HasSuffix(l, ".log"):
			s = s[:len(s)-4]
		case strings.HasPrefix(l, "dmsql_"):
			s = s[6:]
		default:
			return s
		}
	}
}

// handleParams 解析 PARAMS 行并入缓存；off 是 "PARAMS(SEQNO" 在内容段中的起点
func (p *parser) handleParams(rest, sess []byte, off int) {
	eq := bytes.IndexByte(rest[off:], '=')
	if eq < 0 {
		return
	}
	atomic.AddInt64(&p.st.ParamsN, 1)
	// 🩸 这里**不**统计「该事务有多少条 PARAMS 行」。
	// 试过两版：string 键（2.09s → 4.31s）、零分配 uint64 键（→ 3.77s）——
	// PARAMS 行在现网是百万级，任何按行记账都会把这个工具 2 秒扫 2GB 的
	// 卖点毁掉。而这点信息用已有数据就能表达：
	// 事务表里没有它的语句行、却有事务事件 → 就是「语句文本未采集」。
	body := rest[off+eq+1:]
	cnt := countParams(body)
	if cnt > 0 {
		p.pc.pushRaw(p.key(sess), stmtKey(sess), body, cnt)
	}
}

// handleNonSQLEvent 处理非 SQL 事件行。
// 这些行不属于 SQL 事件（内容段没有 ") [XXX] " 标记），但锁等待、锁操作计时、
// 事务起止都在这里 —— 属于 SQL_TRACE_MASK 位号 29。
// 用首字符快速分派（TRX 事件在现网可达百万级，不能对每条都做全文扫描）。
func (p *parser) handleNonSQLEvent(rec, rest, sess []byte) {
	if len(rest) == 0 {
		return
	}
	switch rest[0] {
	case 'T': // TRX: START / COMMIT / ROLLBACK
		if !bytes.HasPrefix(rest, []byte("TRX: ")) {
			return
		}
		trxid := field(sess, "trxid:", "stmt:")
		ev := bytes.TrimSpace(rest[5:])
		kind := ""
		switch {
		case bytes.HasPrefix(ev, []byte("START")):
			kind = "START"
		case bytes.HasPrefix(ev, []byte("COMMIT")):
			kind = "COMMIT"
		case bytes.HasPrefix(ev, []byte("ROLLBACK")):
			kind = "ROLLBACK"
		default:
			return
		}
		if kind != "START" {
			// COMMIT / ROLLBACK 行的 trxid 通常是 0（归属不到具体事务），但次数与时间点够算 TPS/回滚率
			atomic.AddInt64(&p.st.TrxEndN, 1)
			if p.st.agg {
				// COMMIT 行可能带 LSN（`TRX: COMMIT LSN[141832342617]`）—— 恢复定位要用的锚点
				if m := reLSN.FindSubmatch(rest); m != nil {
					p.st.noteLSN(tsOf(rec), string(m[1]))
				}
				p.st.addTrxEnd(tsOf(rec), kind)
				// 本批现网日志实测 COMMIT/ROLLBACK **带真实 trxid** —— 补记结束事件，
				// 否则「持有方最后是提交还是回滚」永远显示不出来（trxid 为 0 时才真归属不到）
				if trxid != "" && trxid != "0" && trxid != "NULL" {
					p.noteTrxEnd(trxid, tsOf(rec), kind)
				}
			}
			return
		}
		atomic.AddInt64(&p.st.TrxEventN, 1)
		if p.st.agg { // 未要统计报告时连事务事件都不必记（现网可达千万级）
			p.st.addTrxEvent(trxid, tsOf(rec), kind)
		}
	case 'D': // DLCK used time:N(us) —— 锁节点自身耗时，不是等待
		if !bytes.HasPrefix(rest, []byte("DLCK used time:")) {
			return
		}
		// V2.12：DLCK 行带**真实 trxid** + **stmt 句柄**，是登记「事务 → 语句键」最省成本的
		// 位置（语句级，不是 PARAMS 那种百万级）。报告期用它把 [ORA] 行的 SQL 归回持有方。
		if p.st.agg {
			if trx := decID(field(sess, "trxid:", "stmt:")); trx != 0 {
				if k := p.key(sess); k != 0 {
					if p.oraKeyByTrx == nil {
						p.oraKeyByTrx = make(map[uint64]uint64, 4096)
					}
					if len(p.oraKeyByTrx) < maxOraTrxKey {
						p.oraKeyByTrx[trx] = k
					}
				}
			}
		}
		if m := reDlck.FindSubmatch(rest); m != nil {
			v, _ := strconv.ParseFloat(string(m[1]), 64)
			if m[2][0] == 'u' {
				v /= 1000
			}
			p.st.addDlck(v)
		}
	case 't': // trx[...] 开头：可能是锁等待行，也可能是 `alloc pseg page[...]` 之类噪声
		if !bytes.HasPrefix(rest, []byte("trx[")) {
			return
		}
		// 入口判据用 LOCK_TID（比 LOCK_ 精确得多：现网有 LOCK_R3 / LOCK_MONITOR
		// 这类表名会让 "LOCK_" 误伤），同时把 alloc pseg 之类的行挡在正则之外
		if !bytes.Contains(rest, lockTidTag) {
			return
		}
		if lk, ok := parseLockLine(rest, rec, sess, p.file); ok {
			p.st.addLockWait(lk, lockKeepCap(p.opt))
			return
		}
		p.st.addLockUnparsed() // 是锁行但三种格式都不认识 —— 留计数，方便发现新变体
	}
}

// parseLockLine 依次试三种锁等待格式，命中即返回结构化结果。
// 三种格式覆盖：① 单阻塞方带 tid[]；② 多阻塞方（现网主流）；③ 老版本"wait for LOCK_TID"。
func parseLockLine(rest, rec, sess []byte, file string) (lockWait, bool) {
	// 三条正则**依次试**、先中先用。
	// 不能按"含 tid[ 就试①、含 wait for 就试②"来分流 —— 格式③ 同时含 `tid[`
	// 与 `wait for`，按关键字分流会把 ③ 误送进 ① 从而判为"格式不认识"。
	var (
		waiter, mode, tableID, holder, num string
		unit                               []byte
		waiters                            int64
	)
	switch {
	case reLockSingle.Match(rest):
		m := reLockSingle.FindSubmatch(rest)
		waiter, mode, tableID, num, unit = string(m[1]), string(m[2]), string(m[3]), string(m[5]), m[6]
		// 这种格式没有"持有方事务号"，只有线程号（tid）—— 有 tid 就能到
		// V$LOCK / V$TRXWAIT 里反查是谁，所以照样保留
		tids := strings.ReplaceAll(string(m[4]), " ", "")
		holder = "tid:" + tids
		waiters = int64(strings.Count(tids, ",") + 1)
	case reLockMulti.Match(rest):
		m := reLockMulti.FindSubmatch(rest)
		waiter, mode, tableID = string(m[1]), string(m[2]), string(m[3])
		waiters, _ = strconv.ParseInt(string(m[4]), 10, 64)
		holder = strings.ReplaceAll(string(m[5]), " ", "")
		num, unit = string(m[6]), m[7]
	case reLockOld.Match(rest):
		m := reLockOld.FindSubmatch(rest)
		waiter, mode, tableID = string(m[1]), string(m[2]), string(m[3])
		// 这一组的第 4 段是 tid 列表（线程号），不是事务号 —— 加前缀，别被读成 trx
		tids := strings.ReplaceAll(strings.ReplaceAll(string(m[4]), " ", ""), "\t", "")
		holder = "tid:" + tids
		num, unit = string(m[5]), m[6]
		waiters = int64(strings.Count(tids, ",") + 1)
	default:
		return lockWait{}, false
	}
	// 持有方列表被 "...more" 截断：剥掉尾巴，避免把 "..." 当成一个事务号
	if i := strings.Index(holder, "...more"); i >= 0 {
		holder = strings.TrimRight(strings.TrimRight(holder[:i], ","), ",")
		// 截断时"声明个数"会大于实际，不作不一致告警
		return lockWait{
			TS: tsOf(rec), User: field(sess, "user:", "trxid:"), File: file,
			Waiter: waiter, Holder: holder, Mode: mode, TableID: tableID,
			Waiters: waiters, MS: lockMS(num, unit), More: true,
		}, true
	}
	actual := int64(1)
	if holder != "" {
		actual = int64(strings.Count(holder, ",") + 1)
	}
	return lockWait{
		TS: tsOf(rec), User: field(sess, "user:", "trxid:"), File: file,
		Waiter: waiter, Holder: holder, Mode: mode, TableID: tableID,
		Waiters: waiters, MS: lockMS(num, unit), CountMismatch: waiters != actual,
	}, true
}

// tsOf 取记录的时间戳；有毫秒/微秒就带上（长事务跨度需要亚秒精度）。
// 长度必须按 tsLen 动态判定 —— 6 位微秒的时间戳若硬截 23 字符，
// 会把微秒的前 3 位留在字符串里，既错位又不可比。
func tsOf(rec []byte) string {
	if n := tsLen(rec); n > 0 {
		return string(rec[:n])
	}
	if len(rec) >= 19 {
		return string(rec[:19])
	}
	return ""
}

// key 参数关联的**严格键**：会话块(截到 trxid 之前，含 thrd/user) + stmt 句柄。
// 之所以截到 trxid 之前：解析行与执行行的 trxid 常常不同（一个是 0，一个是真实事务号）。
// key 主匹配键。
//
// 🩸 为什么改成 uint64：现网日志 PARAMS 行占 98%（1.08GB 里 420 万条），
// 每条都要构键 + 写 map。字符串键要 concat + 哈希 + 堆分配，pprof 显示
// key() 连带 mapaccess/mapassign 吃掉 >25% CPU。
// 会话块里的关键字段都是十六进制地址，天然可解析成整数：
//
//	sess:0x7179eeb8  thrd:2858460  stmt:0x91371f0
//
// 🩸 语义必须与原字符串键等价（否则参数还原数会变）：
//
//	非 looseKey：原键 = sess[:trxid] + "|" + stmt → 即 (sess, thrd, stmt)
//	looseKey  ：原键 = sess[:thrd]  + "|" + stmt → 即 (sess, stmt)，忽略 thrd
//
// 实测 100 万行只有 178 个唯一句柄，整数键让哈希退化成一次乘法。
func (p *parser) key(sess []byte) uint64 {
	sv, th, stv := sessFields(sess)
	if p.opt.looseKey {
		return mix3(sv, 0, stv)
	}
	return mix3(sv, th, stv)
}

// sessFields 一次扫描取出会话块里的 sess / thrd / stmt 三个十六进制字段。
//
// 相比三个独立的 hexField()（各扫一遍整个会话块 = 3 遍），
// 这里只扫一遍：现网会话块字段顺序固定为
//
//	(EP[0] sess:0x.. thrd:.. user:.. trxid:.. stmt:0x.. appname: ip:..)
//
// 用「找关键字起点」的方式定位，命中后立即解析十六进制值。
func sessFields(sess []byte) (sessV, thrdV, stmtV uint64) {
	// 现网会话块字段顺序固定，逐个用 Index 定位即可；
	// 相比原来「key() 里调 3 次 hexField、每次全块扫描」，
	// 这里虽然仍是 3 次 Index，但 Index 是高度优化的 SIMD 实现，
	// 且省掉了每次重建 []byte("sess:") 的开销（改用包级变量）。
	if i := bytes.Index(sess, keySess); i >= 0 {
		sessV = hexAt(sess, i+len(keySess))
	}
	if i := bytes.Index(sess, keyThrd); i >= 0 {
		thrdV = hexAt(sess, i+len(keyThrd))
	}
	if i := bytes.Index(sess, keyStmt); i >= 0 {
		stmtV = hexAt(sess, i+len(keyStmt))
	}
	return
}

var (
	keySess = []byte("sess:")
	keyThrd = []byte("thrd:")
	keyStmt = []byte("stmt:")
)

// decID 把十进制事务号解析成 uint64（0 = 无事务号 / 解析失败）。
// 与 hexAt 分开：日志里 trxid 是十进制（如 391171），sess/stmt 才是十六进制。
func decID(s string) uint64 {
	if s == "" || s == "0" || s == "NULL" {
		return 0
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		v = v*10 + uint64(c-'0')
		if v > 1<<62 {
			return 0
		}
	}
	return v
}

// hexAt 从 p 起解析十六进制值（自动跳过 "0x"），零分配
func hexAt(s []byte, p int) uint64 {
	if p < len(s) && s[p] == 'N' { // NULL
		return 0
	}
	if p+1 < len(s) && s[p] == '0' && (s[p+1] == 'x' || s[p+1] == 'X') {
		p += 2
	}
	var v uint64
	n := 0
	for p < len(s) && n < 16 {
		c := s[p]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return v
		}
		v = v<<4 | d
		p++
		n++
	}
	return v
}

// mix3 把三个数值字段打包成一个 uint64 键（乘法混合，冲突率对本文域可忽略）
func mix3(a, b, c uint64) uint64 {
	return (a*2654435761^b*40503)*2654435761 ^ c
}

// stmtKey 参数关联的**句柄键**（只有 stmt）：官方 Web 版 v1.5.3 的默认策略。
// 不含 thrd / user / trxid —— 线程漂移（同一条 SQL 的解析与执行落在不同线程）时
// 严格键会失配、句柄键仍能命中。stmt 为 NULL/空时返回空串，表示不作退化匹配。
func stmtKey(sess []byte) uint64 {
	return hexField(sess, "stmt:")
}

// stmtKeyStr 句柄键的字符串形态 —— 只有审计明细需要（它把句柄当标识展示/落表），
// 不在热路径上，故用原来的 field() 实现。
func stmtKeyStr(sess []byte) string {
	st := field(sess, "stmt:", "appname:")
	if st == "" || st == "NULL" {
		return ""
	}
	return "stmt:" + st
}

// hexField 从会话块里取出形如 "sess:0x7179eeb8" 的十六进制字段并转成 uint64。
// 零分配：直接扫字节做 base16 累加，不构造 string、不走 strconv。
// 找不到或值为 NULL 时返回 0（与原 field() 返回 ""/被调用方丢弃 的语义对齐 ——
// 原实现在 stmt 为 NULL 时不入缓存，见 handleParams 的 count 判定）。
func hexField(sess []byte, name string) uint64 {
	i := bytes.Index(sess, []byte(name))
	if i < 0 {
		return 0
	}
	i += len(name)
	if i < len(sess) && sess[i] == 'N' { // NULL
		return 0
	}
	if i+1 < len(sess) && sess[i] == '0' && (sess[i+1] == 'x' || sess[i+1] == 'X') {
		i += 2
	}
	var v uint64
	n := 0
	for i < len(sess) && n < 16 {
		c := sess[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return v
		}
		v = v<<4 | d
		i++
		n++
	}
	return v
}

// splitSession 切出内容段与会话块。
// 注意：不能用「第一个 ')'」判定结束 —— 会话块里的 EP[0] 自带一个右括号，
// 官方的 indexOf(")") 会在此处提前截断；这里用括号配对找到真正的收尾。
func splitSession(rec []byte) (rest, sess []byte) {
	lp := bytes.IndexByte(rec, '(')
	if lp < 0 {
		return nil, nil
	}
	// 会话块必须**紧跟时间戳**（官方口径：DM 的会话块一定紧跟在时间戳后）。
	// 这条约束能挡住两类误判：
	//   ① SVR_LOG=3 简单模式的行里 SQL 自带括号，如 `... insert into t values(1);`
	//      —— 若只看"第一个 '('"，会把 values(1) 当会话块，整行被当成非 SQL 事件丢掉；
	//   ② 老格式续行开头的括号。
	if n := tsLen(rec); n > 0 && lp != n+1 {
		return nil, nil
	}
	depth := 0
	for i := lp; i < len(rec); i++ {
		switch rec[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return bytes.TrimLeft(rec[i+1:], " "), rec[lp : i+1]
			}
		}
	}
	return nil, nil
}

// field 取会话块中 a..b 之间的字段值
func field(sess []byte, a, b string) string {
	i := bytes.Index(sess, []byte(a))
	if i < 0 {
		return ""
	}
	i += len(a)
	j := bytes.Index(sess[i:], []byte(b))
	if j < 0 {
		return strings.TrimSpace(string(sess[i:]))
	}
	return strings.TrimSpace(string(sess[i : i+j]))
}

// clientOf 从会话块里取客户端标识（appname + ip）。// 现场日志里 appname 经常是空的、只有 ip，所以两者组合起来才够用。
func clientOf(sess []byte) string {
	app := field(sess, "appname:", "ip:")
	ip := field(sess, "ip:", ")") // IPv6 写法（::ffff:10.0.0.27）原样保留，不做归一化
	switch {
	case app != "" && ip != "":
		return app + " @ " + ip
	case app != "":
		return app
	case ip != "":
		return ip
	}
	return ""
}

// parseExecTime 取 EXECTIME 的数值与单位，并把单位统一归一化成毫秒。
//
// 单位不是恒定的：sqllog.ini 的 EXECTIME_PREC_FLAG 决定它是 (ms) 还是 (us)
// （0→毫秒，1→微秒，2 只改 MIN_EXEC_TIME 的过滤单位）。老版本写死了 "(ms)"，
// 在 =1 的库上会把耗时整体缩小 1000 倍 —— 本工具读单位，所以两种库都对。
// 返回：(毫秒值, 单位字符串)。找不到时是 (0, "")。
func parseExecTime(tail []byte) (float64, string) {
	// 用 LastIndex：一行里可能同时出现 `EXECTIME:` 以外的相似词，取最后一个才是本语句的
	i := bytes.LastIndex(tail, []byte("EXECTIME"))
	if i < 0 {
		return 0, ""
	}
	i += len("EXECTIME")
	for i < len(tail) && (tail[i] == ':' || tail[i] == ' ' || tail[i] == '\t') {
		i++
	}
	j := i
	for j < len(tail) && (tail[j] >= '0' && tail[j] <= '9' || tail[j] == '.' || tail[j] == '-' || tail[j] == '+') {
		j++
	}
	v, err := strconv.ParseFloat(string(tail[i:j]), 64)
	if err != nil {
		return 0, ""
	}
	// 单位：跳过空白后应是 "(ms)" / "(us)" / "(ns)"
	k := j
	for k < len(tail) && (tail[k] == ' ' || tail[k] == '\t') {
		k++
	}
	unit := ""
	if k < len(tail) && tail[k] == '(' {
		e := k + 1
		for e < len(tail) && tail[e] != ')' {
			e++
		}
		unit = strings.ToLower(strings.TrimSpace(string(tail[k+1 : e])))
	}
	switch unit {
	case "us", "\u00b5s":
		return v / 1000, "us" // 微秒 → 毫秒
	case "ns":
		return v / 1e6, "ns" // 纳秒 → 毫秒
	case "ms":
		return v, "ms"
	}
	// 单位缺失：按毫秒处理（老日志/截断），但返回空单位以便调用方发现异常
	return v, ""
}

// parseExecID 取执行行尾部的 `EXEC_ID: 3897078`。
//
// 它对应动态视图 V$SQL_NODE_HISTORY.EXEC_ID —— 有了它，报告里的慢 SQL 就能
// 下钻到"每个执行节点（含 DLCK 锁节点）花了多少时间"，这是 SQL 日志本身
// 没有、只能靠 EXEC_ID 去库里换回来的信息。
func parseExecID(tail []byte) string {
	i := bytes.LastIndex(tail, []byte("EXEC_ID"))
	if i < 0 {
		return ""
	}
	i += len("EXEC_ID")
	for i < len(tail) && (tail[i] == ':' || tail[i] == ' ' || tail[i] == '\t') {
		i++
	}
	j := i
	for j < len(tail) && tail[j] >= '0' && tail[j] <= '9' {
		j++
	}
	if j == i {
		return ""
	}
	return string(tail[i:j])
}

func parseRowCount(tail []byte) string {
	i := bytes.Index(tail, []byte("ROWCOUNT:"))
	if i < 0 {
		return ""
	}
	i += len("ROWCOUNT:")
	for i < len(tail) && tail[i] == ' ' {
		i++
	}
	j := i
	for j < len(tail) && tail[j] >= '0' && tail[j] <= '9' {
		j++
	}
	if j == i {
		return ""
	}
	return string(tail[i:j])
}

func containsFold(hay []byte, needle string) bool {
	n := []byte(needle)
	if len(n) == 0 {
		return true
	}
	// 逐个位置做 ASCII 折叠比较，避免为每条 SQL 分配小写副本
	for i := 0; i+len(n) <= len(hay); i++ {
		ok := true
		for k := 0; k < len(n); k++ {
			a, b := hay[i+k], n[k]
			if a >= 'A' && a <= 'Z' {
				a += 32
			}
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			if a != b {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- 归档与文件处理

// fmtSize 人类可读体积（进度显示用；报告里另有更严格的格式化）
func fmtSize(n int64) string {
	f := float64(n)
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", f/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", f/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", f/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// truncDisp 按「显示宽度」截断（中文按 2 格算），超出加省略号
func truncDisp(s string, w int) string {
	cur, out := 0, make([]rune, 0, len(s))
	for _, r := range s {
		rw := 1
		if r > 0x2E80 {
			rw = 2
		}
		if cur+rw > w {
			return string(out) + "…"
		}
		cur += rw
		out = append(out, r)
	}
	return string(out)
}

// progress 大文件/大压缩包的实时进度。
//
// 为什么需要：5.4GB 的 tar.gz 解压后 107GB，解压阶段本身要 60~160 秒，
// 期间没有任何输出，用户分不清「在跑」还是「卡死」。
//
// 设计：
//
//	· 只朝 stderr 写（stdout 留给数据，可管道）；-q 关闭
//	· TTY 下用 \r 原地刷新一行；非 TTY（重定向/管道）降级为限频整行
//	· 限频 200ms，避免刷屏本身成为开销
type progress struct {
	quiet   bool
	tty     bool
	last    time.Time
	started time.Time
	lastLen int
}

var gProg = &progress{started: time.Now()}

func (p *progress) init(opt *Options) {
	p.quiet = opt.quiet
	p.tty = isTerminal(os.Stderr)
	p.started = time.Now()
}

// tick 周期汇报。total 为 0 表示总量未知（如 zip 无解压尺寸时）
func (p *progress) tick(done, total int64, label string, records int64) {
	if p == nil || p.quiet {
		return
	}
	now := time.Now()
	if now.Sub(p.last) < 200*time.Millisecond {
		return
	}
	p.last = now
	el := now.Sub(p.started).Seconds()

	var speed, eta, pct string
	if el > 0.3 && done > 0 {
		speed = fmt.Sprintf("%s/s", fmtSize(int64(float64(done)/el)))
		if total > done {
			remain := float64(total-done) / (float64(done) / el)
			eta = "  剩余 " + fmtDur(remain*1000)
		}
	}
	if total > 0 {
		pct = fmt.Sprintf(" %5.1f%%", float64(done)*100.0/float64(total))
	}
	line := fmt.Sprintf("  ⏳%s  %s / %s  %s%s  · %s 条  %s",
		pct, fmtSize(done), fmtSize(total), speed, eta, fmtInt(records), truncDisp(label, 30))

	pad := ""
	if p.lastLen > len(line) {
		pad = strings.Repeat(" ", p.lastLen-len(line))
	}
	p.lastLen = len(line)
	if p.tty {
		fmt.Fprintf(os.Stderr, "\r%s%s", line, pad)
	} else {
		fmt.Fprintln(os.Stderr, line)
	}
}

// done 收尾：清掉进度行，避免和后续结论文本黏在一起
func (p *progress) done() {
	if p == nil || p.quiet || !p.tty || p.lastLen == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", p.lastLen))
	p.lastLen = 0
}

func hasSuffixAny(s string, suf ...string) bool {
	for _, x := range suf {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

func isArchiveName(l string) bool {
	return hasSuffixAny(l, ".zip", ".tar.gz", ".tgz", ".gz")
}

// isLogEntry 归档内部的条目名是否为需要处理的日志
func isLogEntry(base string, all bool) bool {
	l := strings.ToLower(base)
	if all {
		return strings.HasSuffix(l, ".log")
	}
	return strings.HasPrefix(l, "dmsql_") && strings.HasSuffix(l, ".log")
}

// processFile 处理一个日志文件；.gz/.zip/.tar.gz 会自动就地解压，无需先手动解包
func processFile(path string, w io.Writer, opt *Options, st *Stats) error {
	lower := strings.ToLower(path)
	switch {
	case hasSuffixAny(lower, ".tar.gz", ".tgz"):
		return processTarGz(path, w, opt, st)
	case strings.HasSuffix(lower, ".zip"):
		return processZip(path, w, opt, st)
	case strings.HasSuffix(lower, ".gz"):
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		zr, err := gzip.NewReader(bufio.NewReaderSize(f, zipReadBuf))
		if err != nil {
			return fmt.Errorf("gzip 解压失败: %w", err)
		}
		defer zr.Close()
		atomic.AddInt64(&st.Files, 1)
		return processStream(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)), zr, w, opt, st)
	default:
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		atomic.AddInt64(&st.Files, 1)
		return processStream(filepath.Base(path), f, w, opt, st)
	}
}

func processZip(path string, w io.Writer, opt *Options, st *Stats) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("zip 打开失败: %w", err)
	}
	defer zr.Close()
	hit := 0
	// zip 有中央目录，解压后总体积可精确得知
	var ztotalZip int64
	for _, e := range zr.File {
		if isLogEntry(filepath.Base(e.Name), opt.allFiles) {
			ztotalZip += int64(e.UncompressedSize64)
		}
	}
	for _, e := range zr.File {
		if e.FileInfo().IsDir() {
			continue
		}
		base := filepath.Base(e.Name)
		if !isLogEntry(base, opt.allFiles) {
			continue
		}
		rc, err := e.Open()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ! %s:%s 打开失败: %v\n", filepath.Base(path), base, err)
			continue
		}
		hit++
		atomic.AddInt64(&st.Files, 1)
		if !opt.quiet {
			fmt.Fprintf(os.Stderr, "  ▸ %s 内的日志 %d：%s（%s）\n",
				filepath.Base(path), hit, base, fmtSize(int64(e.UncompressedSize64)))
		}
		if err := processStream(base, rc, w, opt, st); err != nil {
			fmt.Fprintf(os.Stderr, "  ! %s:%s 处理失败: %v\n", filepath.Base(path), base, err)
		}
		rc.Close()
		gProg.tick(atomic.LoadInt64(&st.Bytes), ztotalZip, base, atomic.LoadInt64(&st.Records))
	}
	if hit == 0 && !opt.quiet {
		fmt.Fprintf(os.Stderr, "  · %s: 包内没有 dmsql_*.log（用 --all-files 可放开）\n", filepath.Base(path))
	}
	return nil
}

func processTarGz(path string, w io.Writer, opt *Options, st *Stats) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// 🩸 进度分母：tar.gz 没有索引，拿不到解压后总量。
	// 朴素做法是「压缩包体积 × 固定压缩比」，但 DM 日志压缩比因数据而异
	// （实测 5.4GB→107GB 是 19.7x，写死 8x 会明显偏低、进度条跑过头）。
	// 这里用**自适应比例**：在 gzip 前挂一个计数 reader，实时算
	//   实际压缩比 = 已解压字节 / 已读压缩字节
	// 再乘上文件总体积即得估算总量 —— 头几十 MB 后就相当准。
	cr := &cntReader{r: bufio.NewReaderSize(f, zipReadBuf)}
	zr, err := gzip.NewReader(cr)
	if err != nil {
		return fmt.Errorf("gzip 解压失败: %w", err)
	}
	defer zr.Close()
	var fileSize int64
	if fi, e := f.Stat(); e == nil {
		fileSize = fi.Size()
	}
	tr := tar.NewReader(zr)
	hit := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar 读取失败: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		base := filepath.Base(hdr.Name)
		if !isLogEntry(base, opt.allFiles) {
			continue
		}
		hit++
		atomic.AddInt64(&st.Files, 1)
		if !opt.quiet {
			fmt.Fprintf(os.Stderr, "  ▸ %s 内的日志 %d：%s（%s）\n",
				filepath.Base(path), hit, base, fmtSize(hdr.Size))
		}
		if err := processStream(base, tr, w, opt, st); err != nil {
			fmt.Fprintf(os.Stderr, "  ! %s:%s 处理失败: %v\n", filepath.Base(path), base, err)
		}
		gProg.tick(atomic.LoadInt64(&st.Bytes), estTotal(cr.nRead(), fileSize, atomic.LoadInt64(&st.Bytes)),
			base, atomic.LoadInt64(&st.Records))
	}
	if hit == 0 && !opt.quiet {
		fmt.Fprintf(os.Stderr, "  · %s: 包内没有 dmsql_*.log（用 --all-files 可放开）\n", filepath.Base(path))
	}
	return nil
}

// cntReader 统计底层读了多少「压缩字节」，用于实时推算压缩比。
type cntReader struct {
	r io.Reader
	n int64
}

func (c *cntReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// nRead 返回已读压缩字节数（供进度估算用）
func (c *cntReader) nRead() int64 { return c.n }

// estTotal 用「已读压缩字节 → 已解压字节」的实际比例，推算整个包的解压总量。
//
// 前 1MB 内比例不稳（gzip 头/字典预热），此时回退为「压缩包体积 × 12」
// 这个 DM 日志的典型量级，避免进度条一开始就显示成 300%。
func estTotal(compressedRead, fileSize, produced int64) int64 {
	if compressedRead < 1<<20 || produced <= 0 || fileSize <= 0 {
		if fileSize > 0 {
			return fileSize * 12
		}
		return 0
	}
	ratio := float64(produced) / float64(compressedRead)
	est := int64(float64(fileSize) * ratio)
	// 估算值至少不小于已产出（否则进度条会 >100%）
	if est < produced {
		est = produced
	}
	return est
}

// processStream 解析一路日志字节流（文件 / 解压流）
func processStream(name string, r io.Reader, w io.Writer, opt *Options, st *Stats) error {
	st.noteSource(name)
	p := &parser{opt: opt, pc: newParamCache(), st: st, file: shortSrc(name)}
	// 文件处理完（含提前结束/出错）把锁溯源缓冲并入全局。
	// 用 defer 而不是写在末尾：processStream 有三处 return，漏一处就会丢这个文件的溯源。
	defer st.mergeTrxTrace(p)
	buf := make([]byte, chunkSize)
	var cur []byte   // 当前记录（含续行）
	var carry []byte // 跨读取块的残行
	seenSess := false
	nRec := 0
	// epStrict：本文件是否用 "(EP[" 会话块格式（现代 DM 日志都是）。
	// 判定在遇到第一条合法时间戳行时做一次；在此之前按宽松判据放行，
	// 避免「老格式 / SVR_LOG=3 简单模式」被整篇拼成一条续行。
	epStrict := false
	epKnown := false

	// feed 处理一个完整行
	feed := func(line []byte) (stop bool) {
		if !epKnown && tsLen(line) > 0 {
			epKnown = true
			epStrict = bytes.Contains(line, []byte("(EP["))
		}
		if n := newRecLen(line, epStrict); n > 0 {
			if n == 26 {
				atomic.AddInt64(&st.Ts26, 1)
			}
			if cur != nil {
				nRec++
				if !seenSess && nRec <= 20 && bytes.Contains(cur, []byte("sess:")) {
					seenSess = true
				}
				p.handleRecord(cur)
				if opt.limit > 0 && atomic.LoadInt64(&st.Out) >= int64(opt.limit) {
					return true
				}
				if p.buf.Len() >= 1<<20 {
					flush(&p.buf, w)
				}
			}
			cur = append(cur[:0], line...)
		} else if cur != nil {
			cur = append(cur, '\n')
			cur = append(cur, line...)
		}
		return false
	}

	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			atomic.AddInt64(&st.Bytes, int64(n))
			data := buf[:n]
			for len(data) > 0 {
				i := bytes.IndexByte(data, '\n')
				if i < 0 { // 残行：留到下一块再拼（不能当整行处理）
					carry = append(carry, data...)
					break
				}
				line := data[:i]
				data = data[i+1:]
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				usedCarry := false
				if len(carry) > 0 {
					carry = append(carry, line...)
					line, usedCarry = carry, true
				}
				stop := feed(line)
				if usedCarry {
					carry = carry[:0]
				}
				if stop {
					flush(&p.buf, w)
					return nil
				}
			}
		}
		if err != nil {
			break
		}
	}
	if len(carry) > 0 { // 文件末尾无换行符的最后一整行
		feed(carry)
	}
	if cur != nil {
		p.handleRecord(cur)
	}
	flush(&p.buf, w)

	if !seenSess && nRec > 0 && !opt.loose && !opt.quiet {
		fmt.Fprintf(os.Stderr, "  ! %s: 未发现会话块，可能不是 SQL 日志（SVR_LOG=3 简单模式可加 --loose）\n", name)
	}
	return nil
}

func flush(b *bytes.Buffer, w io.Writer) {
	if b.Len() > 0 {
		w.Write(b.Bytes())
		b.Reset()
	}
}

// ---------------------------------------------------------------- 文件收集

// isCandidate 目录扫描时的入选项判定
//
//	默认：dmsql_*.log、dmsql_*.log.gz、dmsql_*.log.zip，以及名字含 log/dmsql 的归档
//	      （例如 dm_log_20260910.tar.gz —— 归档会自动解压，不必先解包）
//	--all-files：放开为所有 .log 与所有归档
func isCandidate(name string, all bool) bool {
	l := strings.ToLower(name)
	if all {
		return strings.HasSuffix(l, ".log") || isArchiveName(l)
	}
	if strings.HasSuffix(l, ".log") {
		return strings.HasPrefix(l, "dmsql_") // 避开 dm_ 事件日志 / dmtrc_ 跟踪日志
	}
	if hasSuffixAny(l, ".log.gz", ".log.zip") {
		return strings.HasPrefix(l, "dmsql_")
	}
	return isArchiveName(l) && (strings.Contains(l, "log") || strings.Contains(l, "dmsql"))
}

// collectFiles 汇总待处理文件：支持多路径、绝对/相对路径、通配符、目录递归
func collectFiles(paths []string, all bool) ([]string, int, error) {
	var out []string
	globMiss := 0
	seen := map[string]bool{}
	add := func(p string) {
		ap, err := filepath.Abs(p)
		if err == nil {
			if seen[ap] {
				return
			}
			seen[ap] = true
		}
		out = append(out, p)
	}
	for _, p := range paths {
		// 通配符（cmd.exe 不会自己展开；bash 已展开时这里自然不命中）
		if strings.ContainsAny(p, "*?[") {
			ms, err := filepath.Glob(p)
			if err != nil || len(ms) == 0 {
				globMiss++
				continue
			}
			for _, m := range ms {
				fi, err := os.Stat(m)
				if err != nil {
					continue
				}
				if fi.IsDir() {
					if err := walkDir(m, all, add); err != nil {
						return nil, globMiss, err
					}
					continue
				}
				add(m) // 显式命中的文件一律处理，不看命名规则
			}
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			return nil, globMiss, err
		}
		if !fi.IsDir() {
			add(p) // 显式指定的文件一律处理，不看命名规则
			continue
		}
		if err := walkDir(p, all, add); err != nil {
			return nil, globMiss, err
		}
	}
	sort.Strings(out)
	return out, globMiss, nil
}

func walkDir(dir string, all bool, add func(string)) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !isCandidate(d.Name(), all) {
			return nil
		}
		add(path)
		return nil
	})
}

// ---------------------------------------------------------------- shell 补全
//
// dmsqlq 是「选项驱动」（主命令） + 「watch 子命令」两种形态，补全需分派：
//   dmsqlq <TAB>        → 主命令选项 + watch + 日志文件/目录
//   dmsqlq watch <TAB>  → watch 专属选项 + 目录
// 安装方式与 dmkit 对齐：写补全脚本 → rc 维护带标记的自动同步区块 → 标记文件，
// 支持「首次运行一次性自动安装」。

const (
	dmCompMarkBegin = "# >>> dmsqlq completion >>>"
	dmCompMarkEnd   = "# <<< dmsqlq completion <<<"
)

// dmCompMainFlags 主命令选项（与 parseArgs 注册保持一致）。
var dmCompMainFlags = []string{
	"-f", "--from", "-t", "--to", "-m", "--min-ms", "-M", "--max-ms",
	"-k", "--op", "-E", "--exclude-op", "-K", "--all-ops", "-u", "--user",
	"-x", "--trx", "-l", "--sql-like", "-n", "--limit", "-O", "--obj-map",
	"-s", "--stats", "-S", "--stats-only", "-r", "--stats-out",
	"-e", "--excel", "-p", "--top", "-F", "--full-sql",
	"-o", "--out", "-B", "--top-ms", "-T", "--term", "-N", "--no-meta",
	"-P", "--no-params", "-X", "--skip-missing", "-d", "--danger", "-C", "--max-sql",
	"-A", "--all-files", "-L", "--loose", "-Y", "--loose-key", "-j", "--jobs",
	"-q", "--quiet", "-Q", "--no-open", "-h", "--help", "-V", "--version",
}

// dmCompWatchFlags watch 子命令选项（与 watchParseArgs 注册保持一致）。
var dmCompWatchFlags = []string{
	"-a", "--app", "-k", "--op", "-m", "--min-ms", "-l", "--like",
	"-A", "--all", "-T", "--tail", "-n", "--limit",
	"-i", "--interval", "--poll", "-g", "--gap",
	"-d", "--dir", "-p", "--pass", "-H", "--host", "-P", "--port",
	"-Y", "--sync-log", "--show-paths", "--forget", "-w", "--width",
	"-F", "--full", "--color", "--no-header", "--sql-only",
	"-h", "--help",
}

// dmCompHiddenFlags 补全自身的隐藏选项（主命令层）。
var dmCompHiddenFlags = []string{
	"--completion-install", "--completion-uninstall", "--completion-bash", "--completion-install-dry-run",
}

// dmToBashPath 把 Windows 原生路径转成 Git Bash 能识别的 /c/xxx 形式。
func dmToBashPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) >= 2 && p[1] == ':' {
		p = "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}

// dmCompScript 生成 bash/zsh 通用补全脚本（zsh 下自动启用 bashcompinit）。
func dmCompScript(binPath string) string {
	var b strings.Builder
	b.WriteString("# dmsqlq bash/zsh 补全（由 `dmsqlq --completion-install` 生成）\n")
	b.WriteString("# zsh 用户：本脚本会自动加载 bashcompinit，无需额外配置\n\n")
	fmt.Fprintf(&b, "DMSQLQ_BIN=\"%s\"\n", dmToBashPath(binPath))
	fmt.Fprintf(&b, "DMSQLQ_MAIN_FLAGS=\"%s\"\n", strings.Join(dmCompMainFlags, " "))
	fmt.Fprintf(&b, "DMSQLQ_WATCH_FLAGS=\"%s\"\n", strings.Join(dmCompWatchFlags, " "))
	fmt.Fprintf(&b, "DMSQLQ_HIDDEN_FLAGS=\"%s\"\n\n", strings.Join(dmCompHiddenFlags, " "))
	b.WriteString(`_dmsqlq() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    # 判定是否处于 watch 子命令下（第一个非选项词是 watch）
    local inwatch=0 i w
    for (( i=1; i < COMP_CWORD; i++ )); do
        w="${COMP_WORDS[i]}"
        [[ "$w" == -* ]] && continue
        [[ "$w" == "watch" ]] && inwatch=1
        break
    done
    case "$prev" in
        -k|--op)
            if [[ $inwatch -eq 1 ]]; then
                COMPREPLY=($(compgen -W "SEL INS UPD DEL DML DDL CAL ERR" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "SEL INS UPD DEL DML DDL CAL ERR" -- "$cur"))
            fi ;;
        -E|--exclude-op) COMPREPLY=($(compgen -W "CAL DDL SEL INS UPD DEL" -- "$cur")) ;;
        -e|--excel|-o|--out|-r|--stats-out|-O|--obj-map|-F|--full-sql|-d|--dir)
            COMPREPLY=($(compgen -f -- "$cur")) ;;
    esac
    if [ ${#COMPREPLY[@]} -eq 0 ]; then
        if [[ "$cur" == -* ]]; then
            if [[ $inwatch -eq 1 ]]; then
                COMPREPLY=($(compgen -W "$DMSQLQ_WATCH_FLAGS -h --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$DMSQLQ_MAIN_FLAGS watch $DMSQLQ_HIDDEN_FLAGS" -- "$cur"))
            fi
        else
            COMPREPLY=($(compgen -f -- "$cur"))   # 位置参数：日志文件/目录
        fi
    fi
    return 0
}
if [[ -n "${ZSH_VERSION:-}" ]]; then
    autoload -U +X bashcompinit 2>/dev/null && bashcompinit
fi
complete -o default -o filenames -F _dmsqlq dmsqlq
`)
	return b.String()
}

// dmResolveTargets 返回 rc 文件、补全脚本路径与 shell 名。
func dmResolveTargets() (shell, rcPath, scriptPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", "", err
	}
	if h := os.Getenv("HOME"); h != "" {
		if runtime.GOOS == "windows" && strings.HasPrefix(h, "/") {
			if len(h) >= 3 && h[2] == '/' {
				home = strings.ToUpper(h[1:2]) + ":" + strings.ReplaceAll(h[2:], "/", `\`)
			}
		} else {
			home = h
		}
	}
	shell = "bash"
	if strings.Contains(strings.ToLower(os.Getenv("SHELL")), "zsh") {
		shell = "zsh"
	}
	switch shell {
	case "zsh":
		rcPath = filepath.Join(home, ".zshrc")
	default:
		rcPath = filepath.Join(home, ".bashrc")
	}
	scriptPath = filepath.Join(home, ".dmsqlq", "completion.bash")
	return
}

// dmCompBlock 生成 rc 标记区块：新终端启动时 mtime 比对，二进制更新过才重新生成。
func dmCompBlock(binPath string) string {
	bin := "$(command -v dmsqlq 2>/dev/null)"
	if binPath != "" {
		bin = dmToBashPath(binPath)
	}
	var b strings.Builder
	b.WriteString(dmCompMarkBegin + "\n")
	b.WriteString("# dmsqlq 补全：新终端启动时自动同步（二进制更新后首次启动即刷新；幂等）\n")
	fmt.Fprintf(&b, "_dmsqlq_bin=\"%s\"\n", bin)
	b.WriteString("_dmsqlq_comp=\"$HOME/.dmsqlq/completion.bash\"\n")
	b.WriteString("if [ -x \"$_dmsqlq_bin\" ] && { [ ! -f \"$_dmsqlq_comp\" ] || [ \"$_dmsqlq_bin\" -nt \"$_dmsqlq_comp\" ]; }; then\n")
	b.WriteString("    \"$_dmsqlq_bin\" --completion-bash > \"$_dmsqlq_comp.tmp\" 2>/dev/null \\\n")
	b.WriteString("        && mv -f \"$_dmsqlq_comp.tmp\" \"$_dmsqlq_comp\" 2>/dev/null \\\n")
	b.WriteString("        || rm -f \"$_dmsqlq_comp.tmp\"\n")
	b.WriteString("fi\n")
	b.WriteString("[ -f \"$_dmsqlq_comp\" ] && source \"$_dmsqlq_comp\"\n")
	b.WriteString("unset _dmsqlq_bin _dmsqlq_comp\n")
	b.WriteString(dmCompMarkEnd + "\n")
	return b.String()
}

// dmManageBlock 在 rc 内容中维护标记区块（幂等；返回新内容与动作说明）。
func dmManageBlock(content, block string, exists bool) (string, string) {
	if !exists && strings.TrimSpace(content) == "" {
		return block, "新建文件并写入标记区块"
	}
	blockLines := strings.Split(strings.TrimSuffix(block, "\n"), "\n")
	lines := strings.Split(content, "\n")
	var out []string
	inBlock, closed := false, false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if inBlock {
			if t == dmCompMarkEnd {
				inBlock, closed = false, true
			}
			continue
		}
		if t == dmCompMarkBegin {
			inBlock = true
			out = append(out, blockLines...)
			continue
		}
		out = append(out, ln)
	}
	if !closed {
		res := strings.Join(out, "\n")
		if res != "" && !strings.HasSuffix(res, "\n") {
			res += "\n"
		}
		res += "\n" + block
		return res, "追加标记区块"
	}
	return strings.Join(out, "\n"), "原地更新标记区块"
}

// dmCompInstall 幂等安装：写补全脚本 + 维护 rc 区块。
func dmCompInstall(errW io.Writer, binPath string, dryRun bool) error {
	_, rcPath, scriptPath, err := dmResolveTargets()
	if err != nil {
		return err
	}
	script := dmCompScript(binPath)
	block := dmCompBlock(binPath)
	old, err := os.ReadFile(rcPath)
	rcExists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	newRC, action := dmManageBlock(string(old), block, rcExists)

	if dryRun {
		fmt.Fprintf(errW, "[dry-run] 补全脚本(%d 行) → %s\n", strings.Count(script, "\n"), scriptPath)
		fmt.Fprintf(errW, "[dry-run] rc → %s：%s\n", rcPath, action)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(scriptPath, []byte(script), 0644); err != nil {
		return err
	}
	if newRC != string(old) {
		if err := os.WriteFile(rcPath, []byte(newRC), 0644); err != nil {
			return err
		}
	}
	return nil
}

// dmCompUninstall 幂等卸载：移除 rc 区块 + 删除补全脚本。
func dmCompUninstall(errW io.Writer, dryRun bool) error {
	_, rcPath, scriptPath, err := dmResolveTargets()
	if err != nil {
		return err
	}
	if dryRun {
		fmt.Fprintf(errW, "[dry-run] 将移除 %s 的 dmsqlq 区块，删除 %s\n", rcPath, scriptPath)
		return nil
	}
	if old, err := os.ReadFile(rcPath); err == nil {
		var out []string
		inBlock := false
		for _, ln := range strings.Split(string(old), "\n") {
			t := strings.TrimSpace(ln)
			if t == dmCompMarkBegin {
				inBlock = true
				continue
			}
			if t == dmCompMarkEnd {
				inBlock = false
				continue
			}
			if !inBlock {
				out = append(out, ln)
			}
		}
		_ = os.WriteFile(rcPath, []byte(strings.Join(out, "\n")), 0644)
	}
	_ = os.Remove(scriptPath)
	return nil
}

// dmAutoInstallSupported Windows 原生 cmd/PowerShell（无 POSIX shell）不适用；抽为变量便于测试。
var dmAutoInstallSupported = func() bool {
	if runtime.GOOS != "windows" {
		return true
	}
	return os.Getenv("SHELL") != ""
}

// dmCompEnsureInstalled 首次运行一次性自动安装补全。
// 门槛：① 标记文件 ~/.dmsqlq/.completion_auto 不存在 ② 环境适用 ③ rc 无标记区块（有则只补标记）。
// 提示只写 errW（stderr），绝不触碰 stdout。
func dmCompEnsureInstalled(errW io.Writer, binPath string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	if h := os.Getenv("HOME"); h != "" && !(runtime.GOOS == "windows" && strings.HasPrefix(h, "/")) {
		home = h
	}
	marker := filepath.Join(home, ".dmsqlq", ".completion_auto")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	if !dmAutoInstallSupported() {
		return
	}
	_, rcPath, _, err := dmResolveTargets()
	if err != nil {
		return
	}
	if old, err := os.ReadFile(rcPath); err == nil && strings.Contains(string(old), dmCompMarkBegin) {
		_ = os.MkdirAll(filepath.Dir(marker), 0755)
		_ = os.WriteFile(marker, []byte("rc already configured\n"), 0644)
		return
	}
	if err := dmCompInstall(errW, binPath, false); err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(marker), 0755)
	_ = os.WriteFile(marker, []byte("auto-installed on first run\n"), 0644)
	fmt.Fprintf(errW, "[dmsqlq] 首次运行：已自动安装 TAB 补全（新终端生效；撤销：dmsqlq --completion-uninstall）\n")
}

// dmIsTTY 判断文件是否为终端（stderr 为终端才触发自动安装，避免污染管道）。
func dmIsTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// dmHandleCompletionFlags 处理隐藏补全选项；命中则执行并退出（返回 true）。
func dmHandleCompletionFlags() bool {
	self := ""
	if p, err := os.Executable(); err == nil {
		self = p
	}
	for _, a := range os.Args[1:] {
		switch a {
		case "--completion-bash":
			fmt.Print(dmCompScript(self))
			os.Exit(0)
		case "--completion-install":
			if err := dmCompInstall(os.Stderr, self, false); err != nil {
				fmt.Fprintf(os.Stderr, "补全安装失败: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "[ok] 已安装 dmsqlq TAB 补全（幂等）。当前会话生效: source ~/.dmsqlq/completion.bash")
			os.Exit(0)
		case "--completion-install-dry-run":
			if err := dmCompInstall(os.Stderr, self, true); err != nil {
				fmt.Fprintf(os.Stderr, "补全安装失败: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		case "--completion-uninstall":
			if err := dmCompUninstall(os.Stderr, false); err != nil {
				fmt.Fprintf(os.Stderr, "补全卸载失败: %v\n", err)
				os.Exit(1)
			}
			fmt.Fprintln(os.Stderr, "[ok] 已卸载 dmsqlq TAB 补全（当前会话可 unset -f _dmsqlq 立即停用）。")
			os.Exit(0)
		}
	}
	return false
}

// ---------------------------------------------------------------- main

func main() {
	// 补全相关隐藏选项：最高优先级，尽早处理
	dmHandleCompletionFlags()
	// 子命令分流：watch 模式（实时跟随 SQL 日志）有自己的一套参数与循环，
	// 与批处理报告路径完全隔离 —— 下面那 1 万多行一行都不用动。
	if len(os.Args) > 1 && os.Args[1] == "watch" {
		os.Exit(watchMain(os.Args[2:]))
	}
	start := time.Now()
	if pf := os.Getenv("DMSQLQ_CPU_PROFILE"); pf != "" {
		f, _ := os.Create(pf)
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}
	// 首次运行一次性自动安装补全：仅交互终端触发，提示走 stderr，绝不碰 stdout
	if dmIsTTY(os.Stderr) {
		self := ""
		if p, err := os.Executable(); err == nil {
			self = p
		}
		dmCompEnsureInstalled(os.Stderr, self)
	}
	if len(os.Args) == 1 { // 不带任何参数：给用法，并尽量直接给出「下一步该敲什么」
		usage(nil)()
		if names, total := scanLogsHere(); total > 0 {
			fmt.Fprintf(os.Stdout, "\n当前目录就有 %d 个日志，直接开始吧：\n", total)
			for _, n := range names {
				fmt.Fprintf(os.Stdout, "    %s\n", n)
			}
			if total > len(names) {
				fmt.Fprintf(os.Stdout, "    …另有 %d 个\n", total-len(names))
			}
			fmt.Fprint(os.Stdout, `
  dmsqlq .                 导出全部可执行 SQL（默认就打屏，可接管道）
  dmsqlq . -s              生成统计报告（HTML，会自动用浏览器打开）
  dmsqlq . -S              只在屏幕上看统计，不生成文件
  dmsqlq . -m 1000 -s      只看执行超过 1 秒的慢 SQL
`)
		} else {
			fmt.Fprint(os.Stdout, `
当前目录没有发现日志。把日志文件或它所在的目录当参数传进来即可，例如：
  dmsqlq /dmdata/log -s     或   dmsqlq D:\dmsql_log -s
`)
		}
		waitEnterIfDoubleClick()
		os.Exit(0)
	}
	opt, paths, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "参数错误: %v\n（运行 dmsqlq 不带参数可看到完整用法；-h 同效）\n", err)
		os.Exit(2)
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	files, globMiss, err := collectFiles(paths, opt.allFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "路径错误: %v\n（提示：路径可以是文件或目录，支持通配符；用 dmsqlq --help 看用法）\n", err)
		os.Exit(2)
	}
	if globMiss > 0 && !opt.quiet {
		fmt.Fprintf(os.Stderr, "  · %d 个通配符没有匹配到任何文件\n", globMiss)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "没有找到可处理的日志文件。")
		fmt.Fprintln(os.Stderr, "  · 默认只收 dmsql_*.log / dmsql_*.log.gz / dmsql_*.log.zip，以及文件名含 log 的 .zip/.tar.gz")
		fmt.Fprintln(os.Stderr, "  · 要处理目录下所有 .log，加 --all-files；也可以直接把日志文件拖进来当参数")
		os.Exit(1)
	}
	if !opt.quiet {
		fmt.Fprintf(os.Stderr, "dmsqlq %s: 共 %d 个日志（含归档内条目）\n", ver, len(files))
	}

	// -e auto：用输入日志名自动命名交付件（定期交付时不必每次手打文件名）
	if opt.excelOut != "" {
		if strings.EqualFold(opt.excelOut, "auto") || opt.excelOut == "-" {
			opt.excelOut = defaultExcelName(files)
		}
		if strings.ToLower(filepath.Ext(opt.excelOut)) != ".xlsx" && filepath.Ext(opt.excelOut) == "" {
			opt.excelOut += ".xlsx"
		}
	}

	gProg.init(opt)
	st := newStats()
	st.setSlowN(opt.rowCap())
	st.agg = opt.stats || opt.statsOut != "" || opt.excelOut != ""

	// 输出目标
	var out io.Writer = os.Stdout
	var outFile *os.File
	if opt.out != "" {
		outFile, err = os.Create(opt.out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "无法创建输出文件:", err)
			os.Exit(2)
		}
		out = outFile
	}

	parallel := opt.jobs > 1 && len(files) > 1
	if !parallel {
		for _, f := range files {
			if err := processFile(f, out, opt, st); err != nil {
				fmt.Fprintf(os.Stderr, "  ! %s: %v\n", f, err)
			}
			if opt.limit > 0 && atomic.LoadInt64(&st.Out) >= int64(opt.limit) {
				break
			}
		}
	} else {
		// 每文件输出到独立临时文件，再按文件名顺序拼接（保证顺序 + 内存恒定）
		tmpDir, err := os.MkdirTemp("", "dmsqlq-")
		if err != nil {
			fmt.Fprintln(os.Stderr, "创建临时目录失败:", err)
			os.Exit(2)
		}
		defer os.RemoveAll(tmpDir)
		tmps := make([]string, len(files))
		sem := make(chan struct{}, opt.jobs)
		var wg sync.WaitGroup
		for i, f := range files {
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, f string) {
				defer wg.Done()
				defer func() { <-sem }()
				if opt.limit > 0 && atomic.LoadInt64(&st.Out) >= int64(opt.limit) {
					return
				}
				tp := filepath.Join(tmpDir, fmt.Sprintf("%06d.out", i))
				fh, e := os.Create(tp)
				if e != nil {
					return
				}
				defer fh.Close()
				bw := bufio.NewWriterSize(fh, 1<<20)
				if e = processFile(f, bw, opt, st); e != nil {
					fmt.Fprintf(os.Stderr, "  ! %s: %v\n", f, e)
				}
				bw.Flush()
				tmps[i] = tp
			}(i, f)
		}
		wg.Wait()
		for _, tp := range tmps {
			if tp == "" {
				continue
			}
			fh, e := os.Open(tp)
			if e != nil {
				continue
			}
			io.Copy(out, fh)
			fh.Close()
		}
	}
	gProg.done()
	if outFile != nil {
		outFile.Close()
	}

	// 重复来源告警：散装日志 + 压缩包内同名条目会让统计翻倍
	if len(st.dupes) > 0 && !opt.quiet {
		fmt.Fprintf(os.Stderr, "  ! 检测到重复日志 %d 个（同一文件名被处理了两次，例如散装日志与压缩包内的同名条目）：\n", len(st.dupes))
		for _, d := range st.dupes {
			fmt.Fprintf(os.Stderr, "      %s\n", d)
		}
		fmt.Fprintln(os.Stderr, "    统计会因此翻倍，建议只传散装日志或只传压缩包其中之一。")
	}

	if opt.topMS > 0 {
		sort.SliceStable(st.TopMSList, func(i, j int) bool { return st.TopMSList[i].MS > st.TopMSList[j].MS })
		var b bytes.Buffer
		for _, t := range st.TopMSList {
			formatStmt(&b, &t.Info, t.SQL, t.File, opt)
			if b.Len() > 1<<20 {
				out.Write(b.Bytes())
				b.Reset()
			}
		}
		out.Write(b.Bytes())
	}

	// 统计报告：-s/-S 打到屏幕；-r 写文件。
	// 只给 -r 时视为"要文件不要刷屏"，屏幕不再重复输出（要两份就同时给 -s 与 -r）。
	if opt.stats || opt.statsOut != "" || opt.excelOut != "" {
		// 报告视图：行数取 min(-p, reportTopMax) —— 报告最多显示 20 条
		rTop := opt.top
		if rTop > reportTopMax {
			rTop = reportTopMax
		}
		v := buildStatsViewTop(st, opt, time.Since(start), rTop)

		// 配套"完整 SQL"文件：报告里 SQL 只显示摘要（好看），全文放这里（能溯源）。
		// 位置规则：--full-sql off 关闭；--full-sql FILE 指定；否则与报告同名 + .full.sql。
		// Excel 交付件通常要更多行，另建一个视图 —— 两边 TopN 上限不同，互不牵连。
		//
		// 🩸 必须建在下面 writeFullSQL 之前：writeFullSQL 内部会调 releaseStats()
		// 把聚合表（Tpl / ByOp / ByTable / Slow / Locks / Sec / TrxFirst…）全部置 nil
		// （为的是让随后的二次扫描不被 GC 拖慢），之后再建视图就只能拿到空聚合 ——
		// 实测表现为「交付件只有一张『概览』，明细表全无」。
		vExcel := v
		if opt.excelWanted() && opt.excelTop > rTop {
			vExcel = buildStatsViewTop(st, opt, time.Since(start), opt.excelTop)
		}

		fullPath := ""
		switch {
		case strings.EqualFold(opt.fullSQL, "off") || strings.EqualFold(opt.fullSQL, "none"):
			fullPath = ""
		case opt.fullSQL != "":
			fullPath = opt.fullSQL
		case opt.statsOut != "":
			fullPath = opt.statsOut + ".full.sql"
		case opt.excelOut != "":
			fullPath = strings.TrimSuffix(opt.excelOut, filepath.Ext(opt.excelOut)) + ".full.sql"
		}
		if fullPath != "" {
			if err := writeFullSQL(fullPath, v, st, opt, files); err != nil {
				fmt.Fprintf(os.Stderr, "  ！完整 SQL 文件写出失败（不影响报告）：%v\n", err)
				fullPath = ""
			} else {
				v.FullSQLPath = fullPath
				vExcel.FullSQLPath = fullPath
			}
		}

		// 先定报告文件路径：显式 -r 优先；纯 -s 时自动落一份默认 HTML。
		// 理由：用户既然显式说了"要报告"，核心目标就是看报告；不该让他再补一个路径才拿到文件。
		reportPath := opt.statsOut
		if reportPath == "" && opt.stats && opt.autoReport {
			reportPath = defaultReportName(files)
		}

		// -s：屏幕给简要版（详细内容在报告文件里，简要版末尾会提示路径）；
		// -S：屏幕给完整文本版（这是它唯一的输出，不生成文件）。
		// -e / -r *.xlsx 也要给简要版：用户是「拿文件去发」，但同样该先看到结论，
		// 否则屏幕上只剩一行路径，等于没告诉他这份日志有没有问题。
		if opt.stats || opt.excelWanted() {
			if opt.statsOnly {
				renderStatsText(os.Stderr, v, opt)
			} else {
				// 只给 -e 时 reportPath 是空的，把交付件路径接过去 ——
				// 简要版自己就会印出「▸ Excel 交付件：xxx.xlsx」，屏幕上一处看全。
				briefPath := reportPath
				if briefPath == "" {
					briefPath = opt.excelOut
				}
				renderStatsBrief(os.Stderr, v, briefPath)
			}
		}

		if reportPath != "" {
			rv := v
			if strings.HasSuffix(strings.ToLower(reportPath), ".xlsx") {
				rv = vExcel // -r *.xlsx 走的是交付件行数
			}
			if err := writeStatsFile(reportPath, rv, opt); err != nil {
				fmt.Fprintln(os.Stderr, "统计报告写文件失败:", err)
			} else {
				if !opt.quiet && opt.statsOut != "" {
					// 纯 -s 的自动报告已在简要版末尾提示过路径，这里不再重复
					fmt.Fprintf(os.Stderr, "\n%s已生成: %s\n", reportKindWord(reportPath), reportPath)
				}
				opt.statsOut = reportPath
				// 报告落盘后顺手用默认浏览器打开（HTML 才有效，-Q 可关）。
				maybeOpenReport(reportPath, opt)
			}
		}

		// Excel 交付件（-e / -r *.xlsx）。刻意不自动打开 —— 它是「要发出去的文件」，
		// 不是「要立刻看的报告」；路径已打印在屏幕上，收件方是谁用户自己清楚。
		if opt.excelOut != "" {
			if err := writeExcelReport(opt.excelOut, vExcel, opt); err != nil {
				fmt.Fprintln(os.Stderr, "  ！Excel 交付件写出失败:", err)
			} else if !opt.quiet {
				fmt.Fprintf(os.Stderr, "\nExcel 交付件已生成: %s\n", opt.excelOut)
			}
		}
	}
	if !opt.quiet && opt.out != "" {
		fmt.Fprintf(os.Stderr, "已写出: %s\n", opt.out)
	}
}

func pct(a, b int64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}

// pctF 浮点版百分比（耗时占比这类本身就是浮点的场景）
func pctF(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a * 100 / b
}

// ---------------------------------------------------------------- 统计报告

type opRow struct {
	Op            string
	Count         int64
	Pct           float64
	SumPct        float64 // 累计耗时占比（与次数占比并列看，才能发现次数少但很慢的类型）
	Sum, Avg, Max float64
	P90, P95, P99 float64
}
type tplRow struct {
	Sample   string
	Count    int64
	Sum, Avg float64
	Max      float64
	Min      float64 // 最快一次 —— 与平均对比可区分「稳定慢」与「时快时慢」
}

// adviceRow 一条「优先优化推荐」。
//
// 设计原则：报告是给人做决策的，不是给数据做展示的 ——
// 所以每条推荐要能回答「改它值不值、为什么是它、怎么改」。
type adviceRow struct {
	Rank   int
	Prio   string  // 优先 / 次之 / 一般
	Share  float64 // 影响占比（该模板累计耗时 ÷ 全部语句耗时）
	SaveMS float64 // 预估可省耗时（降到同类中位数水平）
	Count  int64
	Avg    float64
	Max    float64
	Min    float64 // 最快一次（快慢差异大 = 计划/数据不稳，不是单纯缺索引）
	Sum    float64
	Signal string // 问题信号（据数据特征自动识别）
	Action string // 建议动作
	Sample string
}

type userRow struct {
	User     string
	Count    int64
	Sum, Max float64
	P95      float64
}

// tableRow 热表（按 SQL 文本粗提表名聚合）
type tableRow struct {
	Table    string
	Count    int64
	Reads    int64
	Writes   int64
	Sum, Max float64
	Pct      float64 // 累计耗时占比
	RW       float64 // 读/写比（读次数 ÷ 写次数）—— 读多写少却慢的表通常缺索引
}

// secRow 秒级热点（QPS/TPS 的峰值现场）
type secRow struct {
	TS       string
	SQL      int64
	Sum      float64
	Commit   int64
	Rollback int64
}

type trxRow struct {
	Trx    string
	User   string
	First  string
	Last   string
	Count  int64
	SpanMS float64
	ExecMS float64 // 事务内 SQL 累计执行耗时
	Util   float64 // 利用率（%）= ExecMS / SpanMS；越低越说明"占着事务不干活"
}

// lockTableRow 按表聚合的锁等待
type lockTableRow struct {
	TableID string
	Table   string // 表名（--obj-map 映射后才有；否则为空，只显示 ID）
	Count   int64
	Pct     float64
	Sum     float64
	Max     float64
	Mode    string
	Waiters string // 涉及的等待方用户（去重，最多 3 个）
	MaxAt   string // 最长一次等待发生的时间
}

// lockRow 一次锁等待的完整信息（报告展示用）
// 与 lockWait 的区别：补上了"持有方用户"和"表名"——
// 现场最关心的两个问题就是"谁在持锁"和"锁在哪张表上"。
type lockRow struct {
	MS      float64
	Mode    string
	TableID string
	Table   string // 表名：--obj-map 给的，或从等待方 SQL 推断来的（见 TableInfer）
	Waiter  string
	WaiterU string
	Holder  string
	HolderU string
	Waiters int64
	TS      string

	// ---- 双方 SQL 与阻塞链（V2.8）----
	//
	// 现场要的不是"谁等了谁 5 秒"，而是"**哪条 SQL 在持锁、哪条 SQL 被卡住**"。
	// 锁行本身只带 trxid，所以这里靠事前按事务收集的语句（见 parser.addTrxStmt）反查。
	//
	// 🩸 可得性差异很大，报告必须如实呈现而不是留空：
	//   实测本批现网日志（KD1 1008，120 次锁等待）——
	//     等待方 SQL 可得 88%（106/120）：等待方就是触发等待的那条，通常在日志里
	//     持有方 SQL 可得 23%（28/120）：其余只有 TRX: START / PARAMS / alloc pseg
	//   拿不到时 HolderStmts 为空，但要靠 HolderKind/HolderEndTS 说明"它确实跑过，
	//   只是语句文本没进日志（掩码 2~17 未开全）" —— 与"没跑语句"是两回事。
	WaiterSQL   string
	WaiterOp    string
	WaiterMS    float64
	HolderStmts []trxStmtRec
	// HolderSQLFromORA 该持有方的 SQL 是从掩码 27 的 [ORA]（原始语句）行兜底找回来的（V2.12）。
	// 命中它说明：这个事务的语句跑得太快、**执行行被 MIN_EXEC_TIME 滤掉了** ——
	// 既不是"没执行"，也不是"采集位没开全"。报告要如实标出这个来源。
	HolderSQLFromORA bool
	HolderRoot       string // 链首 = 真正的持锁者（其余都是排在它后面的）
	HolderKind       string // 该事务最后的结局：COMMIT / ROLLBACK / ""（日志里未见结束）
	HolderEndTS      string
	Chain            []string // 排队链（含根），来自日志的 trx[...] 列表
	ChainMore        bool     // 该链被日志截断（带 ...more）
	TableInfer       bool     // Table 是从等待方 SQL 推断出来的（不是 --obj-map 给的）
}

// lockChain 一条阻塞链（V2.8）：同表、同根事务的一串等待。
//
// 为什么按「表 + 根事务」聚合：日志的持有方列表是累计排队的，
// 同一条链会在每个等待者那一行里重复出现。聚起来才能回答
// 「是哪一个事务、把多少人堵了多久」—— 这才是根因视角。
type lockChain struct {
	TableID     string
	Table       string
	Root        string
	RootUser    string
	Count       int64   // 该链上的等待事件次数
	MaxMS       float64 // 最长等待（≈ 根事务持锁时长）
	SumMS       float64
	ChainLen    int      // 排队事务数（取日志给出的最长一次）
	Span        string   // 波及时段 "HH:MM:SS ~ HH:MM:SS"
	WaiterUsers []string // 被波及的等待方用户（去重，控量）
	rows        []lockRow
}

// buildLockChains 把锁等待明细聚成阻塞链，按「最长等待」降序。
func buildLockChains(rows []lockRow) []lockChain {
	idx := map[string]*lockChain{}
	var out []lockChain
	for _, r := range rows {
		root := r.HolderRoot
		if root == "" {
			root = r.Holder
		}
		k := r.TableID + "\x00" + root
		c := idx[k]
		if c == nil {
			c = &lockChain{TableID: r.TableID, Table: r.Table, Root: root,
				RootUser: r.HolderU, Span: shortTS(r.TS)}
			idx[k] = c
		}
		c.Count++
		c.SumMS += r.MS
		if r.MS > c.MaxMS {
			c.MaxMS = r.MS
		}
		if len(r.Chain) > c.ChainLen {
			c.ChainLen = len(r.Chain)
		}
		c.Span = shortTS(r.TS) + " ~ " + shortTS(r.TS)
		c.rows = append(c.rows, r)
	}
	for _, c := range idx {
		// 时段取该链上最早/最晚那次等待
		if len(c.rows) > 0 {
			first, last := c.rows[0].TS, c.rows[0].TS
			us := map[string]bool{}
			for _, r := range c.rows {
				if r.TS < first {
					first = r.TS
				}
				if r.TS > last {
					last = r.TS
				}
				if r.WaiterU != "" {
					us[r.WaiterU] = true
				}
			}
			c.Span = shortTS(first) + " ~ " + shortTS(last)
			for u := range us {
				c.WaiterUsers = append(c.WaiterUsers, u)
			}
			sort.Strings(c.WaiterUsers)
			if len(c.WaiterUsers) > 3 {
				c.WaiterUsers = c.WaiterUsers[:3]
			}
		}
		out = append(out, *c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].MaxMS > out[j].MaxMS })
	return out
}

// hLockCards 输出「锁等待双方 SQL」卡片（HTML）。
//
// 一张卡片 = 一次锁等待：左边等待方（它当时在跑哪条 SQL），右边持有方
// （链首事务的完整活动轨迹 + 结局）。超量时沿用长表折叠：默认前 keep 张，
// 打印时全展开（见 .lkcard 的 @media print 规则）。
func hLockCards(w io.Writer, rows []lockRow, keep int) {
	if len(rows) == 0 {
		return
	}
	fold := keep > 0 && len(rows) > keep+1
	// 卡片整体包一层容器，折叠时给容器切 open 类 —— 与长表折叠复用同一套
	// 按钮与 JS（按钮只认「前一兄弟 + open 类」），不必再养第二条交互路径。
	io.WriteString(w, "<div class=\"lkcards\">\n")
	for i, r := range rows {
		cls := "lkcard"
		if fold && i >= keep {
			cls += " hid"
		}
		fmt.Fprintf(w, "<div class=\"%s\">\n", cls)
		// 卡片头
		fmt.Fprintf(w, "<div class=\"lkhead\"><span class=\"lkidx\">#%d</span>"+
			"<span class=\"lkwait\">等待 %s</span><span class=\"lktbl\">%s</span>"+
			"<span class=\"lkmode\">%s 锁</span><span class=\"lkts\">%s</span></div>\n",
			i+1, hEsc(fmtDur(r.MS)), hEsc(lockObj(r.Table, r.TableID)), hEsc(r.Mode), hEsc(shortTS(r.TS)))
		io.WriteString(w, "<div class=\"lkbody\">\n")

		// 等待方
		io.WriteString(w, "<div class=\"lkside\">\n")
		fmt.Fprintf(w, "<div class=\"lksideh\">等待方 · trx <code>%s</code> · %s</div>\n",
			hEsc(dash(r.Waiter)), hEsc(dash(r.WaiterU)))
		if r.WaiterSQL != "" {
			fmt.Fprintf(w, "<div class=\"lksql\"><span class=\"lkop\">[%s]</span> <code>%s</code>"+
				"<span class=\"lkdur\">%s</span></div>\n",
				hEsc(r.WaiterOp), hEsc(clipCell(r.WaiterSQL, 300)), hEsc(fmtDur(r.WaiterMS)))
		} else {
			io.WriteString(w, "<div class=\"lkmiss\">该事务在日志里没有可用 SQL 文本"+
				"（常见成因：语句很快被 <code>MIN_EXEC_TIME</code> 滤掉，或执行中被中止）"+
				"—— 用 <code>-x "+hEsc(dash(r.Waiter))+" -N</code> 可单独抽取确认。</div>\n")
		}
		io.WriteString(w, "</div>\n")

		// 持有方
		io.WriteString(w, "<div class=\"lkside\">\n")
		extra := ""
		if len(r.Chain) > 1 {
			extra = fmt.Sprintf("，另有 %d 个事务排在它后面", len(r.Chain)-1)
		}
		fmt.Fprintf(w, "<div class=\"lksideh\">持有方（链首）· trx <code>%s</code> · %s%s</div>\n",
			hEsc(dash(r.HolderRoot)), hEsc(dash(r.HolderU)), extra)
		if len(r.HolderStmts) > 0 {
			for _, sm := range r.HolderStmts {
				fmt.Fprintf(w, "<div class=\"lksql\"><span class=\"lkop\">[%s]</span> <code>%s</code>"+
					"<span class=\"lkdur\">%s</span></div>\n",
					hEsc(sm.Op), hEsc(clipCell(sm.SQL, 300)), hEsc(fmtDur(sm.MS)))
			}
			if r.HolderSQLFromORA {
				io.WriteString(w, "<div class=\"lkora\">↑ 来源：掩码 <b>27</b> 的 <code>[ORA]</code> 原始语句行"+
					" —— 该语句执行很快，<b>执行完成行被 <code>MIN_EXEC_TIME</code> 滤掉了</b>，"+
					"所以从执行行里看不到它（它不是没执行）。</div>\n")
			}
		} else {
			io.WriteString(w, "<div class=\"lkmiss\">该事务的语句在日志里<b>没有可用的 SQL 文本</b>"+
				"（有 <code>PARAMS</code> 与段页分配，却没有 <code>[类型] … EXECTIME</code>）。"+
				"两种常见成因，<b>都不是「没执行」</b>：<br>① <b>语句执行很快、完成行被 "+
				"<code>MIN_EXEC_TIME</code> 滤掉</b>（现网最常见；采集掩码含位 27 时本工具已能自动找回）；"+
				"<br>② 语句执行中被中止。<b>不是采集位没开全</b>。</div>\n")
		}
		if r.HolderKind != "" {
			act := "提交"
			if r.HolderKind == "ROLLBACK" {
				act = "回滚"
			}
			fmt.Fprintf(w, "<div class=\"lkend\">结局：<b>%s</b>（%s）</div>\n", act, hEsc(shortTS(r.HolderEndTS)))
		} else {
			io.WriteString(w, "<div class=\"lkend\">结局：本批日志里未见 COMMIT / ROLLBACK</div>\n")
		}
		io.WriteString(w, "</div>\n")

		io.WriteString(w, "</div>\n") // lkbody
		io.WriteString(w, "</div>\n") // lkcard
	}
	io.WriteString(w, "</div>\n") // lkcards
	if fold {
		fmt.Fprintf(w, "<div class=\"foldbar\"><button data-fold=\"%d\" type=\"button\">"+
			"展开全部 %d 条</button><span class=\"fnote\">默认只显示前 %d 条；"+
			"打印 / 导出 PDF 时自动全部展开。</span></div>\n", len(rows), len(rows), keep)
	}
}

// clipCell 单行截断（卡片里不让长 SQL 撑破布局）
func clipCell(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + " …"
}

// bucketRow 负载时间桶（QPS/语句数按时间聚合，用于看业务高峰）
type bucketRow struct {
	TS       string // 桶起始时间（完整时间戳）
	Label    string // 显示标签（分钟粒度 "HH:MM"，小时/天粒度 "MM-DD HH:00"）
	SQL      int64
	SumMS    float64
	Commit   int64
	Rollback int64
	Secs     int64 // 桶内真正有事件的秒数
	Pct      float64
	QPS      float64 // 桶内平均 QPS（SQL / 桶宽度秒数）
}

type statsView struct {
	Files              int64
	MBf                float64
	Elapsed            time.Duration
	Records, Exec      int64
	Out                int64
	Matched, Missing   int64
	NoParams, Filtered int64
	Skipped            int64
	Excluded           int64 // 被 -E 排除、未计入统计的语句数
	RestorePct         float64
	OpRows             []opRow
	Hist               [7]int64
	HistMax            int64
	// 全局耗时分位（对数直方图算出来的）
	P50, P90, P95, P99 float64
	DurMax             float64 // 真实最大耗时（与直方图一起，用于分位对照）
	MinExecMS          float64 // 最小耗时（由直方图最低非空桶近似，桶精度约 ±15%）
	// 每事务语句数分布（识别"逐条提交"）
	TrxStmtN    int64
	TrxStmtHist [6]int64 // 1 条 / 2-5 / 6-20 / 21-100 / 101-1000 / >1000
	TrxStmtMed  int64    // 中位数（按语句数）
	ExecIDSeen  int64    // 带 EXEC_ID 的语句数（能否下钻 V$SQL_NODE_HISTORY）
	Slow        []slowRec
	Tpls        []tplRow
	Advice      []adviceRow // 优先优化推荐（HTML/MD/终端共用）
	// WindowDesc 时间窗口描述（非空表示本次统计只覆盖该窗口）。
	//
	// 注意 V2.5 起 -f/-t 会同时收窄统计口径（不再只是筛输出），因此必须在
	// 报告显著位置标出，否则读者会当成全天数据来判读。
	WindowDesc string
	WinSkipped int64 // 窗口外被排除出统计的语句数
	Users      []userRow
	Clients    []userRow
	Tables     []tableRow
	Trxs       []trxRow
	TrxOpenN   int64 // 只见 START、未见后续事件的事务（可能仍未提交/仍持锁）
	TrxTracked int64 // 参与事务统计的事务数
	TrxFull    bool
	// QPS / TPS（时间轴）
	SpanFirst       string
	SpanLast        string
	SpanSec         float64
	AvgQPS, PeakQPS float64
	PeakQPSAt       string
	AvgTPS, PeakTPS float64
	PeakTPSAt       string
	Commits         int64
	Rollbacks       int64
	RollbackPct     float64
	SecCovered      int64 // 有事件的秒数
	LongestIdle     float64
	LongestIdleAt   string
	// 负载时间分布（看业务高峰；粒度按跨度自适应：分钟 / 小时 / 天）
	Buckets     []bucketRow // 完整时间轴（含空桶）
	BucketsTop  []bucketRow // 按 SQL 数排序的高峰时段 TopN
	BucketUnit  string      // "分钟" / "小时" / "天"
	BucketSec   int64
	BucketCount int
	PeakBucket  *bucketRow
	// 锁（掩码 29）
	LockN       int64
	LockSumMS   float64
	LockMaxMS   float64
	LockHist    [5]int64
	LockHistMax int64
	LockRows    []lockRow
	LockTables  []lockTableRow
	LockTableN  int // 涉及对象总数（LockTables 会被 -p 截断，这个不会）
	// 双方 SQL 的可得性（V2.8）：报告要如实说明"取到了几条"，
	// 否则读者会以为"没显示 = 没有"。分母是**全部**锁等待条数（LockTotalN），
	// 不是 -p 截断后的显示条数 —— 用截断值当分母会出现「20/20 但一条 SQL 都没显示」
	// 这种自相矛盾的句子（项目里踩过同类坑：显示上限污染了统计口径）。
	LockWaiterSQLN int
	LockHolderSQLN int
	LockTotalN     int // 本次锁等待总条数（未受 -p 影响）
	// 锁等待明细全量（V2.8）：卡片视图要覆盖**全部**等待（用户明确要求），
	// 而 LockRows 会被 -p 截断给表格用。两个视图分开建，互不污染。
	LockRowsAll []lockRow
	LockChains  []lockChain
	// 表名（大写）→ 锁等待累计毫秒。用 st.LockByTable 全量算，不受 -p 截断影响。
	// 用途：识别「等锁受害者」—— 见 recommend（V2.10）。
	LockSumByName map[string]float64
	// 锁等待排查方向（V2.11）：把分散在几十张卡片里的「结局/时刻/分布」汇总成
	// 「先看什么、再看什么、往哪查」。见 lockGuide()。
	LockGuide []guideRow
	// 溯源
	TrxUser      map[string]string // 报告涉及的 trxid → 用户（回答"谁在持锁"）
	ObjMap       map[string]string // 对象 ID → 表名
	ObjMapFile   string
	FullSQLPath  string // 配套"完整 SQL"文件路径（报告里注明）
	RefSQL       string // 对象 ID 反查表名的 SQL（可直接复制执行）
	LockUnparsed int64
	LockMoreN    int64
	LockCountMis int64
	DlckN        int64
	DlckNonZero  int64
	DlckMaxMS    float64

	// 锁等待的时间聚集（与 QPS 峰值对齐用）
	LockPeakAt    string
	LockPeakN     int64
	LockPeakQPS   int64
	LockPeakIsTop bool
	Hints         []string
	FilterDesc    string
	ModeDesc      string
	StatsOnly     bool
	TopMS         int
	SourceArgs    string   // 本次运行的关键参数（写进配套 .sql 文件的头部，便于复现）
	Sources       []string // 参与扫描的日志文件（写进配套文件头部）

	// 采集配置体检（据日志内容反推 sqllog.ini）
	// 审计
	Dangers    []auditRow
	DangerN    int64 // 高危操作总数（可能多于展示条数）
	DangerORA  int64 // 其中"仅解析未见执行"的条数
	ObjRisk    []cntRow
	Changes    []auditRow
	ChangeSum  []cntRow
	ChangeN    int64
	LSNSampled int64 // 采样到的提交 LSN 桶数
	AuditFull  bool
	LastDDLOf  map[string]string // 表名 → 最近一次结构变更（供慢语句关联）

	DDLVerbs   []cntRow // DDL 首词分布（STAT/CREATE/ALTER…）
	SlowObjDDL []cntRow // 最慢语句涉及的对象 → 最近一次结构变更

	ParamsN      int64
	TrxEventN    int64
	TrxEndN      int64
	OraN         int64
	LgnN         int64
	ErrN         int64
	NoExecN      int64
	EPSeen       int64
	Ts26         int64
	UnitMS       int64
	UnitUS       int64
	UnitNS       int64
	UnitNone     int64
	MatchedLoose int64
	ErrCodes     []errCodeRow

	// Mask29On 位号 29（事务/锁事件）是否真的开着 —— 它决定「锁等待 0 次」
	// 到底是"确实没有等待"还是"根本没采集"。
	//
	// 判据：29 开启后事务事件行**必然出现且量很大**（实测：现网 KD1 有 394 万条
	// `TRX: START`；本机实例 275 条 `TRX: START` + 30 万条 `DLCK`）。反过来，三类行
	// （TRX: / DLCK / LOCK_TID）全为 0，就能判定 29 未开 —— 而不是"这段没锁竞争"。
	// 这也是「锁等待」这一维度唯一可自证的判据，解析器反推不出别的东西来。
	Mask29On bool
	// Headline 头部一句话结论；HeadlineKind 为 "warn" / "info"，空串表示无结论。
	Headline     string
	HeadlineKind string
}

// errCodeRow 错误码分布
type errCodeRow struct {
	Code  string
	Count int64
	Sum   float64 // 该错误码的累计执行耗时
	Avg   float64
}

// buildStatsView 报告视图（HTML / Markdown / 终端文本）：行数取 -p（默认 10）。
//
// Excel 交付件的行数通常更多，走 buildStatsViewTop —— 两者分开建视图、互不牵连。
// （V2.1 把交付件的默认行数写进了 o.top，结果 HTML 报告也被撑到 200 行，很臃肿。）
func buildStatsView(st *Stats, opt *Options, elapsed time.Duration) *statsView {
	return buildStatsViewTop(st, opt, elapsed, opt.top)
}

// buildStatsViewTop 按指定 TopN 上限构建视图。纯聚合、只读 st，可安全重复调用。
func buildStatsViewTop(st *Stats, opt *Options, elapsed time.Duration, top int) *statsView {

	v := &statsView{
		Files: st.Files, MBf: float64(st.Bytes) / 1024 / 1024, Elapsed: elapsed,
		Records: st.Records, Exec: st.Exec, Out: st.Out,
		Matched: st.Matched, Missing: st.Missing,
		NoParams: st.NoParams, Filtered: st.Filtered, Skipped: st.Skipped,
		Excluded:   st.Excluded,
		RestorePct: pct(st.Matched, st.Matched+st.Missing),
		StatsOnly:  opt.statsOnly, TopMS: opt.topMS,

		P50: st.H.quantile(0.50), P90: st.H.quantile(0.90),
		P95: st.H.quantile(0.95), P99: st.H.quantile(0.99),
		DurMax:     st.H.maxMS,
		MinExecMS:  st.H.minApprox(),
		ExecIDSeen: st.execIDSeen,

		ParamsN: st.ParamsN, TrxEventN: st.TrxEventN, TrxEndN: st.TrxEndN,
		OraN: st.OraN, LgnN: st.LgnN, ErrN: st.ErrN, NoExecN: st.NoExecN,
		EPSeen: st.EPSeen, Ts26: st.Ts26, UnitMS: st.UnitMS, UnitUS: st.UnitUS, UnitNS: st.UnitNS,
		UnitNone: st.UnitNone, MatchedLoose: st.MatchedLoose,
	}
	for c, n := range st.ErrCodes {
		sum := st.ErrMS[c]
		v.ErrCodes = append(v.ErrCodes, errCodeRow{Code: c, Count: n, Sum: sum,
			Avg: sum / float64(max64(n, 1))})
	}
	sort.Slice(v.ErrCodes, func(i, j int) bool {
		if v.ErrCodes[i].Count != v.ErrCodes[j].Count {
			return v.ErrCodes[i].Count > v.ErrCodes[j].Count
		}
		return v.ErrCodes[i].Code < v.ErrCodes[j].Code
	})
	if len(v.ErrCodes) > 20 {
		v.ErrCodes = v.ErrCodes[:20]
	}
	st.mu.Lock()
	defer st.mu.Unlock()

	var sumAllMS float64
	for _, a := range st.ByOp {
		sumAllMS += a.SumMS
	}
	for op, a := range st.ByOp {
		v.OpRows = append(v.OpRows, opRow{Op: op, Count: a.Count, Pct: pct(a.Count, st.Exec),
			SumPct: pctF(a.SumMS, sumAllMS),
			Sum:    a.SumMS, Avg: a.SumMS / float64(max64(a.Count, 1)), Max: a.MaxMS,
			P90: a.H.quantile(0.90), P95: a.H.quantile(0.95), P99: a.H.quantile(0.99)})
	}
	sort.Slice(v.OpRows, func(i, j int) bool { return v.OpRows[i].Count > v.OpRows[j].Count })

	v.Hist = st.Hist
	for _, n := range st.Hist {
		if n > v.HistMax {
			v.HistMax = n
		}
	}

	// 容量由扫描期的 setSlowN(rowCap) 决定（交付件可能要到 50 行），
	// 但视图只显示 top 行 —— 不截的话报告会跟着显示 50 行，与其它表不一致。
	v.Slow = append(v.Slow, st.Slow...)
	sort.SliceStable(v.Slow, func(i, j int) bool { return v.Slow[i].MS > v.Slow[j].MS })
	if len(v.Slow) > top {
		v.Slow = v.Slow[:top]
	}

	type tk struct {
		k string
		t *TplAgg
	}
	var all []tk
	for k, t := range st.Tpl {
		all = append(all, tk{k, t})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].t.SumMS != all[j].t.SumMS {
			return all[i].t.SumMS > all[j].t.SumMS
		}
		return all[i].t.Count > all[j].t.Count
	})
	for i, e := range all {
		if i >= top {
			break
		}
		v.Tpls = append(v.Tpls, tplRow{Sample: e.t.Sample, Count: e.t.Count,
			Sum: e.t.SumMS, Avg: e.t.SumMS / float64(max64(e.t.Count, 1)), Max: e.t.MaxMS,
			Min: e.t.MinMS})
	}
	// 优先优化推荐：与 Tpls 同源（已按累计耗时降序），占比分母也用同一批 ——
	// 这样报告里的「影响占比」与 Excel 交付件的「占总耗时」是同一个数。
	//
	// 🩸 但它**不能在这里算**（V2.10）：recommend 现在要用「某张表的锁等待累计」
	// 来识别**等锁受害者**，而那批数据在下面的锁等待段才装配 ——
	// 建早了 LockSumByName 还是 nil，识别静默失效（实测就是这么静默失效的：
	// 改了代码、编译通过、跑起来那条 INSERT 仍被当成优化对象）。
	// 已移到锁等待段之后统一计算。
	_ = adviceLimit // 见下方「锁等待」段末尾的 v.Advice 赋值

	for u, a := range st.ByUser {
		v.Users = append(v.Users, userRow{User: u, Count: a.Count, Sum: a.SumMS, Max: a.MaxMS,
			P95: a.H.quantile(0.95)})
	}
	sort.Slice(v.Users, func(i, j int) bool { return v.Users[i].Count > v.Users[j].Count })
	if len(v.Users) > top {
		v.Users = v.Users[:top]
	}

	// 客户端排行（appname @ ip）：定位"是哪个应用在压库"
	for c, a := range st.ByClient {
		v.Clients = append(v.Clients, userRow{User: c, Count: a.Count, Sum: a.SumMS, Max: a.MaxMS})
	}
	sort.Slice(v.Clients, func(i, j int) bool { return v.Clients[i].Count > v.Clients[j].Count })
	if len(v.Clients) > top {
		v.Clients = v.Clients[:top]
	}

	// 热表 TopN（按累计耗时；同时给读/写次数）
	{
		var totMS float64
		for _, t := range st.ByTable {
			totMS += t.SumMS
		}
		for name, t := range st.ByTable {
			v.Tables = append(v.Tables, tableRow{Table: name, Count: t.Count, Reads: t.Reads,
				RW:     ratioOf(t.Reads, t.Writes),
				Writes: t.Writes, Sum: t.SumMS, Max: t.MaxMS, Pct: pctF(t.SumMS, totMS)})
		}
		sort.Slice(v.Tables, func(i, j int) bool {
			if v.Tables[i].Sum != v.Tables[j].Sum {
				return v.Tables[i].Sum > v.Tables[j].Sum
			}
			return v.Tables[i].Count > v.Tables[j].Count
		})
		if len(v.Tables) > top {
			v.Tables = v.Tables[:top]
		}
	}

	// ---- QPS / TPS：按秒分桶（时间轴视角）----
	v.Commits, v.Rollbacks = st.Commits, st.Rollbacks
	v.RollbackPct = pct(st.Rollbacks, st.Commits+st.Rollbacks)
	v.SpanFirst, v.SpanLast = st.SpanFirst, st.SpanLast
	if len(st.Sec) > 0 {
		keys := make([]int64, 0, len(st.Sec))
		var (
			sqlTot, commitTot int64
			peakSQL, peakCom  int64
			peakSQLAt         int64 = -1
			peakComAt         int64 = -1
			idleMax           int64
			idleAt            int64 = -1
			prev              int64 = -1
		)
		for sec, sa := range st.Sec {
			keys = append(keys, sec)
			sqlTot += sa.SQL
			commitTot += sa.Commit
			if sa.SQL > peakSQL {
				peakSQL, peakSQLAt = sa.SQL, sec
			}
			if sa.Commit > peakCom {
				peakCom, peakComAt = sa.Commit, sec
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		for _, sec := range keys {
			if prev >= 0 && sec-prev-1 > idleMax {
				idleMax, idleAt = sec-prev-1, prev+1
			}
			prev = sec
		}
		v.SecCovered = int64(len(keys))
		// 跨度优先用首末 SQL 事件时间（含无事件的空档）；缺失则退回秒桶首末
		secFirst, secLast := keys[0], keys[len(keys)-1]
		if f, ok := tsUnix(v.SpanFirst); ok && f < secFirst {
			secFirst = f
		}
		if l, ok := tsUnix(v.SpanLast); ok && l > secLast {
			secLast = l
		}
		v.SpanSec = float64(secLast-secFirst) + 1
		if v.SpanSec < 1 {
			v.SpanSec = 1
		}
		v.AvgQPS = float64(sqlTot) / v.SpanSec
		v.AvgTPS = float64(commitTot) / v.SpanSec
		v.PeakQPS, v.PeakTPS = float64(peakSQL), float64(peakCom)
		if peakSQLAt >= 0 {
			v.PeakQPSAt = fmtUnix(peakSQLAt)
		}
		if peakComAt >= 0 {
			v.PeakTPSAt = fmtUnix(peakComAt)
		}
		if idleMax > 0 {
			v.LongestIdle = float64(idleMax)
			v.LongestIdleAt = fmtUnix(idleAt)
		}
		// 负载时间分布：按跨度自适应粒度（分钟/小时/天）
		// —— 秒级 TopN 对"看业务高峰"没什么用，改成时段聚合
		v.buildBuckets(st, keys, secFirst, secLast, opt)
		if len(v.BucketsTop) > top { // 高峰时段榜同样受视图上限约束
			v.BucketsTop = v.BucketsTop[:top]
		}
	}

	// 每事务语句数分布：识别"逐条提交"（批量导入慢的头号原因）。
	// 口径：同一 trxid 在执行行里出现的次数（掩码 29 给出非 0 trxid 才有意义）。
	if len(st.TrxCount) > 0 {
		v.TrxStmtN = int64(len(st.TrxCount))
		counts := make([]int64, 0, len(st.TrxCount))
		for _, c := range st.TrxCount {
			counts = append(counts, c)
			switch {
			case c <= 1:
				v.TrxStmtHist[0]++
			case c <= 5:
				v.TrxStmtHist[1]++
			case c <= 20:
				v.TrxStmtHist[2]++
			case c <= 100:
				v.TrxStmtHist[3]++
			case c <= 1000:
				v.TrxStmtHist[4]++
			default:
				v.TrxStmtHist[5]++
			}
		}
		sort.Slice(counts, func(i, j int) bool { return counts[i] < counts[j] })
		v.TrxStmtMed = counts[len(counts)/2]
	}

	// DDL 首词分布（写进采集配置体检，解释"[DDL] 到底在做什么"）
	if len(st.DDLVerb) > 0 {
		for w, n := range st.DDLVerb {
			v.DDLVerbs = append(v.DDLVerbs, cntRow{Name: w, Count: n})
		}
		sort.Slice(v.DDLVerbs, func(i, j int) bool { return v.DDLVerbs[i].Count > v.DDLVerbs[j].Count })
		if len(v.DDLVerbs) > 8 {
			v.DDLVerbs = v.DDLVerbs[:8]
		}
	}

	// ---- 审计：危险操作 / 结构变更 / 恢复定位 ----
	if len(st.Dangers) > 0 || len(st.Changes) > 0 {
		v.DangerN = int64(len(st.Dangers))
		v.AuditFull = st.auditFull
		v.LastDDLOf = st.LastDDL
		v.LSNSampled = int64(len(st.LSNBucket))
		// LSN 就近查找：某时刻前后各取最近的一桶（30 秒分辨率）
		lsnNear := func(sec int64) (string, string) {
			if len(st.LSNBucket) == 0 {
				return "", ""
			}
			for d := int64(0); d <= 6; d++ {
				if b, ok := st.LSNBucket[sec/30-d]; ok {
					return b.LSN, b.TS
				}
			}
			for d := int64(1); d <= 6; d++ {
				if b, ok := st.LSNBucket[sec/30+d]; ok {
					return b.LSN, b.TS
				}
			}
			return "", ""
		}
		for _, d := range st.Dangers {
			if d.ORAOnly {
				v.DangerORA++
			}
			r := auditRow{TS: d.TS, Level: d.Level, Kind: d.Kind, Object: d.Object, User: d.User,
				Client: d.Client, Op: d.Op, Trx: d.Trx, Rows: d.Rows, ExecID: d.ExecID, MS: d.MS,
				Thrd: d.Thrd, Brief: briefOf(d.SQL, 200), ORAOnly: d.ORAOnly, AuditSQL: d.SQL}
			r.LSNAt, r.LSNTS = lsnNear(tsUnixOf(d.TS))
			v.Dangers = append(v.Dangers, r)
		}
		sort.SliceStable(v.Dangers, func(i, j int) bool { return v.Dangers[i].TS > v.Dangers[j].TS })
		// 对象风险摘要：同一对象被高危操作碰了几次、最近一次是什么
		risk := map[string]*cntRow{}
		for _, d := range v.Dangers {
			if d.Object == "" {
				continue
			}
			if a := risk[d.Object]; a != nil {
				a.Count++
			} else {
				risk[d.Object] = &cntRow{Name: d.Object, Count: 1}
			}
		}
		for _, a := range risk {
			v.ObjRisk = append(v.ObjRisk, *a)
		}
		sort.Slice(v.ObjRisk, func(i, j int) bool { return v.ObjRisk[i].Count > v.ObjRisk[j].Count })
		if len(v.ObjRisk) > top {
			v.ObjRisk = v.ObjRisk[:top]
		}
		// 结构变更时间线（环形缓冲按时间还原）
		ch := st.Changes
		if st.changeN > len(ch) {
			k := st.changeN % len(ch)
			ch = append(append([]auditRec{}, ch[k:]...), ch[:k]...)
		}
		v.ChangeN = int64(st.changeN)
		for _, c := range ch {
			v.Changes = append(v.Changes, auditRow{TS: c.TS, Level: c.Level, Kind: c.Kind,
				Object: c.Object, User: c.User, Client: c.Client, Rows: c.Rows,
				Thrd: c.Thrd, Brief: briefOf(c.SQL, 160)})
		}
		sort.SliceStable(v.Changes, func(i, j int) bool { return v.Changes[i].TS > v.Changes[j].TS })
		for _, c := range ch {
			found := false
			for i := range v.ChangeSum {
				if v.ChangeSum[i].Name == c.Kind {
					v.ChangeSum[i].Count++
					found = true
					break
				}
			}
			if !found {
				v.ChangeSum = append(v.ChangeSum, cntRow{Name: c.Kind, Count: 1})
			}
		}
		// 最慢语句涉及的对象，最近有没有被改过结构 —— 性能劣化常紧跟一次 DDL
		if len(st.LastDDL) > 0 {
			seen := map[string]bool{}
			for _, sr := range v.Slow {
				ob := firstTableOf([]byte(sr.SQL), sr.Op)
				if ob == "" || seen[ob] {
					continue
				}
				seen[ob] = true
				if ddl, ok := st.LastDDL[ob]; ok {
					v.SlowObjDDL = append(v.SlowObjDDL, cntRow{Name: ob + " → " + ddl})
				}
			}
		}
		sort.Slice(v.ChangeSum, func(i, j int) bool { return v.ChangeSum[i].Count > v.ChangeSum[j].Count })
		if len(v.Changes) > top {
			v.Changes = v.Changes[:top]
		}
	}

	// 锁等待最集中的那一秒：与 QPS 峰值一对照，就能看出"压力峰值是否引发了锁竞争"
	if len(st.LockBySec) > 0 {
		var bestSec, bestN int64
		for sec, n := range st.LockBySec {
			if n > bestN {
				bestSec, bestN = sec, n
			}
		}
		v.LockPeakAt, v.LockPeakN = fmtUnix(bestSec), bestN
		if sa := st.Sec[bestSec]; sa != nil {
			v.LockPeakQPS = sa.SQL
		}
		v.LockPeakIsTop = v.PeakQPSAt != "" && v.PeakQPSAt == v.LockPeakAt
	}

	// 长事务（需掩码 29 才有非 0 trxid；按跨度取 Top-N）
	if len(st.TrxFirst) > 0 {
		v.TrxTracked = int64(len(st.TrxFirst))
		v.TrxFull = st.trxFull
		// "只见 START、后续无事件" 这个口径只在**没有** COMMIT/ROLLBACK 事件时才可靠：
		// 有结束事件时它们的 trxid 常为 0、归不到具体事务，会造成大批量假阳性
		// （实测某库 26 万个事务被误报为"可能未提交"，全是这个原因）。
		trackOpen := st.Commits+st.Rollbacks == 0
		for trx, f := range st.TrxFirst {
			if st.TrxKind[trx] == "START" { // 只见 START：可能仍在进行/未提交
				if trackOpen {
					v.TrxOpenN++
				}
				continue
			}
			l := st.TrxLast[trx]
			if f == l {
				continue
			}
			span := spanMS(f, l)
			if span <= 0 {
				continue
			}
			execMS := st.TrxExecMS[trx]
			denom := span + st.TrxFirstMS[trx]
			if denom <= 0 {
				denom = span
			}
			util := pctF(execMS, denom)
			if util > 100 {
				util = 100
			}
			v.Trxs = append(v.Trxs, trxRow{Trx: trx, User: st.TrxUser[trx], First: f, Last: l,
				Count: st.TrxCount[trx], SpanMS: span, ExecMS: execMS,
				Util: util})
		}
		sort.Slice(v.Trxs, func(i, j int) bool { return v.Trxs[i].SpanMS > v.Trxs[j].SpanMS })
		if len(v.Trxs) > top {
			v.Trxs = v.Trxs[:top]
		}
	}

	// 锁等待
	v.LockN, v.LockSumMS, v.LockMaxMS = st.LockN, st.LockSumMS, st.LockMaxMS
	v.LockHist, v.LockUnparsed = st.LockHist, st.LockUnparsed
	v.LockMoreN, v.LockCountMis = st.LockMoreN, st.LockCountMis
	v.DlckN, v.DlckNonZero, v.DlckMaxMS = st.DlckN, st.DlckNonZero, st.DlckMaxMS
	for _, n := range st.LockHist {
		if n > v.LockHistMax {
			v.LockHistMax = n
		}
	}
	// 锁等待明细：补上"持有方用户"和"表名"——
	// 现场最想知道的两件事就是"谁在持锁"和"锁在哪张表上"。
	// 持有方用户靠 trxid → user 反查（日志的锁行只带等待方的会话信息）。
	v.ObjMap = opt.objMap
	holderU := func(holder string) string {
		if holder == "" {
			return ""
		}
		// 持有方可能是多个 trxid（"a,b"），逐个查到就取第一个已知的
		for _, h := range strings.Split(holder, ",") {
			if u := st.TrxUser[h]; u != "" {
				return u
			}
		}
		return ""
	}
	// ---- 锁等待溯源（V2.8）：把锁行与「事务的语句」接起来 ----
	//
	// 采集期把语句按 trxid 平铺存了（st.trxStmts），这里只对**锁等待涉及的事务**
	// 建一次索引 —— 锁等待是百级，索引代价可忽略。
	stmtsByTrx := make(map[string][]trxStmtRec, len(st.trxStmts))
	for _, r := range st.trxStmts {
		stmtsByTrx[r.TrxID] = append(stmtsByTrx[r.TrxID], r)
	}
	endsByTrx := make(map[string]trxEndRec, len(st.trxEnds))
	for _, e := range st.trxEnds {
		endsByTrx[e.TrxID] = e // 后者覆盖前者：取最后一次结束事件
	}

	// 对象 ID → 表名的推断：日志只记 table id 不记表名，以往要靠 --obj-map
	// 手工查数据字典。这里从**等待方 SQL** 里抽表名给同 ID 投票 ——
	// 等待方正卡在这张表上，它的语句里出现的那张表就是高度相关的候选。
	// 实测命中率极高（本批 4 张热表 100% 推对），但要标「推断」而不是当事实。
	tableVotes := make(map[string]map[string]int) // tableID -> 表名 -> 票数
	for _, lk := range st.Locks {
		for _, sm := range stmtsByTrx[lk.Waiter] {
			eachTable([]byte(sm.SQL), sm.Op, func(name string, write bool) {
				if name == "" {
					return
				}
				v := 1
				if write && (lk.Mode == "X" || lk.Mode == "IX") {
					v = 2 // X 锁基本只可能是写目标表
				}
				m := tableVotes[lk.TableID]
				if m == nil {
					m = map[string]int{}
					tableVotes[lk.TableID] = m
				}
				m[strings.ToUpper(name)] += v
			})
		}
	}
	inferName := func(id string) string {
		m := tableVotes[id]
		best, bestN := "", 0
		for k, n := range m {
			if n > bestN || (n == bestN && k < best) {
				best, bestN = k, n
			}
		}
		return best
	}

	for _, lk := range st.Locks {
		row := lockRow{
			MS: lk.MS, Mode: lk.Mode, TableID: lk.TableID,
			Table:  tableNameOf(lk.TableID, opt.objMap),
			Waiter: lk.Waiter, WaiterU: lk.User,
			Holder: lk.Holder, HolderU: holderU(lk.Holder),
			Waiters: lk.Waiters, TS: lk.TS,
		}
		// 等待方：最后一条语句就是触发等待的那条
		if ss := stmtsByTrx[lk.Waiter]; len(ss) > 0 {
			last := ss[len(ss)-1]
			row.WaiterSQL, row.WaiterOp, row.WaiterMS = last.SQL, last.Op, last.MS
		}
		// 持有方：链首才是真正持锁的那个事务
		chain := splitTrxList(lk.Holder)
		if len(chain) > 0 {
			root := chain[0]
			row.HolderRoot = root
			row.Chain = chain
			row.HolderStmts = stmtsByTrx[root]
			if len(row.HolderStmts) == 0 {
				// V2.12 兜底：持有方没有执行行（语句跑得太快、被 MIN_EXEC_TIME 滤掉）时，
				// 用 DLCK 行留下的 (sess,thrd,stmt) 键，到掩码 27 的 [ORA] 行取回原始 SQL。
				// 取不到才真的"取不到"—— 此时报告仍要显式说明原因（见 HolderStmts 注释）。
				if sql := st.oraSQLOfTrx(root); sql != "" {
					row.HolderStmts = []trxStmtRec{{TrxID: root, Op: "ORA", SQL: sql}}
					row.HolderSQLFromORA = true
				}
			}
			if e, ok := endsByTrx[root]; ok {
				row.HolderKind, row.HolderEndTS = e.Kind, e.TS
			}
		}
		row.ChainMore = lk.More
		if row.Table == "" {
			if nm := inferName(lk.TableID); nm != "" {
				row.Table, row.TableInfer = nm, true
			}
		}
		v.LockRows = append(v.LockRows, row)
	}
	sort.SliceStable(v.LockRows, func(i, j int) bool { return v.LockRows[i].MS > v.LockRows[j].MS })
	// 链与可得性统计都在**截断之前**算：它们描述的是全量事实，
	// 不该被 -p 的显示上限影响（否则改显示条数会连结论一起变）。
	v.LockTotalN = len(v.LockRows)
	for _, r := range v.LockRows {
		if r.WaiterSQL != "" {
			v.LockWaiterSQLN++
		}
		if len(r.HolderStmts) > 0 {
			v.LockHolderSQLN++
		}
	}
	v.LockChains = buildLockChains(v.LockRows)
	// 卡片视图用全量副本（上面那两处统计也基于它）；LockRows 随后会被 -p 截断
	v.LockRowsAll = v.LockRows
	// 排查方向（V2.11）：必须在 LockRowsAll 就绪之后算（它读的是全量）。
	// 与 V2.10 那个「建太早导致判定静默失效」同一个坑，这里按依赖顺序摆。
	v.LockGuide = v.lockGuide()
	if len(v.LockRows) > top { // 同「最慢语句」：容量按 rowCap，展示按 top
		v.LockRows = v.LockRows[:top]
	}
	// 表名 → 锁等待累计（V2.10）：供「优先优化推荐」识别**等锁受害者**。
	// 用全量的 st.LockByTable（v.LockTables 会被 top 截断，统计不能取自截断后的表）。
	// 名字优先 --obj-map，其次用与锁卡片同一套「等待方 SQL 投票」推断。
	v.LockSumByName = make(map[string]float64, len(st.LockByTable))
	for id, a := range st.LockByTable {
		nm := tableNameOf(id, opt.objMap)
		if nm == "" {
			nm = inferName(id)
		}
		if nm == "" {
			continue
		}
		v.LockSumByName[strings.ToUpper(baseTableName(nm))] += a.SumMS
	}
	v.LockTableN = len(st.LockByTable)
	// 「优先优化推荐」放到这里算：它依赖上面的 LockSumByName（识别等锁受害者）。
	// 建在结构体初始化处会因数据未就绪而静默失效 —— 见那里的注释。
	v.Advice = v.recommend(adviceLimit)
	for id, a := range st.LockByTable {
		users := make([]string, 0, len(a.Users))
		for u := range a.Users {
			users = append(users, u)
		}
		sort.Strings(users)
		if len(users) > 3 {
			users = users[:3]
		}
		v.LockTables = append(v.LockTables, lockTableRow{TableID: id,
			Table: tableNameOf(id, opt.objMap), Count: a.Count,
			Pct: pct(a.Count, st.LockN), Sum: a.SumMS, Max: a.MaxMS, Mode: a.Mode,
			Waiters: strings.Join(users, ","), MaxAt: a.MaxAt})
	}
	sort.Slice(v.LockTables, func(i, j int) bool {
		if v.LockTables[i].Sum != v.LockTables[j].Sum {
			return v.LockTables[i].Sum > v.LockTables[j].Sum
		}
		return v.LockTables[i].Count > v.LockTables[j].Count
	})
	if len(v.LockTables) > top {
		v.LockTables = v.LockTables[:top]
	}
	// 报告涉及的 trxid（长事务 + 锁等待的等待方/持有方）→ 用户，供渲染时反查
	v.TrxUser = map[string]string{}
	addUser := func(trx string) {
		if trx == "" || v.TrxUser[trx] != "" {
			return
		}
		if u := st.TrxUser[trx]; u != "" {
			v.TrxUser[trx] = u
		}
	}
	for _, r := range v.Trxs {
		addUser(r.Trx)
	}
	for _, lk := range v.LockRows {
		addUser(lk.Waiter)
		for _, h := range strings.Split(lk.Holder, ",") {
			addUser(h)
		}
	}
	// 锁等待表 ID 反查 SQL（用户复制执行即可拿到表名，再配合 --obj-map 下次直接显示表名）
	if len(st.LockByTable) > 0 {
		ids := make([]string, 0, len(st.LockByTable))
		for id := range st.LockByTable {
			if _, known := opt.objMap[id]; !known {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool {
			a, _ := strconv.ParseInt(ids[i], 10, 64)
			b, _ := strconv.ParseInt(ids[j], 10, 64)
			return a < b
		})
		if len(ids) > 0 {
			v.RefSQL = fmt.Sprintf("SELECT ID, NAME, SCHID FROM SYS.SYSOBJECTS WHERE ID IN (%s);\n"+
				"-- 把结果存成 UTF-8 文本（每行 ID=表名 或直接粘贴 ID 与表名两列），\n"+
				"-- 下次加 --obj-map 文件名 即可在报告里直接显示表名", strings.Join(ids, ", "))
		}
	}

	// 筛选条件摘要
	var fs []string
	if opt.from != "" {
		fs = append(fs, "--from "+opt.from)
	}
	if opt.to != "" {
		fs = append(fs, "--to "+opt.to)
	}
	if opt.minMS > 0 {
		fs = append(fs, fmt.Sprintf("--min-ms %g", opt.minMS))
	}
	if opt.maxMS > 0 {
		fs = append(fs, fmt.Sprintf("--max-ms %g", opt.maxMS))
	}
	if opt.opSet != nil {
		fs = append(fs, "--op "+opt.ops)
	}
	if opt.excludeOps != "" {
		fs = append(fs, "--exclude-op "+opt.excludeOps)
	}
	if opt.user != "" {
		fs = append(fs, "--user "+opt.user)
	}
	if opt.trx != "" {
		fs = append(fs, "--trx "+opt.trx)
	}
	if opt.sqlLike != "" {
		fs = append(fs, "--sql-like "+opt.sqlLike)
	}
	if opt.limit > 0 {
		fs = append(fs, fmt.Sprintf("--limit %d", opt.limit))
	}
	v.FilterDesc = strings.Join(fs, "  ")
	// 时间窗口单独标出：它决定统计范围，与其它「只筛输出」的选项语义不同。
	if opt.from != "" || opt.to != "" {
		fr, to := opt.from, opt.to
		if fr == "" {
			fr = "（起点）"
		}
		if to == "" {
			to = "（终点）"
		}
		v.WindowDesc = fr + " ~ " + to
	}
	v.WinSkipped = st.WinSkew
	if v.FilterDesc == "" {
		v.FilterDesc = "（无）"
	}
	switch {
	case opt.statsOnly:
		v.ModeDesc = "只出统计，未导出 SQL（--stats-only）"
	case opt.topMS > 0:
		v.ModeDesc = fmt.Sprintf("导出最慢 %d 条（--top-ms）", opt.topMS)
	case opt.noParams:
		v.ModeDesc = "未还原参数（--no-params）"
	default:
		v.ModeDesc = "导出全部命中语句（参数已还原）"
	}
	// 位号 29 是否开启：三类事务/锁事件行全为 0 即未开（判据见 Mask29On 注释）。
	// 有一类不为 0 就说明 29 已开，此时 LockN==0 才是可信的"没有锁等待"。
	v.Mask29On = v.TrxEventN > 0 || v.TrxEndN > 0 || v.DlckN > 0 || v.LockN > 0

	v.Headline, v.HeadlineKind = buildHeadline(v)
	v.Hints = buildHints(v, st)
	return v
}

// ------------------------------------------------------------------ 审计
//
// 为什么专门做这一块：SQL 日志里最有价值的"事后取证"信息就在危险操作上。
// 误删表/误删数据、权限被改、批量 UPDATE 打错条件 —— 这些事后要回答四个问题：
//   谁（用户 + 客户端 IP）、什么时候、对哪个对象、影响多少行，以及能不能恢复（时间点/事务/LSN）。
// 而 `[ORA]` 行恰好补上一段别人都丢掉的盲区：**语句已到达服务器并完成语法解析，
// 但可能没执行成功**（权限不足、超时、客户端取消、事务被回滚）。桌面版把它排除在统计外、
// Web 版默认整个丢弃 —— 审计场景下这恰恰是要留的："有人试图删这张表"本身就是证据。

const (
	maxAudit     = 20000 // 危险操作清单上限
	maxChange    = 4000  // 结构变更时间线保留条数（环形）
	maxLastDDL   = 20000 // "表名 → 最近一次结构变更" 的键上限
	maxLSNBucket = 20000 // LSN 采样桶上限（每 30 秒一桶）
	auditWinSec  = 300   // ORA 与执行行的关联时间窗（秒）
)

// auditRec 一条审计记录（危险操作 或 结构变更）
type auditRec struct {
	TS      string
	Level   int    // 2 = 高危；1 = 结构变更
	Kind    string // DROP TABLE / TRUNCATE / DELETE（无 WHERE）/ GRANT …
	Object  string // 涉及的表（能提取到才有）
	User    string
	Client  string
	Op      string // 日志里的类型码
	Trx     string
	Rows    string // 影响行数（[DDL]/[CAL] 不带，为空）
	ExecID  string
	File    string
	MS      float64
	SQL     string // 完整语句（参数还原后）
	Thrd    string // 线程号（同一秒里多个会话做同样的事时，靠它区分是哪个连接）
	ORAOnly bool   // 只见到 [ORA]（解析了但没有执行行 —— 很可能没执行成功）
	key     string // 关联键（语句句柄），仅内部用
}

// pendRef ORA 候选的索引（用于和执行行配对）
type pendRef struct {
	key string
	idx int
	sec int64
}

// lsnRef 一次事务提交的 LSN 采样
type lsnRef struct {
	TS  string
	LSN string
}

// auditRow 审计节展示用的一行
type auditRow struct {
	TS       string
	Level    int
	Kind     string
	Object   string
	User     string
	Client   string
	Op       string
	Trx      string
	Rows     string
	ExecID   string
	Thrd     string
	MS       float64
	Brief    string
	ORAOnly  bool
	LSNAt    string // 该时刻前后最近的提交 LSN（恢复定位用）
	LSNTS    string
	AuditSQL string // 完整 SQL（写进配套附件）
}

// cntRow 通用"名称 + 次数"
type cntRow struct {
	Name  string
	Count int64
}

// cfgRow 采集配置体检表的一行
type cfgRow struct {
	Item   string // 检查项
	Value  string // 日志里实测到的
	Advice string // 怎么改配置（对应 sqllog.ini / dm.ini 的哪个参数）
}

// configCheck 据日志内容反推采集侧配置开了哪些位。
//
// 现场最常见的误判是"工具是不是坏了"——其实十有八九是 sqllog.ini 的
// SQL_TRACE_MASK 没开对应的位（28 才有 PARAMS、24/25 才有 EXECTIME/ROWCOUNT、
// 29 才有锁等待与事务事件、27 才有 [ORA]、31 才有 [LGN]）。
// 这一节把这些一次性列清楚，并给出该怎么改。
func configCheck(v *statsView) []cfgRow {
	var rows []cfgRow
	pad := func(n int64) string { return fmtInt(n) }

	// 1) 时间戳精度
	if v.Ts26 > 0 {
		rows = append(rows, cfgRow{"时间戳精度",
			fmt.Sprintf("微秒（6 位小数）%s 行 / 合计 %s 行", pad(v.Ts26), pad(v.Records)),
			"SDK 侧开启了微秒时间戳；本工具两种精度都能解析"})
	} else {
		rows = append(rows, cfgRow{"时间戳精度",
			fmt.Sprintf("毫秒（3 位小数），共 %s 行", pad(v.Records)),
			"常规形态"})
	}
	// 2) 会话块格式
	if v.EPSeen > 0 {
		rows = append(rows, cfgRow{"会话块格式", "现代格式（含 (EP[n] 执行节点段）", "单机恒为 EP[0]；MPP/DPC 集群会有多个"})
	} else {
		rows = append(rows, cfgRow{"会话块格式", "无 (EP[n] 段（老版本 DM 或 SVR_LOG=3 简单模式）",
			"老格式日志本工具仍按宽松判据解析，不丢数据"})
	}
	// 3) 执行行有没有耗时（掩码 24/25）
	execRows := v.Exec - v.OraN - v.LgnN
	if execRows > 0 {
		miss := v.NoExecN
		cov := pctF(float64(execRows-miss), float64(execRows))
		adv := "正常"
		if miss > 0 {
			adv = "有 SQL 却缺 EXECTIME 的行（现网实测多为 DM 自身的维护类语句，如 " +
				"create index / update ... from 子查询）；也可能是掩码 24/25 没开全 —— 这些行的耗时统计不到"
		}
		rows = append(rows, cfgRow{"执行行耗时覆盖（掩码 24/25）",
			fmt.Sprintf("%.2f%%（%s / %s 行带 EXECTIME）", cov, pad(execRows-miss), pad(execRows)), adv})
	}
	// 3b) 最小耗时：识别采集侧的 MIN_EXEC_TIME
	//
	// 🩸 现网实测（金蝶 ERP，2026-10-08）：那份日志里 **UPDATE 一条都没有**，
	// 但同期重做日志 3 分钟涨 635MB、归档文件 16 分钟长 2GB —— 写量与日志严重不符，
	// 第一反应会归因成「UPDATE 采集位没开」。**那是错的**：
	// 线上 SQL_TRACE_MASK=2:3:25:28:29 中位号 2（=DML=4~10）本就含 UPDATE。
	// 真正的过滤器是 **MIN_EXEC_TIME = 100** —— 任何单条 <100ms 的语句都不写日志，
	// **与语句类型无关**。判据就是这一条：日志里最小 EXECTIME 恰好卡在某整数阈值上
	// （实测最小值 100.00ms、低于 100ms 的 0 条 / 1729 条）。
	// 所以「日志里没有某类语句」不能直接推「掩码漏开」，得先看最小耗时。
	if v.MinExecMS > 0 && execRows > 0 {
		adv := "正常（采集侧未设最小耗时阈值，或阈值低于日志里最快的语句）"
		for _, th := range []float64{1, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000} {
			if v.MinExecMS >= th && v.MinExecMS <= th*1.16 {
				adv = fmt.Sprintf("⚠️ 最小耗时**恰好卡在 %s 附近**，极可能采集侧设了 MIN_EXEC_TIME=%s"+
					"——**低于该值的语句不写日志，且与语句类型无关**。"+
					"此时「日志里没有某类语句」（如 UPDATE / DELETE）不代表掩码漏开，先核对 V$DM_SQLLOG_CONFIG 的 MIN_EXEC_TIME",
					fmtDur(th), fmtInt(int64(th)))
				break
			}
		}
		rows = append(rows, cfgRow{"最小 EXECTIME", fmtDur(v.MinExecMS) + "（由耗时直方图近似，精度约 ±15%）", adv})
	}
	// 4) 参数行（掩码 28）
	if v.ParamsN == 0 {
		adv := "日志里一行 PARAMS 都没有：SQL_TRACE_MASK 需含 28（22 才有 Load para 行）"
		if v.Missing > 0 {
			adv += "。当前有 " + pad(v.Missing) + " 条语句的 ? 无法还原，根因在此，不是解析问题"
		}
		rows = append(rows, cfgRow{"参数行 PARAMS（掩码 28）", "0 行", adv})
	} else {
		rows = append(rows, cfgRow{"参数行 PARAMS（掩码 28）", pad(v.ParamsN) + " 行", "正常"})
	}
	// 5) 事务事件与锁（掩码 29）
	if v.TrxEventN == 0 && v.TrxEndN == 0 {
		rows = append(rows, cfgRow{"事务事件 TRX:（掩码 29）", "0 行",
			"SQL_TRACE_MASK 需含 29，否则长事务与 TPS 都算不出来"})
	} else {
		rows = append(rows, cfgRow{"事务事件 TRX:（掩码 29）",
			fmt.Sprintf("START %s 行 / COMMIT·ROLLBACK %s 行", pad(v.TrxEventN), pad(v.TrxEndN)),
			"正常（COMMIT/ROLLBACK 行的 trxid 常为 0，无法归属到具体事务）"})
	}
	if !v.Mask29On {
		rows = append(rows, cfgRow{"锁等待 LOCK_TID（掩码 29）", "0 行",
			"⚠️ 判定位号 29 未开（事务事件 TRX: 与 DLCK 计时行同样为 0）：此时「锁等待 0 次」是数据缺失，" +
				"不能读成「没有锁竞争」。把 SQL_TRACE_MASK 的 29 位打开后重采，才有这一维度"})
	} else if v.LockN == 0 {
		rows = append(rows, cfgRow{"锁等待 LOCK_TID（掩码 29）",
			fmt.Sprintf("0 次真等待 / 事务事件 %s 行", pad(v.TrxEventN+v.TrxEndN)),
			"位号 29 已开（日志里确有事务/锁事件行），所以这个 0 可信 —— 该时段确实无锁竞争。" +
				"判据必须是 LOCK_TID + wait for 同时出现；DLCK 是锁节点的自身耗时，不是等待"})
	} else {
		rows = append(rows, cfgRow{"锁等待 LOCK_TID（掩码 29）",
			fmt.Sprintf("%s 次真等待 / 最长 %s", pad(v.LockN), fmtDur(v.LockMaxMS)), "正常"})
	}
	// 6) 日志时间连续性 —— 断档往往意味着"采集中断"，而不是"这段时间业务安静"。
	// 用完整时间桶（含空桶）数连续空段，比逐个文件报时间范围更能反映采集完整性。
	if n := len(v.Buckets); n > 3 {
		var run, mx int
		var at string
		for _, b := range v.Buckets {
			if b.SQL == 0 {
				run++
				if run > mx {
					mx, at = run, b.Label
				}
			} else {
				run = 0
			}
		}
		adv := fmt.Sprintf("时间轴连续（共 %d 个%s桶，无空档）", n, v.BucketUnit)
		if mx > 0 {
			adv = fmt.Sprintf("最长连续空档 %d 个%s桶（止于 %s）：可能是采集中断/实例停过，"+
				"也可能是业务真空 —— 看到空档先确认采集是否连续，别把「这段时间没问题」当成结论", mx, v.BucketUnit, at)
		}
		rows = append(rows, cfgRow{"日志时间连续性", fmt.Sprintf("%d 个%s桶 / 最长空档 %d 个", n, v.BucketUnit, mx), adv})
	}

	// 7) [ORA] / [LGN] / [ERR]
	oraAdv := "SQL_TRACE_MASK 需含 27 才会记录原始语句（[ORA] 只解析未执行，不计入负载）"
	if v.OraN > 0 {
		oraAdv = "[ORA] 只解析未执行，本工具默认不输出（要看就加 --op ORA 或 --all-ops）"
	}
	rows = append(rows, cfgRow{"原始语句 [ORA]（掩码 27）", pad(v.OraN) + " 行", oraAdv})
	rows = append(rows, cfgRow{"登录事件 [LGN]（掩码 31）", pad(v.LgnN) + " 行",
		"要登录审计必须让掩码含 31；本工具可用 -k LGN 抽出登录事件"})
	errAdv := "SQL_TRACE_MASK 需含 23 才会记录报错语句"
	if v.ErrN > 0 && len(v.ErrCodes) > 0 {
		top := v.ErrCodes[0]
		errAdv = fmt.Sprintf("最主要的错误码是 %s（%s 次），可优先排查", top.Code, pad(top.Count))
	}
	rows = append(rows, cfgRow{"报错语句 [ERR(...)]（掩码 23）", pad(v.ErrN) + " 行", errAdv})
	// 7) 耗时单位
	switch {
	case v.UnitUS > 0:
		rows = append(rows, cfgRow{"EXECTIME 单位", fmt.Sprintf("微秒 (us)，%s 行", pad(v.UnitUS)),
			"该库 EXECTIME_PREC_FLAG=1；本工具已自动换算成毫秒，两个库的报告可直接横向比"})
	case v.UnitNS > 0:
		rows = append(rows, cfgRow{"EXECTIME 单位", fmt.Sprintf("纳秒 (ns)，%s 行", pad(v.UnitNS)),
			"已自动换算成毫秒"})
	case v.UnitMS > 0:
		rows = append(rows, cfgRow{"EXECTIME 单位", fmt.Sprintf("毫秒 (ms)，%s 行", pad(v.UnitMS)),
			"EXECTIME_PREC_FLAG=0（常规）"})
	}
	if v.UnitNone > 0 {
		rows = append(rows, cfgRow{"缺少单位的耗时行", pad(v.UnitNone) + " 行",
			"按毫秒处理；若该库是微秒制，建议核对 V$DM_SQLLOG_CONFIG 的 EXECTIME_PREC_FLAG"})
	}
	if v.MatchedLoose > 0 {
		rows = append(rows, cfgRow{"句柄键兜底还原", pad(v.MatchedLoose) + " 条",
			"这些语句的解析与执行落在不同线程，靠「仅语句句柄」的键兜底还原成功"})
	}
	return rows
}

// firstWord 取 SQL 的第一个词（大写），用于 DDL 归类
func firstWord(sql []byte) string {
	i := 0
	n := len(sql)
	for i < n && (sql[i] == ' ' || sql[i] == '\t' || sql[i] == '\n' || sql[i] == '\r' || sql[i] == '(') {
		i++
	}
	j := i
	for j < n && (sql[j] == '_' || sql[j] >= 'A' && sql[j] <= 'Z' || sql[j] >= 'a' && sql[j] <= 'z') {
		j++
	}
	if j == i {
		return ""
	}
	w := upperBytes(sql[i:j])
	if len(w) > 20 {
		w = w[:20]
	}
	return w
}

// noteDDLVerb 记 DDL 首词
func (s *Stats) noteDDLVerb(w string) {
	if w == "" {
		return
	}
	s.ddlVerbMu.Lock()
	defer s.ddlVerbMu.Unlock()
	if len(s.DDLVerb) < 200 {
		s.DDLVerb[w]++
	}
}

// firstTableOf 取语句涉及的第一张表（复用 eachTable 的提取逻辑）
func firstTableOf(sql []byte, op string) string {
	got := ""
	stop := false
	eachTable(sql, op, func(name string, write bool) {
		if got == "" {
			got = name
		}
		stop = true
	})
	_ = stop
	return got
}

// dangerLevel 判定语句的审计级别：2 = 高危，1 = 结构变更，0 = 普通。
//
// 只把 SQL 开头 160 字节大写化后做前缀匹配（结构关键字必然在开头），
// 所以绝大多数语句（SELECT/INSERT…）在第一个字节就被排除，对扫描耗时几乎无影响。
func dangerLevel(sql []byte, op string) (int, string, string) {
	n := len(sql)
	if n == 0 {
		return 0, "", ""
	}
	// 跳过前导空白与换行
	i := 0
	for i < n && (sql[i] == ' ' || sql[i] == '\t' || sql[i] == '\n' || sql[i] == '\r') {
		i++
	}
	if i >= n {
		return 0, "", ""
	}
	// 快捷排除：以 S/I/M/B 等开头的常见语句直接返回
	// 快捷排除：只有这几种开头才可能命中（D=DROP/DELETE、T=TRUNCATE、U=UPDATE、
	// G=GRANT、R=REVOKE/RENAME、A=ALTER、C=CREATE/COMMENT）
	switch sql[i] {
	case 'D', 'd', 'T', 't', 'U', 'u', 'G', 'g', 'R', 'r', 'A', 'a', 'C', 'c':
	default:
		return 0, "", ""
	}
	var buf [160]byte
	m := n - i
	if m > len(buf) {
		m = len(buf)
	}
	for k := 0; k < m; k++ {
		c := sql[i+k]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		buf[k] = c
	}
	up := buf[:m] // 用 []byte 而不是 string —— 这个函数每条语句都会调，
	//              转成 string 就是每条一次堆分配，467 万条语句下 GC 会很难看
	has := func(w string) bool { return bytes.HasPrefix(up, []byte(w)) }
	foldFind := func(w string) bool { return containsFold(sql, w) }

	objOf := func(o string) string { return firstTableOf(sql, o) }

	switch {
	case has("DROP "):
		kind := "DROP"
		for _, k := range []string{"TABLE", "INDEX", "VIEW", "USER", "SCHEMA", "TABLESPACE",
			"PROCEDURE", "FUNCTION", "TRIGGER", "PACKAGE", "SEQUENCE", "SYNONYM", "PARTITION"} {
			if bytes.HasPrefix(up[5:], []byte(k)) {
				kind = "DROP " + k
				break
			}
		}
		return 2, kind, objOf("DDL")
	case has("TRUNCATE"):
		return 2, "TRUNCATE TABLE", objOf("DDL")
	case has("DELETE"):
		if !foldFind(" where ") && !foldFind("\nwhere ") {
			return 2, "DELETE 无 WHERE（整表删除）", objOf("DEL")
		}
		return 0, "", ""
	case has("UPDATE"):
		if !foldFind(" where ") && !foldFind("\nwhere ") {
			return 2, "UPDATE 无 WHERE（整表更新）", objOf("UPD")
		}
		return 0, "", ""
	case has("GRANT "):
		return 2, "GRANT 授权", ""
	case has("REVOKE "):
		return 2, "REVOKE 收权", ""
	case has("ALTER "):
		if foldFind("DROP COLUMN") || foldFind("DROP PARTITION") || foldFind("DROP CONSTRAINT") {
			return 2, "ALTER … DROP（删除列/分区/约束）", objOf("DDL")
		}
		return 1, "ALTER 表/对象", objOf("DDL")
	case has("CREATE "):
		if bytes.HasPrefix(up[7:], []byte("USER")) {
			return 2, "CREATE USER", ""
		}
		return 1, "CREATE 表/对象", objOf("DDL")
	case has("RENAME "):
		return 1, "RENAME", objOf("DDL")
	case has("COMMENT ON"):
		return 1, "COMMENT ON", objOf("DDL")
	case has("COMMIT"), has("ROLLBACK"):
		return 0, "", ""
	}
	return 0, "", ""
}

// batchDanger 影响行数超过阈值的 DML —— 也算"批量误操作"的形态之一
func batchDanger(op, rows string) (bool, string) {
	// 先按类型短路：只有 DEL/UPD 才可能命中，省掉绝大多数行的 ParseInt
	if op != "DEL" && op != "UPD" || rows == "" {
		return false, ""
	}
	v, err := strconv.ParseInt(rows, 10, 64)
	if err != nil {
		return false, ""
	}
	if op == "DEL" && v >= 10000 {
		return true, fmt.Sprintf("DELETE 大批量（%d 行）", v)
	}
	if op == "UPD" && v >= 50000 {
		return true, fmt.Sprintf("UPDATE 大批量（%d 行）", v)
	}
	return false, ""
}

// auditBody 生成审计节的中间内容（三种格式共用：先算好要显示哪些行）
func auditSlice(v *statsView, opt *Options) (dangers, changes []auditRow) {
	n := min2(len(v.Dangers), opt.top)
	dangers = v.Dangers[:n]
	m := min2(len(v.Changes), opt.top)
	changes = v.Changes[:m]
	return
}

// auditAuditLine 一行"线程 / LSN / 溯源"的说明（md 与 html 共用）
func auditFootNote(v *statsView) string {
	return "**恢复定位四要素**：时间点 / 对象 / 操作人（用户 + 客户端 + 线程）/ **提交 LSN**" +
		"（本次采样到 " + fmtInt(v.LSNSampled) + " 个 LSN 时间点）。" +
		"具体恢复手段（闪回、备份还原、归档不完全恢复）请按你的 DM 版本与备份策略确认后执行。"
}

// auditTS 审计用时间戳：带上月日（"09-10 00:00:18"）。
// 日志常常跨天，审计场景只给 "00:00:18" 会分不清是哪一天 —— 而出事时间点是要写进笔录的。
func auditTS(ts string) string {
	if len(ts) >= 19 {
		return ts[5:19]
	}
	return ts
}

// ratioDisp 读写比展示：写为 0 时显示 "只读"（比 "∞" 好读，也不误导成 0）
func ratioDisp(r float64) string {
	if r <= 0 {
		return "-"
	}
	if r >= 1000 {
		return "只读"
	}
	return fmt.Sprintf("%.1f", r)
}

// renderAuditText 文本版：审计与恢复定位
func renderAuditText(w io.Writer, v *statsView, opt *Options) {
	if len(v.Dangers) == 0 && len(v.Changes) == 0 {
		return
	}
	sec(w, "审计与恢复定位（危险操作 / 结构变更）")
	two := func(k, val string) { fmt.Fprintf(w, "  %s %s\n", pad(k, 18), val) }
	if len(v.Dangers) > 0 {
		two("高危操作", fmt.Sprintf("%s 条（下表列出最近 %d 条）", fmtInt(v.DangerN), min2(len(v.Dangers), opt.top)))
		if v.DangerORA > 0 {
			two("仅解析未见执行", fmt.Sprintf("%s 条 —— 语句已到达服务器但没看到执行行，"+
				"常见于权限不足/超时/客户端取消/事务回滚。**「有人试图这么干」本身就是证据**", fmtInt(v.DangerORA)))
		}
		fmt.Fprintf(w, "  %s %s %s %s %s %s %s %s\n",
			pad("#", 3), pad("时间", 14), pad("类型", 26), pad("对象", 18), pad("用户", 16),
			pad("客户端", 20), lpad("影响", 7), pad("状态", 12))
		n := min2(len(v.Dangers), opt.top)
		for i := 0; i < n; i++ {
			r := v.Dangers[i]
			st := "已执行"
			if r.ORAOnly {
				st = "仅解析未执行"
			}
			fmt.Fprintf(w, "  %s %s %s %s %s %s %s %s\n",
				lpad(strconv.Itoa(i+1), 3), pad(auditTS(r.TS), 14), pad(clip(r.Kind, 26), 26),
				pad(clip(r.Object, 18), 18), pad(clip(r.User, 16), 16), pad(clip(r.Client, 20), 20),
				lpad(rowsDisp(r.Rows), 7), pad(st, 12))
			fmt.Fprintf(w, "      线程 %s", clip(r.Thrd, 9))
			if r.LSNAt != "" {
				fmt.Fprintf(w, " · 最近提交 LSN %s（%s）", r.LSNAt, shortTS(r.LSNTS))
			}
			if r.Trx != "" && r.Trx != "0" {
				fmt.Fprintf(w, " · 溯源 dmsqlq <同一路径> -x %s -N", r.Trx)
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "      %s\n", briefOf(r.Brief, 132))
		}
		if len(v.ObjRisk) > 0 {
			fmt.Fprint(w, "  被反复操作的对象：")
			for i, o := range v.ObjRisk {
				if i > 0 {
					fmt.Fprint(w, " · ")
				}
				fmt.Fprintf(w, "%s %d 次", o.Name, o.Count)
			}
			fmt.Fprintln(w)
		}
	}
	if len(v.Changes) > 0 {
		fmt.Fprintf(w, "  结构变更 Top%d（共 %s 条，时间倒序）\n", min2(len(v.Changes), opt.top), fmtInt(v.ChangeN))
		fmt.Fprintf(w, "  %s %s %s %s %s\n",
			pad("#", 3), pad("时间", 15), pad("类型", 20), pad("对象", 22), "用户 / 客户端")
		n := min2(len(v.Changes), opt.top)
		for i := 0; i < n; i++ {
			r := v.Changes[i]
			fmt.Fprintf(w, "  %s %s %s %s %s · %s\n",
				lpad(strconv.Itoa(i+1), 3), pad(auditTS(r.TS), 14), pad(clip(r.Kind, 20), 20),
				pad(clip(r.Object, 22), 22), clip(r.User, 16), clip(r.Client, 22))
		}
		if len(v.ChangeSum) > 0 {
			fmt.Fprint(w, "  变更类型统计：")
			for i, c := range v.ChangeSum {
				if i > 0 {
					fmt.Fprint(w, " · ")
				}
				fmt.Fprintf(w, "%s %s", c.Name, fmtInt(c.Count))
			}
			fmt.Fprintln(w)
		}
	}
	fmt.Fprintln(w, "  ▸ 本工具能给到的恢复定位四要素：**时间点 / 对象 / 操作人（用户+客户端）/**")
	fmt.Fprintf(w, "    **提交 LSN**（本次采样到 %s 个 LSN 时间点）。具体恢复手段（闪回、备份还原、\n", fmtInt(v.LSNSampled))
	fmt.Fprintln(w, "    归档不完全恢复）请按你的 DM 版本与备份策略确认后执行。")
	fmt.Fprintln(w, "  ▸ 完整语句（含参数还原）见配套附件的「4) 审计明细」；只要审计命中的语句可加 -d。")
	if v.AuditFull {
		fmt.Fprintln(w, "  ! 危险操作条数已达上限，清单被截断 —— 建议按时间段分批分析。")
	}
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// trxStmtNames 每事务语句数分布的分档名
var trxStmtNames = []string{"1 条", "2-5 条", "6-20 条", "21-100 条", "101-1000 条", ">1000 条"}

func hist6Max(h [6]int64) int64 {
	var m int64
	for _, x := range h {
		if x > m {
			m = x
		}
	}
	return m
}

// renderTrxStmtHist 文本版：每事务语句数分布
//
// 为什么单列这一节：批量导入慢的头号原因不是"某条 SQL 慢"，而是**逐条提交** ——
// 10 万条 INSERT 分 10 万次提交 vs 一个事务 10 万条，差的不是 SQL 而是提交次数。
// 只看长事务跨度是看不出这个的，看语句数分布才一眼分明。
func (v *statsView) renderTrxStmtHist(w io.Writer, indent string) {
	if v.TrxStmtN == 0 {
		return
	}
	fmt.Fprintf(w, "%s每事务语句数分布（共 %s 个事务，中位数 %d 条）\n",
		indent, fmtInt(v.TrxStmtN), v.TrxStmtMed)
	mx := hist6Max(v.TrxStmtHist)
	for i, n := range v.TrxStmtHist {
		fmt.Fprintf(w, "%s  %s %s %s  %s\n", indent, pad(trxStmtNames[i], 12),
			lpad(fmtInt(n), 10), lpad(fmt.Sprintf("%.1f%%", pct(n, v.TrxStmtN)), 8),
			bar(ratioOf(n, mx), 26))
	}
	fmt.Fprintf(w, "%s  口径：同一 trxid 内的**执行语句**条数（TRX: START 事件不计）。"+
		"「1 条」占比高 = 应用在逐条提交（批量导入慢的头号原因）；「>1000 条」= 大事务，注意 undo 与持锁\n", indent)
}

// rowsDisp 行数展示：ROWCOUNT 缺失（[DDL]/[CAL] 本来就不带）显示 "-"，
// 不能显示 0 —— 那会让人误以为"这条 DDL 影响了 0 行"。
func rowsDisp(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// utilDisp 事务利用率展示
func utilDisp(u float64) string {
	return fmt.Sprintf("%.1f%%", u)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// minInt 两整数取小（终端视图截断条数用）
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// buildBuckets 按自适应粒度聚合负载时间分布（看业务高峰用）。
//
// 粒度规则：跨度 ≤2 小时 → 分钟；≤3 天 → 小时；更长 → 天。
// 另加保护：桶数超过 240 就升一级粒度，避免报告里出现几百行表格。
// 秒级 TopN 被替换掉的原因：一次高峰里秒与秒之间的差异是噪声，看不出"业务高峰"。
func (v *statsView) buildBuckets(st *Stats, keys []int64, first, last int64, opt *Options) {
	bw := int64(60)
	switch {
	case v.SpanSec <= 7200:
		bw = 60
	case v.SpanSec <= 3*86400:
		bw = 3600
	default:
		bw = 86400
	}
	for n := int64(v.SpanSec) / bw; n > 240; n = int64(v.SpanSec) / bw {
		switch bw {
		case 60:
			bw = 3600
		case 3600:
			bw = 86400
		default:
			bw *= 7
		}
	}
	v.BucketSec = bw
	switch {
	case bw < 3600:
		v.BucketUnit = "分钟"
	case bw < 86400:
		v.BucketUnit = "小时"
	default:
		v.BucketUnit = "天"
	}
	// 对齐到本地日历边界：时间戳在本工具里按"日历字段折 UTC"处理，
	// 所以要先补上本地时区偏移再取模（分钟/小时粒度下偏移是 3600 的整数倍，不影响结果）
	_, off := time.Now().Zone()
	offS := int64(off)
	// 只把偏移加进"取模"里，不能再减回去 —— 否则每个桶的起点会整体前移一个时区宽度，
	// 桶数虚增（实测 11 个桶变成 491 个）
	start := first - (((first+offS)%bw)+bw)%bw

	n := int((last-start)/bw) + 1
	if n <= 0 {
		return
	}
	if n > 4000 { // 极端跨度保护（天粒度下 4000 天）
		n = 4000
	}
	buckets := make([]bucketRow, n)
	for i := range buckets {
		t := start + int64(i)*bw
		buckets[i].TS = fmtUnix(t)
		buckets[i].Label = bucketLabel(fmtUnix(t), bw)
	}
	for _, sec := range keys {
		idx := int((sec - start) / bw)
		if idx < 0 || idx >= n {
			continue
		}
		sa := st.Sec[sec]
		b := &buckets[idx]
		b.SQL += sa.SQL
		b.SumMS += sa.SumMS
		b.Commit += sa.Commit
		b.Rollback += sa.Rollback
		b.Secs++
	}
	var tot int64
	peak := 0
	for i := range buckets {
		b := &buckets[i]
		b.QPS = float64(b.SQL) / float64(bw)
		tot += b.SQL
		if b.SQL > buckets[peak].SQL {
			peak = i
		}
	}
	for i := range buckets {
		buckets[i].Pct = pct(buckets[i].SQL, tot)
	}
	v.Buckets = buckets
	v.BucketCount = n
	if buckets[peak].SQL > 0 {
		pb := buckets[peak]
		v.PeakBucket = &pb
	}
	// 高峰时段 TopN（只看有数据的桶）
	top := make([]bucketRow, 0, n)
	for _, b := range buckets {
		if b.SQL > 0 {
			top = append(top, b)
		}
	}
	sort.SliceStable(top, func(i, j int) bool { return top[i].SQL > top[j].SQL })
	if len(top) > opt.top {
		top = top[:opt.top]
	}
	v.BucketsTop = top
}

// bucketLabel 时间桶的显示标签（分钟级只显示时分，避免表格太宽）
func bucketLabel(ts string, bw int64) string {
	switch {
	case bw < 3600:
		if len(ts) >= 16 {
			return ts[11:16]
		}
	case bw < 86400:
		if len(ts) >= 16 {
			return ts[5:16]
		}
	default:
		if len(ts) >= 10 {
			return ts[:10]
		}
	}
	return ts
}

// fmtUnix Unix 秒 → "yyyy-MM-dd HH:mm:ss"
// 必须用 UTC：tsUnix 是"把日志里的日历字段直接当 UTC 折算"，
// 若这里再按本地时区 +8 还原，就会出现"日志是 00:00、峰值显示 08:00"的错位。
func fmtUnix(sec int64) string {
	return time.Unix(sec, 0).UTC().Format("2006-01-02 15:04:05")
}

// spanMS 两个时间戳之间的毫秒差（支持带毫秒与不带毫秒两种写法）
func spanMS(a, b string) float64 {
	ta, ok1 := parseTS(a)
	tb, ok2 := parseTS(b)
	if !ok1 || !ok2 {
		return 0
	}
	return float64(tb.Sub(ta)) / float64(time.Millisecond)
}

func parseTS(s string) (time.Time, bool) {
	if len(s) >= 23 {
		if t, err := time.Parse("2006-01-02 15:04:05.000", s[:23]); err == nil {
			return t, true
		}
	}
	if len(s) >= 19 {
		if t, err := time.Parse("2006-01-02 15:04:05", s[:19]); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// buildHints 判读提示：根据数据给出可操作的建议
// buildHeadline 报告头部的一句话结论 —— 回答"这份报告该先看哪里"。
//
// 顺序刻意如此（参考 AWR 把 DB Time 摆在报告最前）：
//
//	① 先看"代价畸高的错误码"。次数与耗时是两种量纲 —— 实测现网 [ERR(-608)]
//	   只占 3.4% 的次数，却占 74.9% 的语句总耗时；只看次数榜会完全漏掉它。
//	② 再看"累计耗时最大的语句模板"，那是优化收益最大的入口。
//
// 返回 (文本, 级别)；级别用于渲染器着色，空文本表示没有值得置顶的结论。
func buildHeadline(v *statsView) (string, string) {
	total := v.TotalExecMS()
	if total <= 0 {
		return "", ""
	}
	var worst *errCodeRow
	for i := range v.ErrCodes {
		e := &v.ErrCodes[i]
		if e.Sum/total < 0.5 {
			continue
		}
		if worst == nil || e.Sum > worst.Sum {
			worst = e
		}
	}
	if worst != nil {
		return fmt.Sprintf("头号问题：错误码 %s 占了语句总耗时的 %.1f%%（%s 次 / 累计 %s），"+
			"而它的次数只占 %.1f%% —— 先查它，别被「次数榜」骗过。",
			worst.Code, worst.Sum/total*100, fmtInt(worst.Count), fmtDur(worst.Sum),
			float64(worst.Count)*100/float64(max64(v.Exec, 1))), "warn"
	}
	if len(v.Tpls) > 0 {
		t := v.Tpls[0]
		if t.Sum/total >= 0.1 {
			return fmt.Sprintf("头号问题：累计耗时最高的是一类语句（%s 次 / 累计 %s，占语句总耗时的 %.1f%%）"+
				"—— 从它开始优化收益最大。", fmtInt(t.Count), fmtDur(t.Sum), t.Sum/total*100), "info"
		}
	}
	return "", ""
}

func buildHints(v *statsView, st *Stats) []string {
	var h []string
	if v.Records == 0 {
		h = append(h, "一条记录都没解析出来：确认文件是 dmsql_*.log（不是 dm_*.log 事件日志）；"+
			"若日志只有“时间+语句”没有会话块，那是 SVR_LOG=3 简单模式，加 --loose 再试。")
		return h
	}
	if v.Exec == 0 {
		h = append(h, "记录能读到但没有任何 SQL 事件行：多半是 sqllog.ini 的 SQL_TRACE_MASK 没开 24/25，"+
			"或日志里只有 TRX/PARAMS 之类非 SQL 事件。先用 --all-ops 看看到底有哪些行类型。")
	}
	if st.Skipped > 0 && v.Exec > 0 {
		h = append(h, fmt.Sprintf("有 %s 条 [ORA]（只解析未执行）被默认跳过，占事件行 %.1f%%；"+
			"这是预编译语句的正常现象，需要的话用 --op ORA 一并导出。", fmtInt(st.Skipped), pct(st.Skipped, v.Exec)))
	}
	if !v.Mask29On {
		h = append(h, "本批日志里没有任何事务/锁事件行（TRX: / DLCK / LOCK_TID 全为 0），说明采集侧 "+
			"SQL_TRACE_MASK 缺 29：报告里的「锁等待」「长事务」「TPS」三项是没采集到、不是没发生，"+
			"不要据此下「这库没有锁竞争」的结论。要这几项就得把 29 打开后重新采集。")
	} else if v.LockN == 0 && v.Exec > 0 {
		h = append(h, "位号 29 已开（日志里确实有事务/锁事件行），本次一条锁等待都没有 —— "+
			"这个 0 是可信的「确实没发生」，不是「没采集」。")
	}
	if v.Missing > 0 {
		h = append(h, fmt.Sprintf("有 %s 条语句带 ? 但没配上参数（占 %.2f%%）：通常是日志缺 PARAMS 行（掩码 28 未开），"+
			"或该语句在日志里只有执行行。这些语句仍会输出，但保留原样的 ?（--skip-missing 可滤掉）。",
			fmtInt(v.Missing), 100-v.RestorePct))
	}
	if len(v.Slow) > 0 && v.Slow[0].MS >= 1000 {
		h = append(h, fmt.Sprintf("最慢一条 %s（%s / %s / %s）。下一步直接复制执行："+
			"dmsqlq <同一路径> --top-ms 20 -o slow.sql ，即可拿到最慢 20 条的完整可执行 SQL。",
			fmtDur(v.Slow[0].MS), v.Slow[0].Op, v.Slow[0].User, v.Slow[0].TS))
	}
	if len(v.Tpls) > 0 && v.HistTotal() > 0 {
		top1 := v.Tpls[0]
		totalMS := v.TotalExecMS()
		if totalMS > 0 && top1.Sum/totalMS > 0.3 {
			h = append(h, fmt.Sprintf("最耗时的语句模板占了全部执行耗时的 %.0f%%（累计 %s，共 %s 次）："+
				"这是优化收益最大的一条，先看它。", top1.Sum/totalMS*100, fmtDur(top1.Sum), fmtInt(top1.Count)))
		}
	}
	if n := v.Hist[6]; n > 0 {
		h = append(h, fmt.Sprintf("有 %s 条语句单次执行超过 60 秒，属于严重慢 SQL，建议优先排查。", fmtInt(n)))
	}
	// ---- 锁等待（与"长事务"是两件事，判定依据完全不同）----
	switch {
	case v.LockN > 0:
		tbl := ""
		if len(v.LockTables) > 0 {
			t := v.LockTables[0]
			tbl = fmt.Sprintf("、集中在表 ID %s（%s 次 / 累计 %s / 锁模式 %s）", t.TableID, fmtInt(t.Count), fmtDur(t.Sum), t.Mode)
		}
		h = append(h, fmt.Sprintf("发生锁等待 %s 次、累计 %s、最长 %s%s。下一步：用 --trx <等待方事务号> 导出它当时在跑的 SQL，"+
			"并用表 ID 到数据字典反查表名（不同版本视图列名略有差异，可试 DBA_TABLES / SYS.SYSOBJECTS / V$LOCK 按对象 ID 过滤）；"+
			"锁模式为 X 且伴随行数大时，留意是否发生了行锁升级。",
			fmtInt(v.LockN), fmtDur(v.LockSumMS), fmtDur(v.LockMaxMS), tbl))
	case v.DlckN > 0:
		h = append(h, fmt.Sprintf("日志里有 %s 条锁操作计时行（DLCK）但**没有一条真实等待**（无 wait for）："+
			"说明这段时间没有阻塞。注意 `DLCK used time:0(us)` 是常态 —— 它是执行计划里锁节点的自身耗时，不是等待时长。", fmtInt(v.DlckN)))
	case v.Mask29On:
		// 🩸 这一支必须有：位号 29 是**日志的属性**，不是「本次范围内的行数」。
		// 用 -f/-t 过滤出一个小窗口时，窗口内事务事件数天然是 0，
		// 若掉进下面那个 default 就会写出「日志里没有任何事务事件行、请确认掩码是否含 29」——
		// 而同一份报告的锁等待小节刚说过「位号 29 已开」。两句话自相矛盾。
		h = append(h, fmt.Sprintf("位号 29 已开（日志里有 %s 条事务事件），本次范围内**一条锁等待都没有** —— "+
			"这个 0 是可信的「确实没发生」，不是「没采集」。", fmtInt(v.TrxEventN+v.TrxEndN)))
	default:
		h = append(h, "日志里没有任何锁/事务事件行：先确认 sqllog.ini 的 SQL_TRACE_MASK 是否含 29（锁类型与锁等待时间、"+
			"事务起止都归这一位），其次是 sqllog.ini 有没有真正生效（看 V$DM_SQLLOG_CONFIG.MODE_NAME 是否为 <DEFAULT>）；"+
			"两者都正常则说明该时段确实没有锁竞争。")
	}
	if v.LockUnparsed > 0 {
		h = append(h, fmt.Sprintf("有 %s 条锁相关行未能识别（格式与已知的 LOCK_TID 形态不同）："+
			"请挑一条原始行提供给我，补上解析。", fmtInt(v.LockUnparsed)))
	}
	if v.TrxOpenN > 0 {
		h = append(h, fmt.Sprintf("有 %s 个事务只见到 TRX: START、之后没有任何语句或结束事件："+
			"可能是仍未提交的事务（长期持锁的常见原因），也可能是日志刚好在这些事务结束前被截断 —— 需要结合 -x 逐个看。", fmtInt(v.TrxOpenN)))
	}
	if v.TrxFull {
		h = append(h, fmt.Sprintf("识别到的事务数已达上限 %s，长事务统计只覆盖先出现的部分（防止超大日志吃内存）；"+
			"要完整分析请按文件或时间段分批扫描，例如逐个文件跑 -S。", fmtInt(maxTrx)))
	}
	if len(v.Trxs) > 0 && v.Trxs[0].SpanMS >= 10000 {
		h = append(h, fmt.Sprintf("发现长事务：trxid %s 跨度 %s（%s 条语句，%s → %s）。"+
			"单条 SQL 快不代表没问题，长事务会拖住 undo 与锁，可用 -x %s 导出它的全部语句。",
			v.Trxs[0].Trx, fmtDur(v.Trxs[0].SpanMS), fmtInt(v.Trxs[0].Count), v.Trxs[0].First, v.Trxs[0].Last, v.Trxs[0].Trx))
	}
	// ---- 采集配置类提示（先对掩码，再怀疑解析器）----
	if v.ParamsN == 0 && v.Missing > 0 {
		h = append(h, fmt.Sprintf("日志里一行 PARAMS 都没有，但有 %s 条语句带 ? 无法还原 —— "+
			"这是**采集侧**没开参数位（SQL_TRACE_MASK 需含 28），解析器无能为力。先在库上跑 "+
			"SELECT PARA_NAME,PARA_VALUE FROM V$DM_SQLLOG_CONFIG; 核对掩码。", fmtInt(v.Missing)))
	}
	if v.NoExecN > 0 {
		h = append(h, fmt.Sprintf("有 %s 行 SQL 带文本却没有 EXECTIME：这些语句的耗时统计不到"+
			"（现网实测多出现在 DM 自身的维护类语句上，如 create index、update … from 子查询；"+
			"若占比很高则要查掩码 24/25）。报告里的耗时分布只覆盖有耗时的部分。", fmtInt(v.NoExecN)))
	}
	if v.UnitUS > 0 {
		h = append(h, fmt.Sprintf("该库的 EXECTIME 单位是**微秒**（EXECTIME_PREC_FLAG=1，共 %s 行），"+
			"本工具已自动换算成毫秒；与其它毫秒制库的报告可直接横向比较。", fmtInt(v.UnitUS)))
	}
	if v.LockN == 0 && v.DlckN == 0 && v.TrxEventN == 0 {
		h = append(h, "日志里完全没有掩码 29 的产物（锁等待 / 事务事件行）：SQL_TRACE_MASK 需含 29，"+
			"否则长事务、TPS、锁等待都无从分析。")
	}
	if v.LockUnparsed > 0 {
		h = append(h, fmt.Sprintf("有 %s 行含 LOCK_TID 但不符合已知的三种格式 —— 可能是新版本 DM 的"+
			"格式变体，欢迎把它反馈给工具维护方（保留原始行即可）。", fmtInt(v.LockUnparsed)))
	}
	if v.LockCountMis > 0 {
		h = append(h, fmt.Sprintf("%s 条锁等待行里「声明被等事务数」与「实际列出的持有方个数」不一致，"+
			"建议按行号抽查（工具的格式变体告警）。", fmtInt(v.LockCountMis)))
	}
	if v.LockMoreN > 0 {
		h = append(h, fmt.Sprintf("%s 条锁等待行的持有方列表被日志截断（带 ...more），"+
			"报告的持有方只是实际的一部分。", fmtInt(v.LockMoreN)))
	}
	// 长事务利用率：占着事务不干活
	if len(v.Trxs) > 0 {
		worst := -1
		for i := range v.Trxs {
			if v.Trxs[i].SpanMS >= 60000 && (worst < 0 || v.Trxs[i].Util < v.Trxs[worst].Util) {
				worst = i
			}
		}
		if worst >= 0 && v.Trxs[worst].Util < 20 {
			t := v.Trxs[worst]
			h = append(h, fmt.Sprintf("长事务 %s 跨度 %s，但事务内 SQL 只执行了 %s（利用率 %.1f%%）："+
				"典型的「占着事务不干活」—— 大概率是应用侧忘了 commit/rollback 或长时间持锁，"+
				"比单条慢 SQL 更该先处理。用 dmsqlq <同一路径> -x %s -N 看它到底在干什么。",
				t.Trx, fmtDur(t.SpanMS), durOrDash(t.ExecMS), t.Util, t.Trx))
		}
	}
	if v.DangerN > 0 {
		h = append(h, fmt.Sprintf("审计节发现 %s 条高危操作（DROP / TRUNCATE / 无 WHERE 的 DELETE·UPDATE / "+
			"权限变更 / 大批量 DML）。误删或误改后的取证看这一节：时间点、对象、操作人（用户+客户端+线程）、"+
			"影响行数、提交 LSN 都在一张表里；完整语句在配套附件的「4) 审计明细」。", fmtInt(v.DangerN)))
	}
	if v.DangerORA > 0 {
		h = append(h, fmt.Sprintf("其中 %s 条只有 [ORA] 没有执行行 —— 语句已到达服务器并完成语法解析，"+
			"但没看到执行。常见于权限不足、超时、客户端取消、事务被回滚。**「有人试图这么干」本身就是证据**，"+
			"所以这一类也留在清单里（用 dmsqlq <同一路径> -k ORA 可以单独看全部原始语句）。", fmtInt(v.DangerORA)))
	}
	if len(v.DDLVerbs) > 0 && v.DDLVerbs[0].Name == "STAT" {
		h = append(h, fmt.Sprintf("日志里 [DDL] 的绝大多数其实是 **STAT（更新统计信息）**（%s 次，占 DDL 的多数）—— "+
			"它不是业务在改表结构，但往往占掉可观的耗时；排查慢查询时优先把它用 -E STAT,DDL 排除掉，再看真正的业务 SQL。",
			fmtInt(v.DDLVerbs[0].Count)))
	}
	if st.TplFull {
		h = append(h, fmt.Sprintf("语句模板数量超过 %d，仅统计了先出现的部分模板（大数据量下的保护措施）。", maxTpl))
	}

	// ---- 吞吐与时轴（QPS/TPS）----
	// 先看「日志覆盖度」：跨度 7 天但只有 654 秒有事件，说明是零星采集而非连续压测；
	// 此时平均 QPS 与「静默空档」都没有意义，必须先说清楚，
	// 否则会得出荒谬结论（实测某样例：峰值是平均的 9884 倍）。
	coverRatio := 0.0
	if v.SpanSec > 0 {
		coverRatio = float64(v.SecCovered) / v.SpanSec
	}
	if v.SpanSec > 60 && coverRatio < 0.5 {
		cr := coverRatio * 100
		cover := fmt.Sprintf("%.0f%%", cr)
		if cr < 1 { // 0.1% 这类小值不能四舍五入成 "0%"，否则读起来像笔误
			cover = fmt.Sprintf("%.1f%%", cr)
		}
		h = append(h, fmt.Sprintf("日志覆盖稀疏：跨度 %s内只有 %s 秒真正出现过 SQL 事件（约 %s），"+
			"说明是按需开启 SQL 日志或跨多天零星采集 —— 此时「平均 QPS」与「静默空档」参考意义有限，"+
			"请看峰值 QPS、最繁忙的秒与具体时段的语句，不要用这些均值下结论。",
			fmtSpan(v.SpanSec), fmtInt(v.SecCovered), cover))
	} else {
		if v.AvgQPS > 0 && v.PeakQPS >= v.AvgQPS*5 && v.PeakQPS >= 50 {
			h = append(h, fmt.Sprintf("峰值 QPS %s 是平均 %.1f 的 %.1f 倍（峰值出现在 %s）：负载呈尖峰型。"+
				"尖峰压力下最容易出现排队与锁竞争，建议重点看该时段的慢 SQL 与锁等待。",
				fmtNum(v.PeakQPS), v.AvgQPS, v.PeakQPS/v.AvgQPS, v.PeakQPSAt))
		}
		if v.LongestIdle >= 60 {
			h = append(h, fmt.Sprintf("存在 %s 的静默空档（起于 %s）：若业务本不应停顿，需先分清是业务低峰还是**采集中断** ——"+
				"采集中断会让各项统计偏低，容易误判。", fmtDur(v.LongestIdle*1000), v.LongestIdleAt))
		}
	}
	if v.Commits+v.Rollbacks > 0 && v.RollbackPct >= 5 {
		h = append(h, fmt.Sprintf("回滚率 %.2f%%（ROLLBACK %s 次 / 事务结束 %s 次）偏高。若不是业务预期，"+
			"常见原因是应用侧超时重试、唯一键或约束冲突、锁等待超时被回滚 —— 建议与锁等待一节对照看。",
			v.RollbackPct, fmtInt(v.Rollbacks), fmtInt(v.Commits+v.Rollbacks)))
	}
	if v.LockPeakN > 0 && v.LockPeakIsTop {
		h = append(h, fmt.Sprintf("锁等待最密集的那一秒（%s，%d 次等待）正好是 QPS 峰值那一秒："+
			"尖峰负载与锁竞争重合，优先排查那一刻的热点行更新。", v.LockPeakAt, v.LockPeakN))
	}
	if len(v.Tables) > 0 && v.Tables[0].Pct >= 30 {
		t := v.Tables[0]
		tip := "以读为主，看是否缺索引或返回行数过大"
		if t.Writes > t.Reads {
			tip = "以写为主，留意行锁与提交频率"
		}
		h = append(h, fmt.Sprintf("热表集中：%s 占全部执行耗时 %.1f%%（语句 %s 次，读 %s / 写 %s）—— %s。"+
			"下一步用 -l %s -m 500 单独导出它的慢语句。",
			t.Table, t.Pct, fmtInt(t.Count), fmtInt(t.Reads), fmtInt(t.Writes), tip, strings.ToLower(t.Table)))
	}
	return h
}

// recommend 生成「优先优化推荐」清单。
//
// 判据按「影响占比」排序（而非次数或单次耗时）—— 因为优化的目标是
// 让系统整体变快，占比高 = 改它收益最大。
// 这是现场最容易被忽略的一点：最慢的一条 SQL 可能一天只跑 1 次，
// 而一条 200ms 的 SQL 跑了 50 万次，后者才是真正的负载。
func (v *statsView) recommend(limit int) []adviceRow {
	if len(v.Tpls) == 0 {
		return nil
	}
	// 分母 = 全部语句的累计耗时（v.TotalExecMS()，与实际总耗时一致）。
	// 🩸 不能用「v.Tpls 各项之和」：v.Tpls 会被 -p / excelTop 截断，
	// 同一个模板在 HTML（top20 分母）与 Excel（top50 分母）里会算出不同的占比 ——
	// 交付件与自看报告打架，开发商一眼就能看出来。
	totalMS := v.TotalExecMS()
	if totalMS <= 0 {
		return nil
	}
	// 同类中位数耗时 —— 用作「优化后应达到的水平」的保守参照
	medMS := medianSum(v.Tpls)
	var out []adviceRow
	for _, r := range v.Tpls {
		share := r.Sum / totalMS
		prio := "一般"
		switch {
		case share >= 0.10:
			prio = "优先"
		case share >= 0.03:
			prio = "次之"
		}
		sig, act := diagnoseSQL(r, medMS)
		// 🩸 先排除「等锁受害者」（V2.10）：这条语句的累计耗时如果基本就是
		// 某张表上的锁等待，那么它**不是优化对象** —— 单行 INSERT / 等值 UPDATE
		// 本身不慢，去 EXPLAIN 它什么也看不出来。真正的动作在「锁等待」一节：
		// 处理那个长时间持锁的根事务。
		// 排序（占比）保持不动：这份耗时是真实发生的，账要照记；
		// 但优先级标签改成「等锁」，避免把注意力引到 SQL 改写上。
		if ratio, tbl := v.lockVictim(r.Sample, r.Sum); ratio > 0 {
			prio = "等锁"
			sig = "等锁，不是语句本身慢"
			act = fmt.Sprintf("这条累计 %s，其中 **%.0f%%** 是堵在 `%s` 的锁上（该表锁等待累计 %s）—— "+
				"单行/等值访问本身不慢，**改这条 SQL 没有收益，EXPLAIN 也看不出问题**。"+
				"要动的是**持有方**：见「锁等待」一节的阻塞链，处理那个长时间持锁的根事务"+
				"（缩短事务跨度、或把它拆小）；必要时核对 `V$TRXWAIT` / `V$LOCK`。",
				fmtDur(r.Sum), ratio*100, tbl, fmtDur(v.LockSumByName[tbl]))
		}
		out = append(out, adviceRow{
			Prio: prio, Share: share, Count: r.Count,
			Avg: r.Avg, Max: r.Max, Sum: r.Sum, Min: r.Min,
			SaveMS: r.Sum - r.Avg, // 至少能省掉「最慢那条」以外的部分（保守下限）
			Signal: sig, Action: act, Sample: r.Sample,
		})
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	for i := range out {
		out[i].Rank = i + 1
	}
	return out
}

// baseTableName 去掉 schema 前缀与双引号：`"SCH"."T_X"` → `T_X`。
// 用于把「对象映射里给的名字」与「SQL 里出现的表名」对齐 ——
// 两边一个带 schema 一个不带就会配不上，白白漏掉匹配。
func baseTableName(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	}
	return strings.Trim(s, "\"`[]")
}

// stmtMainTable 取语句的「主表」：写语句取写目标表，读语句取第一张 FROM 表。
// 取不到返回空串。用途：把一条语句与「某张表上的锁等待」对上（见 recommend）。
func stmtMainTable(sql string) string {
	op := "SEL"
	switch u := strings.ToUpper(strings.TrimLeft(sql, " \t\r\n(")); {
	case strings.HasPrefix(u, "INSERT"):
		op = "INS"
	case strings.HasPrefix(u, "UPDATE"):
		op = "UPD"
	case strings.HasPrefix(u, "DELETE"):
		op = "DEL"
	case strings.HasPrefix(u, "MERGE"):
		op = "DML"
	}
	var w, anyT string
	eachTable([]byte(sql), op, func(name string, write bool) {
		if name == "" {
			return
		}
		if write && w == "" {
			w = name
		}
		if anyT == "" {
			anyT = name
		}
	})
	if w != "" {
		return w
	}
	return anyT
}

// guideRow 「锁等待排查方向」的一条。设计原则与诊断信号同源：
// **只写日志能证实的事实（Fact）**，推断要标出来（Note），并且每条都给「往哪查」。
type guideRow struct {
	Step  int
	Title string
	Fact  string // 实测事实（来自日志，可直接引用）
	Note  string // 形态推断（有假设，要说清"日志不能证明什么"）
	Next  string // 往哪查 / 怎么查
}

// tsMillis 把 "2026-10-08 09:06:55.428" 解成当天毫秒数（只用于比较先后与间隔）。
// 解析失败返回 -1。
func tsMillis(ts string) int64 {
	if len(ts) < 23 {
		return -1
	}
	// "YYYY-MM-DD HH:MM:SS.mmm" —— 取 11..22 段
	var hh, mm, ss, ms int64
	ok := true
	dig := func(a, b int) int64 {
		v := int64(0)
		for i := a; i < b; i++ {
			c := ts[i]
			if c < '0' || c > '9' {
				ok = false
				return 0
			}
			v = v*10 + int64(c-'0')
		}
		return v
	}
	hh, mm, ss, ms = dig(11, 13), dig(14, 16), dig(17, 19), dig(20, 23)
	if !ok {
		return -1
	}
	return ((hh*60+mm)*60+ss)*1000 + ms
}

// lockGuide 生成「锁等待排查方向」。
//
// 🩸 为什么要有这一节（V2.11，现场提问）：报告把根事务的**结局**（提交/回滚）都列出来了，
// 读者下一句必然问「**全是回滚，那我往哪儿查？**」。这些信息分散在几十张卡片里，
// 读者得自己横着看才能拼出结论 —— 那是报告该替他做的事。
//
// 本节的规矩：**每一步先给"日志能证实的事实"，再给"怎么读"，最后给"往哪查"**；
// 形态推断单独标出并写明「日志不能证明什么」—— 不替读者下没有依据的结论。
// lockGuide 生成「锁等待排查方向」。
//
// 🩸 为什么要有这一节（V2.11，现场提问）：报告把根事务的**结局**（提交/回滚）都列出来了，
// 读者下一句必然问「**全是回滚，那我往哪儿查？**」。这些信息分散在几十张卡片里，
// 读者得自己横着看才能拼出结论 —— 那是报告该替他做的事。
//
// 本节的规矩：**每一步先给「日志能证实的事实」，再给「怎么读」，最后给「往哪查」**；
// 形态推断单独标出并写明「日志不能证明什么」—— 不替读者下没有依据的结论。
func (v *statsView) lockGuide() []guideRow {
	if len(v.LockRowsAll) == 0 {
		return nil
	}
	// 根事务（链首）去重
	type rootInfo struct {
		kind string
		end  string
	}
	roots := map[string]*rootInfo{}
	for i := range v.LockRowsAll {
		r := &v.LockRowsAll[i]
		root := r.HolderRoot
		if root == "" {
			continue
		}
		if _, ok := roots[root]; !ok {
			roots[root] = &rootInfo{kind: r.HolderKind, end: r.HolderEndTS}
		}
	}
	if len(roots) == 0 {
		return nil
	}
	nRoll, nCommit, nNone := 0, 0, 0
	for _, ri := range roots {
		switch ri.kind {
		case "ROLLBACK":
			nRoll++
		case "COMMIT":
			nCommit++
		default:
			nNone++
		}
	}

	var out []guideRow
	step := 0
	add := func(title, fact, note, next string) {
		step++
		out = append(out, guideRow{Step: step, Title: title, Fact: fact, Note: note, Next: next})
	}

	// ---- 第 1 步：结局分布 ----
	noneTail := ""
	if nNone > 0 {
		noneTail = fmt.Sprintf(" / 日志里未见结束 %d", nNone)
	}
	fact1 := fmt.Sprintf("根事务共 %d 个：**回滚 %d / 提交 %d**%s。", len(roots), nRoll, nCommit, noneTail)
	note1 := "回滚通常意味着「这一批业务没做成」。但**日志只能告诉你它回滚了，不能告诉你为什么回滚**" +
		" —— 可能是应用主动回滚（业务校验不通过），也可能是被中止（批次超时 / 任务被取消 / 连接被断）。"
	next1 := "如果回滚占多数，下一步看**回滚时刻**（见下一步），而不是急着去改 SQL。"
	add("先看根事务的结局分布", fact1, note1, next1)

	// ---- 第 2 步：回滚时刻是否成簇（本节最有信息量的一条）----
	type tsPair struct {
		ms int64
		ts string
	}
	var rb []tsPair
	for _, ri := range roots {
		if ri.kind != "ROLLBACK" || ri.end == "" {
			continue
		}
		if ms := tsMillis(ri.end); ms >= 0 {
			rb = append(rb, tsPair{ms: ms, ts: ri.end})
		}
	}
	if len(rb) >= 2 {
		sort.Slice(rb, func(i, j int) bool { return rb[i].ms < rb[j].ms })
		const win = 3000 // 3 秒窗口
		best, bestI := 0, 0
		for i := 0; i < len(rb); i++ {
			j := i
			for j+1 < len(rb) && rb[j+1].ms-rb[i].ms <= win {
				j++
			}
			if n := j - i + 1; n > best {
				best, bestI = n, i
			}
		}
		if best >= 2 {
			ratio := float64(best) / float64(len(rb))
			span := v.lockGuideSpan(rb[bestI].ts, rb[bestI+best-1].ts)
			fact2 := fmt.Sprintf("**%d 个根事务在 %s内集中回滚**（%s ~ %s，占全部回滚根事务的 %.0f%%）。",
				best, span, shortTS(rb[bestI].ts), shortTS(rb[bestI+best-1].ts), ratio*100)
			note2 := ""
			if best >= 3 && ratio >= 0.5 {
				note2 = "形态上更像**一次协调性中止**（应用决定整体回滚），而不是偶发失败 —— " +
					"但**这只是形态推断**：日志能证明的是「同一时刻集中回滚」，**证明不了原因**，" +
					"原因必须去应用侧确认。"
			}
			next2 := "**先去应用日志找这个时刻前后发生了什么**：批次超时？任务被取消？连接被断？" +
				"集中回滚更符合「应用侧一次性把这一批全部回滚」，而不是各事务自己失败。"
			add("再看回滚时刻是不是成簇（这一条最有用）", fact2, note2, next2)
		}
	}

	// ---- 第 3 步：是不是多个会话在做同一件事 ----
	tplCnt := map[string]int{}
	for i := range v.LockRowsAll {
		if s := v.LockRowsAll[i].WaiterSQL; s != "" {
			tplCnt[normalizeTpl(s)]++
		}
	}
	topTpl, topN := "", 0
	for t, n := range tplCnt {
		if n > topN {
			topTpl, topN = t, n
		}
	}
	if topN >= 3 {
		fact3 := fmt.Sprintf("等待方执行得最多的一条语句出现了 **%d 次**：`%s`；根事务分布在 **%d 个不同的事务**上。",
			topN, clipCell(topTpl, 110), len(roots))
		note3 := "多个会话反复执行同一条语句、落在同一批表上，像是**同一个批次被并发执行**。" +
			"但要区分「抢同一张表」和「抢同一个业务键」—— 日志里的语句模板一样，" +
			"**不代表参数（业务键）一样**。"
		next3 := "用 `dmsqlq <同一路径> -x <根事务号> -N` 导出几个根事务，**比对它们的参数值是否相同**。" +
			"若相同 ⇒ 并发批次在抢同一业务范围，查应用侧的批次拆分/分片逻辑；" +
			"若不同 ⇒ 只是表级热点，考虑缩短事务或调整并发度。"
		add("确认是不是多个会话在做同一件事", fact3, note3, next3)
	}

	// ---- 第 4 步：根事务为什么能持锁这么久 ----
	longMS := int64(0)
	longRoot, longTbl := "", ""
	missRoot := 0
	for i := range v.LockRowsAll {
		r := &v.LockRowsAll[i]
		if r.HolderRoot == "" {
			continue
		}
		if r.MS > float64(longMS) {
			longMS, longRoot, longTbl = int64(r.MS), r.HolderRoot, r.Table
		}
		if len(r.HolderStmts) == 0 {
			missRoot++
		}
	}
	if longMS > 0 {
		fact4 := fmt.Sprintf("最长一次等待 **%s**（根事务 `%s`，表 %s）；全部 %d 次等待里有 **%d 次**的持有方在日志里拿不到语句文本。",
			fmtDur(float64(longMS)), longRoot, dash(longTbl), len(v.LockRowsAll), missRoot)
		note4 := "持锁时间 = 根事务那条语句的执行时间。持有方 SQL 缺失**不等于「没执行」** —— " +
			"实测（133 构造实验）**最常见的原因是「语句执行很快、执行完成行被采集侧的 `MIN_EXEC_TIME` 滤掉了」**" +
			"（这类事务的 `TRX: START`、`PARAMS`、段页分配都在，唯独没有 SQL 文本）；" +
			"次因是「语句执行中被中止」。**两者都不是采集位没开全。**"
		next4 := "① 若采集掩码含**位 27（原始语句）**，本工具已把 `[ORA]` 行里的 SQL 自动找回来（见上方持有方明细，会标出来源）；" +
			"② 否则复现时把 `MIN_EXEC_TIME` 调小，或直接到库上抓现场（下一步）。"
		add("看根事务为什么能持锁这么久", fact4, note4, next4)
	}

	// ---- 第 5 步：库上抓现场 ----
	fact5 := "日志是事后回溯，**看不到当时在等什么内部资源**。"
	note5 := "SQL 日志只记「谁等谁的锁」，不记 latch、I/O 这类内部等待。"
	next5 := "```sql\nSELECT * FROM V$TRXWAIT;\nSELECT SESS_ID, SQL_TEXT, TRX_ID, STATE FROM V$SESSIONS WHERE STATE = 'ACTIVE';\n```\n" +
		"在锁等待发生期间反复抓这几个视图；另可让采集侧加**掩码位 27**（记原始语句，不受 `MIN_EXEC_TIME` 限制，代价小），" +
		"或临时把 `MIN_EXEC_TIME` 调小（代价大：日志量会涨）。"
	add("下次复现时在库上抓现场", fact5, note5, next5)

	return out
}

// lockGuideSpan 把两个时间戳的间隔描述成人话（"3 秒内" / "40 毫秒内"）。
func (v *statsView) lockGuideSpan(a, b string) string {
	d := tsMillis(b) - tsMillis(a)
	if d <= 0 {
		return "同一时刻"
	}
	return fmtDur(float64(d))
}

// normalizeTpl 归一化语句模板：去掉字面量与数字，便于把"同一条语句"聚到一起。
// 只用于「出现次数」这类形态统计，不用于任何需要精确值的场合。
func normalizeTpl(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inStr := false
	prevNum := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\'' {
			inStr = !inStr
			if !prevNum {
				b.WriteByte('?')
				prevNum = true
			}
			continue
		}
		if inStr {
			continue
		}
		if c >= '0' && c <= '9' {
			if !prevNum {
				b.WriteByte('?')
				prevNum = true
			}
			continue
		}
		prevNum = false
		b.WriteByte(c)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// lockVictim 判断一条语句模板是不是「等锁受害者」：它的累计耗时里有多大比例
// 其实是**堵在锁上**。
//
// 🩸 为什么必须做这件事（V2.10，现场反馈）：报告把
// `INSERT INTO T_IM_INV_PER_BAL_KL (FKEYCOL) VALUES (?)` 排在「优先优化」第 1 位
// （28 次 / 累计 8.4min / 最快 500ms / 平均 18s），并建议「抓最快与最慢各跑一次
// EXPLAIN 对比扫描方式」。用户直接质疑：**单行 INSERT 有什么可优化的？**
// 用日志自身一对账就清楚了：
//   - 该模板累计耗时 **505.0 s**
//   - 该表（76196）上的锁等待累计 **505.0 s** —— **占比 100.0%**
//   - 逐事务核对，等锁耗时与语句耗时**差值 0.00**（25.84 vs 25.84 …）
//
// 也就是说那 18 秒平均耗时**几乎全是等 X 锁**，语句本身是主键单行插入、快得不能再快。
// 去 EXPLAIN 它什么也看不出来 —— **误报比不报更坏**：会让人去改没问题的写法。
//
// 判据：同表锁等待累计 ÷ 本模板累计耗时 ≥ 60% 即认定。
// 返回 (比例, 命中表名)；不是受害者返回 (0, "")。
func (v *statsView) lockVictim(sql string, sumMS float64) (float64, string) {
	if sumMS <= 0 || len(v.LockSumByName) == 0 {
		return 0, ""
	}
	tbl := stmtMainTable(sql)
	if tbl == "" {
		return 0, ""
	}
	key := strings.ToUpper(baseTableName(tbl))
	lsum, ok := v.LockSumByName[key]
	if !ok || lsum <= 0 {
		return 0, ""
	}
	r := lsum / sumMS
	if r > 1 {
		r = 1 // 一次等待可能牵连多条语句，比值封顶
	}
	if r < 0.6 {
		return 0, ""
	}
	return r, key
}

// adviseCoverPct 推荐清单覆盖的耗时占比（回答"照这个清单改，收益上限是多少"）
func adviceCoverPct(as []adviceRow) float64 {
	var s float64
	for _, a := range as {
		s += a.Share
	}
	if s > 1 {
		s = 1
	}
	return s * 100
}

// primarySignal 取信号的主动部分（分号之前）——终端列窄，只显示主要判据；
// 「；外层分页…」这类补充说明留在报告里，不占用终端宽度。
func primarySignal(s string) string {
	if i := strings.Index(s, "；"); i > 0 {
		return s[:i]
	}
	return s
}

// medianSum 求各模板累计耗时的中位数（用于「优化后能到多少」的参照）
func medianSum(rs []tplRow) float64 {
	if len(rs) == 0 {
		return 0
	}
	xs := make([]float64, 0, len(rs))
	for _, r := range rs {
		if r.Avg > 0 {
			xs = append(xs, r.Avg)
		}
	}
	if len(xs) == 0 {
		return 0
	}
	sort.Float64s(xs)
	return xs[len(xs)/2]
}

// diagnoseSQL 据语句特征给出「问题信号 + 建议动作」。
//
// 只看能从日志本身确证的特征 —— 不做没有依据的猜测（比如不能断言"缺索引"，
// 只能说"全表扫描特征明显，建议 EXPLAIN 确认"）。
// ---------------------------------------------------------------- 语句形态诊断
//
// 原则：只看**语句文本本身能确证的事实** —— 不猜索引、不猜数据分布。
// 这里只回答「它为什么慢」；排序由影响占比（累计耗时）决定，信号不参与排序。
//
// 🩸 V2.5 修（现场反馈的实际误报）：
// 最初判据是 `strings.Contains(up, "SELECT *")` 就报「取全字段」，
// 但现网 TOP 模板全是这种形态：
//
//	SELECT * FROM (SELECT TOP 0, 11000 <明确列清单> FROM ... ORDER BY ...) WHERE ROWNUM <= 11000
//
// 这是 DM 的双层分页惯用法 —— 星号在**外层包装**上，内层列写得清清楚楚
// （实测有个模板内层只取 3 列）。所以必须先剥包装再诊断，
// 并把这类 workload 真正的问题补上：超长 IN 列表、单次取数过大、运行时动态 DDL。

// isIdentChar SQL 标识符字符（关键字边界判定用）
func isIdentChar(c byte) bool {
	return c == '_' || c == '$' || c == '#' ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// topLevelKeyword 从 s[start:] 找括号深度 0、且不在单引号内的关键字 kw，返回下标；-1 未找到。
// 必须跟踪括号与引号：否则子查询里的 FROM 会被误当成主 FROM。
func topLevelKeyword(s string, start int, kw string) int {
	depth, inStr, n := 0, false, len(kw)
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inStr = false
			}
			continue
		}
		switch c {
		case '\'':
			inStr = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && i+n <= len(s) && strings.EqualFold(s[i:i+n], kw) {
				prevOK := i == 0 || !isIdentChar(s[i-1])
				nxt := i + n
				nextOK := nxt >= len(s) || !isIdentChar(s[nxt])
				if prevOK && nextOK {
					return i
				}
			}
		}
	}
	return -1
}

// matchParen 返回 s[open]（须为 '('）对应的右括号下标；-1 表示不匹配。
func matchParen(s string, open int) int {
	depth, inStr := 0, false
	for i := open; i < len(s); i++ {
		c := s[i]
		if inStr {
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inStr = false
			}
			continue
		}
		switch c {
		case '\'':
			inStr = true
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// selectListIsStar 选择列表是否就是 `*`（允许 TOP n / TOP n,m / DISTINCT / ALL 前缀）
func selectListIsStar(t string) bool {
	t = strings.TrimSpace(t)
	for {
		u := strings.ToUpper(t)
		switch {
		case strings.HasPrefix(u, "DISTINCT"):
			t = strings.TrimSpace(t[8:])
		case strings.HasPrefix(u, "ALL") && (len(u) == 3 || !isIdentChar(u[3])):
			t = strings.TrimSpace(t[3:])
		case strings.HasPrefix(u, "TOP") && (len(u) == 3 || !isIdentChar(u[3])):
			rest := strings.TrimSpace(t[3:])
			if strings.HasPrefix(rest, "(") {
				c := matchParen(rest, 0)
				if c < 0 {
					return false
				}
				rest = strings.TrimSpace(rest[c+1:])
			} else {
				k := 0
				for k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
					k++
				}
				if k < len(rest) && rest[k] == ',' { // TOP offset, count
					k++
					for k < len(rest) && (rest[k] == ' ' || rest[k] == '\t') {
						k++
					}
					for k < len(rest) && rest[k] >= '0' && rest[k] <= '9' {
						k++
					}
				}
				rest = strings.TrimSpace(rest[k:])
			}
			t = rest
		default:
			return t == "*"
		}
	}
}

// peelWrapper 剥掉 `SELECT * FROM ( ... ) [WHERE ROWNUM <= n]` 这类包装层，
// 返回内层查询与包装说明。不是该形态时返回 ("", "")。
func peelWrapper(sql string) (inner, note string) {
	s := strings.TrimSpace(sql)
	if len(s) < 7 || !strings.EqualFold(s[:6], "SELECT") {
		return "", ""
	}
	frm := topLevelKeyword(s, 6, "FROM")
	if frm < 0 || !selectListIsStar(s[6:frm]) {
		return "", ""
	}
	j := frm + 4
	for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
		j++
	}
	if j >= len(s) || s[j] != '(' {
		return "", ""
	}
	close := matchParen(s, j)
	if close < 0 {
		return "", ""
	}
	tail := strings.TrimSpace(s[close+1:])
	if strings.Contains(strings.ToUpper(tail), "ROWNUM") {
		note = "外层分页（ROWNUM 截断）"
	} else {
		note = "子查询包装"
	}
	return strings.TrimSpace(s[j+1 : close]), note
}

var (
	reRownumCap = regexp.MustCompile(`(?i)\bROWNUM\s*<=\s*(\d+)`)
	reTopCap    = regexp.MustCompile(`(?i)\bTOP\s*\(?\s*(?:\d+\s*,\s*)?(\d+)\s*\)?`)
	reLimitCap  = regexp.MustCompile(`(?i)\bLIMIT\s+(?:\d+\s*,\s*)?(\d+)`)
)

// maxFetchRows 估算单次取数规模（TOP n / TOP offset,n / ROWNUM <= n / LIMIT n 的最大值）
func maxFetchRows(s string) int {
	best := 0
	for _, rx := range []*regexp.Regexp{reRownumCap, reTopCap, reLimitCap} {
		for _, m := range rx.FindAllStringSubmatch(s, -1) {
			if v, err := strconv.Atoi(m[1]); err == nil && v > best {
				best = v
			}
		}
	}
	return best
}

// maxINList 语句中最长 `IN (...)` 列表的元素个数（顶层逗号计数）。
//
// 现网常见把上千个 ID 直接拼进 IN：优化器要为每个值估算代价、生成巨大的执行计划，
// 还可能因选择性判断失真而放弃索引。实测有个模板拼了 999 个字面量、单条 SQL 49KB ——
// DM 的 IN 上限常是 1000，应用就卡在 999 这个边界上。
func maxINList(s string) int {
	up := strings.ToUpper(s)
	best := 0
	for i := 0; ; {
		p := strings.Index(up[i:], "IN")
		if p < 0 {
			break
		}
		i += p + 2
		if i >= 3 && isIdentChar(s[i-3]) { // 排除 POINT / INNER 之类
			continue
		}
		j := i
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
			j++
		}
		if j >= len(s) || s[j] != '(' {
			continue
		}
		c := matchParen(s, j)
		if c < 0 {
			continue
		}
		body := s[j+1 : c]
		n, depth, inStr := 1, 0, false
		for k := 0; k < len(body); k++ {
			ch := body[k]
			if inStr {
				if ch == '\'' {
					if k+1 < len(body) && body[k+1] == '\'' {
						k++
						continue
					}
					inStr = false
				}
				continue
			}
			switch ch {
			case '\'':
				inStr = true
			case '(':
				depth++
			case ')':
				depth--
			case ',':
				if depth == 0 {
					n++
				}
			}
		}
		if n > best {
			best = n
		}
	}
	return best
}

// dynamicDDL 识别脚本里动态执行 DDL。现网常见：先查数据字典判断索引是否存在，
// 再 EXECUTE IMMEDIATE 建索引 —— 每次调用都要跑一遍字典查询与建对象，
// 高并发下会争抢字典锁、拖慢所有会话。实测有个模板这样跑了 17,613 次。
func dynamicDDL(s string) string {
	up := strings.ToUpper(s)
	if !strings.Contains(up, "EXECUTE IMMEDIATE") {
		return ""
	}
	for _, kv := range []struct{ key, label string }{
		{"CREATE UNIQUE INDEX", "运行时建唯一索引"},
		{"CREATE INDEX", "运行时建索引"},
		{"CREATE TABLE", "运行时建表"},
		{"CREATE SEQUENCE", "运行时建序列"},
		{"ALTER TABLE", "运行时改表结构"},
		{"TRUNCATE", "运行时清空表"},
		{"DROP ", "运行时删对象"},
		{"DBMS_STATS", "运行时收集统计信息"},
		{"ANALYZE", "运行时收集统计信息"},
	} {
		if strings.Contains(up, kv.key) {
			return kv.label
		}
	}
	return "运行时动态 DDL"
}

// baseTableStar 判断 `SELECT *` 是否直接打在**基表**上（而非子查询包装）。
// 🩸 这就是 V2.5 修的误报点：`SELECT * FROM (SELECT 明确列 FROM t)` 的星号只是包装。
func baseTableStar(sql string) bool {
	s := strings.TrimSpace(sql)
	if len(s) < 7 || !strings.EqualFold(s[:6], "SELECT") {
		return false
	}
	frm := topLevelKeyword(s, 6, "FROM")
	if frm < 0 || !selectListIsStar(s[6:frm]) {
		return false
	}
	j := frm + 4
	for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\r' || s[j] == '\n') {
		j++
	}
	return j < len(s) && s[j] != '('
}

// shapeSignal 只据语句形态给信号；无确证特征时返回 ("", "")
func shapeSignal(sql string) (signal, action string) {
	if d := dynamicDDL(sql); d != "" {
		return d, "脚本里运行时执行 DDL：每次调用都要跑一遍字典查询再建对象，高并发下会争抢字典锁、" +
			"拖慢所有会话。应在部署期一次性建好，而不是运行时反复判断"
	}
	if n := maxINList(sql); n >= 100 {
		return fmt.Sprintf("超长 IN 列表（%s 个字面量）", fmtInt(int64(n))),
			"IN 值过多会让优化器逐个估算代价、生成巨大的执行计划，还可能因选择性判断失真而放弃索引；" +
				"语句文本也随之膨胀（实测到 49 KB）。改为批量 JOIN 临时表，或把列表拆成多批"
	}
	if f := maxFetchRows(sql); f >= 5000 {
		return fmt.Sprintf("单次取数过大（约 %s 行）", fmtInt(int64(f))),
			"一次拉这么多行，网络传输与客户端处理都是成本。确认业务是否真需要全量；" +
				"分页场景应只取当前页，而不是每次把整个结果集取回来"
	}
	if baseTableStar(sql) {
		return "SELECT * 取全字段（直接查基表）",
			"多取了用不到的列，增加回表与网络传输。建议只取需要的列 —— 覆盖索引时才可能免回表"
	}
	up := strings.ToUpper(sql)
	if strings.HasPrefix(strings.TrimSpace(up), "SELECT") && !strings.Contains(up, "WHERE") {
		return "疑似全表扫描（无 WHERE 条件）",
			"语句本身没有过滤条件，必然读全表。确认是否真需要全量（可分页/加时间范围），" +
				"或该查询应改为走索引的等值/范围条件"
	}
	if strings.Contains(up, "LIKE '%") {
		return "前导通配 LIKE（索引失效特征）",
			"`LIKE '%xxx'` 无法使用 B 树索引。改用后缀匹配、全文检索，或把条件反转（存反转串建索引）"
	}
	if len(sql) >= 8192 {
		return fmt.Sprintf("语句文本过长（%s）", fmtSize(int64(len(sql)))),
			"超长语句的解析与网络传输本身就有成本。常见成因是 IN 列表或 OR 条件堆积 —— " +
				"先按上面的信号处理；确需超长条件时考虑改用临时表传参"
	}
	return "", ""
}

// diagnoseSQL 给出「问题信号 + 建议动作」。
//
// 排序依据是影响占比（＝累计耗时占比），这里只回答「它为什么慢」，不参与排序。
func diagnoseSQL(r tplRow, medAvg float64) (signal, action string) {
	raw := strings.TrimSpace(r.Sample)
	inner, wrapNote := peelWrapper(raw)
	target := raw
	if inner != "" {
		target = inner
	}
	// 形态信号优先（它给出的是具体的、可改的东西），但若同时存在极大波动，
	// 要把波动一并说出来 —— 否则读者会以为"改掉写法就够了"，
	// 而实际上"时快时慢"往往另有原因（计划突变/数据倾斜/偶发锁等待）。
	volatileNote := ""
	if r.Min > 0 && r.Avg >= r.Min*10 && r.Avg >= 200 {
		volatileNote = fmt.Sprintf("；同时波动极大（最快 %s / 平均 %s），"+
			"多半还有计划或数据分布问题，别只看写法", fmtDur(r.Min), fmtDur(r.Avg))
	}
	join := func(sig string) string {
		if wrapNote != "" {
			sig += "；" + wrapNote
		}
		return sig + volatileNote
	}
	if sig, act := shapeSignal(target); sig != "" {
		return join(sig), act
	}
	if target != raw { // 剥过包装时，原始语句本身也可能带信号
		if sig, act := shapeSignal(raw); sig != "" {
			return join(sig), act
		}
	}

	// ---- 形态无特征，看耗时形态 ----
	switch {
	case r.Min > 0 && r.Avg >= r.Min*10 && r.Avg >= 200:
		// 最快与平均差一个数量级以上 —— 优化方向与「稳定慢」完全不同，
		// 所以排在其它耗时形态之前。
		return fmt.Sprintf("快慢差异极大（最快 %s / 平均 %s）", fmtDur(r.Min), fmtDur(r.Avg)),
			"同一条语句最快只要 " + fmtDur(r.Min) + "，平均却是 " + fmtDur(r.Avg) +
				" —— 说明计划或数据分布不稳定，**不是单纯缺索引**。常见成因：绑定变量窥探导致计划突变、" +
				"数据倾斜（不同参数命中不同数据量）、或其中几次正好撞上锁等待。" +
				"分别抓最快与最慢那次的完整语句，各跑一次 EXPLAIN 对比，差异通常在扫描方式上"
	case r.Count >= 100000 && r.Avg < 50:
		return "高频轻量（次数极多、单次很快）",
			"看似无害，但累计耗时高。优先考虑：批量合并 / 应用层缓存 / 减少往返，而不是改 SQL 本身"
	case r.Max >= 10000 && r.Max >= r.Avg*20:
		return "偶发极慢（最大值远超平均，存在长尾）",
			"典型是数据量增长后计划突变或锁等待。建议：抓最大值那条的完整语句 EXPLAIN，并核对是否偶发全表扫描"
	case r.Avg >= 1000:
		return "单次即慢（平均超过 1 秒）",
			"直接优化：EXPLAIN 看是否走索引、是否有大量回表；确认 WHERE 条件列可加索引"
	case r.Avg >= medAvg*3 && r.Avg >= 100:
		return "显著慢于同类（平均是其他模板的 3 倍以上）",
			"对比同类快语句的写法差异，通常能找到索引或写法问题"
	}
	return "耗时偏高但特征不突出", "按累计耗时排序优先处理；先 EXPLAIN 定位"
}

// qpsUnderReported QPS 是否被严重低估。
//
// 🩸 现场问题（用户指出）：报告显示平均 QPS 1.6 条/秒，但 TPS 有 499 事务/秒 ——
// 同一个库不可能"每秒提交 500 个事务却只执行 1.6 条 SQL"。查下去发现：
// 这份日志里 SQL 执行行只有 473 条，而 COMMIT 行有 38,670 条、PARAMS 行 407 万条
// （单个预编译句柄就对应 5.3 万条 PARAMS）。也就是 SQL 语句文本在日志里的记录密度极低。
//
// 所以 QPS ≠ 业务吞吐，它只是"日志里记到的语句数"。两者口径不同、覆盖度差两个数量级，
// **不能横向比**。命中这个条件时报告要明说，否则读者会以为系统很闲。
func (v *statsView) qpsUnderReported() bool {
	trxEnd := v.Commits + v.Rollbacks
	return v.Exec > 0 && trxEnd > v.Exec*20
}

// trxPerSQL 平均每记录 1 条 SQL 就伴随多少条事务结束事件（用于告警文案）
func (v *statsView) trxPerSQL() float64 {
	if v.Exec <= 0 {
		return 0
	}
	return float64(v.Commits+v.Rollbacks) / float64(v.Exec)
}

func (v *statsView) HistTotal() int64 {
	var n int64
	for _, x := range v.Hist {
		n += x
	}
	return n
}

func (v *statsView) TotalExecMS() float64 {
	var s float64
	for _, r := range v.OpRows {
		s += r.Sum
	}
	return s
}

// spanText 日志时段的一行文字：「起 → 止（跨度 X）」。
// 报告头部要一眼看到"这份统计覆盖哪段时间"，所以四个渲染器统一走这里，
// 免得四处各写一遍格式、还都忘了处理"没采到时间戳"的情况。
func spanText(v *statsView) string {
	if v.SpanFirst == "" && v.SpanLast == "" {
		return "（日志里没有可识别的时间戳，给不出时段）"
	}
	if v.SpanSec > 0 {
		return fmt.Sprintf("%s → %s（跨度 %s）", v.SpanFirst, v.SpanLast, fmtSpan(v.SpanSec))
	}
	if v.SpanFirst == "" || v.SpanLast == "" {
		return nz(v.SpanFirst) + " → " + nz(v.SpanLast)
	}
	return v.SpanFirst + " → " + v.SpanLast
}

// renderStatsBrief -s 在终端的简要版：只给"扫一眼就知道要不要深看"的关键指标，
// 详细内容引导去看 HTML 报告。
//
// 为什么要做这一版：-s 会自动生成 HTML 报告（那才是核心产物），
// 若终端再把十五节全文刷一遍，既淹没真正要看的那行"报告路径"，也没人会在终端读条形图。
// 想完整看文本版 → 用 -r 报告.txt；想只看终端 → 用 -S。
func renderStatsBrief(w io.Writer, v *statsView, reportPath string) {
	fmt.Fprintf(w, "\ndmsqlq %s 统计结果   %s\n", ver, time.Now().Format("2006-01-02 15:04:05"))
	// 结论先行：终端第一屏先给"该看什么"，再给基础数字
	if v.Headline != "" {
		fmt.Fprintf(w, "  ★ %s\n", v.Headline)
	}
	if !v.Mask29On {
		fmt.Fprintln(w, "  ⚠ 采集缺口：本批日志没有事务/锁事件行（TRX: / DLCK / LOCK_TID 全为 0），"+
			"SQL_TRACE_MASK 缺 29")
		fmt.Fprintln(w, "    → 「锁等待」「长事务」「TPS」是没采集到，不是没发生")
	}
	kv := func(k, val string) { fmt.Fprintf(w, "  %s %s\n", pad(k, 12), val) }
	kv("日志记录", fmt.Sprintf("%s 条", fmtInt(v.Records)))
	kv("命中语句", fmt.Sprintf("%s 条", fmtInt(v.Out)))
	kv("参数还原", fmt.Sprintf("%.2f%%（%s 成功 / %s 待还原）", v.RestorePct, fmtInt(v.Matched), fmtInt(v.Missing)))
	if v.SpanFirst != "" {
		kv("日志时段", spanText(v))
	}
	kv("性能", fmt.Sprintf("%v → %.0f MB/s", v.Elapsed.Round(time.Millisecond),
		v.MBf/maxF(v.Elapsed.Seconds(), 0.001)))

	fmt.Fprintln(w)
	// 最该被一眼看到的三件事：慢在哪、有没有锁、有没有危险操作
	var hot []string
	if t := v.HistTotal(); t > 0 {
		hot = append(hot, fmt.Sprintf("耗时 P50 %s / P95 %s / P99 %s / 最大 %s",
			fmtDur(v.P50), fmtDur(v.P95), fmtDur(v.P99), fmtDur(v.DurMax)))
	}
	if len(v.OpRows) > 0 {
		// 耗时占比最高的类型 —— 优化收益最大的地方
		best := v.OpRows[0]
		for _, r := range v.OpRows {
			if r.SumPct > best.SumPct {
				best = r
			}
		}
		if best.Sum > 0 {
			hot = append(hot, fmt.Sprintf("最耗时类型 %s（%s，占 %.1f%% 耗时）",
				best.Op, fmtDur(best.Sum), best.SumPct))
		}
	}
	if v.Commits+v.Rollbacks > 0 {
		hot = append(hot, fmt.Sprintf("回滚率 %.2f%%（COMMIT %s / ROLLBACK %s）",
			v.RollbackPct, fmtInt(v.Commits), fmtInt(v.Rollbacks)))
	}
	if v.LockN > 0 {
		hot = append(hot, fmt.Sprintf("锁等待 %s 次 / 累计 %s / 最长 %s",
			fmtInt(v.LockN), fmtDur(v.LockSumMS), fmtDur(v.LockMaxMS)))
	}
	if v.DangerN > 0 {
		extra := ""
		if v.DangerORA > 0 {
			extra = fmt.Sprintf("，其中 %s 条仅解析未执行", fmtInt(v.DangerORA))
		}
		hot = append(hot, fmt.Sprintf("⚠ 高危操作 %s 条%s（DROP/TRUNCATE/无 WHERE 的 DML/权限变更）",
			fmtInt(v.DangerN), extra))
	}
	if v.Slow[0].MS > 0 && len(v.Slow) > 0 {
		r := v.Slow[0]
		hot = append(hot, fmt.Sprintf("最慢一条 %s（%s %s @ %s）",
			fmtDur(r.MS), r.Op, r.User, shortTS(r.TS)))
	}
	for _, h := range hot {
		fmt.Fprintf(w, "  · %s\n", h)
	}

	// 时间窗口：非空时要显眼 —— 它决定统计范围
	if v.WindowDesc != "" {
		fmt.Fprintf(w, "\n  ★ 统计时间窗口 %s（窗口外 %s 条语句未计入统计）\n",
			v.WindowDesc, fmtInt(v.WinSkipped))
	}

	// 优先优化推荐 Top3：终端只给「先改哪条、占比多少」，明细与完整语句进报告。
	// 占比是排优先级的依据 —— 一条 200ms 的语句跑 50 万次，比跑 1 次的最慢语句更值得改。
	if n := len(v.Advice); n > 0 {
		if n > 3 {
			n = 3
		}
		fmt.Fprintf(w, "\n  优先优化推荐 TOP%d（按影响占比排序，完整 %d 条见报告）\n",
			n, len(v.Advice))
		fmt.Fprintf(w, "  %s %s %s %s %s %s\n",
			pad("#", 3), pad("优先级", 6), pad("影响占比", 9), pad("次数", 10),
			pad("平均", 9), "问题信号")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 88))
		for i := 0; i < n; i++ {
			a := v.Advice[i]
			fmt.Fprintf(w, "  %s %s %s %s %s %s\n",
				pad(strconv.Itoa(i+1), 3), pad(a.Prio, 6),
				pad(fmt.Sprintf("%.1f%%", a.Share*100), 9), pad(fmtInt(a.Count), 10),
				pad(fmtDur(a.Avg), 9), clip(primarySignal(a.Signal), 34))
		}
		fmt.Fprintf(w, "  （本清单覆盖本次总耗时的 %.1f%%）\n", adviceCoverPct(v.Advice))
	}

	// 最慢语句 TOP5：终端的精简版要给出能直接截图反馈的干货，
	// 而不是只给几个指标（对齐 dmmem-go 的「精短结论 + TOP5 表格，适合截图」）。
	// 完整 TopN 与可展开的 SQL 在 HTML 报告里。
	if n := len(v.Slow); n > 0 {
		if n > 5 {
			n = 5
		}
		fmt.Fprintf(w, "\n  最慢语句 TOP%d\n", n)
		fmt.Fprintf(w, "  %s %s %s %s %s\n",
			pad("#", 3), pad("耗时", 9), pad("类型", 5), pad("用户", 12), "语句（摘要）")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 88))
		for i := 0; i < n; i++ {
			r := v.Slow[i]
			fmt.Fprintf(w, "  %s %s %s %s %s\n",
				pad(strconv.Itoa(i+1), 3), pad(fmtDur(r.MS), 9), pad(r.Op, 5),
				pad(clip(r.User, 12), 12), clip(briefOf(r.SQL, 62), 62))
		}
	}

	if reportPath != "" {
		if strings.HasSuffix(strings.ToLower(reportPath), ".xlsx") {
			fmt.Fprintf(w, "\n  ▸ Excel 交付件（多张工作表，可直接发给开发商）：\n    %s\n", reportPath)
		} else {
			fmt.Fprintf(w, "\n  ▸ 完整报告（十五节，含图表、SQL 可点击展开/复制）：\n    %s\n", reportPath)
		}
	}
	fmt.Fprintln(w, "  ▸ 想看完整文本版：加 -r 报告.txt；只看终端不生成文件：用 -S。")
}

// renderStatsText 终端版报告（列对齐按显示宽度计算，中文不跑版）
func renderStatsText(w io.Writer, v *statsView, opt *Options) {
	fmt.Fprintf(w, "\ndmsqlq %s 统计报告   %s\n", ver, time.Now().Format("2006-01-02 15:04:05"))

	sec(w, "概览")
	kv := func(k, val string) { fmt.Fprintf(w, "  %s %s\n", pad(k, 16), val) }
	// 结论先行：先给"该看什么"和"哪些结论不能下"，再给基础数字
	if v.Headline != "" {
		fmt.Fprintf(w, "  ★ %s\n", v.Headline)
	}
	if !v.Mask29On {
		kv("采集缺口", "缺位号 29：本批日志无事务/锁事件行（TRX: / DLCK / LOCK_TID 全为 0）")
		kv("", "→ 「锁等待」「长事务」「TPS」是没采集到，不是没发生")
	}
	kv("日志文件", fmt.Sprintf("%d 个（%.1f MB）", v.Files, v.MBf))
	kv("日志记录", fmt.Sprintf("%s 条（时间戳行 + 续行合并后）", fmtInt(v.Records)))
	kv("SQL 事件", fmt.Sprintf("%s 条", fmtInt(v.Exec)))
	kv("命中语句", fmt.Sprintf("%s 条%s", fmtInt(v.Out), opt.ExtraNote()))
	if v.Excluded > 0 {
		kv("已排除", fmt.Sprintf("%s 条（-E，未计入下列统计）", fmtInt(v.Excluded)))
	}
	kv("参数还原", fmt.Sprintf("%s 成功 / %s 待还原  (%.2f%%)",
		fmtInt(v.Matched), fmtInt(v.Missing), v.RestorePct))
	kv("扫描耗时", fmt.Sprintf("%v → %.0f MB/s", v.Elapsed.Round(time.Millisecond),
		v.MBf/maxF(v.Elapsed.Seconds(), 0.001)))
	if v.SpanFirst != "" {
		kv("日志时段", spanText(v))
	}
	if v.WindowDesc != "" {
		// 时间窗口现在决定统计范围（不只是筛输出），必须显眼标注
		kv("★ 统计时间窗口", fmt.Sprintf("%s（仅统计窗口内语句；窗口外 %s 条已排除）",
			v.WindowDesc, fmtInt(v.WinSkipped)))
	}
	kv("筛选条件", v.FilterDesc)
	kv("输出模式", v.ModeDesc)
	if v.FullSQLPath != "" {
		kv("完整 SQL 附件", v.FullSQLPath)
		fmt.Fprintln(w, "                   （纯文本里 SQL 只显示摘要；要看/复制全文用 -r 出 HTML 报告，")
		fmt.Fprintln(w, "                     报告里的语句可点击展开、悬停预览、一键复制）")
	}

	// 优先优化推荐：放在所有明细之前 —— 读者要的是「先改哪条」，不是全部数据。
	if len(v.Advice) > 0 {
		sec(w, fmt.Sprintf("优先优化推荐 Top%d（按影响占比排序）", len(v.Advice)))
		fmt.Fprintln(w, "  （影响占比 = 该语句累计耗时 / 全部语句耗时 = 执行次数 × 平均耗时）")
		fmt.Fprintln(w, "  （为什么用累计耗时：衡量 SQL 代价最理想的是「逻辑读」，但 DM 的 SQL 日志不记录逻辑读，")
		fmt.Fprintln(w, "    只能退用「次数 × 平均耗时」作代理 —— 它同样反映「这条语句总共让系统忙了多久」）")
		fmt.Fprintln(w, "  （按单条最慢排会把「一天只跑 1 次」的排前面，按次数排会把 5ms 的高频查询排前面，都不对）")
		fmt.Fprintln(w, "  （阈值：≥10% 优先，3%~10% 次之；与 Excel 交付件同一口径）")
		for _, a := range v.Advice {
			fmt.Fprintf(w, "\n  %s [%s] 影响占比 %.1f%%  次数 %s  平均 %s  最大 %s  累计 %s\n",
				lpad(strconv.Itoa(a.Rank), 3), a.Prio, a.Share*100,
				pad(fmtInt(a.Count), 10), pad(fmtDur(a.Avg), 9), pad(fmtDur(a.Max), 9), fmtDur(a.Sum))
			fmt.Fprintf(w, "      问题信号：%s\n", a.Signal)
			fmt.Fprintf(w, "      建议动作：%s\n", a.Action)
			fmt.Fprintf(w, "      语句样例：%s\n", briefSQL(a.Sample, 110))
		}
		fmt.Fprintf(w, "\n  （本清单覆盖本次总耗时的 %.1f%%）\n", adviceCoverPct(v.Advice))
	}

	if len(v.OpRows) > 0 {
		sec(w, "语句类型分布")
		fmt.Fprintf(w, "  （次数占比 vs 耗时占比：两者偏离大时，说明该类型「次数不多但很慢」或「数量大但很轻」）\n")
		fmt.Fprintf(w, "  %s %s %s %s %s %s %s %s  %s\n",
			pad("类型", 6), lpad("次数", 12), lpad("次数占比", 9), lpad("累计耗时", 11),
			lpad("耗时占比", 9), lpad("平均", 10), lpad("P95", 10), lpad("最大", 10), "")
		for _, r := range v.OpRows {
			fmt.Fprintf(w, "  %s %s %s %s %s %s %s %s  %s\n",
				pad(r.Op, 6), lpad(fmtInt(r.Count), 12), lpad(fmt.Sprintf("%.1f%%", r.Pct), 9),
				lpad(durOrDash(r.Sum), 11), lpad(pctStr(r.SumPct, r.Sum), 9),
				lpad(durOrDash(r.Avg), 10), lpad(durOrDash(r.P95), 10), lpad(durOrDash(r.Max), 10),
				bar(r.SumPct/100, 20))
		}
	}

	if len(v.ErrCodes) > 0 {
		sec(w, fmt.Sprintf("错误码分布（[ERR] 行，共 %s 条）", fmtInt(v.ErrN)))
		fmt.Fprintln(w, "  （次数与耗时并列看：次数不多却吃掉大量耗时的错误码才是重点。")
		fmt.Fprintln(w, "    -608 = 会话请求超时 / 锁超时 —— 它本身只说明超时，不能单凭它断定是锁等待；")
		fmt.Fprintln(w, "    要定性需在库上核对 V$TRXWAIT / V$LOCK，或让采集侧 SQL_TRACE_MASK 补上 29）")
		fmt.Fprintf(w, "  %s %s %s %s %s\n",
			pad("错误码", 14), lpad("次数", 10), lpad("占比", 9), lpad("累计耗时", 12), lpad("平均", 11))
		for _, r := range v.ErrCodes {
			fmt.Fprintf(w, "  %s %s %s %s %s\n",
				pad(clip(r.Code, 14), 14), lpad(fmtInt(r.Count), 10),
				lpad(fmt.Sprintf("%.1f%%", pct(r.Count, v.ErrN)), 9),
				lpad(durOrDash(r.Sum), 12), lpad(durOrDash(r.Avg), 11))
		}
	}

	if t := v.HistTotal(); t > 0 {
		sec(w, "执行耗时分布")
		fmt.Fprintf(w, "  分位数 P50 %s · P90 %s · P95 %s · P99 %s · 最大 %s（%s 条有耗时语句）\n",
			fmtDur(v.P50), fmtDur(v.P90), fmtDur(v.P95), fmtDur(v.P99), fmtDur(v.DurMax), fmtInt(t))
		fmt.Fprintln(w, "  （平均/最大看不出分布形态：P50 与 P99 差距越大，说明越少数语句在拖后腿）")
		for i, n := range v.Hist {
			fmt.Fprintf(w, "  %s %s %s  %s\n",
				pad(histNames[i], 11), lpad(fmtInt(n), 12), lpad(fmt.Sprintf("%.1f%%", pct(n, t)), 8),
				bar(ratioOf(n, v.HistMax), 34))
		}
	}

	if len(v.Slow) > 0 {
		sec(w, fmt.Sprintf("最慢语句 Top%d", len(v.Slow)))
		for i, r := range v.Slow {
			fmt.Fprintf(w, "  %s %s %s %s %s %s  %s\n",
				lpad(strconv.Itoa(i+1), 3), lpad(fmtDur(r.MS), 9), lpad(rowsDisp(r.Rows)+"行", 8),
				pad(r.Op, 5), pad(r.User, 18), pad(shortTS(r.TS), 9), briefSQL(r.SQL, 100))
			if r.ExecID != "" {
				fmt.Fprintf(w, "      EXEC_ID %s —— 下钻节点耗时：SELECT * FROM V$SQL_NODE_HISTORY WHERE EXEC_ID=%s;\n",
					r.ExecID, r.ExecID)
			}
		}
	}

	if len(v.Tpls) > 0 {
		sec(w, fmt.Sprintf("最耗时语句模板 Top%d", len(v.Tpls)))
		fmt.Fprintln(w, "  （同一模板：字面量与数字已归一化；看“累计耗时”找优化收益最大的语句）")
		fmt.Fprintln(w, "  （标 [参数未还原] 的语句：日志里该语句前没有 PARAMS 行，只能给带 ? 的原文；查掩码 28）")
		for i, r := range v.Tpls {
			fmt.Fprintf(w, "  %s 累计 %s  次数 %s  最快 %s  平均 %s  最大 %s\n     %s\n",
				lpad(strconv.Itoa(i+1), 3), pad(fmtDur(r.Sum), 9), pad(fmtInt(r.Count), 11),
				pad(durOrDash(r.Min), 9), pad(fmtDur(r.Avg), 9), pad(fmtDur(r.Max), 9),
				briefSQL(r.Sample, 110))
		}
	}

	if len(v.Users) > 0 {
		sec(w, "用户排行（按语句数）")
		for _, r := range v.Users {
			fmt.Fprintf(w, "  %s 语句 %s  累计 %s  P95 %s  最大 %s\n",
				pad(r.User, 20), lpad(fmtInt(r.Count), 12), lpad(fmtDur(r.Sum), 11),
				lpad(durOrDash(r.P95), 10), lpad(fmtDur(r.Max), 10))
		}
	}

	if len(v.Clients) > 0 {
		sec(w, "客户端排行（appname @ IP，按语句数）")
		for _, r := range v.Clients {
			fmt.Fprintf(w, "  %s 语句 %s  累计 %s  最大 %s\n",
				pad(clip(r.User, 40), 40), lpad(fmtInt(r.Count), 12), lpad(fmtDur(r.Sum), 11), lpad(fmtDur(r.Max), 10))
		}
	}

	if len(v.Tables) > 0 {
		sec(w, fmt.Sprintf("热表 Top%d（按累计耗时；表名取自 SQL 文本）", len(v.Tables)))
		fmt.Fprintln(w, "  （口径：表名取自 SQL 文本，已去 schema、统一大写；一条语句涉及多张表时每张表各计一次，")
		fmt.Fprintln(w, "    故耗时占比之和可能超过 100%。含数据字典视图与临时表（USER_/DBA_/V$/TMP_ 开头），")
		fmt.Fprintln(w, "    不关心可用 -E 排除，例：-E USER_,DBA_,TMP_）")
		// 8 个占位符对 8 个参数 —— 少了会打印 %!(EXTRA string=耗时占比) 且表头与数据列错位
		fmt.Fprintf(w, "  %s %s %s %s %s %s %s %s\n",
			pad("表名", 30), lpad("语句数", 10), lpad("读", 9), lpad("写", 9),
			lpad("读写比", 8), lpad("累计耗时", 11), lpad("最大", 9), lpad("耗时占比", 9))
		for _, r := range v.Tables {
			fmt.Fprintf(w, "  %s %s %s %s %s %s %s %s  %s\n",
				pad(clip(r.Table, 30), 30), lpad(fmtInt(r.Count), 10), lpad(fmtInt(r.Reads), 9),
				lpad(fmtInt(r.Writes), 9), lpad(ratioDisp(r.RW), 8),
				lpad(durOrDash(r.Sum), 11), lpad(durOrDash(r.Max), 9),
				lpad(pctStr(r.Pct, r.Sum), 9), bar(r.Pct/100, 14))
		}
	}

	if v.SpanSec > 0 {
		sec(w, "吞吐与时轴（QPS / TPS）")
		kv2 := func(k, val string) { fmt.Fprintf(w, "  %s %s\n", pad(k, 16), val) }
		kv2("日志时段", spanText(v))
		if v.qpsUnderReported() {
			// QPS 与 TPS 口径不同、覆盖度差两个数量级，必须显式提醒，否则会被当成"系统很闲"
			fmt.Fprintf(w, "  ⚠ QPS 被严重低估，不要与 TPS 横向比较：本批有事务结束事件 %s 条，"+
				"只记录到 SQL 语句 %s 条（每 1 条 SQL 伴随约 %.0f 条 COMMIT/ROLLBACK）。\n"+
				"    QPS 只是「日志里记到的语句数」，不是业务真实吞吐 —— 查 SQL_TRACE_MASK 的语句类型位是否开全。\n",
				fmtInt(v.Commits+v.Rollbacks), fmtInt(v.Exec), v.trxPerSQL())
		}
		kv2("平均 QPS", fmt.Sprintf("%.2f 条/秒", v.AvgQPS))
		kv2("峰值 QPS", fmt.Sprintf("%s 条/秒 @ %s", fmtNum(v.PeakQPS), shortTS(v.PeakQPSAt)))
		if v.Commits+v.Rollbacks > 0 {
			kv2("平均 TPS", fmt.Sprintf("%.2f 事务/秒（按 COMMIT）", v.AvgTPS))
			kv2("峰值 TPS", fmt.Sprintf("%s 事务/秒 @ %s", fmtNum(v.PeakTPS), shortTS(v.PeakTPSAt)))
			kv2("事务结束事件", fmt.Sprintf("COMMIT %s  /  ROLLBACK %s  （回滚率 %.2f%%）",
				fmtInt(v.Commits), fmtInt(v.Rollbacks), v.RollbackPct))
		} else {
			kv2("事务事件", "未发现 TRX: COMMIT/ROLLBACK（掩码 29 未开或该时段无事务结束事件），TPS 无法计算")
		}
		kv2("有事件的秒数", fmt.Sprintf("%s / 共约 %.0f 秒", fmtInt(v.SecCovered), v.SpanSec))
		if v.LongestIdle > 0 {
			kv2("最长静默空档", fmt.Sprintf("%s（起于 %s）—— 业务停顿 or 采集中断，值得对视时间线复核",
				fmtDur(v.LongestIdle*1000), shortTS(v.LongestIdleAt)))
		}
		// 负载趋势：一行字符图看形态（逐时段完整表格太啰嗦，完整时间轴走 Excel 交付件）
		if len(v.Buckets) > 0 {
			vals := make([]int64, 0, len(v.Buckets))
			for _, b := range v.Buckets {
				vals = append(vals, b.SQL)
			}
			fmt.Fprintf(w, "  %s %s\n", pad("负载趋势", 16), sparkline(vals, 106))
			fmt.Fprintf(w, "  %s %s → %s（%s 粒度 × %d 个时段；完整时间轴见 Excel 交付件的「时段分布」）\n",
				pad("", 16), v.Buckets[0].TS, v.Buckets[len(v.Buckets)-1].TS, v.BucketUnit, v.BucketCount)
		}
		// 高峰时段（替代原来的秒级 TopN —— 秒与秒之间的差异是噪声，看不出"业务高峰"）
		if len(v.BucketsTop) > 0 {
			fmt.Fprintf(w, "  高峰时段 Top%d（按 SQL 数；粒度：%s，共 %d 个时段）\n",
				len(v.BucketsTop), v.BucketUnit, v.BucketCount)
			if v.PeakBucket != nil {
				fmt.Fprintf(w, "  峰值时段：%s  （%s 条 SQL，平均 QPS %.2f）\n",
					v.PeakBucket.TS, fmtInt(v.PeakBucket.SQL), v.PeakBucket.QPS)
			}
			fmt.Fprintf(w, "    %s %s %s %s %s %s %s\n",
				lpad("#", 3), pad("时段", 21), lpad("SQL数", 10), lpad("平均QPS", 9),
				lpad("累计耗时", 11), lpad("COMMIT", 9), lpad("ROLLBACK", 9))
			top1 := v.BucketsTop[0].SQL
			for i, r := range v.BucketsTop {
				fmt.Fprintf(w, "    %s %s %s %s %s %s %s  %s\n",
					lpad(strconv.Itoa(i+1), 3), pad(r.TS, 21), lpad(fmtInt(r.SQL), 10),
					lpad(fmt.Sprintf("%.2f", r.QPS), 9), lpad(durOrDash(r.SumMS), 11),
					lpad(fmtInt(r.Commit), 9), lpad(fmtInt(r.Rollback), 9),
					bar(ratioOf(r.SQL, top1), 12))
			}
			if v.BucketCount > len(v.BucketsTop) {
				fmt.Fprintf(w, "  （完整 %d 个时段的时间轴见 Excel 交付件的「时段分布」工作表：加 -e 交付.xlsx）\n", v.BucketCount)
			}
		}
	}

	if len(v.SlowObjDDL) > 0 {
		fmt.Fprintln(w, "  相关对象最近一次结构变更（性能劣化常紧跟一次 DDL）：")
		for _, d := range v.SlowObjDDL {
			fmt.Fprintf(w, "    %s\n", d.Name)
		}
	}

	if len(v.Trxs) > 0 || v.TrxOpenN > 0 {
		sec(w, fmt.Sprintf("长事务 Top%d（按跨度）", len(v.Trxs)))
		fmt.Fprintf(w, "  口径：同一 trxid 的首次事件 → 末次事件（事件＝该事务的语句，以及掩码 29 的 TRX: START）\n")
		if v.Commits+v.Rollbacks > 0 {
			fmt.Fprintf(w, "  注：COMMIT/ROLLBACK 行的 trxid 通常为 0，无法与 START 关联，因此无法判定单个事务是否已提交；"+
				"跨度只到该事务最后一条语句为止\n")
		}
		fmt.Fprintf(w, "  %s %s %s %s %s %s %s\n",
			pad("trxid", 16), lpad("跨度", 10), lpad("SQL耗时", 10), lpad("利用率", 8),
			lpad("语句", 7), pad("用户", 14), "起止时间")
		for _, r := range v.Trxs {
			fmt.Fprintf(w, "  %s %s %s %s %s %-14s %s → %s\n",
				pad(r.Trx, 16), lpad(fmtDur(r.SpanMS), 10), lpad(durOrDash(r.ExecMS), 10),
				lpad(utilDisp(r.Util), 8), lpad(fmtInt(r.Count), 7),
				trxUserOf(v, r.Trx), shortTS(r.First), shortTS(r.Last))
		}
		if len(v.Trxs) > 0 {
			fmt.Fprintf(w, "  口径：利用率 = 该事务内 SQL 的累计执行耗时 ÷（事务跨度 + 首条 SQL 耗时）。利用率低说明「占着事务不干活」\n"+
				"        （长时间持锁、应用侧没提交），这类事务比「SQL 慢」更该先处理\n")
		}
		v.renderTrxStmtHist(w, "  ")
		if v.TrxOpenN > 0 {
			fmt.Fprintf(w, "  另有 %s 个事务只见 TRX: START、后续无语句或结束事件（可能仍未提交/日志被截断）\n", fmtInt(v.TrxOpenN))
		}
		fmt.Fprintln(w, "  ▸ 看某个事务里到底是哪些 SQL：")
		if v.FullSQLPath != "" {
			fmt.Fprintf(w, "    配套文件已列出这些事务的全部语句（含参数还原）：%s\n", v.FullSQLPath)
		}
		if len(v.Trxs) > 0 {
			fmt.Fprintf(w, "    或直接抽取：dmsqlq <同一路径> -x %s -N -o trx_%s.sql\n",
				v.Trxs[0].Trx, v.Trxs[0].Trx)
		}
	}

	// ---- 锁等待：与长事务是两件事，这里给的是"真发生等待"的事件 ----
	sec(w, "锁等待（掩码 29）")
	if v.LockN == 0 {
		if !v.Mask29On {
			fmt.Fprintln(w, "  ⚠ 本节无数据 ≠ 没有锁等待：日志里 TRX: / DLCK / LOCK_TID 三类行全为 0，")
			fmt.Fprintln(w, "    判定 SQL_TRACE_MASK 缺 29 —— 29 一旦开启，事务事件行必然大量出现，不会是 0。")
			fmt.Fprintln(w, "    要锁等待数据请开 29 后重采；短期替代：在库上查 V$TRXWAIT / V$LOCK。")
		} else if v.DlckN > 0 {
			fmt.Fprintf(w, "  未发现锁等待事件（LOCK_TID … wait for）—— 位号 29 已开（日志里有 %s 条事务事件），"+
				"所以这个 0 是可信的：该时段确实无锁竞争。\n", fmtInt(v.TrxEventN+v.TrxEndN))
			fmt.Fprintf(w, "  （另有 %s 条 DLCK 锁操作计时行，那是执行计划里锁节点的自身耗时，不是等待。）\n", fmtInt(v.DlckN))
		} else {
			fmt.Fprintln(w, "  未发现锁等待事件；位号 29 已开（日志里有事务事件行），该时段确实无锁竞争。")
		}
	} else {
		kv2 := func(k, val string) { fmt.Fprintf(w, "  %s %s\n", pad(k, 16), val) }
		kv2("锁等待事件", fmt.Sprintf("%s 次", fmtInt(v.LockN)))
		kv2("累计等待", fmt.Sprintf("%s（平均 %s）", fmtDur(v.LockSumMS), fmtDur(v.LockSumMS/float64(max64(v.LockN, 1)))))
		kv2("最长等待", fmtDur(v.LockMaxMS))
		kv2("涉及对象数", fmt.Sprintf("%d 个（按表 ID）", v.LockTableN))
		if v.LockPeakN > 0 {
			extra := ""
			if v.LockPeakIsTop {
				extra = "  ← 正好是 QPS 峰值那一秒"
			}
			kv2("等待最密的一秒", fmt.Sprintf("%s（%d 次等待，该秒 QPS %d）%s",
				v.LockPeakAt, v.LockPeakN, v.LockPeakQPS, extra))
		}
		fmt.Fprintln(w, "  等待时长分布")
		var t int64
		for _, n := range v.LockHist {
			t += n
		}
		for i, n := range v.LockHist {
			fmt.Fprintf(w, "    %s %s %s  %s\n", pad(lockNames[i], 11), lpad(fmtInt(n), 10),
				lpad(fmt.Sprintf("%.1f%%", pct(n, t)), 8), bar(ratioOf(n, v.LockHistMax), 30))
		}
		// 明细：把"谁在等、谁在持、锁在哪张表"一次给全
		fmt.Fprintf(w, "  最久等待 Top%d\n", len(v.LockRows))
		fmt.Fprintf(w, "    %s %s %s %s %s\n",
			lpad("#", 3), lpad("等待", 9), pad("对象", 30), pad("等待方（trx / 用户）", 26), pad("持有方（谁在持锁）", 27))
		for i, lk := range v.LockRows {
			fmt.Fprintf(w, "    %s %s %s %s %s  等 %d 个  %s\n",
				lpad(strconv.Itoa(i+1), 3), lpad(fmtDur(lk.MS), 9), pad(clip(lockObj(lk.Table, lk.TableID), 30), 30),
				pad(clip(lockParty(lk.Waiter, lk.WaiterU), 26), 26), pad(clip(lockParty(lk.Holder, lk.HolderU), 27), 27),
				lk.Waiters, shortTS(lk.TS))
			fmt.Fprintf(w, "        模式 %-3s  %s\n", lk.Mode, lockTraceCmd(lk))
		}
		// 阻塞链（V2.8）：终端只给前 3 条 —— 够截图看清"谁堵了谁"，
		// 完整清单在 HTML 报告的「阻塞链」一节。
		if len(v.LockChains) > 0 {
			n := len(v.LockChains)
			if n > 3 {
				n = 3
			}
			fmt.Fprintf(w, "  阻塞链 Top%d（一条链 = 一个根事务堵住的一串等待；共 %d 条）\n", n, len(v.LockChains))
			fmt.Fprintf(w, "    %s %s %s %s %s %s\n",
				lpad("#", 3), pad("对象", 26), pad("根事务（真正持锁者）", 24), lpad("最长等待", 10),
				lpad("等待次数", 8), lpad("链长", 6))
			for i, c := range v.LockChains[:n] {
				fmt.Fprintf(w, "    %s %s %s %s %s %s\n",
					lpad(strconv.Itoa(i+1), 3), pad(clip(lockObj(c.Table, c.TableID), 26), 26),
					pad(clip(c.Root+" "+c.RootUser, 24), 24), lpad(fmtDur(c.MaxMS), 10),
					lpad(fmtInt(c.Count), 8), lpad(strconv.Itoa(c.ChainLen), 6))
			}
		}
		// 排查方向（V2.11）：终端给完整步骤 —— 这是现场真正照着做的部分，
		// 截断它等于把最该看的东西藏起来。步骤本身只有 3~5 条，占不了几行。
		if len(v.LockGuide) > 0 {
			fmt.Fprintf(w, "  排查方向（按日志能证实的顺序，逐条缩小范围）\n")
			for _, g := range v.LockGuide {
				fmt.Fprintf(w, "    %d) %s\n", g.Step, g.Title)
				if g.Fact != "" {
					fmt.Fprintf(w, "       实测：%s\n", wrapIndent(oneLine(g.Fact), 11, 96))
				}
				if g.Note != "" {
					fmt.Fprintf(w, "       推断：%s\n", wrapIndent(oneLine(g.Note), 11, 96))
				}
				if g.Next != "" {
					fmt.Fprintf(w, "       往哪查：%s\n", wrapIndent(oneLine(g.Next), 11, 96))
				}
			}
		}
		// 双方 SQL（V2.8）：只给最久的 3 条，明细全在 HTML。
		if n := minInt(len(v.LockRowsAll), 3); n > 0 {
			fmt.Fprintf(w, "  锁等待双方的 SQL（Top%d；等待方取到 %d/%d，持有方取到 %d/%d，明细见 HTML 报告）\n",
				n, v.LockWaiterSQLN, v.LockTotalN, v.LockHolderSQLN, v.LockTotalN)
			for i, lk := range v.LockRowsAll[:n] {
				fmt.Fprintf(w, "    #%d 等待 %s  %s\n", i+1, fmtDur(lk.MS), lockObj(lk.Table, lk.TableID))
				if lk.WaiterSQL != "" {
					fmt.Fprintf(w, "      等待方 trx[%s]：%s\n", lk.Waiter, clip(lk.WaiterSQL, 110))
				} else {
					fmt.Fprintf(w, "      等待方 trx[%s]：语句只见开始、无完成行（非「没执行」）\n", lk.Waiter)
				}
				root := lk.HolderRoot
				if root == "" {
					root = lk.Holder
				}
				if len(lk.HolderStmts) > 0 {
					src := ""
					if lk.HolderSQLFromORA {
						src = "   ← 来源：掩码 27 的 [ORA] 原始语句行（该语句执行很快，完成行被 MIN_EXEC_TIME 滤掉了）"
					}
					fmt.Fprintf(w, "      持有方 trx[%s]：%s%s\n", root, clip(lk.HolderStmts[0].SQL, 110), src)
				} else {
					act := "结局未知（日志里未见 COMMIT/ROLLBACK）"
					if lk.HolderKind == "ROLLBACK" {
						act = "结局：回滚"
					} else if lk.HolderKind == "COMMIT" {
						act = "结局：提交"
					}
					fmt.Fprintf(w, "      持有方 trx[%s]：日志里没有它的 SQL 文本；%s\n", root, act)
					io.WriteString(w, "        （成因通常是「语句很快、完成行被 MIN_EXEC_TIME 滤掉」或「执行中被中止」，"+
						"都不是没执行；开掩码位 27 可自动找回前者）\n")
				}
			}
		}
		fmt.Fprintf(w, "  被争抢的表 Top%d（按累计等待）\n", len(v.LockTables))
		fmt.Fprintf(w, "    %s %s %s %s %s %s\n",
			pad("对象", 26), lpad("次数", 8), lpad("累计等待", 10), lpad("最长", 9), pad("锁模式", 8), pad("等待方用户", 24))
		for _, r := range v.LockTables {
			fmt.Fprintf(w, "    %s %s %s %s %s %s\n",
				pad(clip(lockObj(r.Table, r.TableID), 26), 26), lpad(fmtInt(r.Count), 8),
				lpad(fmtDur(r.Sum), 10), lpad(fmtDur(r.Max), 9), pad(r.Mode, 8),
				pad(clip(r.Waiters, 24), 24))
		}
		if v.RefSQL != "" {
			fmt.Fprintln(w, "  ▸ 上面显示的是对象 ID（DM 日志只记 ID，不记表名）。复制执行下面这条即可拿到表名：")
			for _, ln := range strings.Split(v.RefSQL, "\n") {
				fmt.Fprintln(w, "    "+ln)
			}
			fmt.Fprintln(w, "    拿到后存成文本文件，再加 --obj-map 该文件 重跑，报告就显示表名了。")
		}
		if v.DlckN > 0 {
			fmt.Fprintf(w, "  另：DLCK 锁操作计时行 %s 条（used time>0 的 %s 条，最大 %s）—— 节点自身耗时，不是等待\n",
				fmtInt(v.DlckN), fmtInt(v.DlckNonZero), fmtDur(v.DlckMaxMS))
		}
	}

	renderAuditText(w, v, opt)

	if cr := configCheck(v); len(cr) > 0 {
		sec(w, "采集配置体检（据日志内容反推 sqllog.ini）")
		fmt.Fprintf(w, "  %s %s  %s\n", pad("检查项", 26), pad("实测", 34), "结论 / 怎么改")
		for _, r := range cr {
			fmt.Fprintf(w, "  %s %s  %s\n", pad(clip(r.Item, 26), 26), pad(clip(r.Value, 34), 34), r.Advice)
		}
		if len(v.DDLVerbs) > 0 {
			fmt.Fprint(w, "  DDL 首词分布      ")
			for i, d := range v.DDLVerbs {
				if i > 0 {
					fmt.Fprint(w, " · ")
				}
				fmt.Fprintf(w, "%s %s 次", d.Name, fmtInt(d.Count))
			}
			fmt.Fprintln(w, "\n                    （看清 [DDL] 到底在做什么：STAT = 更新统计信息，"+
				"不是业务在改表结构；CREATE OR REPLACE INDEX 多为工具/任务维护）")
		}
		fmt.Fprintln(w, "  （「分析不出锁等待 / 没有参数」这类问题，第一嫌疑是采集侧配置，不是解析器；"+
			"库上执行 SELECT PARA_NAME,PARA_VALUE FROM V$DM_SQLLOG_CONFIG; 可核对）")
	}

	if len(v.Hints) > 0 {
		sec(w, "判读提示")
		for _, hh := range v.Hints {
			for i, ln := range wrapText("· "+hh, 92) {
				if i == 0 {
					fmt.Fprintln(w, "  "+ln)
				} else {
					fmt.Fprintln(w, "    "+ln)
				}
			}
		}
	}
	fmt.Fprintf(w, "%s\n", strings.Repeat("─", 66))
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// durOrDash 耗时展示：完全没有耗时数据的事件（如 [ORA]）显示 "-"，避免一排 0 干扰阅读
func durOrDash(ms float64) string {
	if ms <= 0 {
		return "-"
	}
	return fmtDur(ms)
}

// pctStr 百分比展示：对应量本身为 0 时显示 "-"（否则一排 0.0% 也干扰阅读）
func pctStr(p, sum float64) string {
	if sum <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", p)
}

// bar 生成字符柱状图（等宽终端友好）。ratio 取 0~1；>0 至少画 1 格，否则看不清"有还是没有"
func bar(ratio float64, width int) string {
	if ratio <= 0 || width <= 0 {
		return ""
	}
	n := int(ratio*float64(width) + 0.5)
	if n < 1 {
		n = 1
	}
	if n > width {
		n = width
	}
	return strings.Repeat("█", n)
}

// ratioOf a/b 的比值（b<=0 时返回 0，供柱状图用）
func ratioOf(a, b int64) float64 {
	if b <= 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// fmtSpan 秒数 → 人类可读跨度
func fmtSpan(sec float64) string {
	switch {
	case sec <= 0:
		return "-"
	case sec < 60:
		return fmt.Sprintf("%.0f 秒", sec)
	case sec < 3600:
		return fmt.Sprintf("%.1f 分钟", sec/60)
	case sec < 86400:
		return fmt.Sprintf("%.2f 小时", sec/3600)
	default:
		return fmt.Sprintf("%.2f 天", sec/86400)
	}
}

// fmtNum 带小数就保留一位，整数不带小数点（QPS 峰值这类数值用）
func fmtNum(f float64) string {
	if f >= 1000 {
		return fmtInt(int64(f + 0.5))
	}
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return fmt.Sprintf("%.1f", f)
}

// clip 按显示宽度截断（超长表名/客户端标识别撑爆表格）
func clip(s string, w int) string {
	if dispWidth(s) <= w {
		return s
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := dispWidth(string(r))
		if used+rw > w-1 {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	return b.String() + "…"
}

func shortTS(ts string) string {
	if len(ts) >= 19 {
		return ts[11:19]
	}
	return ts
}

// wrapText 按显示宽度折行（中文按 2 列计）
func wrapText(s string, width int) []string {
	var out []string
	var cur strings.Builder
	w := 0
	for _, r := range s {
		rw := dispWidth(string(r))
		if w+rw > width && cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
			w = 0
		}
		cur.WriteRune(r)
		w += rw
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// renderStatsMarkdown Markdown 版报告（便于归档/发给同事）
func renderStatsMarkdown(w io.Writer, v *statsView, opt *Options) {
	fmt.Fprintf(w, "# dmsqlq 统计报告\n\n")
	fmt.Fprintf(w, "- **日志时段**：%s\n- 扫描范围：%d 个文件 · %.1f MB · %v · %.0f MB/s\n"+
		"- 筛选条件：%s\n- 输出模式：%s\n- 生成时间：%s\n\n",
		mdEsc(spanText(v)), v.Files, v.MBf, v.Elapsed.Round(time.Millisecond),
		v.MBf/maxF(v.Elapsed.Seconds(), 0.001), v.FilterDesc, v.ModeDesc,
		time.Now().Format("2006-01-02 15:04:05"))
	if v.Headline != "" {
		fmt.Fprintf(w, "> **%s**\n\n", mdEsc(v.Headline))
	}
	if !v.Mask29On {
		fmt.Fprintf(w, "> ⚠️ 本批日志没有事务/锁事件行（`TRX:` / `DLCK` / `LOCK_TID` 全为 0），"+
			"采集侧 `SQL_TRACE_MASK` 缺 **29**：**「锁等待」「长事务」「TPS」是没采集到，不是没发生**，"+
			"别把「锁等待 0 次」读成「这库没有锁竞争」。\n\n")
	}
	if v.FullSQLPath != "" {
		fmt.Fprintf(w, "- 完整 SQL 附件：`%s`（Markdown 里 SQL 为摘要，全文在该文件；"+
			"想要点击展开/复制请用 `-r 报告.html`）\n\n", v.FullSQLPath)
	}

	fmt.Fprintf(w, "## 概览\n\n| 指标 | 数值 |\n|---|---|\n")
	fmt.Fprintf(w, "| 日志记录 | %s 条 |\n", fmtInt(v.Records))
	fmt.Fprintf(w, "| SQL 事件 | %s 条 |\n", fmtInt(v.Exec))
	fmt.Fprintf(w, "| 命中语句 | %s 条 |\n", fmtInt(v.Out))
	if v.Excluded > 0 {
		fmt.Fprintf(w, "| 已排除（-E，未计入统计） | %s 条 |\n", fmtInt(v.Excluded))
	}
	fmt.Fprintf(w, "| 参数还原成功 | %s 条（%.2f%%） |\n", fmtInt(v.Matched), v.RestorePct)
	fmt.Fprintf(w, "| 参数待还原 | %s 条 |\n", fmtInt(v.Missing))
	if v.SpanFirst != "" {
		fmt.Fprintf(w, "| 日志时段 | %s |\n", mdEsc(spanText(v)))
	}
	if v.WindowDesc != "" {
		fmt.Fprintf(w, "| **统计时间窗口** | **%s**（仅统计窗口内语句，窗口外排除 %s 条） |\n",
			mdEsc(v.WindowDesc), fmtInt(v.WinSkipped))
	}
	fmt.Fprintln(w)

	// ---- 优先优化推荐（放最前：报告是给人做决策的，先说改什么）----
	if len(v.Advice) > 0 {
		fmt.Fprintf(w, "## 优先优化推荐\n\n"+
			"> 按**影响占比**排序 = 该语句累计耗时（执行次数 × 平均耗时）÷ 全部语句耗时。\n"+
			"> **为什么用累计耗时**：衡量 SQL 代价最理想的指标是**逻辑读**（buffer gets），"+
			"但达梦的 SQL 日志不记录逻辑读，只能退而用「次数 × 平均耗时」作代理 —— "+
			"它同样反映「这条语句总共让系统忙了多久」。\n"+
			"> 其它排法都不对：按单条最慢会把「一天只跑 1 次」的语句排前面；"+
			"按次数会把 5ms 的高频查询排前面 —— 两者都偏离真实负载。\n"+
			"> 阈值与 Excel 交付件一致：≥10%% 优先、3%%~10%% 次之。共 %d 条，合计覆盖 **%.1f%%**。\n\n",
			len(v.Advice), adviceCoverPct(v.Advice))
		fmt.Fprintf(w, "| # | 优先级 | 影响占比 | 次数 | 平均 | 最大 | 累计 | 问题信号 |\n")
		fmt.Fprintf(w, "|---:|:---:|---:|---:|---:|---:|---:|:---|\n")
		for _, a := range v.Advice {
			fmt.Fprintf(w, "| %d | %s | **%.1f%%** | %s | %s | %s | %s | %s |\n",
				a.Rank, a.Prio, a.Share*100, fmtInt(a.Count),
				fmtDur(a.Avg), fmtDur(a.Max), fmtDur(a.Sum), mdEsc(a.Signal))
		}
		fmt.Fprintln(w)
		for _, a := range v.Advice {
			fmt.Fprintf(w, "**%d. [%s] 影响占比 %.1f%%** —— %s\n\n",
				a.Rank, a.Prio, a.Share*100, mdEsc(a.Signal))
			fmt.Fprintf(w, "- 建议动作：%s\n", mdEsc(a.Action))
			fmt.Fprintf(w, "- 语句样例：\n\n```sql\n%s\n```\n\n", strings.TrimSpace(a.Sample))
		}
	}

	if len(v.OpRows) > 0 {
		fmt.Fprintf(w, "## 语句类型分布\n\n> 次数占比与耗时占比偏离大时，说明该类型「次数不多但很慢」或「数量大但很轻」。\n\n| 类型 | 次数 | 次数占比 | 累计耗时 | 耗时占比 | 平均 | P95 | 最大 |\n|---|---:|---:|---:|---:|---:|---:|---:|\n")
		for _, r := range v.OpRows {
			fmt.Fprintf(w, "| %s | %s | %.1f%% | %s | %s | %s | %s | %s |\n",
				r.Op, fmtInt(r.Count), r.Pct, durOrDash(r.Sum), pctStr(r.SumPct, r.Sum),
				durOrDash(r.Avg), durOrDash(r.P95), durOrDash(r.Max))
		}
		fmt.Fprintln(w)
	}

	if len(v.ErrCodes) > 0 {
		fmt.Fprintf(w, "## 错误码分布（[ERR] 行，共 %s 条）\n\n> 次数与耗时并列看：**次数不多却吃掉大量耗时**的错误码才是重点。"+
			"`-608` 是「会话请求超时 / 锁超时」——它本身只说明超时，**不能单凭它断定就是锁等待**："+
			"要定性需在库上核对 `V$TRXWAIT` / `V$LOCK`，或让采集侧把 `SQL_TRACE_MASK` 补上 29。\n\n"+
			"| 错误码 | 次数 | 占 [ERR] 次数 | 累计耗时 | 平均 |\n|---|---:|---:|---:|---:|\n", fmtInt(v.ErrN))
		for _, r := range v.ErrCodes {
			fmt.Fprintf(w, "| `%s` | %s | %.1f%% | %s | %s |\n",
				r.Code, fmtInt(r.Count), pct(r.Count, v.ErrN), durOrDash(r.Sum), durOrDash(r.Avg))
		}
		fmt.Fprintln(w)
	}

	if t := v.HistTotal(); t > 0 {
		fmt.Fprintf(w, "## 执行耗时分布\n\n> P50 **%s** · P90 **%s** · P95 **%s** · P99 **%s** · 最大 **%s**\n>\n"+
			"> 平均值/最大值看不出分布形态：P50 与 P99 差距越大，说明越少数语句在拖后腿。\n\n| 区间 | 次数 | 占比 |\n|---|---:|---:|\n",
			fmtDur(v.P50), fmtDur(v.P90), fmtDur(v.P95), fmtDur(v.P99), fmtDur(v.DurMax))
		for i, n := range v.Hist {
			fmt.Fprintf(w, "| %s | %s | %.1f%% |\n", histNames[i], fmtInt(n), pct(n, t))
		}
		fmt.Fprintln(w)
	}

	if len(v.Slow) > 0 {
		fmt.Fprintf(w, "## 最慢语句 Top%d\n\n| # | 耗时 | 行数 | 类型 | 用户 | 时间 | EXEC_ID | SQL（摘要） |\n|---:|---:|---:|---|---|---|---|---|\n", len(v.Slow))
		for i, r := range v.Slow {
			fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s | %s | `%s` |\n",
				i+1, fmtDur(r.MS), rowsDisp(r.Rows), r.Op, r.User, shortTS(r.TS), r.ExecID,
				mdEsc(briefSQL(r.SQL, 100)))
		}
		if v.ExecIDSeen > 0 && len(v.Slow) > 0 && v.Slow[0].ExecID != "" {
			fmt.Fprintf(w, "\n**下钻到执行节点**（SQL 日志本身没有逻辑读，需要拿 EXEC_ID 去库里换）：\n\n"+
				"```sql\nSELECT * FROM V$SQL_NODE_HISTORY WHERE EXEC_ID = %s;\n```\n\n"+
				"> 该视图按执行节点给出 `TIME_USED`（微秒）与 `N_ENTER`，其中 `DLCK` 节点就是日志里 "+
				"`DLCK used time:N(us)` 的来源 —— 想把「锁开销」算清楚，就从这里下钻。\n",
				v.Slow[0].ExecID)
		}
		fmt.Fprintln(w)
	}

	if len(v.Tpls) > 0 {
		fmt.Fprintf(w, "## 最耗时语句模板 Top%d\n\n> 字面量与数字已归一化；累计耗时最高的模板优化收益最大。\n"+
			"> **最快 / 平均 / 最大 一起看**：三者接近 → 稳定慢（缺索引/写法），改了就好；"+
			"最快远小于平均 → 时快时慢（计划突变、数据倾斜、偶发锁等待），先查为什么不稳定。\n\n"+
			"| # | 累计耗时 | 次数 | 最快 | 平均 | 最大 | 模板 |\n|---:|---:|---:|---:|---:|---:|---|\n", len(v.Tpls))
		for i, r := range v.Tpls {
			fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s | `%s` |\n",
				i+1, fmtDur(r.Sum), fmtInt(r.Count), durOrDash(r.Min), fmtDur(r.Avg), fmtDur(r.Max),
				mdEsc(briefSQL(r.Sample, 110)))
		}
		fmt.Fprintln(w)
	}

	if len(v.Users) > 0 {
		fmt.Fprintf(w, "## 用户排行\n\n| 用户 | 语句数 | 累计耗时 | P95 | 最大 |\n|---|---:|---:|---:|---:|\n")
		for _, r := range v.Users {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", r.User, fmtInt(r.Count), fmtDur(r.Sum),
				durOrDash(r.P95), fmtDur(r.Max))
		}
		fmt.Fprintln(w)
	}

	if len(v.Clients) > 0 {
		fmt.Fprintf(w, "## 客户端排行（appname @ IP）\n\n| 客户端 | 语句数 | 累计耗时 | 最大 |\n|---|---:|---:|---:|\n")
		for _, r := range v.Clients {
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n", mdEsc(r.User), fmtInt(r.Count), fmtDur(r.Sum), fmtDur(r.Max))
		}
		fmt.Fprintln(w)
	}

	if len(v.Tables) > 0 {
		fmt.Fprintf(w, "## 热表 Top%d\n\n> 表名取自 SQL 文本（FROM/JOIN/INSERT INTO/UPDATE/DELETE FROM 等位置），已去 schema、统一大写；"+
			"一条语句涉及多张表时每张表各计一次，故耗时占比之和可能超过 100%%。\n> 含数据字典视图与临时表（USER_/DBA_/V$/TMP_ 开头），不关心可用 `-E` 排除。\n\n| 表名 | 语句数 | 读 | 写 | 读写比 | 累计耗时 | 最大 | 耗时占比 |\n|---|---:|---:|---:|---:|---:|---:|---:|\n", len(v.Tables))
		for _, r := range v.Tables {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				r.Table, fmtInt(r.Count), fmtInt(r.Reads), fmtInt(r.Writes), ratioDisp(r.RW),
				durOrDash(r.Sum), durOrDash(r.Max), pctStr(r.Pct, r.Sum))
		}
		fmt.Fprintln(w)
	}

	if v.SpanSec > 0 {
		fmt.Fprintf(w, "## 吞吐与时轴（QPS / TPS）\n\n> QPS 只统计**有耗时**的语句事件（排除 `[ORA]` 仅解析未执行的行），与耗时口径一致。\n\n")
		if v.qpsUnderReported() {
			fmt.Fprintf(w, "> ⚠ **QPS 被严重低估，不要与 TPS 横向比较。** 本批日志有事务结束事件 %s 条，"+
				"却只记录到 SQL 语句 %s 条（每 1 条 SQL 伴随约 %.0f 条 COMMIT/ROLLBACK）—— "+
				"QPS 只是「日志里记到的语句数」，不是业务真实吞吐。详见 HTML 报告的同一节。\n\n",
				fmtInt(v.Commits+v.Rollbacks), fmtInt(v.Exec), v.trxPerSQL())
		}
		fmt.Fprintf(w, "| 指标 | 数值 |\n|---|---|\n")
		fmt.Fprintf(w, "| 日志时段 | %s |\n", mdEsc(spanText(v)))
		fmt.Fprintf(w, "| 平均 QPS | %.2f 条/秒 |\n", v.AvgQPS)
		fmt.Fprintf(w, "| 峰值 QPS | %s 条/秒 @ %s |\n", fmtNum(v.PeakQPS), v.PeakQPSAt)
		if v.Commits+v.Rollbacks > 0 {
			fmt.Fprintf(w, "| 平均 TPS | %.2f 事务/秒（按 COMMIT） |\n", v.AvgTPS)
			fmt.Fprintf(w, "| 峰值 TPS | %s 事务/秒 @ %s |\n", fmtNum(v.PeakTPS), v.PeakTPSAt)
			fmt.Fprintf(w, "| 事务结束事件 | COMMIT %s / ROLLBACK %s（回滚率 %.2f%%） |\n",
				fmtInt(v.Commits), fmtInt(v.Rollbacks), v.RollbackPct)
		} else {
			fmt.Fprintf(w, "| 事务结束事件 | 未发现（掩码 29 未开或该时段无提交，TPS 无法计算） |\n")
		}
		fmt.Fprintf(w, "| 有事件的秒数 | %s / 共约 %.0f 秒 |\n", fmtInt(v.SecCovered), v.SpanSec)
		if v.LongestIdle > 0 {
			fmt.Fprintf(w, "| 最长静默空档 | %s（起于 %s） |\n", fmtDur(v.LongestIdle*1000), v.LongestIdleAt)
		}
		fmt.Fprintln(w)

		if len(v.Buckets) > 0 { // 负载趋势：一行字符图给形态，完整时间轴走 Excel 交付件
			vals := make([]int64, 0, len(v.Buckets))
			for _, b := range v.Buckets {
				vals = append(vals, b.SQL)
			}
			fmt.Fprintf(w, "### 负载时间分布（%s 粒度 × %d 个时段）\n\n> 横轴按时间顺序（左起 %s，右至 %s），每格代表一个时段，高度为该时段 SQL 数的相对量；`·` 表示该时段无事件。\n> "+
				"完整时间轴见 Excel 交付件的「时段分布」工作表（加 `-e 交付.xlsx`）。\n\n```text\n%s\n```\n\n",
				v.BucketUnit, v.BucketCount, v.Buckets[0].TS, v.Buckets[len(v.Buckets)-1].TS, sparkline(vals, 120))
			if v.PeakBucket != nil {
				fmt.Fprintf(w, "> 峰值时段 **%s**：%s 条 SQL · 平均 QPS %.2f · 累计耗时 %s。\n\n",
					v.PeakBucket.TS, fmtInt(v.PeakBucket.SQL), v.PeakBucket.QPS, durOrDash(v.PeakBucket.SumMS))
			}
		}

		if len(v.BucketsTop) > 0 {
			fmt.Fprintf(w, "### 高峰时段 Top%d\n\n> 按 SQL 数排序；按时间顺序的完整形态见上面的趋势图。\n\n| # | 时段 | SQL 数 | 平均 QPS | 累计耗时 | COMMIT | ROLLBACK | 占比 |\n|---:|---|---:|---:|---:|---:|---:|---:|\n", len(v.BucketsTop))
			for i, r := range v.BucketsTop {
				fmt.Fprintf(w, "| %d | %s | %s | %.2f | %s | %s | %s | %.1f%% |\n",
					i+1, r.TS, fmtInt(r.SQL), r.QPS, durOrDash(r.SumMS), fmtInt(r.Commit), fmtInt(r.Rollback), r.Pct)
			}
			fmt.Fprintln(w)
		}
	}

	if len(v.Trxs) > 0 || v.TrxOpenN > 0 {
		fmt.Fprintf(w, "## 长事务 Top%d\n\n> 口径：同一 trxid 的首次事件 → 末次事件（事件＝该事务的语句，以及掩码 29 的 `TRX: START`）。\n", len(v.Trxs))
		if v.Commits+v.Rollbacks > 0 {
			fmt.Fprintf(w, "> 注：`COMMIT`/`ROLLBACK` 行的 trxid 通常为 0，无法与 `START` 关联，故无法判定单个事务是否已提交，跨度只到该事务最后一条语句为止。\n")
		}
		fmt.Fprintf(w, "\n| trxid | 用户 | 跨度 | SQL 执行耗时 | 利用率 | 语句数 | 起始 | 结束 |\n|---|---|---:|---:|---:|---:|---|---|\n")
		for _, r := range v.Trxs {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
				r.Trx, trxUserOf(v, r.Trx), fmtDur(r.SpanMS), durOrDash(r.ExecMS), utilDisp(r.Util),
				fmtInt(r.Count), r.First, r.Last)
		}
		fmt.Fprintf(w, "\n> 利用率 = 该事务内 SQL 的累计执行耗时 ÷（事务跨度 + 首条 SQL 耗时）。**利用率低 = 占着事务不干活**"+
			"（长时间持锁、应用侧没提交），比「SQL 慢」更该先处理。\n")
		if v.TrxStmtN > 0 {
			fmt.Fprintf(w, "\n### 每事务语句数分布（共 %s 个事务，中位数 %d 条）\n\n| 每事务语句数 | 事务数 | 占比 |\n|---|---:|---:|\n",
				fmtInt(v.TrxStmtN), v.TrxStmtMed)
			for i, n := range v.TrxStmtHist {
				fmt.Fprintf(w, "| %s | %s | %.1f%% |\n", trxStmtNames[i], fmtInt(n), pct(n, v.TrxStmtN))
			}
			fmt.Fprintf(w, "\n> 口径：同一 trxid 内的**执行语句**条数（`TRX: START` 不计）。"+
				"「1 条」占比高 = 应用在**逐条提交**（批量导入慢的头号原因）；「>1000 条」= 大事务，注意 undo 与持锁。\n")
		}
		if v.TrxOpenN > 0 {
			fmt.Fprintf(w, "\n另有 **%s** 个事务只见 `TRX: START`、后续无语句或结束事件（可能仍未提交 / 日志被截断）。\n", fmtInt(v.TrxOpenN))
		}
		fmt.Fprintf(w, "\n**看某个事务里到底是哪些 SQL**：")
		if v.FullSQLPath != "" {
			fmt.Fprintf(w, "配套文件已列出这些事务的全部语句 —— `%s`；", v.FullSQLPath)
		}
		if len(v.Trxs) > 0 {
			fmt.Fprintf(w, "也可单独抽取：`dmsqlq <同一路径> -x %s -N -o trx_%s.sql`。", v.Trxs[0].Trx, v.Trxs[0].Trx)
		}
		fmt.Fprintln(w)
	}

	// 锁等待（与长事务不是一回事）
	fmt.Fprintf(w, "## 锁等待（掩码 29）\n\n")
	if v.LockN == 0 {
		if !v.Mask29On {
			fmt.Fprintf(w, "**这一节没有数据，不等于没有锁等待。** 本批日志里 `TRX:` / `DLCK` / `LOCK_TID` "+
				"三类行全为 0，判定采集侧 `SQL_TRACE_MASK` 缺 **29**（位号 29 = 记录事务相关事件，含锁类型与锁等待时间）。\n\n"+
				"**判据**：29 一旦开启，事务事件行必然大量出现 —— 实测现网库有 **394 万**条 `TRX: START`、"+
				"本机实例有 **30 万**条 `DLCK`；一条都没有，只能是没开，而不是「这段没锁竞争」。\n\n"+
				"**要这一维度**：把 29 打开后重新采集。短期替代：在库上查 `V$TRXWAIT` / `V$LOCK`。\n\n")
		} else if v.DlckN > 0 {
			fmt.Fprintf(w, "未发现真实锁等待（无 `LOCK_TID … wait for` 行）—— 位号 29 已开"+
				"（日志里有 %s 条事务事件与 %s 条 `DLCK` 计时行），所以这个 0 是可信的："+
				"该时段**确实没有发生锁竞争**。\n\n", fmtInt(v.TrxEventN+v.TrxEndN), fmtInt(v.DlckN))
		} else {
			fmt.Fprintf(w, "未发现真实锁等待；位号 29 已开（日志里有事务事件行），该时段确实无锁竞争。\n\n")
		}
	} else {
		fmt.Fprintf(w, "| 指标 | 数值 |\n|---|---|\n")
		fmt.Fprintf(w, "| 锁等待事件 | %s 次 |\n", fmtInt(v.LockN))
		fmt.Fprintf(w, "| 累计等待 | %s（平均 %s） |\n", fmtDur(v.LockSumMS), fmtDur(v.LockSumMS/float64(max64(v.LockN, 1))))
		fmt.Fprintf(w, "| 最长等待 | %s |\n", fmtDur(v.LockMaxMS))
		fmt.Fprintf(w, "| 涉及表数 | %d 张（按表 ID） |\n", v.LockTableN)
		if v.LockPeakN > 0 {
			extra := ""
			if v.LockPeakIsTop {
				extra = " ← 正好是 QPS 峰值那一秒"
			}
			fmt.Fprintf(w, "| 等待最密的一秒 | %s（%d 次等待，该秒 QPS %d）%s |\n", v.LockPeakAt, v.LockPeakN, v.LockPeakQPS, extra)
		}
		fmt.Fprintln(w)

		var t int64
		for _, n := range v.LockHist {
			t += n
		}
		fmt.Fprintf(w, "| 等待时长 | 次数 | 占比 |\n|---|---:|---:|\n")
		for i, n := range v.LockHist {
			fmt.Fprintf(w, "| %s | %s | %.1f%% |\n", lockNames[i], fmtInt(n), pct(n, t))
		}
		fmt.Fprintln(w)

		fmt.Fprintf(w, "### 最久等待 Top%d\n\n> 持有方用户靠「事务号 → 用户」反查（日志的锁行只带等待方会话信息），查不到显示 `?`。\n\n"+
			"| # | 等待时长 | 锁模式 | 对象 | 等待方（trxid / 用户） | 持有方（谁在持锁） | 被等事务数 | 时间 |\n|---:|---:|---|---|---|---|---:|---|\n", len(v.LockRows))
		for i, lk := range v.LockRows {
			fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s | %d | %s |\n",
				i+1, fmtDur(lk.MS), lk.Mode, mdEsc(lockObj(lk.Table, lk.TableID)),
				mdEsc(lockParty(lk.Waiter, lk.WaiterU)), mdEsc(lockParty(lk.Holder, lk.HolderU)),
				lk.Waiters, shortTS(lk.TS))
		}
		fmt.Fprintln(w)

		// 阻塞链 + 双方 SQL（V2.8）：与 HTML 同一份数据，这里给 Markdown 版
		if len(v.LockChains) > 0 {
			fmt.Fprintf(w, "### 阻塞链 Top%d\n\n> 一条链 = 一个根事务堵住的一串等待。"+
				"**链越长越该先动根事务** —— 它的持锁时长就是后面所有人的等待时长。\n"+
				"（根事务 = 日志 `trx[…]` 列表的第一个；日志在队列过长时会截断成 `...more`。）\n\n", len(v.LockChains))
			fmt.Fprintf(w, "| # | 对象 | 根事务（真正持锁者） | 根事务用户 | 最长等待 | 等待次数 | 链长 | 波及时段 | 等待方用户 |\n"+
				"|---:|---|---|---|---:|---:|---:|---|---|\n")
			for i, c := range v.LockChains {
				fmt.Fprintf(w, "| %d | %s | `%s` | %s | %s | %s | %d | %s | %s |\n",
					i+1, mdEsc(lockObj(c.Table, c.TableID)), c.Root, mdEsc(dash(c.RootUser)),
					fmtDur(c.MaxMS), fmtInt(c.Count), c.ChainLen, c.Span, mdEsc(strings.Join(c.WaiterUsers, " ")))
			}
			fmt.Fprintln(w)
		}
		if len(v.LockRowsAll) > 0 {
			if len(v.LockGuide) > 0 {
				io.WriteString(w, "### 排查方向（按日志能证实的顺序，逐条缩小范围）\n\n"+
					"> 每一步先给**日志能证实的事实**，再给怎么读，最后给往哪儿查。"+
					"标了**推断**的地方是形态推断 —— 日志能证明现象，**证明不了原因**。\n\n")
				for _, g := range v.LockGuide {
					fmt.Fprintf(w, "**%d. %s**\n\n", g.Step, g.Title)
					if g.Fact != "" {
						fmt.Fprintf(w, "- **实测**：%s\n", oneLine(g.Fact))
					}
					if g.Note != "" {
						fmt.Fprintf(w, "- **推断**：%s\n", oneLine(g.Note))
					}
					if g.Next != "" {
						fmt.Fprintf(w, "- **往哪查**：%s\n", oneLine(g.Next))
					}
					io.WriteString(w, "\n")
				}
			}
			fmt.Fprintf(w, "### 锁等待双方的 SQL（全量 %d 条）\n\n> 等待方 SQL 取到 **%d/%d**，持有方 SQL 取到 **%d/%d**。"+
				"取不到**不是解析问题、也不是采集位没开全**：**最常见成因是「语句执行很快、执行完成行被 `MIN_EXEC_TIME` 滤掉了」**"+
				"（133 构造实验实测），次因是「语句执行中被中止」；两者都不是「没执行」。"+
				"若采集掩码含**位 27（原始语句）**，本工具会自动从 `[ORA]` 行把 SQL 找回并标出来源；"+
				"否则复现时抓 `V$SESSIONS.SQL_TEXT` / `V$TRXWAIT`。\n\n",
				v.LockTotalN, v.LockWaiterSQLN, v.LockTotalN, v.LockHolderSQLN, v.LockTotalN)
			for i, lk := range v.LockRowsAll {
				root := lk.HolderRoot
				if root == "" {
					root = lk.Holder
				}
				fmt.Fprintf(w, "**#%d　等待 %s　%s　%s 锁　%s**\n\n", i+1, fmtDur(lk.MS),
					mdEsc(lockObj(lk.Table, lk.TableID)), lk.Mode, shortTS(lk.TS))
				if lk.WaiterSQL != "" {
					fmt.Fprintf(w, "- 等待方 `trx[%s]`（%s）：`%s`\n", lk.Waiter, mdEsc(dash(lk.WaiterU)),
						strings.ReplaceAll(clipCell(lk.WaiterSQL, 400), "`", "'"))
				} else {
					fmt.Fprintf(w, "- 等待方 `trx[%s]`：语句只见开始、没有完成行（非「没执行」）\n", lk.Waiter)
				}
				if len(lk.HolderStmts) > 0 {
					for _, sm := range lk.HolderStmts {
						src := ""
						if lk.HolderSQLFromORA {
							src = "（**来源：掩码 27 的 `[ORA]` 原始语句行** —— 该语句执行很快，完成行被 `MIN_EXEC_TIME` 滤掉了）"
						}
						fmt.Fprintf(w, "- 持有方 `trx[%s]`（链首）：[%s] `%s` %s\n", root, sm.Op,
							strings.ReplaceAll(clipCell(sm.SQL, 400), "`", "'"), src)
					}
				} else {
					fmt.Fprintf(w, "- 持有方 `trx[%s]`（链首）：日志里没有它的 SQL 文本。成因通常是"+
						"「**语句执行很快、完成行被 `MIN_EXEC_TIME` 滤掉**」或「执行中被中止」"+
						"—— 都不是「没执行」；若采集掩码含位 27（原始语句），本工具会自动找回前者\n", root)
				}
				act := "结局未知（日志里未见 COMMIT/ROLLBACK）"
				switch lk.HolderKind {
				case "ROLLBACK":
					act = "结局：**回滚**（" + shortTS(lk.HolderEndTS) + "）"
				case "COMMIT":
					act = "结局：**提交**（" + shortTS(lk.HolderEndTS) + "）"
				}
				if lk.HolderKind != "" {
					fmt.Fprintf(w, "- %s\n", act)
				} else {
					fmt.Fprintf(w, "- %s\n", act)
				}
				if len(lk.Chain) > 1 {
					fmt.Fprintf(w, "- 排队：`trx[%s]` 后面还有 **%d** 个事务（%s）\n",
						root, len(lk.Chain)-1, mdEsc(strings.Join(lk.Chain[1:], ", ")))
				}
				fmt.Fprintln(w)
			}
		}

		fmt.Fprintf(w, "### 被争抢的表 Top%d（按累计等待）\n\n| 对象 | 次数 | 累计等待 | 最长 | 锁模式 | 等待方用户 | 最长一次发生在 |\n|---|---:|---:|---:|---|---|---|\n", len(v.LockTables))
		for _, r := range v.LockTables {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s |\n",
				mdEsc(lockObj(r.Table, r.TableID)), fmtInt(r.Count), fmtDur(r.Sum), fmtDur(r.Max),
				r.Mode, mdEsc(r.Waiters), r.MaxAt)
		}
		fmt.Fprintln(w)
		if v.RefSQL != "" {
			fmt.Fprintf(w, "> **表名怎么来**：DM 的 SQL 日志只记对象 ID、不记表名。复制执行下面这条即可反查：\n>\n> ```sql\n%s\n```\n>\n> 拿到结果存成文本文件（UTF-8），再加 `--obj-map 文件名` 重跑，报告就会直接显示表名。\n\n", v.RefSQL)
		}

		if v.DlckN > 0 {
			fmt.Fprintf(w, "另：`DLCK` 锁操作计时行 %s 条（`used time>0` 的 %s 条，最大 %s）——节点自身耗时，不是等待。\n\n",
				fmtInt(v.DlckN), fmtInt(v.DlckNonZero), fmtDur(v.DlckMaxMS))
		}
	}

	if len(v.Dangers) > 0 || len(v.Changes) > 0 {
		fmt.Fprintf(w, "## 审计与恢复定位（危险操作 / 结构变更）\n\n")
		if len(v.Dangers) > 0 {
			ds, _ := auditSlice(v, opt)
			fmt.Fprintf(w, "**高危操作** 共 %s 条（下表列出最近 %d 条，时间倒序）\n\n",
				fmtInt(v.DangerN), len(ds))
			fmt.Fprintf(w, "| # | 时间 | 类型 | 对象 | 用户 | 客户端 | 影响行数 | 线程 | 最近提交 LSN | 状态 |\n")
			fmt.Fprintf(w, "|---:|---|---|---|---|---|---:|---|---|---|\n")
			for i, r := range ds {
				st := "已执行"
				if r.ORAOnly {
					st = "**仅解析未执行**"
				}
				lsn := r.LSNAt
				if lsn != "" {
					lsn = fmt.Sprintf("`%s` @ %s", lsn, shortTS(r.LSNTS))
				}
				fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n",
					i+1, auditTS(r.TS), mdEsc(r.Kind), mdEsc(r.Object), mdEsc(r.User),
					mdEsc(r.Client), rowsDisp(r.Rows), r.Thrd, lsn, st)
			}
			fmt.Fprintln(w)
			if v.DangerORA > 0 {
				fmt.Fprintf(w, "> **仅解析未见执行 %s 条**：语句已到达服务器、完成了语法解析，"+
					"但没有对应的执行行 —— 常见于权限不足、超时、客户端取消、事务回滚。"+
					"**「有人试图这么干」本身就是证据**，所以这一类也留在清单里。\n\n", fmtInt(v.DangerORA))
			}
			if len(v.ObjRisk) > 0 {
				fmt.Fprint(w, "> 被反复操作的对象：")
				for i, o := range v.ObjRisk {
					if i > 0 {
						fmt.Fprint(w, " · ")
					}
					fmt.Fprintf(w, "`%s` %d 次", o.Name, o.Count)
				}
				fmt.Fprintln(w)
				fmt.Fprintln(w)
			}
			if v.Dangers[0].AuditSQL != "" {
			}
		}
		if len(v.Changes) > 0 {
			_, cs := auditSlice(v, opt)
			fmt.Fprintf(w, "**结构变更** Top%d（共 %s 条，时间倒序）\n\n", len(cs), fmtInt(v.ChangeN))
			fmt.Fprintf(w, "| # | 时间 | 类型 | 对象 | 用户 | 客户端 |\n|---:|---|---|---|---|---|\n")
			for i, r := range cs {
				fmt.Fprintf(w, "| %d | %s | %s | %s | %s | %s |\n",
					i+1, auditTS(r.TS), mdEsc(r.Kind), mdEsc(r.Object), mdEsc(r.User), mdEsc(r.Client))
			}
			fmt.Fprintln(w)
			if len(v.ChangeSum) > 0 {
				fmt.Fprint(w, "> 变更类型统计：")
				for i, c := range v.ChangeSum {
					if i > 0 {
						fmt.Fprint(w, " · ")
					}
					fmt.Fprintf(w, "%s %s", c.Name, fmtInt(c.Count))
				}
				fmt.Fprintln(w)
				fmt.Fprintln(w)
			}
		}
		fmt.Fprintf(w, "> %s\n>\n> 完整语句（含参数还原）见配套附件的「4) 审计明细」；"+
			"只要审计命中的语句可加 `-d`。\n\n", auditFootNote(v))
	}

	if cr := configCheck(v); len(cr) > 0 {
		fmt.Fprintf(w, "## 采集配置体检（据日志内容反推 sqllog.ini）\n\n")
		fmt.Fprintf(w, "| 检查项 | 实测 | 结论 / 怎么改 |\n|---|---|---|\n")
		for _, r := range cr {
			fmt.Fprintf(w, "| %s | %s | %s |\n", mdEsc(r.Item), mdEsc(r.Value), mdEsc(r.Advice))
		}
		fmt.Fprintln(w)
	}

	if len(v.Hints) > 0 {
		fmt.Fprintf(w, "## 判读提示\n\n")
		for _, h := range v.Hints {
			fmt.Fprintf(w, "- %s\n", h)
		}
		fmt.Fprintln(w)
	}
}

// ---------------------------------------------------------------- HTML 报告
//
// 为什么报告用 HTML 而不是 Excel：
//
//	· Excel 需要第三方库（Go 标准库不支持 xlsx），一引入就破坏"单文件零依赖"这个前提；
//	· HTML 单文件自带样式与图表，浏览器直接打开、能发邮件、能 Ctrl+P 出 PDF，不装任何东西；
//	· 需要 Excel 的话，Markdown 表格或 CSV 更合适（便于二次加工），HTML 负责"看"。
const htmlStyle = `<style>
:root{--bg:#f6f8fb;--card:#fff;--line:#e2e8f0;--ink:#1e293b;--dim:#64748b;
      --blue:#2563eb;--sky:#0ea5e9;--amber:#d97706;--red:#dc2626}
*{box-sizing:border-box}
body{margin:0;padding:28px 18px 60px;background:var(--bg);color:var(--ink);
     font:14px/1.65 "Segoe UI","Microsoft YaHei",-apple-system,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto}
h1{font-size:22px;margin:0 0 6px}
h2{font-size:16px;margin:30px 0 10px;padding-left:9px;border-left:4px solid var(--blue)}
h3{font-size:14px;margin:16px 0 6px;color:#334155}
.sub{color:var(--dim);font-size:13px;margin-bottom:14px}
.meta{display:grid;grid-template-columns:auto 1fr;gap:2px 14px;font-size:13px;color:var(--dim);margin:0 0 14px}
.meta dt{color:#94a3b8;white-space:nowrap}
.meta dd{margin:0;color:#475569;min-width:0}
.meta .k{color:var(--ink);font-weight:600}
.meta code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(124px,1fr));gap:10px;margin:14px 0 6px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;min-width:0}
.kpi b{display:block;font-size:19px;font-weight:600;letter-spacing:.2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kpi span{display:block;color:var(--dim);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kpi.warn{border-color:#fcd34d;background:#fffbeb;border-left:3px solid var(--amber)}
.kpi.warn b{color:#b45309}
.kpi.risk{border-left:3px solid var(--line)}
.kpi.na{background:#f8fafc;border-style:dashed;border-color:#cbd5e1}
.kpi.na b{color:#94a3b8}
.kpinote{margin:2px 0 10px;padding:7px 11px;background:#fffbeb;border:1px solid #fcd34d;
  border-left:3px solid var(--amber);border-radius:6px;font-size:12.5px;line-height:1.6;color:#92400e}
.kpinote code{background:#fff7ed;padding:1px 5px;border-radius:4px}
.hl{background:#fffbeb;border:1px solid #fcd34d;border-left:4px solid var(--amber);border-radius:6px;
    padding:8px 12px;margin:0 0 10px;font-size:13px;color:#92400e}
.hl.info{background:#eff6ff;border-color:#bfdbfe;border-left-color:var(--blue);color:#1e40af}
.warnbar{background:#fef2f2;border:1px solid #fecaca;border-left:4px solid var(--red);border-radius:6px;
    padding:8px 12px;margin:0 0 10px;font-size:13px;color:#991b1b;line-height:1.6}
.warnbar code{background:#fff1f2;padding:1px 5px;border-radius:4px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);
      border-radius:8px;overflow:hidden;font-size:13px;margin:6px 0}
th,td{padding:7px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#f1f5f9;font-weight:600;color:#334155;white-space:nowrap}
tr:last-child td{border-bottom:none}
tbody tr:nth-child(even){background:#fafcff}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
pre.sql{background:#0f172a;color:#e2e8f0;padding:10px 12px;border-radius:6px;overflow:auto;font-size:12.5px;line-height:1.6;margin:8px 0}
pre.sql code{background:none;color:inherit;padding:0}
code{background:#f1f5f9;padding:1px 5px;border-radius:4px;
     font:12px/1.55 Consolas,"Courier New",monospace;word-break:break-all}
.csvh{max-width:520px}
.csvh .tx{min-width:0;cursor:pointer}
.csvh .tx .one{display:block;overflow:hidden;text-overflow:ellipsis}
.csvh .tx .one:hover{color:var(--blue)}
.csvh .tx .hintcp{color:var(--dim);font-size:11px;font-weight:400}
.csvh .tx .full{display:none;white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;
  padding:8px 10px;border-radius:6px;font:12px/1.6 Consolas,"Courier New",monospace;margin-top:4px;
  max-height:420px;overflow:auto}
.csvh.open .tx .full{display:block}
.csvh .ops{display:flex;gap:4px;margin-top:4px}
.csvh button,.tbh button{font:11px/1 "Segoe UI","Microsoft YaHei",sans-serif;padding:4px 8px;border-radius:5px;
  border:1px solid var(--line);background:#fff;color:#475569;cursor:pointer;white-space:nowrap}
.csvh button:hover,.tbh button:hover{border-color:var(--blue);color:var(--blue)}
.csvh button.ok,.tbh button.ok{border-color:#16a34a;color:#16a34a}
.tbh{display:flex;align-items:baseline;gap:10px;margin:6px 0 2px}
.tbh .tbn{font-weight:600;color:#334155}
.tbh .tbhint{color:var(--dim);font-size:12px;flex:1}
.longnote{color:var(--dim);font-size:11px}
.muted{color:var(--dim)}
.tag{display:inline-block;padding:1px 8px;border-radius:999px;background:#eff6ff;color:#1d4ed8;font-size:12px}
.note{color:var(--dim);font-size:12px;margin:4px 0 8px}
.bars{margin:4px 0 2px}
.brow{display:flex;align-items:center;gap:10px;margin:3px 0}
.brow .lbl{flex:0 0 120px;color:#475569;font-size:12px;text-align:right;
           overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.brow .track{flex:1;background:#eef2f7;border-radius:4px;height:16px;overflow:hidden}
.brow .fill{display:block;height:100%;border-radius:4px;background:linear-gradient(90deg,var(--sky),var(--blue))}
.brow .fill.warn{background:linear-gradient(90deg,#f59e0b,var(--red))}
.brow .val{flex:0 0 104px;font-size:12px;color:#475569;font-variant-numeric:tabular-nums}
.hint{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--amber);
      border-radius:8px;padding:8px 14px;margin:8px 0}
.hint p{margin:6px 0}
footer{margin-top:34px;color:var(--dim);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
.chart{margin:10px 0 4px;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:6px 4px}
.chart svg{display:block;width:100%;height:auto}
.chart .grid{stroke:#eef2f7;stroke-width:1}
.chart .axis{stroke:#cbd5e1;stroke-width:1}
.chart .ax{fill:#64748b;font:11px "Segoe UI","Microsoft YaHei",Arial,sans-serif}
.chart .bl{fill:#93c5fd}
.chart .bl:hover{fill:#2563eb}
.chart .bl.pk{fill:#dc2626}
.chart .area{fill:rgba(37,99,235,.16);stroke:none}
.chart .line{fill:none;stroke:#2563eb;stroke-width:1.6;stroke-linejoin:round}
.adv{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--line);border-radius:8px;padding:11px 13px;margin:10px 0}
.adv.prio1{border-left-color:#dc2626;background:#fef2f2}
.adv.prio2{border-left-color:#f59e0b;background:#fffbeb}
.advh{display:flex;align-items:center;flex-wrap:wrap;gap:9px;margin-bottom:7px}
.advr{background:#334155;color:#fff;border-radius:5px;min-width:21px;height:21px;line-height:21px;text-align:center;font-size:12px;font-weight:600;padding:0 5px}
.adv.prio1 .advr{background:#dc2626}
.adv.prio2 .advr{background:#f59e0b}
/* 「等锁」用另一个色系：它不是"优先级更高的 SQL"，而是"这一类根本不该去改 SQL"——
   颜色区分开，读者才不会把它当成"最该优化的那条"。 */
.adv.prio3{border-left-color:#7c3aed;background:#f5f3ff}
.adv.prio3 .advr{background:#7c3aed}
.adv.prio3 .advp{background:#7c3aed;color:#fff}
/* 「锁等待排查方向」（V2.11）：把散在几十张卡片里的结论汇总成一条可执行的排查路径。
   视觉上做成"步骤流"，与上面的数据表区分开 —— 它是要照着做的，不是要读的。 */
.guide{margin:10px 0}
.gstep{background:var(--card);border:1px solid var(--line);border-left:3px solid #0891b2;
  border-radius:8px;padding:10px 13px;margin:9px 0}
.gst{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600;color:var(--ink);margin-bottom:6px}
.gsn{background:#0891b2;color:#fff;border-radius:5px;min-width:20px;height:20px;line-height:20px;
  text-align:center;font-size:12px;padding:0 5px;flex:0 0 auto}
.gf,.gn,.gx{font-size:13px;line-height:1.65;margin:3px 0;color:var(--ink)}
.gf b{color:#0e7490}
.gn{color:var(--dim)}
.gn b{color:#b45309}
.gx b{color:#15803d}
.gstep code{background:var(--code-bg,rgba(127,127,127,.14));padding:0 4px;border-radius:3px;font-size:12px}
.gstep pre{background:var(--code-bg,rgba(127,127,127,.14));padding:8px 10px;border-radius:6px;
  overflow-x:auto;font-size:12px;margin:5px 0}
.advp{font-size:12px;font-weight:600;padding:1px 8px;border-radius:10px;background:#e2e8f0;color:#334155}
.adv.prio1 .advp{background:#dc2626;color:#fff}
.adv.prio2 .advp{background:#f59e0b;color:#fff}
.advs{font-size:13px;color:var(--ink)}
.advs b{color:#b91c1c}
.advm{font-size:12px;color:var(--dim)}
.advg{font-size:13px;color:var(--ink);line-height:1.65;margin-top:3px}
.advg b{color:#475569}
.advq{margin-top:8px;background:#f8fafc;border:1px solid var(--line);border-radius:6px;padding:7px 9px;font-size:12px}
.winscope{color:#b45309;font-weight:600}
.wnote{margin-left:8px;font-weight:400;color:var(--dim);font-size:12px}
/* 长表折叠：tbody 里超出前 N 行的部分默认隐藏，避免一屏刷不完 */
table.fold tbody tr.hid{display:none}
table.fold.open tbody tr.hid{display:table-row}
.foldbar{display:flex;align-items:baseline;gap:10px;margin:2px 0 8px;color:var(--dim);font-size:12px}
.foldbar button{font:11px/1 "Segoe UI","Microsoft YaHei",sans-serif;padding:4px 10px;border-radius:5px;
  border:1px solid var(--line);background:#fff;color:#475569;cursor:pointer;white-space:nowrap}
.foldbar button:hover{border-color:var(--blue);color:var(--blue)}
.foldbar .fnote{flex:1}
/* 锁等待双方 SQL 卡片（V2.8）：一张卡 = 一次锁等待 */
.lkcard{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:8px 0;overflow:hidden}
.lkcard.hid{display:none}
.lkcards.open .lkcard.hid{display:block}
.lkhead{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;padding:7px 12px;
  background:#f8fafc;border-bottom:1px solid var(--line);font-size:12.5px}
.lkidx{font-weight:700;color:var(--blue)}
.lkwait{font-weight:700;color:#b45309}
.lktbl{color:#334155}
.lkmode{color:var(--dim)}
.lkts{margin-left:auto;color:var(--dim)}
.lkbody{display:grid;grid-template-columns:1fr 1fr;gap:0}
.lkside{padding:9px 12px;min-width:0}
.lkside+.lkside{border-left:1px dashed var(--line)}
.lksideh{font-size:12px;color:var(--dim);margin-bottom:6px}
.lkcard code{font-family:"Cascadia Mono",Consolas,"Courier New",monospace;font-size:12px;
  background:#f1f5f9;padding:1px 5px;border-radius:4px;word-break:break-all}
.lksql{margin:4px 0;line-height:1.6}
.lkop{font:600 11px/1 "Cascadia Mono",Consolas,monospace;color:#0369a1;background:#e0f2fe;
  padding:2px 5px;border-radius:4px;margin-right:4px}
.lkdur{color:var(--dim);font-size:11.5px;margin-left:5px}
.lkora{font-size:12px;color:#1e40af;background:#eff6ff;border-left:3px solid #3b82f6;padding:6px 9px;border-radius:4px;margin-top:6px;line-height:1.6}
.lkmiss{font-size:12px;color:#92400e;background:#fffbeb;border-left:3px solid var(--amber);
  border-radius:0 5px 5px 0;padding:6px 9px;line-height:1.6}
.lkend{margin-top:6px;font-size:12px;color:#334155}
@media (max-width:820px){.lkbody{grid-template-columns:1fr}
  .lkside+.lkside{border-left:none;border-top:1px dashed var(--line)}}
@media print{body{background:#fff;padding:0}.card,table,.hint{break-inside:avoid}h2{break-after:avoid}

  .tbh .tbhint,.tbh button{display:none}.csvh .ops{display:none}.csvh .tx .hintcp{display:none}.chart{break-inside:avoid}
  /* 打印/导出 PDF 时自动全展开：折叠只是屏读时的减法，不能影响归档件 */
  table.fold tbody tr.hid{display:table-row}
  .foldbar{display:none}
  .lkcard.hid{display:block}
  .lkcards .lkcard{break-inside:avoid}}
</style>
`

// ---------------------------------------------------------------- 负载时间图（内联 SVG）

// sparkline 把一串数值压成 Unicode 方块字符（▁▂▃▄▅▆▇█），供终端与 Markdown 用。
//
// 为什么用字符图：文本报告里逐时段列表格同样啰嗦（分钟粒度动辄上千行）。
// 一行 sparkline 就能看出"什么时候是高峰"，宽度可裁剪。
// 超过 width 时按「每格取最大」降采样 —— 用平均会把高峰抹平，那是这里最不能丢的信息。
func sparkline(vals []int64, width int) string {
	if len(vals) == 0 || width <= 0 {
		return ""
	}
	out := make([]int64, 0, width)
	if len(vals) <= width {
		out = append(out, vals...)
	} else {
		step := float64(len(vals)) / float64(width)
		for i := 0; i < width; i++ {
			lo := int(float64(i) * step)
			hi := int(float64(i+1) * step)
			if hi <= lo {
				hi = lo + 1
			}
			if hi > len(vals) {
				hi = len(vals)
			}
			if lo >= len(vals) {
				break
			}
			mx := int64(0)
			for _, v := range vals[lo:hi] {
				if v > mx {
					mx = v
				}
			}
			out = append(out, mx)
		}
	}
	var mx int64
	for _, v := range out {
		if v > mx {
			mx = v
		}
	}
	if mx <= 0 {
		return ""
	}
	blocks := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	for _, v := range out {
		if v <= 0 {
			b.WriteRune('·')
			continue
		}
		i := int(v) * (len(blocks) - 1) / int(mx)
		if i < 0 {
			i = 0
		}
		if i >= len(blocks) {
			i = len(blocks) - 1
		}
		b.WriteRune(blocks[i])
	}
	return b.String()
}

// renderLoadChartHTML 负载时间分布图：时段不多画柱状图，时段多改画折线（带面积）。
//
// 为什么换成图：「负载时间分布」原来是逐时段一行的表格 —— 分钟粒度下动辄上千行，
// 报告被撑得极长，反而看不出「什么时候是高峰」。换成一张按时间的图后形态一眼可见；
// **完整时间轴**交给 Excel 交付件的「时段分布」工作表（那才是要"完整"的地方）。
//
// 依旧是单文件、零依赖：直接内联 <svg>，不引任何图表库。
func renderLoadChartHTML(w io.Writer, v *statsView) {
	if len(v.Buckets) == 0 || v.PeakBucket == nil || v.PeakBucket.SQL <= 0 {
		return
	}
	const (
		cw, ch                 = 960.0, 250.0
		padL, padR, padT, padB = 66.0, 16.0, 14.0, 44.0
	)
	plotW, plotH := cw-padL-padR, ch-padT-padB
	n := len(v.Buckets)
	maxSQL := float64(v.PeakBucket.SQL)
	step := plotW / float64(n)
	xAt := func(i int) float64 { return padL + float64(i)*step }
	yAt := func(val int64) float64 { return padT + plotH*(1-float64(val)/maxSQL) }

	fmt.Fprintf(w, `<div class="chart"><svg viewBox="0 0 %.0f %.0f" preserveAspectRatio="xMidYMid meet" role="img" aria-label="负载时间分布">`, cw, ch)
	// 横向网格 + Y 轴刻度
	for i := 0; i <= 4; i++ {
		y := padT + plotH*float64(i)/4
		fmt.Fprintf(w, `<line class="grid" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>`, padL, y, cw-padR, y)
		fmt.Fprintf(w, `<text class="ax" x="%.1f" y="%.1f" text-anchor="end">%d</text>`,
			padL-8, y+3.5, int64(maxSQL*(1-float64(i)/4)))
	}
	fmt.Fprintf(w, `<line class="axis" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>`, padL, padT+plotH, cw-padR, padT+plotH)

	if n <= 150 { // 柱状图：桶数适中时最直观
		bw := step * 0.82
		if bw < 1.2 {
			bw = 1.2
		}
		for i, bk := range v.Buckets {
			if bk.SQL <= 0 { // 空桶留白 —— 采集中断/业务停顿要能看见
				continue
			}
			cls := "bl"
			if bk.SQL == v.PeakBucket.SQL {
				cls = "bl pk"
			}
			fmt.Fprintf(w, `<rect class="%s" x="%.2f" y="%.2f" width="%.2f" height="%.2f"><title>%s · %s 条 SQL · 累计 %s</title></rect>`,
				cls, xAt(i)+(step-bw)/2, yAt(bk.SQL), bw, padT+plotH-yAt(bk.SQL),
				hEsc(bk.TS), fmtInt(bk.SQL), durOrDash(bk.SumMS))
		}
	} else { // 折线 + 面积：桶数多到柱子细不可见时
		var ln, ar strings.Builder
		fmt.Fprintf(&ar, "M%.2f %.1f", xAt(0)+step/2, padT+plotH)
		for i, bk := range v.Buckets {
			x, y := xAt(i)+step/2, yAt(bk.SQL)
			fmt.Fprintf(&ln, "L%.2f %.2f", x, y)
			fmt.Fprintf(&ar, "L%.2f %.2f", x, y)
		}
		fmt.Fprintf(&ar, "L%.2f %.1fZ", xAt(n-1)+step/2, padT+plotH)
		fmt.Fprintf(w, `<path class="area" d="%s"/>`, ar.String())
		fmt.Fprintf(w, `<path class="line" d="%s"/>`, ln.String())
	}

	// X 轴刻度：首 / 1/4 / 中 / 3/4 / 末（去重，桶少时不会重影）
	seen := map[int]bool{}
	for _, i := range []int{0, n / 4, n / 2, n * 3 / 4, n - 1} {
		if i < 0 || i >= n || seen[i] {
			continue
		}
		seen[i] = true
		anchor := "middle"
		if i == 0 {
			anchor = "start"
		} else if i == n-1 {
			anchor = "end"
		}
		fmt.Fprintf(w, `<text class="ax" x="%.1f" y="%.1f" text-anchor="%s">%s</text>`,
			xAt(i)+step/2, padT+plotH+18, anchor, hEsc(v.Buckets[i].Label))
	}
	io.WriteString(w, `</svg></div>`)
}

// sqlExportScript 报告里「导出全部 TopN」的交互脚本（与 htmlScript 分开两个常量）。
//
// 数据来源：每张表后面挂一个 <script type="application/json" class="expdata">，
// 内容是 [[注释头, 完整SQL], ...]。这里只负责「读 JSON -> 拼文本 -> 触发下载」。
//
// 为什么用 <script type="application/json">：浏览器的 HTML 解析器不会把
// 它的内容当 JS 执行，也不会显示出来，天然是「隐藏的数据块」；相比 data-* 属性
// 免去了属性值里 &quot; &#10; 一堆转义的麻烦，几万字符的 SQL 也不用担心属性长度。
//
// 导出格式：每条语句前一行 `-- [#n] 耗时 ...`，语句本身把换行压成空格保持单行，
// 方便直接粘进 disql 或 grep。整个文件仍是合法 SQL（-- 是行注释）。
const sqlExportScript = `<script>
(function(){
  function q(sel, root){
    var r = document.querySelectorAll(sel);
    for (var i = 0; i < r.length; i++) if (root ? root.contains(r[i]) : true) return r[i];
    return null;
  }
  function payload(btn){
    var tb = btn.closest('.tbh');
    var host = tb ? tb.parentNode : document;
    var s = host.querySelector('script.expdata') || document.querySelector('script.expdata');
    if (!s) return null;
    try { return JSON.parse(s.textContent); } catch (e) { return null; }
  }
  function build(rows){
    var out = [];
    for (var i = 0; i < rows.length; i++) {
      var head = rows[i][0] || ('-- [#' + (i + 1) + ']');
      var sql = String(rows[i][1] || '').replace(/\s+/g, ' ').replace(/\s*;\s*$/, '');
      if (sql === '') continue;
      out.push(head);
      out.push(sql + ';');
      if (i !== rows.length - 1) out.push('');
    }
    return out.join('\n') + '\n';
  }
  function save(t, name){
    var blob = new Blob([t], {type: 'text/plain;charset=utf-8'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name || 'dmsqlq_top.sql';
    document.body.appendChild(a);
    a.click();
    setTimeout(function(){ URL.revokeObjectURL(a.href); document.body.removeChild(a); }, 0);
  }
  document.addEventListener('click', function(ev){
    var fb = ev.target.closest ? ev.target.closest('button[data-fold]') : null;
    if (fb) {
      ev.stopPropagation();
      // 从 .foldbar 往前找最近的 <table>（注意起点是 foldbar 自己，别从它的兄弟起跳）
      var tbl = fb.closest ? fb.closest('.foldbar') : null;
      tbl = tbl ? tbl.previousElementSibling : null;
      while (tbl && tbl.tagName !== 'TABLE') tbl = tbl.previousElementSibling;
      if (!tbl) return;
      var opening = !tbl.classList.contains('open');
      tbl.classList.toggle('open', opening);
      var note = fb.parentNode.querySelector('.fnote');
      var n = fb.getAttribute('data-fold');
      if (opening) {
        fb.textContent = '收起';
        if (note) note.textContent = '已展开全部 ' + n + ' 行，点击收起。';
      } else {
        fb.textContent = '展开全部 ' + n + ' 行';
        if (note) note.textContent = '默认只显示前几行，点击展开全部；打印 / 导出 PDF 时自动全部展开。';
      }
      return;
    }
    var btn = ev.target.closest ? ev.target.closest('button[data-exp]') : null;
    if (!btn) return;
    ev.stopPropagation();
    var rows = payload(btn);
    if (!rows || !rows.length) return;
    save(build(rows), btn.getAttribute('data-exp'));
    var old = btn.getAttribute('data-label') || btn.textContent;
    btn.setAttribute('data-label', old);
    btn.textContent = '已导出 ' + rows.length + ' 条';
    btn.className = 'ok';
    setTimeout(function(){ btn.textContent = old; btn.className = ''; }, 1600);
  });
})();
</script>
`

// htmlScript 报告里「完整 SQL」的交互脚本。
//
// 设计取舍：报告要单文件、零依赖、双击就能看，所以不引任何外部库。
// 复制优先用 navigator.clipboard（需要 https 或 localhost），本地 file:// 打开时会被
// 浏览器策略拒绝，因此保留 execCommand('copy') + 隐藏 textarea 的降级路径 ——
// 这正是本项目最常见的用法（日志和报告都在本机，直接双击打开）。
const htmlScript = `<script>
(function(){
  function copyText(t, btn){
    var done = function(ok){
      var old = btn.getAttribute('data-label') || btn.textContent;
      btn.setAttribute('data-label', old);
      btn.textContent = ok ? '已复制' : '复制失败';
      btn.className = ok ? 'ok' : '';
      setTimeout(function(){ btn.textContent = old; btn.className = ''; }, 1400);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(t).then(function(){ done(true); }, function(){ done(fallback(t)); });
    } else {
      done(fallback(t));
    }
  }
  function fallback(t){
    var ta = document.createElement('textarea');
    ta.value = t;
    ta.setAttribute('readonly','');
    ta.style.position = 'fixed';
    ta.style.top = '-2000px';
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }
  function save(t, name){
    var blob = new Blob([t], {type: 'text/plain;charset=utf-8'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name || 'dmsqlq_stmt.sql';
    document.body.appendChild(a);
    a.click();
    setTimeout(function(){ URL.revokeObjectURL(a.href); document.body.removeChild(a); }, 0);
  }
  function toggle(box){
    box.classList.toggle('open');
  }
  document.addEventListener('click', function(ev){
    var btn = ev.target.closest ? ev.target.closest('button[data-act]') : null;
    if (btn) {
      var box = btn.closest('.csvh');
      var pre = box.querySelector('.full');
      var act = btn.getAttribute('data-act');
      if (act === 'copy') copyText(pre.textContent, btn);
      ev.stopPropagation();
      return;
    }
    var tx = ev.target.closest ? ev.target.closest('.csvh .tx') : null;
    if (tx) toggle(tx.closest('.csvh'));
  });
  document.addEventListener('keydown', function(ev){
    if (ev.key !== 'Escape') return;
    var all = document.querySelectorAll('.csvh.open');
    for (var i = 0; i < all.length; i++) all[i].classList.remove('open');
  });
})();
</script>
`

// hBar HTML 条形图的一行
type hBar struct {
	Label string
	Note  string
	Pct   float64 // 条长（0~100，相对本组最大值）
	Warn  bool
}

// hEsc HTML 转义
// oneLine 把文案压成单行：去掉换行（终端里用 wrapIndent 自己折）、
// 去掉 Markdown 的粗体/代码标记（终端不渲染，留着反而占宽度）。
func oneLine(s string) string {
	// 先摘掉代码围栏：去掉反引号后会剩下个孤零零的 "sql"
	s = strings.ReplaceAll(s, "```sql", " ")
	s = strings.ReplaceAll(s, "```", " ")
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "`", "")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Join(strings.Fields(s), " ")
}

// wrapIndent 按「显示宽度」折行留白：中文算 2 列，ASCII 算 1 列。
// 终端里 long line 折行后没有缩进，会与下一条挤在一起 —— 这里手工折，
// 保证续行也带缩进，读起来连成一整段。
func wrapIndent(s string, indent, width int) string {
	pad := strings.Repeat(" ", indent)
	var b strings.Builder
	col := 0
	line := 0
	for _, r := range s {
		w := 1
		if r > 0x2E80 { // 粗略：CJK 及全角符号占两列
			w = 2
		}
		if col+w > width-indent {
			b.WriteString("\n")
			b.WriteString(pad)
			col = 0
			line++
		}
		b.WriteRune(r)
		col += w
	}
	_ = line
	return b.String()
}

// mdInline 把诊断文案里的 **粗体** 与 `等宽` 转成 HTML。
//
// 输入是工具自己生成的受限 Markdown（只有这两种标记），所以不需要完整解析器；
// 但**必须先转义 HTML** —— 文案里含 `V$SESSIONS`、`<` 之类字符，
// 不转义会破坏页面结构（这类"文本里有尖括号"的坑在报告里踩过）。
func mdInline(s string) string {
	s = hEsc(s)
	var b strings.Builder
	b.Grow(len(s) + 32)
	strong, code := false, false
	for i := 0; i < len(s); {
		switch {
		case !code && strings.HasPrefix(s[i:], "**"):
			if strong {
				b.WriteString("</b>")
			} else {
				b.WriteString("<b>")
			}
			strong = !strong
			i += 2
		case !strong && s[i] == '`':
			if code {
				b.WriteString("</code>")
			} else {
				b.WriteString("<code>")
			}
			code = !code
			i++
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	// 标记没配平时补上收尾，避免留下未闭合标签
	if strong {
		b.WriteString("</b>")
	}
	if code {
		b.WriteString("</code>")
	}
	return b.String()
}

func hEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// expData 一张表的批量导出描述。
//
// 为什么导出要挂在「表」上而不是「行」上：报告里的 SQL 是按类别归堆的
// （最慢语句 / 最耗时模板 / 高危操作），使用者真正想拿走的往往是「这一类全部」，
// 而不是某一条 —— 逐行按钮既占地方又要点很多次。所以 V1.9 把逐行「存为 .sql」
// 换成表头的「导出全部 TopN」。
type expData struct {
	Title string      // 工具条上的小标题，如「最慢语句 Top10」
	Hint  string      // 右侧灰字说明（已是安全 HTML，允许内嵌 <b> 等）
	File  string      // 下载文件名，如 slow_top10.sql
	Rows  [][2]string // 每行：[0]=注释头，[1]=完整 SQL
}

// dash 注释头里的空值占位：字段为空时写 "-"，免得注释头出现「用户  行数 」这种空档。
func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// expJSON 把导出数据编成 JSON 数组，塞进 <script type="application/json">。
//
// 输出结构是**二维数组** [["注释头","SQL"], ...]，必须与 JS 侧 build() 的
// rows[i][0] / rows[i][1] 取值方式一致 —— 早先这里错写成扁平 [头,SQL,头,SQL]，
// 结果 rows[i] 是个字符串、rows[i][0] 只取到首字符，导出内容全变成 "-" / "S"。
// 改动这里务必同步改 sqlExportScript 里的 build()。
//
// 关键：必须让 JSON 里绝不出现字面量 "</"（尤其是 "</script"），否则 SQL 里一旦
// 出现（注释或字符串里很可能有）就会被 HTML 解析器当成 script 结束标签，后面的
// 数据全丢、页面结构也会崩。json.Marshal 恰好默认就把 < > & 转成 \u003c \u003e
// \u0026，`</script>` 这一类序列天然被打散，所以直接用 json.Marshal 就够了 ——
// 自己再手写一层 "\/" 转义反而会写进非法 JSON（"\/" 在 Go 字符串字面量里也不是
// 合法转义）。这也是为什么用 JSON 文件块而不是 data-* 属性。
func expJSON(rows [][2]string) string {
	pairs := make([][2]string, len(rows))
	copy(pairs, rows)
	b, err := json.Marshal(pairs)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// sqlCell 表格里的「完整 SQL」单元格：摘要常显（太长自动省略号），
// 点击行内展开全文、悬停有 title 预览、[复制] 一键复制可执行语句。
//
// 为什么要把全文内嵌进 HTML：报告本来就要发给别人看，SQL 只给摘要时对方得再找
// 配套附件、靠序号人工对应。内嵌后「看到即拿到」，报告仍是单文件、零依赖。
// 体积由 inlineBudget 兜底：超出后只保留摘要 + 悬停预览，并提示去看配套附件。
//
// 展开方式只有一种：点摘要文字（行内展开）。早先还有 [展开]/[收起] 按钮，与
// 点击文字功能完全重复，V1.9 已去掉；整类 SQL 的批量导出改由表头的
// 「导出全部 TopN」负责（见 sqlExportScript），单条不再单独「存为 .sql」。
func sqlCell(full string, max int) string {
	if strings.TrimSpace(full) == "" {
		return ""
	}
	brief := briefOf(full, max)
	long := len(full) > 160
	// 体积红线：报告太大浏览器打开会卡，超预算后退化成「摘要 + 附件指引」
	inline := long
	if inline {
		if inlineBudget <= 0 {
			inline = false
		} else {
			inlineBudget -= len(full)
		}
	}
	// 悬停预览：title 里给前 20 行，避免超长 SQL 把浏览器 tooltip 撑得没法看
	title := full
	if n := strings.Count(full, "\n"); n > 20 {
		lines := strings.SplitN(full, "\n", 21)
		title = strings.Join(lines[:20], "\n") + fmt.Sprintf("\n…（共 %d 行 %d 字符，点击展开看全部）", n+1, len(full))
	}
	var b strings.Builder
	b.WriteString(`<div class="csvh">`)
	b.WriteString(`<div class="tx" title="`)
	b.WriteString(hEsc(title))
	b.WriteString(`"><span class="one"><code>`)
	b.WriteString(hEsc(brief))
	b.WriteString(`</code></span>`)
	if inline {
		b.WriteString(`<span class="hintcp">点击展开全文（`)
		b.WriteString(strconv.Itoa(len(full)))
		b.WriteString(` 字符）</span>`)
	} else if long {
		b.WriteString(`<span class="hintcp">全文见配套 .full.sql 附件</span>`)
	}
	b.WriteString(`<span class="full">`)
	b.WriteString(hEsc(full))
	b.WriteString(`</span></div><div class="ops">`)
	// 复制按钮在超预算时同样保留：全文一直躺在 DOM 里，复制不花额外体积
	b.WriteString(`<button data-act="copy" type="button">复制</button>`)
	b.WriteString(`</div></div>`)
	return b.String()
}

// renderStatsHTML 单文件 HTML 报告：自带样式与条形图，浏览器直接打开、可打印
func renderStatsHTML(w io.Writer, v *statsView, opt *Options) {
	gen := time.Now().Format("2006-01-02 15:04:05")
	resetInlineBudget()
	io.WriteString(w, "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n")
	io.WriteString(w, "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
	fmt.Fprintf(w, "<title>dmsqlq 统计报告 %s</title>\n", gen)
	io.WriteString(w, htmlStyle)
	io.WriteString(w, "</head>\n<body><div class=\"wrap\">\n")

	fmt.Fprintf(w, "<h1>dmsqlq 统计报告 <span class=\"tag\">v%s</span></h1>\n", ver)
	io.WriteString(w, "<dl class=\"meta\">\n")
	fmt.Fprintf(w, "<dt class=\"k\">日志时段</dt><dd class=\"k\">%s</dd>\n", hEsc(spanText(v)))
	if v.WindowDesc != "" {
		// 时间窗口决定统计范围，必须显眼 —— 否则读者会当成全天数据判读
		fmt.Fprintf(w, "<dt class=\"k\">统计时间窗口</dt><dd class=\"winscope\">%s"+
			"<span class=\"wnote\">仅统计窗口内语句，窗口外 %s 条已排除</span></dd>\n",
			hEsc(v.WindowDesc), fmtInt(v.WinSkipped))
	}
	fmt.Fprintf(w, "<dt>扫描范围</dt><dd>%d 个日志 · %.1f MB · %v · %.0f MB/s</dd>\n",
		v.Files, v.MBf, v.Elapsed.Round(time.Millisecond), v.MBf/maxF(v.Elapsed.Seconds(), 0.001))
	fmt.Fprintf(w, "<dt>筛选条件</dt><dd>%s</dd>\n", hEsc(v.FilterDesc))
	fmt.Fprintf(w, "<dt>输出模式</dt><dd>%s</dd>\n", hEsc(v.ModeDesc))
	fmt.Fprintf(w, "<dt>生成时间</dt><dd>%s</dd>\n", gen)
	if v.FullSQLPath != "" {
		fmt.Fprintf(w, "<dt>配套文件</dt><dd class=\"muted\"><code>%s</code>　完整 SQL 亦已内嵌在本报告中"+
			"（点击展开 / 悬停预览 / 一键复制），该文件可整批拿去 disql 执行。</dd>\n", hEsc(v.FullSQLPath))
	}
	io.WriteString(w, "</dl>\n")

	// 头号问题 / 采集完整性 —— 排在 KPI 之前：读者先要知道「该看什么」「哪些结论不能下」。
	// AWR 把 DB Time 摆在报告最前是同一个道理。
	if v.Headline != "" {
		cls := "hl"
		if v.HeadlineKind == "info" {
			cls = "hl info"
		}
		fmt.Fprintf(w, "<div class=\"%s\">%s</div>\n", cls, hEsc(v.Headline))
	}
	if !v.Mask29On {
		io.WriteString(w, "<div class=\"warnbar\">⚠️ 本批日志里没有事务/锁事件行（<code>TRX:</code> / <code>DLCK</code> / "+
			"<code>LOCK_TID</code> 全为 0），采集侧 <code>SQL_TRACE_MASK</code> 缺 <b>29</b>。"+
			"<b>「锁等待」「长事务」「TPS」是没采集到，不是没发生</b> —— 别把「锁等待 0 次」读成「这库没有锁竞争」。"+
			"要这三项，把 29 打开后重新采集即可。</div>\n")
	}

	// ---- KPI 卡片 ----
	io.WriteString(w, "<div class=\"kpis\">\n")
	kpi := func(label, val, unit string, extra ...string) {
		cls := "kpi"
		for _, e := range extra {
			if e != "" {
				cls += " " + e
			}
		}
		fmt.Fprintf(w, "<div class=\"%s\"><b>%s</b><span>%s%s</span></div>\n",
			cls, hEsc(val), hEsc(label), hEsc(unit))
	}
	kpi("日志记录", fmtInt(v.Records), " 条")
	kpi("SQL 事件", fmtInt(v.Exec), " 条")
	kpi("命中语句", fmtInt(v.Out), " 条")
	kpi("参数还原率", fmt.Sprintf("%.2f%%", v.RestorePct), "")
	if v.SpanSec > 0 {
		// 🩸 KPI 上的 QPS 最容易被误读：33 条/秒 与 4,933 事务/秒 并排，读者会以为
		// 系统很闲。卡片本身太窄（minmax(124px,1fr) + ellipsis），把口径塞进数值或
		// 标签都会被截断成「33（日志…」——等于没说。所以：
		//   · 卡片保持干净：只放数字 + 短标签（给「读数」用）
		//   · 口径写在卡片下方的 kpinote（给「判读」用），宽度不受限、不会被截
		kpi("平均 QPS", fmtNum(v.AvgQPS), " 条/秒")
		kpi("峰值 QPS", fmtNum(v.PeakQPS), " 条/秒")
		if v.Commits+v.Rollbacks > 0 {
			kpi("峰值 TPS", fmtNum(v.PeakTPS), " 事务/秒")
		}
	}
	if v.Commits+v.Rollbacks > 0 {
		kpi("回滚率", fmt.Sprintf("%.2f%%", v.RollbackPct), "")
	}
	// 锁等待卡片三态：29 未开 → 不可判定（「0 次」与「没数据」的分水岭，必须区分）
	switch {
	case !v.Mask29On:
		kpi("锁等待", "—", " 未采集", "na")
	case v.LockN > 0:
		kpi("锁等待", fmtInt(v.LockN), " 次", "warn")
	default:
		kpi("锁等待", fmtInt(v.LockN), " 次", "risk")
	}
	if v.Excluded > 0 {
		kpi("已排除(-E)", fmtInt(v.Excluded), " 条")
	}
	io.WriteString(w, "</div>\n")
	// KPI 下方的口径注（不放进卡片：卡片窄、会截断，见上方注释）。
	// 只在真会误读时出现，避免每份报告都挂一条没信息量的注。
	if v.SpanSec > 0 && v.qpsUnderReported() {
		fmt.Fprintf(w, "<div class=\"kpinote\">⚠ 上面两个 QPS 是<b>日志记到的语句数</b>，不是业务真实吞吐"+
			"（本批有事务结束事件 %s 条，却只记到 SQL 语句 %s 条）—— <b>不要与 TPS 横向比较</b>；"+
			"TPS 按 <code>COMMIT</code> 计数。详见下文「吞吐与时轴」。</div>\n",
			fmtInt(v.Commits+v.Rollbacks), fmtInt(v.Exec))
	}

	// 通用表格 / 条形图辅助
	//
	// aligns 里的标记："" 普通文本（会被转义）、"n" 右对齐数字、"c" 等宽代码、
	// "r" 已构造好的安全 HTML（如 sqlCell 的交互组件）—— 原样输出，不再转义。
	//
	// exp 非 nil 时，表格上方多一条「导出全部 TopN」工具条：点一下把该表所有行的
	// SQL 拼成一个 .sql 下载（每条前面一行 -- 注释头），方便整批拿去 disql 执行。
	// foldKeep 长表默认折叠后保留的行数：超过这个行数才出现「展开全部」。
	//
	// 取值 8 的理由：榜单类表格（热表/最慢/模板）默认 20 行，折叠后剩 8 行刚好
	// 一屏之内看完「最该看的头几名」；再少就开始丢有效信息（第 9、10 名常常仍有
	// 优化价值）。行数 ≤8 的表格不受影响，照常全显示。
	const foldKeep = 8
	// hTableFold 与 hTable 相同，但可指定折叠后保留的前 N 行（keep<=0 表示不折叠）。
	//
	// 为什么要折叠：报告里 20 行级的榜单有 4 张、锁等待与高危操作动辄 25~48 行，
	// 一屏读不完，真正要看的那几条反而被淹。默认只留前 N 行 + 一个「展开全部」，
	// 打印时 CSS 自动全展开 —— 归档件与 PDF 依旧完整（见 htmlStyle 的 @media print）。
	//
	// 用 var + 先声明后赋值：hTable 要复用 hTableFold，而 Go 的函数字面量不能
	// 在声明处自引用（闭包只在被调用时才求值，但标识符必须先定义）。
	var hTableFold func(head []string, aligns []string, rows [][]string, exp *expData, keep int)
	hTableFold = func(head []string, aligns []string, rows [][]string, exp *expData, keep int) {
		if exp != nil && len(exp.Rows) > 0 {
			fmt.Fprintf(w, "<div class=\"tbh\"><span class=\"tbn\">%s</span>", hEsc(exp.Title))
			fmt.Fprintf(w, "<span class=\"tbhint\">%s</span>", exp.Hint)
			fmt.Fprintf(w, "<button data-exp=\"%s\" type=\"button\">导出全部 %d 条 SQL</button>",
				hEsc(exp.File), len(exp.Rows))
			io.WriteString(w, "</div>\n")
			// 数据块：浏览器不解析、不显示，只给上面的按钮读
			io.WriteString(w, "<script type=\"application/json\" class=\"expdata\">")
			io.WriteString(w, expJSON(exp.Rows))
			io.WriteString(w, "</script>\n")
		}
		fold := keep > 0 && len(rows) > keep+1 // 只多 1 行就不值得折
		if fold {
			io.WriteString(w, "<table class=\"fold\"><thead><tr>")
		} else {
			io.WriteString(w, "<table><thead><tr>")
		}
		for i, hh := range head {
			if aligns[i] == "n" {
				fmt.Fprintf(w, "<th class=\"n\">%s</th>", hEsc(hh))
			} else {
				fmt.Fprintf(w, "<th>%s</th>", hEsc(hh))
			}
		}
		io.WriteString(w, "</tr></thead><tbody>")
		for ri, r := range rows {
			if fold && ri >= keep {
				io.WriteString(w, "<tr class=\"hid\">")
			} else {
				io.WriteString(w, "<tr>")
			}
			for i, c := range r {
				switch aligns[i] {
				case "n":
					fmt.Fprintf(w, "<td class=\"n\">%s</td>", c)
				case "c":
					fmt.Fprintf(w, "<td><code>%s</code></td>", hEsc(c))
				case "r":
					// 已是安全 HTML（sqlCell 等自建组件），原样输出
					fmt.Fprintf(w, "<td>%s</td>", c)
				default:
					fmt.Fprintf(w, "<td>%s</td>", hEsc(c))
				}
			}
			io.WriteString(w, "</tr>")
		}
		io.WriteString(w, "</tbody></table>\n")
		if fold {
			fmt.Fprintf(w, "<div class=\"foldbar\"><button data-fold=\"%d\" type=\"button\">"+
				"展开全部 %d 行</button><span class=\"fnote\">默认只显示前 %d 行，"+
				"点击展开其余 %d 行；打印 / 导出 PDF 时自动全部展开。</span></div>\n",
				len(rows), len(rows), keep, len(rows)-keep)
		}
	}
	// hTable 常规表格：按全局 foldKeep 决定是否折叠。
	hTable := func(head []string, aligns []string, rows [][]string, exp *expData) {
		hTableFold(head, aligns, rows, exp, foldKeep)
	}
	hBars := func(bars []hBar) {
		io.WriteString(w, "<div class=\"bars\">\n")
		for _, b := range bars {
			p := b.Pct
			if p < 0 {
				p = 0
			}
			if p > 100 {
				p = 100
			}
			cls := "fill"
			if b.Warn {
				cls = "fill warn"
			}
			fmt.Fprintf(w, "<div class=\"brow\"><span class=\"lbl\">%s</span><span class=\"track\">"+
				"<span class=\"%s\" style=\"width:%.2f%%\"></span></span><span class=\"val\">%s</span></div>\n",
				hEsc(b.Label), cls, p, hEsc(b.Note))
		}
		io.WriteString(w, "</div>\n")
	}

	// ---- 优先优化推荐（放最前：报告是给人做决策的，先说改什么）----
	if len(v.Advice) > 0 {
		io.WriteString(w, "<h2>优先优化推荐</h2>\n")
		fmt.Fprintf(w, "<div class=\"note\">按<b>影响占比</b>排序 = 该语句累计耗时（执行次数 × 平均耗时）÷ 全部语句耗时。<br>"+
			"<b>为什么用累计耗时</b>：衡量 SQL 代价最理想的指标是<b>逻辑读</b>（buffer gets），"+
			"但达梦的 SQL 日志不记录逻辑读，只能退而用「次数 × 平均耗时」作代理 —— "+
			"它同样反映「这条语句总共让系统忙了多久」。<br>"+
			"其它排法都不对：按单条最慢会把「一天只跑 1 次」的语句排前面；"+
			"按次数会把 5ms 的高频查询排前面 —— 两者都偏离真实负载。<br>"+
			"阈值与 Excel 交付件一致：≥10%% 优先、3%%~10%% 次之。共 %d 条建议，覆盖本次总耗时的 <b>%.1f%%</b>。</div>\n",
			len(v.Advice), adviceCoverPct(v.Advice))
		for _, a := range v.Advice {
			cls := "adv"
			if a.Prio == "优先" {
				cls = "adv prio1"
			} else if a.Prio == "次之" {
				cls = "adv prio2"
			} else if a.Prio == "等锁" {
				cls = "adv prio3"
			}
			fmt.Fprintf(w, "<div class=\"%s\">\n", cls)
			fmt.Fprintf(w, "<div class=\"advh\"><span class=\"advr\">%d</span>"+
				"<span class=\"advp\">%s</span>"+
				"<span class=\"advs\">影响占比 <b>%.1f%%</b></span>"+
				"<span class=\"advm\">%s 次 · 最快 %s / 平均 %s / 最大 %s · 累计 %s</span></div>\n",
				a.Rank, hEsc(a.Prio), a.Share*100, fmtInt(a.Count),
				durOrDash(a.Min), fmtDur(a.Avg), fmtDur(a.Max), fmtDur(a.Sum))
			fmt.Fprintf(w, "<div class=\"advg\"><b>问题信号：</b>%s</div>\n", mdInline(a.Signal))
			fmt.Fprintf(w, "<div class=\"advg\"><b>建议动作：</b>%s</div>\n", mdInline(a.Action))
			fmt.Fprintf(w, "<div class=\"advq\">%s</div>\n", sqlCell(a.Sample, 110))
			io.WriteString(w, "</div>\n")
		}
	}

	// ---- 语句类型分布 ----
	if len(v.OpRows) > 0 {
		fmt.Fprintf(w, "<h2>语句类型分布</h2>\n<div class=\"note\">次数占比与耗时占比偏离大时，"+
			"说明该类型「次数不多但很慢」或「数量大但很轻」——优化收益看耗时占比，不看次数。</div>\n")
		var rows [][]string
		var bars []hBar
		var maxPct float64
		for _, r := range v.OpRows {
			if r.SumPct > maxPct {
				maxPct = r.SumPct
			}
		}
		for _, r := range v.OpRows {
			rows = append(rows, []string{r.Op, fmtInt(r.Count), fmt.Sprintf("%.1f%%", r.Pct),
				durOrDash(r.Sum), pctStr(r.SumPct, r.Sum), durOrDash(r.Avg),
				durOrDash(r.P95), durOrDash(r.Max)})
			bars = append(bars, hBar{Label: r.Op, Note: pctStr(r.SumPct, r.Sum),
				Pct: ratioOf64(r.SumPct, maxPct) * 100, Warn: r.SumPct >= 50})
		}
		hTable([]string{"类型", "次数", "次数占比", "累计耗时", "耗时占比", "平均", "P95", "最大"},
			[]string{"", "n", "n", "n", "n", "n", "n", "n"}, rows, nil)
		io.WriteString(w, "<div class=\"note\">耗时占比：</div>\n")
		hBars(bars)
	}

	// ---- 错误码分布（[ERR] 行）----
	//
	// 只看次数很容易漏掉真问题：DM 的 [ERR(-608)]（会话请求超时 / 锁超时）每次都要等满超时阈值，
	// 实测某库 4,581 次就吃掉 79.7 小时 —— 次数只占 3.4%、耗时却占 74.9%。
	// 所以这里**次数与耗时并列**，并给出官方口径的提醒（-608 是"超时"，不等于"锁等待"）。
	if len(v.ErrCodes) > 0 {
		fmt.Fprintf(w, "<h2>错误码分布（[ERR] 行，共 %s 条）</h2>\n", fmtInt(v.ErrN))
		io.WriteString(w, "<div class=\"note\">次数与耗时并列看：<b>次数不多却吃掉大量耗时</b>的错误码才是重点。"+
			"<code>-608</code> 是「会话请求超时 / 锁超时」—— 它本身只说明超时，<b>不能单凭它断定就是锁等待</b>："+
			"要定性得在库上核对 <code>V$TRXWAIT</code> / <code>V$LOCK</code>，或让采集侧把 <code>SQL_TRACE_MASK</code> 补上 29，让日志直接记录锁等待。"+
			"其余错误码含义请以达梦官方文档为准。</div>\n")
		var rows [][]string
		for _, r := range v.ErrCodes {
			rows = append(rows, []string{r.Code, fmtInt(r.Count),
				fmt.Sprintf("%.1f%%", pct(r.Count, v.ErrN)), durOrDash(r.Sum), durOrDash(r.Avg)})
		}
		hTable([]string{"错误码", "次数", "占 [ERR] 次数", "累计耗时", "平均"}, []string{"c", "n", "n", "n", "n"}, rows, nil)
	}

	// ---- 执行耗时分布 ----
	if t := v.HistTotal(); t > 0 {
		fmt.Fprintf(w, "<h2>执行耗时分布</h2>\n<div class=\"note\">共 %s 条有耗时的语句（不含 [ORA] 仅解析行）。"+
			"分位数 P50 <b>%s</b> · P90 <b>%s</b> · P95 <b>%s</b> · P99 <b>%s</b> · 最大 <b>%s</b>；"+
			"P50 与 P99 差距越大，说明越少数语句在拖后腿。</div>\n", fmtInt(t),
			fmtDur(v.P50), fmtDur(v.P90), fmtDur(v.P95), fmtDur(v.P99), fmtDur(v.DurMax))
		var bars []hBar
		for i, n := range v.Hist {
			bars = append(bars, hBar{Label: histNames[i],
				Note: fmt.Sprintf("%s（%.1f%%）", fmtInt(n), pct(n, t)),
				Pct:  ratioOf(n, v.HistMax) * 100,
				Warn: i >= 4 && n > 0})
		}
		hBars(bars)
	}

	// ---- 吞吐与时轴 + 负载时间分布（合并一节：指标表 → 时间图 → 高峰时段榜）----
	//
	// 原来这是两节，而且负载那节把每个时段都列成一行表格 —— 分钟粒度下动辄上千行，
	// 报告被撑得极长，反而看不出"高峰在哪"。现在合成一节：指标给数、图给形态、榜给可下钻的时段；
	// **完整时间轴**交给 Excel 交付件的「时段分布」工作表（那才是要"完整"的地方）。
	if v.SpanSec > 0 || len(v.Buckets) > 0 {
		fmt.Fprintf(w, "<h2>吞吐与时轴（QPS / TPS）</h2>\n")
		if v.qpsUnderReported() {
			fmt.Fprintf(w, "<div class=\"warnbar\">⚠ <b>QPS 被严重低估，不要与 TPS 横向比较。</b>"+
				"本批日志有事务结束事件 %s 条，却只记录到 SQL 语句 %s 条"+
				"（每 1 条 SQL 伴随约 %.0f 条 COMMIT/ROLLBACK）—— 说明 SQL 语句文本的记录密度很低，"+
				"<b>QPS 只是「日志里记到的语句数」，不是业务真实吞吐</b>。<br>"+
				"常见成因：<code>SQL_TRACE_MASK</code> 的语句类型位（2~17）只开了一部分；"+
				"或应用大量复用同一个预编译句柄（实测单个句柄对应 5.3 万条 PARAMS 行、却只有极少执行行）。"+
				"要拿到真实 QPS，需让采集覆盖全部语句类型（核对 "+
				"<code>SELECT PARA_NAME,PARA_VALUE FROM V$DM_SQLLOG_CONFIG</code>）。</div>\n",
				fmtInt(v.Commits+v.Rollbacks), fmtInt(v.Exec), v.trxPerSQL())
		}
		if v.SpanSec > 0 {
			io.WriteString(w, "<div class=\"note\">QPS 只统计有耗时的语句事件（排除 <code>[ORA]</code> 仅解析未执行的行），与耗时口径一致。</div>\n")
			var rows [][]string
			rows = append(rows, []string{"日志时段", hEsc(spanText(v))})
			rows = append(rows, []string{"平均 QPS", fmt.Sprintf("%.2f 条/秒", v.AvgQPS)})
			rows = append(rows, []string{"峰值 QPS", fmt.Sprintf("%s 条/秒 @ %s", fmtNum(v.PeakQPS), v.PeakQPSAt)})
			if v.Commits+v.Rollbacks > 0 {
				rows = append(rows, []string{"平均 TPS", fmt.Sprintf("%.2f 事务/秒（按 COMMIT）", v.AvgTPS)})
				rows = append(rows, []string{"峰值 TPS", fmt.Sprintf("%s 事务/秒 @ %s", fmtNum(v.PeakTPS), v.PeakTPSAt)})
				rows = append(rows, []string{"事务结束事件", fmt.Sprintf("COMMIT %s / ROLLBACK %s（回滚率 %.2f%%）",
					fmtInt(v.Commits), fmtInt(v.Rollbacks), v.RollbackPct)})
			} else {
				rows = append(rows, []string{"事务结束事件", "未发现（掩码 29 未开或该时段无提交，TPS 无法计算）"})
			}
			rows = append(rows, []string{"有事件的秒数", fmt.Sprintf("%s / 共约 %.0f 秒", fmtInt(v.SecCovered), v.SpanSec)})
			if v.LongestIdle > 0 {
				rows = append(rows, []string{"最长静默空档", fmt.Sprintf("%s（起于 %s）", fmtDur(v.LongestIdle*1000), v.LongestIdleAt)})
			}
			hTable([]string{"指标", "数值"}, []string{"", ""}, rows, nil)
		}

		if len(v.Buckets) > 0 {
			var empty int
			for _, b := range v.Buckets {
				if b.SQL == 0 {
					empty++
				}
			}
			fmt.Fprintf(w, "<h3>负载时间分布（按%s，共 %d 个时段）</h3>\n", v.BucketUnit, v.BucketCount)
			fmt.Fprintf(w, "<div class=\"note\">横轴时间、纵轴 SQL 数，红色是峰值时段，悬停看该时段明细。"+
				"空时段 %d 个 —— 业务低峰或采集中断（可与「最长静默空档」对照）。"+
				"完整时间轴见 Excel 交付件的「时段分布」工作表。</div>\n", empty)
			renderLoadChartHTML(w, v)
			if v.PeakBucket != nil {
				fmt.Fprintf(w, "<div class=\"note\">峰值时段 <b>%s</b>：%s 条 SQL · 平均 QPS %.2f · 累计耗时 %s。</div>\n",
					hEsc(v.PeakBucket.TS), fmtInt(v.PeakBucket.SQL), v.PeakBucket.QPS, durOrDash(v.PeakBucket.SumMS))
			}
		}

		if len(v.BucketsTop) > 0 {
			fmt.Fprintf(w, "<h3>高峰时段 Top%d</h3>\n", len(v.BucketsTop))
			fmt.Fprintf(w, "<div class=\"note\">按 SQL 数排序；按时间顺序的完整形态见上图。</div>\n")
			var br [][]string
			for i, r := range v.BucketsTop {
				br = append(br, []string{strconv.Itoa(i + 1), r.TS, fmtInt(r.SQL),
					fmt.Sprintf("%.2f", r.QPS), durOrDash(r.SumMS), fmtInt(r.Commit), fmtInt(r.Rollback),
					fmt.Sprintf("%.1f%%", r.Pct)})
			}
			hTable([]string{"#", "时段", "SQL 数", "平均 QPS", "累计耗时", "COMMIT", "ROLLBACK", "占比"},
				[]string{"n", "", "n", "n", "n", "n", "n", "n"}, br, nil)
		}
	}

	// ---- 热表 ----
	if len(v.Tables) > 0 {
		fmt.Fprintf(w, "<h2>热表 Top%d</h2>\n", len(v.Tables))
		io.WriteString(w, "<div class=\"note\">表名取自 SQL 文本（FROM / JOIN / INSERT INTO / UPDATE / DELETE FROM 等位置），已去 schema、统一大写；"+
			"一条语句涉及多张表时每张表各计一次，故耗时占比之和可能超过 100%。含数据字典视图与临时表"+
			"（USER_/DBA_/V$/TMP_ 开头），不关心可用 <code>-E</code> 排除。</div>\n")
		var rows [][]string
		var bars []hBar
		var maxSum float64
		for _, r := range v.Tables {
			if r.Sum > maxSum {
				maxSum = r.Sum
			}
		}
		for _, r := range v.Tables {
			rows = append(rows, []string{r.Table, fmtInt(r.Count), fmtInt(r.Reads), fmtInt(r.Writes),
				ratioDisp(r.RW), durOrDash(r.Sum), durOrDash(r.Max), pctStr(r.Pct, r.Sum)})
			bars = append(bars, hBar{Label: r.Table, Note: pctStr(r.Pct, r.Sum),
				Pct: ratioOf64(r.Sum, maxSum) * 100, Warn: r.Max >= 1000})
		}
		hTableFold([]string{"表名", "语句数", "读", "写", "读写比", "累计耗时", "最大", "耗时占比"},
			[]string{"c", "n", "n", "n", "n", "n", "n", "n"}, rows, nil, foldKeep)
		io.WriteString(w, "<div class=\"note\">累计耗时：</div>\n")
		hBars(bars)
	}

	// ---- 最慢语句 ----
	if len(v.Slow) > 0 {
		fmt.Fprintf(w, "<h2>最慢语句 Top%d</h2>\n", len(v.Slow))
		io.WriteString(w, "<div class=\"note\">SQL 列默认只显示摘要：<b>点击展开全文</b>、<b>鼠标悬停</b>可预览、"+
			"<b>[复制]</b> 直接复制可执行语句（参数已还原）；"+
			"要整类拿走就用上方的<b>[导出全部]</b>，存成 .sql 直接跑。</div>\n")
		var rows [][]string
		var exp expData
		exp.Title = fmt.Sprintf("最慢语句 Top%d", len(v.Slow))
		exp.File = "slow_top" + strconv.Itoa(len(v.Slow)) + ".sql"
		exp.Hint = "按耗时降序，注释头给出耗时/时间/用户，语句单行不折行，可直接整批执行"
		for i, r := range v.Slow {
			rows = append(rows, []string{strconv.Itoa(i + 1), fmtDur(r.MS), rowsDisp(r.Rows), r.Op, r.User,
				shortTS(r.TS), r.ExecID, sqlCell(r.SQL, 100)})
			exp.Rows = append(exp.Rows, [2]string{
				fmt.Sprintf("-- [#%d] %s  %s  用户 %s  行数 %s", i+1, fmtDur(r.MS), shortTS(r.TS), dash(r.User), rowsDisp(r.Rows)),
				r.SQL})
		}
		hTableFold([]string{"#", "耗时", "行数", "类型", "用户", "时间", "EXEC_ID", "SQL（点击展开 / 复制）"},
			[]string{"n", "n", "n", "", "", "", "c", "r"}, rows, &exp, foldKeep)
		if v.ExecIDSeen > 0 && v.Slow[0].ExecID != "" {
			fmt.Fprintf(w, "<div class=\"note\">下钻到执行节点（SQL 日志没有逻辑读，需要拿 EXEC_ID 去库里换）："+
				"<code>SELECT * FROM V$SQL_NODE_HISTORY WHERE EXEC_ID = %s;</code> —— "+
				"该视图给出每个节点的 <code>TIME_USED</code>（微秒）与 <code>N_ENTER</code>，"+
				"其中 <code>DLCK</code> 节点正是日志里 <code>DLCK used time:N(us)</code> 的来源。</div>\n",
				hEsc(v.Slow[0].ExecID))
		}
	}

	// ---- 最耗时模板 ----
	if len(v.Tpls) > 0 {
		fmt.Fprintf(w, "<h2>最耗时语句模板 Top%d</h2>\n", len(v.Tpls))
		io.WriteString(w, "<div class=\"note\">字面量与数字已归一化；累计耗时最高的模板优化收益最大。"+
			"样例同样可点击展开 / 悬停预览 / 一键复制（样例是该模板参数还原后的一条真实语句）。<br>"+
			"<b>最快 / 平均 / 最大 三个一起看</b>：三者接近 → 稳定慢，是结构性问题（缺索引/写法），改了就好；"+
			"最快远小于平均 → 时快时慢，是计划突变、数据倾斜或偶发锁等待，得先查「为什么不稳定」。</div>\n")
		var rows [][]string
		var exp expData
		exp.Title = fmt.Sprintf("最耗时语句模板 Top%d", len(v.Tpls))
		exp.File = "template_top" + strconv.Itoa(len(v.Tpls)) + ".sql"
		exp.Hint = "每条是模板的代表语句（参数已还原），注释头给出累计耗时/次数/平均/最大"
		for i, r := range v.Tpls {
			rows = append(rows, []string{strconv.Itoa(i + 1), fmtDur(r.Sum), fmtInt(r.Count),
				durOrDash(r.Min), fmtDur(r.Avg), fmtDur(r.Max), sqlCell(r.Sample, 110)})
			exp.Rows = append(exp.Rows, [2]string{
				fmt.Sprintf("-- [#%d] 累计 %s  %s 次  平均 %s  最大 %s", i+1, fmtDur(r.Sum), fmtInt(r.Count), fmtDur(r.Avg), fmtDur(r.Max)),
				r.Sample})
		}
		hTableFold([]string{"#", "累计耗时", "次数", "最快", "平均", "最大", "样例（点击展开 / 复制）"},
			[]string{"n", "n", "n", "n", "n", "n", "r"}, rows, &exp, foldKeep)
	}

	// ---- 用户 / 客户端 ----
	if len(v.Users) > 0 {
		io.WriteString(w, "<h2>用户排行（按语句数）</h2>\n")
		var rows [][]string
		for _, r := range v.Users {
			rows = append(rows, []string{r.User, fmtInt(r.Count), fmtDur(r.Sum), durOrDash(r.P95), fmtDur(r.Max)})
		}
		hTable([]string{"用户", "语句数", "累计耗时", "P95", "最大"}, []string{"", "n", "n", "n", "n"}, rows, nil)
	}
	if len(v.Clients) > 0 {
		io.WriteString(w, "<h2>客户端排行（appname @ IP）</h2>\n")
		io.WriteString(w, "<div class=\"note\">生产日志里 appname 经常为空，此时按连接来源 IP 归类。</div>\n")
		var rows [][]string
		for _, r := range v.Clients {
			rows = append(rows, []string{r.User, fmtInt(r.Count), fmtDur(r.Sum), fmtDur(r.Max)})
		}
		hTable([]string{"客户端", "语句数", "累计耗时", "最大"}, []string{"", "n", "n", "n"}, rows, nil)
	}

	// ---- 长事务 ----
	if len(v.Trxs) > 0 || v.TrxOpenN > 0 {
		fmt.Fprintf(w, "<h2>长事务 Top%d</h2>\n", len(v.Trxs))
		io.WriteString(w, "<div class=\"note\">口径：同一 trxid 的首次事件 → 末次事件（事件＝该事务的语句，以及掩码 29 的 <code>TRX: START</code>）。</div>\n")
		if v.Commits+v.Rollbacks > 0 {
			io.WriteString(w, "<div class=\"note\">注：<code>COMMIT</code>/<code>ROLLBACK</code> 行的 trxid 通常为 0，无法与 <code>START</code> 关联，"+
				"故无法判定单个事务是否已提交，跨度只到该事务最后一条语句为止。</div>\n")
		}
		var rows [][]string
		for _, r := range v.Trxs {
			rows = append(rows, []string{r.Trx, trxUserOf(v, r.Trx), fmtDur(r.SpanMS), durOrDash(r.ExecMS),
				utilDisp(r.Util), fmtInt(r.Count), r.First, r.Last})
		}
		hTableFold([]string{"trxid", "用户", "跨度", "SQL 执行耗时", "利用率", "语句数", "起始", "结束"},
			[]string{"c", "", "n", "n", "n", "n", "", ""}, rows, nil, foldKeep)
		io.WriteString(w, "<div class=\"note\">利用率 = 该事务内 SQL 的累计执行耗时 ÷（事务跨度 + 首条 SQL 耗时）。"+
			"<b>利用率低 = 占着事务不干活</b>（长时间持锁、应用侧没提交），比「SQL 慢」更该先处理。</div>\n")
		if v.TrxStmtN > 0 {
			fmt.Fprintf(w, "<h3>每事务语句数分布（共 %s 个事务，中位数 %d 条）</h3>\n", fmtInt(v.TrxStmtN), v.TrxStmtMed)
			var rs [][]string
			for i, n := range v.TrxStmtHist {
				rs = append(rs, []string{trxStmtNames[i], fmtInt(n), fmt.Sprintf("%.1f%%", pct(n, v.TrxStmtN)),
					fmt.Sprintf("%.2f%%", pct(n, v.TrxStmtN))})
			}
			hTable([]string{"每事务语句数", "事务数", "占比", "占比条"}, []string{"", "n", "n", "n"}, rs, nil)
			io.WriteString(w, "<div class=\"note\">口径：同一 trxid 内的<b>执行语句</b>条数（<code>TRX: START</code> 不计）。"+
				"「1 条」占比高 = 应用在<b>逐条提交</b>（批量导入慢的头号原因）；「&gt;1000 条」= 大事务，注意 undo 与持锁。</div>\n")
		}
		if v.FullSQLPath != "" {
			fmt.Fprintf(w, "<p class=\"muted\">这些事务的全部语句（含参数还原）已写入配套文件 <code>%s</code>；"+
				"也可单独抽取：<code>dmsqlq &lt;同一路径&gt; -x %s -N -o trx.sql</code>。</p>\n",
				hEsc(v.FullSQLPath), hEsc(v.Trxs[0].Trx))
		}
		if v.TrxOpenN > 0 {
			fmt.Fprintf(w, "<p class=\"muted\">另有 %s 个事务只见 <code>TRX: START</code>、后续无事件（可能未提交/日志被截断）。</p>\n", fmtInt(v.TrxOpenN))
		}
	}

	// ---- 锁等待 ----
	io.WriteString(w, "<h2>锁等待（掩码 29）</h2>\n")
	if v.LockN == 0 {
		if !v.Mask29On {
			io.WriteString(w, "<div class=\"warnbar\"><b>这一节没有数据，不等于没有锁等待。</b>"+
				"本批日志里 <code>TRX:</code> / <code>DLCK</code> / <code>LOCK_TID</code> 三类行全为 0，"+
				"判定采集侧 <code>SQL_TRACE_MASK</code> 缺 <b>29</b>（位号 29 = 记录事务相关事件，含锁类型与锁等待时间）。"+
				"<br><b>判据</b>：29 一旦开启，事务事件行必然大量出现 —— 实测现网库有 <b>394 万</b>条 <code>TRX: START</code>、"+
				"本机实例有 <b>30 万</b>条 <code>DLCK</code>；一条都没有，只能是没开，而不是「这段没锁竞争」。"+
				"<br><b>要这一维度</b>：把 29 打开后重新采集。短期替代：在库上查 <code>V$TRXWAIT</code> / <code>V$LOCK</code>。</div>\n")
		} else if v.DlckN > 0 {
			fmt.Fprintf(w, "<p class=\"muted\">未发现真实锁等待（无 <code>LOCK_TID … wait for</code> 行）—— "+
				"位号 29 已开（日志里有 %s 条事务事件与 %s 条 <code>DLCK</code> 计时行），"+
				"所以这个 0 是可信的：该时段<b>确实没有发生锁竞争</b>。<br>"+
				"（<code>DLCK</code> 是执行计划里锁节点的自身耗时，不是等待 —— 两者别混。）</p>\n",
				fmtInt(v.TrxEventN+v.TrxEndN), fmtInt(v.DlckN))
		} else {
			io.WriteString(w, "<p class=\"muted\">未发现真实锁等待；位号 29 已开（日志里有事务事件行），该时段确实无锁竞争。</p>\n")
		}
	} else {
		var rows [][]string
		rows = append(rows, []string{"锁等待事件", fmt.Sprintf("%s 次", fmtInt(v.LockN))})
		rows = append(rows, []string{"累计等待", fmt.Sprintf("%s（平均 %s）", fmtDur(v.LockSumMS), fmtDur(v.LockSumMS/float64(max64(v.LockN, 1))))})
		rows = append(rows, []string{"最长等待", fmtDur(v.LockMaxMS)})
		rows = append(rows, []string{"涉及表数", fmt.Sprintf("%d 张（按表 ID）", v.LockTableN)})
		if v.LockPeakN > 0 {
			extra := ""
			if v.LockPeakIsTop {
				extra = " ← 正好是 QPS 峰值那一秒"
			}
			rows = append(rows, []string{"等待最密的一秒", fmt.Sprintf("%s（%d 次等待，该秒 QPS %d）%s", v.LockPeakAt, v.LockPeakN, v.LockPeakQPS, extra)})
		}
		hTable([]string{"指标", "数值"}, []string{"", ""}, rows, nil)

		var lt int64
		for _, n := range v.LockHist {
			lt += n
		}
		var bars []hBar
		for i, n := range v.LockHist {
			bars = append(bars, hBar{Label: lockNames[i],
				Note: fmt.Sprintf("%s（%.1f%%）", fmtInt(n), pct(n, lt)),
				Pct:  ratioOf(n, v.LockHistMax) * 100,
				Warn: i >= 2 && n > 0})
		}
		io.WriteString(w, "<div class=\"note\">等待时长分布：</div>\n")
		hBars(bars)

		if len(v.LockRows) > 0 {
			fmt.Fprintf(w, "<h3>最久等待 Top%d</h3>\n", len(v.LockRows))
			io.WriteString(w, "<div class=\"note\">持有方用户靠「事务号 → 用户」反查（日志的锁行只带等待方会话信息），查不到显示 <code>?</code>。</div>\n")
			var rows2 [][]string
			for i, lk := range v.LockRows {
				rows2 = append(rows2, []string{strconv.Itoa(i + 1), fmtDur(lk.MS), lk.Mode,
					lockObj(lk.Table, lk.TableID), lockParty(lk.Waiter, lk.WaiterU),
					lockParty(lk.Holder, lk.HolderU), strconv.FormatInt(lk.Waiters, 10), shortTS(lk.TS)})
			}
			hTableFold([]string{"#", "等待时长", "锁模式", "对象", "等待方（trxid / 用户）", "持有方（谁在持锁）", "被等事务数", "时间"},
				[]string{"n", "n", "", "", "c", "c", "n", ""}, rows2, nil, foldKeep)
		}

		// ---- 阻塞链（V2.8）----
		//
		// 锁行的持有方列表是**累计排队**的：`wait for 7 trxs, trx[A, B, C …]`，
		// A 才是真正持锁的，B、C… 全堵在 A 后面。按「表 + 链首」聚起来看，
		// 一眼就知道是"一个慢事务拖住一串人"还是"多处在互相等"。
		if chains := v.LockChains; len(chains) > 0 {
			fmt.Fprintf(w, "<h3>阻塞链 Top%d（一条链 = 一个根事务堵住的一串等待）</h3>\n", len(chains))
			io.WriteString(w, "<div class=\"note\">口径：把同表、同根事务的等待并成一条链。"+
				"<b>链越长越该先动根事务</b> —— 它的持锁时长就是后面所有人的等待时长。"+
				"（根事务 = 日志 <code>trx[…]</code> 列表里的第一个；日志在队列过长时会截断成 <code>...more</code>。）</div>\n")
			var rowsC [][]string
			for i, c := range chains {
				rowsC = append(rowsC, []string{strconv.Itoa(i + 1), lockObj(c.Table, c.TableID),
					c.Root, c.RootUser, fmtDur(c.MaxMS), fmtInt(c.Count),
					strconv.Itoa(c.ChainLen), c.Span, strings.Join(c.WaiterUsers, " ")})
			}
			hTableFold([]string{"#", "对象", "根事务（真正持锁者）", "根事务用户", "最长等待", "等待次数", "链长（排队事务数）", "波及时段", "等待方用户"},
				[]string{"n", "", "c", "", "n", "n", "n", "", ""}, rowsC, nil, foldKeep)
		}

		// ---- 排查方向（V2.11）----
		//
		// 🩸 为什么要有这一节（现场提问）：报告把根事务的「结局」（提交/回滚）都列出来了，
		// 读者下一句必然问「都是回滚，那我往哪儿查？」。这些信息分散在几十张卡片里，
		// 得自己横着看才能拼出结论 —— 那是报告该替他做的事。
		if len(v.LockGuide) > 0 {
			io.WriteString(w, "<h3>排查方向（按日志能证实的顺序，逐条缩小范围）</h3>\n")
			io.WriteString(w, "<div class=\"note\">每一步先给<b>日志能证实的事实</b>，再给怎么读，最后给往哪儿查。"+
				"标了<b>推断</b>的地方是形态推断 —— 日志能证明现象，<b>证明不了原因</b>，"+
				"原因要到对应的位置（多半是应用侧）确认。</div>\n")
			io.WriteString(w, "<div class=\"guide\">\n")
			for _, g := range v.LockGuide {
				fmt.Fprintf(w, "<div class=\"gstep\"><div class=\"gst\"><span class=\"gsn\">%d</span>%s</div>\n",
					g.Step, hEsc(g.Title))
				if g.Fact != "" {
					fmt.Fprintf(w, "<div class=\"gf\"><b>实测：</b>%s</div>\n", mdInline(g.Fact))
				}
				if g.Note != "" {
					fmt.Fprintf(w, "<div class=\"gn\"><b>推断：</b>%s</div>\n", mdInline(g.Note))
				}
				if g.Next != "" {
					fmt.Fprintf(w, "<div class=\"gx\"><b>往哪查：</b>%s</div>\n", mdInline(g.Next))
				}
				io.WriteString(w, "</div>\n")
			}
			io.WriteString(w, "</div>\n")
		}

		// ---- 双方 SQL 明细（V2.8）----
		//
		// 这一节才是现场真正要的："哪条 SQL 在持锁、哪条 SQL 被卡住"。
		// 取不到语句时**必须说清是「没采到」还是「没跑」** —— 沿用 V2.4 起的一贯原则。
		if len(v.LockRowsAll) > 0 {
			fmt.Fprintf(w, "<h3>锁等待双方的 SQL（全量 %d 条，默认显示前 %d 条）</h3>\n", v.LockTotalN, foldKeep)
			fmt.Fprintf(w, "<div class=\"note\">等待方 SQL 取到 <b>%d/%d</b>，持有方 SQL 取到 <b>%d/%d</b>。"+
				"取不到<b>不是解析问题、也不是采集位没开全</b>：<b>最常见成因是「语句执行很快、"+
				"执行完成行被 <code>MIN_EXEC_TIME</code> 滤掉了」</b>（133 构造实验实测），"+
				"次因是「语句执行中被中止」；两者都不是「没执行」。"+
				"若采集掩码含<b>位 27（原始语句）</b>，本工具会自动从 <code>[ORA]</code> 行把 SQL 找回并标出来源；"+
				"否则复现时抓 <code>V$SESSIONS.SQL_TEXT</code> / <code>V$TRXWAIT</code>。</div>\n",
				v.LockWaiterSQLN, v.LockTotalN, v.LockHolderSQLN, v.LockTotalN)
			hLockCards(w, v.LockRowsAll, foldKeep)
		}
		if len(v.LockTables) > 0 {
			fmt.Fprintf(w, "<h3>被争抢的表 Top%d（按累计等待）</h3>\n", len(v.LockTables))
			var rows3 [][]string
			for _, r := range v.LockTables {
				rows3 = append(rows3, []string{lockObj(r.Table, r.TableID), fmtInt(r.Count),
					fmtDur(r.Sum), fmtDur(r.Max), r.Mode, r.Waiters, r.MaxAt})
			}
			hTable([]string{"对象", "次数", "累计等待", "最长", "锁模式", "等待方用户", "最长一次发生在"},
				[]string{"", "n", "n", "n", "", "", ""}, rows3, nil)
		}
		if v.RefSQL != "" {
			io.WriteString(w, "<div class=\"note\">DM 的 SQL 日志只记对象 ID、不记表名。复制执行下面这条即可反查，"+
				"结果存成 UTF-8 文本文件后再加 <code>--obj-map 文件名</code> 重跑，报告就直接显示表名了：</div>\n")
			fmt.Fprintf(w, "<pre class=\"sql\"><code>%s</code></pre>\n", hEsc(v.RefSQL))
		}
		if v.DlckN > 0 {
			fmt.Fprintf(w, "<p class=\"muted\">另：<code>DLCK</code> 锁操作计时行 %s 条（<code>used time&gt;0</code> 的 %s 条，最大 %s）—— 节点自身耗时，不是等待。</p>\n",
				fmtInt(v.DlckN), fmtInt(v.DlckNonZero), fmtDur(v.DlckMaxMS))
		}
	}

	if len(v.Dangers) > 0 || len(v.Changes) > 0 {
		io.WriteString(w, "<h2>审计与恢复定位（危险操作 / 结构变更）</h2>\n")
		if len(v.Dangers) > 0 {
			ds, _ := auditSlice(v, opt)
			fmt.Fprintf(w, "<div class=\"note\">高危操作共 %s 条（列出最近 %d 条，时间倒序）。"+
				"「仅解析未执行」= 语句到达服务器并完成语法解析、但没有执行行 —— 权限不足/超时/被取消都可能，本身即证据。</div>\n",
				fmtInt(v.DangerN), len(ds))
			var rows [][]string
			var exp expData
			exp.Title = fmt.Sprintf("高危操作最近 %d 条", len(ds))
			exp.File = "danger_top" + strconv.Itoa(len(ds)) + ".sql"
			exp.Hint = "时间倒序；注释头给出类型/对象/用户/状态，便于按序核对影响范围"
			for i, r := range ds {
				st := "已执行"
				if r.ORAOnly {
					st = "仅解析未执行"
				}
				lsn := r.LSNAt
				if lsn != "" {
					lsn = lsn + " @ " + shortTS(r.LSNTS)
				}
				rows = append(rows, []string{strconv.Itoa(i + 1), auditTS(r.TS), r.Kind, r.Object,
					r.User, r.Client, rowsDisp(r.Rows), r.Thrd, lsn, st,
					sqlCell(r.AuditSQL, 96)})
				exp.Rows = append(exp.Rows, [2]string{
					fmt.Sprintf("-- [#%d] %s  %s  %s  用户 %s  %s", i+1, auditTS(r.TS), r.Kind, dash(r.Object), dash(r.User), st),
					r.AuditSQL})
			}
			hTableFold([]string{"#", "时间", "类型", "对象", "用户", "客户端", "影响行数", "线程", "最近提交 LSN", "状态", "语句（点击展开 / 复制）"},
				[]string{"n", "", "", "", "", "", "n", "n", "c", "", "r"}, rows, &exp, foldKeep)
			if len(v.ObjRisk) > 0 {
				io.WriteString(w, "<p class=\"muted\">被反复操作的对象：")
				for i, o := range v.ObjRisk {
					if i > 0 {
						io.WriteString(w, " · ")
					}
					fmt.Fprintf(w, "<code>%s</code> %d 次", hEsc(o.Name), o.Count)
				}
				io.WriteString(w, "</p>\n")
			}
		}
		if len(v.Changes) > 0 {
			_, cs := auditSlice(v, opt)
			fmt.Fprintf(w, "<h3>结构变更 Top%d（共 %s 条，时间倒序）</h3>\n", len(cs), fmtInt(v.ChangeN))
			var rows [][]string
			for i, r := range cs {
				rows = append(rows, []string{strconv.Itoa(i + 1), auditTS(r.TS), r.Kind, r.Object, r.User, r.Client})
			}
			hTableFold([]string{"#", "时间", "类型", "对象", "用户", "客户端"},
				[]string{"n", "", "", "", "", ""}, rows, nil, foldKeep)
			if len(v.ChangeSum) > 0 {
				io.WriteString(w, "<p class=\"muted\">变更类型统计：")
				for i, c := range v.ChangeSum {
					if i > 0 {
						io.WriteString(w, " · ")
					}
					fmt.Fprintf(w, "%s %s", hEsc(c.Name), fmtInt(c.Count))
				}
				io.WriteString(w, "</p>\n")
			}
		}
		fmt.Fprintf(w, "<div class=\"note\">%s<br>完整语句已内嵌在上表「语句」列（点击展开 / 悬停预览 / 一键复制）；"+
			"如需整批导出可加 <code>-d</code>，同时也会写入配套附件的「4) 审计明细」。</div>\n", hEsc(auditFootNote(v)))
	}

	if cr := configCheck(v); len(cr) > 0 {
		io.WriteString(w, "<h2>采集配置体检（据日志内容反推 sqllog.ini）</h2>\n")
		io.WriteString(w, "<div class=\"note\">「分析不出锁等待 / 没有参数」这类问题，第一嫌疑是采集侧配置而不是解析器；"+
			"库上执行 <code>SELECT PARA_NAME, PARA_VALUE FROM V$DM_SQLLOG_CONFIG;</code> 可核对。</div>\n")
		var rows [][]string
		for _, r := range cr {
			// 用 "r" 列（原样输出安全 HTML）：结论里带 **粗体** / `等宽`，
			// 走默认列会被 hEsc 转义、把标记原样显示出来。
			rows = append(rows, []string{hEsc(r.Item), hEsc(r.Value), mdInline(r.Advice)})
		}
		hTable([]string{"检查项", "实测", "结论 / 怎么改"}, []string{"r", "r", "r"}, rows, nil)
	}

	// ---- 判读提示 ----
	if len(v.Hints) > 0 {
		io.WriteString(w, "<h2>判读提示</h2>\n<div class=\"hint\">\n")
		for _, hh := range v.Hints {
			fmt.Fprintf(w, "<p>· %s</p>\n", hEsc(hh))
		}
		io.WriteString(w, "</div>\n")
	}

	fmt.Fprintf(w, "<footer>由 dmsqlq v%s 生成 · 单文件报告，可直接归档或分享 · 打印时自动适配 A4</footer>\n", ver)
	io.WriteString(w, htmlScript)
	io.WriteString(w, sqlExportScript)
	io.WriteString(w, "</div></body></html>\n")
}

// ratioOf64 a/b（b<=0 返回 0），供 HTML 条形图换算百分比
func ratioOf64(a, b float64) float64 {
	if b <= 0 {
		return 0
	}
	return a / b
}

func mdEsc(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// writeAuditPart 写附件的第 4 部分：审计明细（危险操作 + 结构变更，含完整语句）。
//
// 这是"事后取证"用的：报告里只给一行摘要，这里给完整语句 + 四要素
// （时间 / 对象 / 操作人 / 提交 LSN），可以直接粘进事故记录或拿去复核。
func writeAuditPart(bw *bufio.Writer, v *statsView) {
	if len(v.Dangers) == 0 && len(v.Changes) == 0 {
		return
	}
	fmt.Fprintf(bw, "\n-- ######################################################################\n")
	fmt.Fprintf(bw, "-- 4) 审计明细（危险操作 %s 条 / 结构变更 %s 条）\n", fmtInt(v.DangerN), fmtInt(v.ChangeN))
	fmt.Fprintf(bw, "--    用途: 误删/误改后的取证与恢复定位；四要素 = 时间 / 对象 / 操作人 / 提交 LSN\n")
	fmt.Fprintf(bw, "--    注: 「仅解析未执行」= 语句到达服务器并完成语法解析，但没有执行行\n")
	if len(v.Dangers) > 0 {
		fmt.Fprintf(bw, "\n-- ---- 一、高危操作（时间倒序）----\n")
		for _, r := range v.Dangers {
			st := "已执行"
			if r.ORAOnly {
				st = "仅解析未执行"
			}
			fmt.Fprintf(bw, "\n-- [高危] %s  %s  %s\n", r.TS, r.Kind, r.Object)
			fmt.Fprintf(bw, "--   用户 %s  客户端 %s  线程 %s  影响行数 %s  事务 %s  EXEC_ID %s\n",
				r.User, r.Client, r.Thrd, rowsDisp(r.Rows), nz(r.Trx), nz(r.ExecID))
			fmt.Fprintf(bw, "--   状态 %s", st)
			if r.LSNAt != "" {
				fmt.Fprintf(bw, "  最近提交 LSN %s（%s）", r.LSNAt, r.LSNTS)
			}
			fmt.Fprintln(bw)
			if r.AuditSQL != "" {
				bw.WriteString(r.AuditSQL)
				bw.WriteString(";\n")
			} else {
				fmt.Fprintf(bw, "--   %s;\n", r.Brief)
			}
		}
	}
	if len(v.Changes) > 0 {
		fmt.Fprintf(bw, "\n-- ---- 二、结构变更（时间倒序，共 %s 条，这里列出最近 %d 条）----\n",
			fmtInt(v.ChangeN), len(v.Changes))
		for _, r := range v.Changes {
			fmt.Fprintf(bw, "-- %s  %-22s %-30s %s · %s\n",
				r.TS, clip(r.Kind, 22), clip(r.Object, 30), clip(r.User, 16), clip(r.Client, 24))
		}
	}
	fmt.Fprintf(bw, "\n-- 恢复定位：具体手段（闪回 / 备份还原 / 归档不完全恢复）请按 DM 版本与备份策略确认\n")
}

// nz 空值显示 "-"
func nz(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// writeFullSQL 写"配套完整 SQL"附件。
//
// 为什么要有这个文件：报告要好看 → SQL 只能显示摘要；但排查需要全文。
// 拆成两份文件即可两全：报告看结论，附件看全文，靠事务号/编号对应。
//
// 全文有两个来源：
//  1. 最慢语句 TopN、最耗时模板 TopN —— 扫描时就完整存在内存里（受 maxFullSQL 限制），直接写；
//  2. 长事务、锁等待涉及的事务里的**全部语句** —— trxid 要等排序完才知道，
//     所以这里做**二次扫描**按事务号抽取（零额外内存，代价是多读一遍日志）。
func writeFullSQL(path string, v *statsView, st *Stats, opt *Options, files []string) error {
	const trxPerLimit = 200 // 单个事务最多列出多少条语句
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	defer bw.Flush()

	fmt.Fprintf(bw, "-- ======================================================================\n")
	fmt.Fprintf(bw, "-- dmsqlq v%s 完整 SQL 附件\n", ver)
	fmt.Fprintf(bw, "-- 生成时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(bw, "-- 说明: 报告里 SQL 只显示摘要（为了排版），全文在本文件里。\n")
	fmt.Fprintf(bw, "--       语句已按日志 PARAMS 行还原参数，可直接整段复制到 disql 执行。\n")
	if len(files) > 0 {
		fmt.Fprintf(bw, "-- 来源日志: %d 个", len(files))
		for i, fp := range files {
			if i >= 5 {
				fmt.Fprintf(bw, " …（另有 %d 个）", len(files)-5)
				break
			}
			fmt.Fprintf(bw, " %s", filepath.Base(fp))
		}
		fmt.Fprintf(bw, "\n")
	}
	fmt.Fprintf(bw, "-- 参数还原: %s 成功 / %s 待还原（%.2f%%）\n", fmtInt(v.Matched), fmtInt(v.Missing), v.RestorePct)
	if v.FilterDesc != "" && v.FilterDesc != "（无）" {
		fmt.Fprintf(bw, "-- 当时筛选条件: %s（注意：附件同样只含满足这些条件的语句）\n", v.FilterDesc)
	}
	fmt.Fprintf(bw, "-- ======================================================================\n")

	// ---- 1) 最慢语句 TopN ----
	if len(v.Slow) > 0 {
		fmt.Fprintf(bw, "\n-- ######################################################################\n")
		fmt.Fprintf(bw, "-- 1) 最慢语句 Top%d（按单次执行耗时）\n", len(v.Slow))
		fmt.Fprintf(bw, "-- ######################################################################\n")
		for i, r := range v.Slow {
			fmt.Fprintf(bw, "\n-- [%d] 耗时 %s  类型 %s  影响 %s行  用户 %s  来源 %s  时间 %s\n",
				i+1, fmtDur(r.MS), r.Op, rowsDisp(r.Rows), r.User, r.File, r.TS)
			bw.WriteString(r.SQL)
			bw.WriteString(";\n")
		}
	}

	// ---- 2) 最耗时语句模板 TopN ----
	if len(v.Tpls) > 0 {
		fmt.Fprintf(bw, "\n-- ######################################################################\n")
		fmt.Fprintf(bw, "-- 2) 最耗时语句模板 Top%d（字面量与数字已归一化，这里是该模板的一个完整样例）\n", len(v.Tpls))
		fmt.Fprintf(bw, "--    累计耗时最高的模板 = 优化收益最大的地方\n")
		fmt.Fprintf(bw, "-- ######################################################################\n")
		for i, r := range v.Tpls {
			fmt.Fprintf(bw, "\n-- [%d] 累计 %s  次数 %s  平均 %s  最大 %s\n",
				i+1, fmtDur(r.Sum), fmtInt(r.Count), fmtDur(r.Avg), fmtDur(r.Max))
			bw.WriteString(r.Sample)
			bw.WriteString(";\n")
		}
	}

	// ---- 3) 事务明细（二次扫描）----
	trxSet := map[string]bool{}
	for _, r := range v.Trxs {
		trxSet[r.Trx] = true
	}
	for _, lk := range v.LockRows {
		if lk.Waiter != "" {
			trxSet[lk.Waiter] = true
		}
		for _, h := range strings.Split(lk.Holder, ",") {
			if h != "" {
				trxSet[h] = true
			}
		}
	}
	if len(trxSet) == 0 || len(files) == 0 {
		writeAuditPart(bw, v)
		return nil
	}
	fmt.Fprintf(bw, "\n-- ######################################################################\n")
	fmt.Fprintf(bw, "-- 3) 事务明细（长事务与锁等待涉及的事务，逐条语句；每事务最多 %d 条）\n", trxPerLimit)
	if v.Commits+v.Rollbacks > 0 {
		fmt.Fprintf(bw, "--    注: COMMIT/ROLLBACK 行的 trxid 通常为 0，无法与事务关联，故这里只到该事务最后一条语句\n")
	}
	fmt.Fprintf(bw, "-- ######################################################################\n")
	bw.Flush() // 先落盘，二次扫描期间用户能看到已写内容

	releaseStats(st) // 先放开聚合表，否则二次扫描会被 GC 拖慢数倍
	g := newTrxGroup(trxPerLimit)
	opt2 := *opt
	opt2.trxSet = trxSet
	opt2.stats = false
	opt2.statsOnly = false
	opt2.topMS = 0
	opt2.limit = 0
	opt2.out = ""
	opt2.noMeta = false
	opt2.term = ";"
	opt2.trxGroup = g
	opt2.quiet = true
	opt2.fullSQL = "off" // 避免递归
	st2 := newStats()

	jobs := opt.jobs
	if jobs < 1 {
		jobs = 1
	}
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for _, fp := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(fp string) {
			defer wg.Done()
			defer func() { <-sem }()
			_ = processFile(fp, io.Discard, &opt2, st2)
		}(fp)
	}
	wg.Wait()

	// 输出顺序：按事务号数值排序，稳定可读
	keys := make([]string, 0, len(g.bufs))
	for k := range g.bufs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, e1 := strconv.ParseInt(keys[i], 10, 64)
		b, e2 := strconv.ParseInt(keys[j], 10, 64)
		if e1 == nil && e2 == nil {
			return a < b
		}
		return keys[i] < keys[j]
	})
	spanOf := map[string]trxRow{}
	for _, r := range v.Trxs {
		spanOf[r.Trx] = r
	}
	lockRole := map[string]string{}
	for _, lk := range v.LockRows {
		if lk.Waiter != "" && lockRole[lk.Waiter] == "" {
			lockRole[lk.Waiter] = "锁等待·等待方"
		}
		for _, h := range strings.Split(lk.Holder, ",") {
			if h != "" && lockRole[h] == "" {
				lockRole[h] = "锁等待·持有方（持锁者）"
			}
		}
	}
	wrote := 0
	for _, k := range keys {
		buf := g.bufs[k]
		if buf == nil || buf.Len() == 0 {
			continue
		}
		role := lockRole[k]
		if role != "" {
			role = "  [" + role + "]"
		}
		if r, ok := spanOf[k]; ok {
			// fmtInt 返回的是带千分位的字符串，占位符必须是 %s（写成 %d 会打印 %!d(string=1,234)）
			fmt.Fprintf(bw, "\n-- ==== trxid %s  跨度 %s  语句 %s 条  用户 %s  %s → %s%s ====\n",
				k, fmtDur(r.SpanMS), fmtInt(r.Count), trxUserOf(v, k), r.First, r.Last, role)
		} else {
			fmt.Fprintf(bw, "\n-- ==== trxid %s%s ====\n", k, role)
		}
		bw.Write(buf.Bytes())
		wrote++
	}
	if wrote == 0 {
		fmt.Fprintf(bw, "\n-- （二次扫描没有抽到这些事务的语句：可能日志被截断、或这些事务只出现在锁等待行里）\n")
	}
	writeAuditPart(bw, v)
	return nil
}

// ---------------------------------------------------------------- Excel 交付件（.xlsx）
//
// 为什么单独做一份 Excel：HTML 报告是「给人看」的（图表、交互、可打印），
// 而定期交付给开发商做 SQL 优化，需要的是「能排序、能筛选、能批注」的工作表 ——
// 开发商拿到后按「累计耗时」降序，从第一行往下改即可，改完还能把状态填回来。
//
// 实现刻意不引任何社区库（交付约定：单文件、零依赖、离线、跨平台）：
// .xlsx 本质就是一个 zip 包，里面装几段 XML。用标准库 archive/zip + 手写 XML
// 就能生成 Excel / WPS / LibreOffice 都能打开的表格。
// 文本统一走 inlineStr（省掉 sharedStrings.xml 这一层），数字走 <v> ——
// 这样数字在 Excel 里是「真数字」，可以直接排序、求和、画图，而不是一串死文本。

// 样式索引 —— 必须与 xlStylesXML 里 <cellXfs> 的顺序一一对应，改一处就得改另一处。
const (
	xlDef   = 0  // 默认
	xlHead  = 1  // 表头：粗体白字 + 深蓝底 + 居中 + 边框
	xlTitle = 2  // 分区标题：粗体深蓝字 + 浅蓝底
	xlNum2  = 3  // 数字 #,##0.00
	xlInt   = 4  // 整数 #,##0
	xlPct1  = 5  // 百分比 0.0%
	xlText  = 6  // 文本：自动换行 + 顶端对齐 + 边框
	xlCode  = 7  // SQL：等宽字体 + 自动换行 + 顶端对齐 + 边框
	xlPlain = 8  // 文本：左对齐 + 边框
	xlNote  = 9  // 说明：灰色斜体，无边框
	xlPct2  = 10 // 百分比 0.00%
)

const xlXMLHead = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

// xlCell 一个单元格。num 为 true 时 v 是数字字面量（如 "12.34"），否则是文本。
type xlCell struct {
	v   string
	num bool
	s   int
}

func xc(s string) xlCell    { return xlCell{v: s, s: xlPlain} }
func xt(s string) xlCell    { return xlCell{v: s, s: xlText} }
func xq(s string) xlCell    { return xlCell{v: s, s: xlCode} }
func xh(s string) xlCell    { return xlCell{v: s, s: xlHead} }
func xnote(s string) xlCell { return xlCell{v: s, s: xlNote} }
func xn(f float64) xlCell   { return xlCell{v: xlNum(f), num: true, s: xlNum2} }
func xi(n int64) xlCell     { return xlCell{v: strconv.FormatInt(n, 10), num: true, s: xlInt} }
func xp(f float64) xlCell   { return xlCell{v: xlNum(f), num: true, s: xlPct1} }
func xp2(f float64) xlCell  { return xlCell{v: xlNum(f), num: true, s: xlPct2} }

// xlNum 数字 → 单元格字面量。不用科学计数法（Excel 会把它当文本或显示成 1E+06）。
func xlNum(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "0"
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// xlCol 列序号 → 列名（0 → A，26 → AA）。Excel 的列名是 26 进制但没有 0 位。
func xlCol(i int) string {
	s := ""
	for i >= 0 {
		s = string([]byte{byte('A' + i%26)}) + s
		i = i/26 - 1
	}
	return s
}

// xlEsc XML 文本转义。比 html.EscapeString 多两件事，都是"不处理就打不开"的：
//   - 剔除 XML 1.0 不允许的控制字符（SQL 文本里可能有 \f \v \0，Excel 会直接拒绝打开）；
//   - 把 \r 丢掉（Excel 的换行只认 \n，留着 \r 会变成一个小方块）。
//
// 顺带用 ToValidUTF8 兜底：日志是 GBK 原样透传的，万一有被截断的多字节序列，
// 这里补成 U+FFFD，免得非法 UTF-8 让 Excel 报"文件已损坏"。
func xlEsc(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ToValidUTF8(s, "\uFFFD")
	var b strings.Builder
	b.Grow(len(s) + 16)
	for _, r := range s {
		switch r {
		case '\t':
			b.WriteByte('\t')
		case '\n':
			b.WriteByte('\n')
		case '\r':
			// 丢：Excel 只认 \n 换行
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			if r < 0x20 {
				continue // XML 1.0 禁止的控制字符，直接剔除
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// clipRunes 按字符（而不是字节）截断，避免把多字节汉字劈成半个。
// xlCell 的文本上限是 Excel 的 32767 字符，超了必须截 —— 但必须截在字符边界上。
func clipRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	n := 0
	for i := range s {
		if i > max {
			break
		}
		n = i
	}
	return s[:n]
}

// ---------------------------------------------------------------- 工作表模型

// xlSheet 一张工作表：列宽 + 若干行 + 合并区 + 冻结/筛选。
// cols 给几个值就有几列宽，行里的单元格按位置落列。
type xlSheet struct {
	name   string
	cols   []float64
	rows   [][]xlCell
	merges []string
	freeze int  // 冻结前 N 行（让表头滚动时始终可见）
	filter bool // 首行加自动筛选（只对"纯表格"用，混排章节的表加了会错位）
}

func newSheet(name string, cols ...float64) *xlSheet {
	return &xlSheet{name: name, cols: cols}
}

func (s *xlSheet) add(cells ...xlCell) { s.rows = append(s.rows, cells) }
func (s *xlSheet) blank()              { s.rows = append(s.rows, nil) }

// head 表头行（粗体白字 + 深蓝底）
func (s *xlSheet) head(names ...string) {
	var r []xlCell
	for _, n := range names {
		r = append(r, xh(n))
	}
	s.rows = append(s.rows, r)
}

// section 分区标题，横向合并到最后一列
func (s *xlSheet) section(title string) {
	r := len(s.rows)
	s.add(xlCell{v: title, s: xlTitle})
	if n := len(s.cols); n > 1 {
		s.merge(r, 0, n-1)
	}
}

// merge 合并单元格（0 基的行列号）
func (s *xlSheet) merge(row, c1, c2 int) {
	if c2 <= c1 {
		return
	}
	ref := xlCol(c1) + strconv.Itoa(row+1) + ":" + xlCol(c2) + strconv.Itoa(row+1)
	s.merges = append(s.merges, ref)
}

// kv 键值行：键占 A 列，值从 B 列起横向合并到最后一列。
// 用于「指标 / 数值」这种宽值不适合塞进窄列的场合。
func (s *xlSheet) kv(k, val string) {
	r := len(s.rows)
	s.add(xc(k), xt(val))
	s.merge(r, 1, len(s.cols)-1)
}

// safeName 工作表名的合法性清理：Excel 限制 31 字符，且不允许 []:*?/\ 这几个字符。
func (s *xlSheet) safeName() string {
	n := strings.Map(func(r rune) rune {
		switch r {
		case '[', ']', ':', '*', '?', '/', '\\':
			return '-'
		}
		return r
	}, s.name)
	n = strings.TrimSpace(n)
	if n == "" {
		n = "Sheet"
	}
	if rs := []rune(n); len(rs) > 31 {
		n = string(rs[:31])
	}
	return n
}

// ---------------------------------------------------------------- xlsx 写出

// xlStylesXML 样式表。<cellXfs> 的顺序 = 上面的样式常量，务必对齐。
const xlStylesXML = xlXMLHead + `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
	`<numFmts count="2">` +
	`<numFmt numFmtId="164" formatCode="#,##0.00"/>` +
	`<numFmt numFmtId="165" formatCode="0.0%"/>` +
	`</numFmts>` +
	`<fonts count="5">` +
	`<font><sz val="10"/><color rgb="FF1A1A1A"/><name val="微软雅黑"/><charset val="134"/></font>` +
	`<font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="微软雅黑"/><charset val="134"/></font>` +
	`<font><b/><sz val="11"/><color rgb="FF1F4E79"/><name val="微软雅黑"/><charset val="134"/></font>` +
	`<font><sz val="9"/><color rgb="FF333333"/><name val="Consolas"/></font>` +
	`<font><i/><sz val="9"/><color rgb="FF7F7F7F"/><name val="微软雅黑"/><charset val="134"/></font>` +
	`</fonts>` +
	`<fills count="4">` +
	`<fill><patternFill patternType="none"/></fill>` +
	`<fill><patternFill patternType="gray125"/></fill>` +
	`<fill><patternFill patternType="solid"><fgColor rgb="FF2F5597"/><bgColor indexed="64"/></patternFill></fill>` +
	`<fill><patternFill patternType="solid"><fgColor rgb="FFDCE6F1"/><bgColor indexed="64"/></patternFill></fill>` +
	`</fills>` +
	`<borders count="2">` +
	`<border><left/><right/><top/><bottom/><diagonal/></border>` +
	`<border><left style="thin"><color rgb="FFD9D9D9"/></left><right style="thin"><color rgb="FFD9D9D9"/></right>` +
	`<top style="thin"><color rgb="FFD9D9D9"/></top><bottom style="thin"><color rgb="FFD9D9D9"/></bottom><diagonal/></border>` +
	`</borders>` +
	`<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>` +
	`<cellXfs count="11">` +
	// 0 xlDef
	`<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>` +
	// 1 xlHead
	`<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment horizontal="center" vertical="center" wrapText="1"/></xf>` +
	// 2 xlTitle
	`<xf numFmtId="0" fontId="2" fillId="3" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment vertical="center"/></xf>` +
	// 3 xlNum2
	`<xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1" applyAlignment="1"><alignment horizontal="right" vertical="center"/></xf>` +
	// 4 xlInt
	`<xf numFmtId="3" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1" applyAlignment="1"><alignment horizontal="right" vertical="center"/></xf>` +
	// 5 xlPct1
	`<xf numFmtId="165" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1" applyAlignment="1"><alignment horizontal="right" vertical="center"/></xf>` +
	// 6 xlText
	`<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>` +
	// 7 xlCode
	`<xf numFmtId="0" fontId="3" fillId="0" borderId="1" xfId="0" applyFont="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>` +
	// 8 xlPlain
	`<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="center"/></xf>` +
	// 9 xlNote
	`<xf numFmtId="0" fontId="4" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="center"/></xf>` +
	// 10 xlPct2
	`<xf numFmtId="10" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1" applyAlignment="1"><alignment horizontal="right" vertical="center"/></xf>` +
	`</cellXfs>` +
	`<cellStyles count="1"><cellStyle name="常规" xfId="0" builtinId="0"/></cellStyles>` +
	`</styleSheet>`

// xlCellXML 单个单元格
func xlCellXML(ref string, c xlCell) string {
	if c.num {
		return `<c r="` + ref + `" s="` + strconv.Itoa(c.s) + `"><v>` + c.v + `</v></c>`
	}
	t := clipRunes(c.v, 32000)
	if len(t) < len(c.v) {
		t += "…（超长已截断，完整语句请用 -o 导出或看配套 .full.sql）"
	}
	return `<c r="` + ref + `" s="` + strconv.Itoa(c.s) + `" t="inlineStr"><is><t xml:space="preserve">` +
		xlEsc(t) + `</t></is></c>`
}

func xlSheetXML(s *xlSheet) string {
	var b strings.Builder
	b.WriteString(xlXMLHead)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	if s.freeze > 0 {
		fmt.Fprintf(&b, `<sheetViews><sheetView workbookViewId="0">`+
			`<pane ySplit="%d" topLeftCell="A%d" activePane="bottomLeft" state="frozen"/>`+
			`</sheetView></sheetViews>`, s.freeze, s.freeze+1)
	}
	b.WriteString(`<sheetFormatPr defaultRowHeight="15"/>`)
	if len(s.cols) > 0 {
		b.WriteString(`<cols>`)
		for i, w := range s.cols {
			fmt.Fprintf(&b, `<col min="%d" max="%d" width="%s" customWidth="1"/>`, i+1, i+1, xlNum(w))
		}
		b.WriteString(`</cols>`)
	}
	b.WriteString(`<sheetData>`)
	maxC := 0
	for ri, row := range s.rows {
		if len(row) > maxC {
			maxC = len(row)
		}
		if len(row) == 0 {
			continue // 空行：不写 <row>，Excel 自然留空
		}
		fmt.Fprintf(&b, `<row r="%d">`, ri+1)
		for ci, c := range row {
			if c.v == "" {
				continue
			}
			b.WriteString(xlCellXML(xlCol(ci)+strconv.Itoa(ri+1), c))
		}
		b.WriteString(`</row>`)
	}
	b.WriteString(`</sheetData>`)
	// 注意 XML Schema 对子元素的顺序有要求：sheetData → autoFilter → mergeCells
	if s.filter && len(s.rows) > 1 && maxC > 0 {
		fmt.Fprintf(&b, `<autoFilter ref="A1:%s%d"/>`, xlCol(maxC-1), len(s.rows))
	}
	if len(s.merges) > 0 {
		fmt.Fprintf(&b, `<mergeCells count="%d">`, len(s.merges))
		for _, m := range s.merges {
			fmt.Fprintf(&b, `<mergeCell ref="%s"/>`, m)
		}
		b.WriteString(`</mergeCells>`)
	}
	b.WriteString(`</worksheet>`)
	return b.String()
}

// writeXLSX 把若干工作表写成一个 .xlsx（zip 包）。
//
// 包内结构（最小可用集合，不含 theme/docProps —— 各家阅读器都能正常打开）：
//
//	[Content_Types].xml
//	_rels/.rels                      → 指向 xl/workbook.xml
//	xl/workbook.xml                  工作表清单
//	xl/_rels/workbook.xml.rels       → 各 sheet + styles
//	xl/styles.xml                    样式表
//	xl/worksheets/sheetN.xml         各表本体
func writeXLSX(w io.Writer, sheets []*xlSheet) error {
	zw := zip.NewWriter(w)
	put := func(name, body string) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetModTime(time.Now())
		f, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = io.WriteString(f, body)
		return err
	}

	var ct strings.Builder
	ct.WriteString(xlXMLHead)
	ct.WriteString(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`)
	ct.WriteString(`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`)
	ct.WriteString(`<Default Extension="xml" ContentType="application/xml"/>`)
	ct.WriteString(`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`)
	ct.WriteString(`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`)
	for i := range sheets {
		fmt.Fprintf(&ct, `<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, i+1)
	}
	ct.WriteString(`</Types>`)
	if err := put("[Content_Types].xml", ct.String()); err != nil {
		return err
	}

	if err := put("_rels/.rels", xlXMLHead+
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>`+
		`</Relationships>`); err != nil {
		return err
	}

	var wb strings.Builder
	wb.WriteString(xlXMLHead)
	wb.WriteString(`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ` +
		`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>`)
	for i, s := range sheets {
		fmt.Fprintf(&wb, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, xlEsc(s.safeName()), i+1, i+1)
	}
	wb.WriteString(`</sheets></workbook>`)
	if err := put("xl/workbook.xml", wb.String()); err != nil {
		return err
	}

	var rel strings.Builder
	rel.WriteString(xlXMLHead)
	rel.WriteString(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for i := range sheets {
		fmt.Fprintf(&rel, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, i+1, i+1)
	}
	fmt.Fprintf(&rel, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`, len(sheets)+1)
	rel.WriteString(`</Relationships>`)
	if err := put("xl/_rels/workbook.xml.rels", rel.String()); err != nil {
		return err
	}

	if err := put("xl/styles.xml", xlStylesXML); err != nil {
		return err
	}
	for i, s := range sheets {
		if err := put("xl/worksheets/sheet"+strconv.Itoa(i+1)+".xml", xlSheetXML(s)); err != nil {
			return err
		}
	}
	return zw.Close()
}

// ---------------------------------------------------------------- 交付件内容

// writeExcelReport 生成 Excel 交付件。
func writeExcelReport(path string, v *statsView, opt *Options) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	if err := writeXLSX(bw, buildExcelSheets(v, opt)); err != nil {
		return err
	}
	return bw.Flush()
}

// buildExcelSheets 组织交付件的各张工作表。
//
// 排序原则：把「能直接拿去改的」放最前面 —— 概览（背景）→ SQL优化清单（行动项）
// → 慢SQL明细（取证）→ 热表（索引依据）→ 锁等待/长事务（并发问题）→ 分布类（画像）。
func buildExcelSheets(v *statsView, opt *Options) []*xlSheet {
	gen := time.Now().Format("2006-01-02 15:04:05")
	totalMS := v.TotalExecMS()
	var out []*xlSheet

	// ============ 1) 概览 ============
	{
		s := newSheet("概览", 26, 36, 62)
		s.section("dmsqlq SQL 优化交付件 · 概览（工具版本 v" + ver + "）")
		s.add(xnote("生成时间 " + gen + "｜先看「SQL优化清单」工作表：已按累计耗时降序，从第一行往下改收益最大。"))

		s.section("一、分析范围")
		s.head("项目", "值", "说明")
		s.add(xc("扫描日志"), xc(fmtInt(v.Files)+" 个"), xt(fmt.Sprintf("共 %.1f MB；分析耗时 %v（%.0f MB/s）",
			v.MBf, v.Elapsed.Round(time.Millisecond), v.MBf/maxF(v.Elapsed.Seconds(), 0.001))))
		s.add(xc("日志时段"), xc(spanText(v)), xt("起止取日志中首末 SQL 事件时间；即本交付件统计覆盖的时间范围"))
		s.add(xc("筛选条件"), xc(v.FilterDesc), xt("-k/-m/-u/-x/-l/-f/-t 只影响「导出哪些 SQL」；统计仍反映日志全貌，只有 -E 的排除会同时剔出统计"))
		s.add(xc("输出模式"), xc(v.ModeDesc), xt("决定配套 .sql 文件里放哪些语句，不影响本交付件的统计口径"))
		if v.SourceArgs != "" {
			s.add(xc("本次命令"), xq(v.SourceArgs), xt("复现用；同一份日志按此重跑，结果一致"))
		}
		if v.Headline != "" {
			s.add(xc("头号问题"), xc("优先"), xt(v.Headline))
		}
		if !v.Mask29On {
			s.add(xc("采集缺口"), xc("缺 29"), xt("本批日志没有事务/锁事件行（TRX: / DLCK / LOCK_TID 全为 0）—— "+
				"「锁等待」「长事务」「TPS」是没采集到，不是没发生。要这几项，把 SQL_TRACE_MASK 的 29 位打开后重新采集"))
		}
		s.blank()

		s.section("二、关键指标")
		s.head("指标", "数值", "说明")
		s.add(xc("日志记录（条）"), xi(v.Records), xt("日志中所有以时间戳开头的记录行"))
		s.add(xc("SQL 事件（条）"), xi(v.Exec), xt("可解析出执行信息的语句，是下面所有统计的分母"))
		s.add(xc("命中语句（条）"), xi(v.Out), xt("通过筛选、进入导出与统计的语句"))
		s.add(xc("参数还原率"), xp2(v.RestorePct/100), xt(fmt.Sprintf("成功 %s 条 / 缺失 %s 条。缺失指日志里没有 PARAMS 行（采集侧 SQL_TRACE_MASK 缺 28），不是解析失败",
			fmtInt(v.Matched), fmtInt(v.Missing))))
		if v.SpanSec > 0 {
			s.add(xc("平均 QPS（条/秒）"), xn(v.AvgQPS), xt("只统计有耗时的语句事件，排除 [ORA] 仅解析未执行的行"))
			s.add(xc("峰值 QPS（条/秒）"), xn(v.PeakQPS), xt("发生于 "+nz(v.PeakQPSAt)))
		}
		if v.Commits+v.Rollbacks > 0 {
			s.add(xc("平均 TPS（事务/秒）"), xn(v.AvgTPS), xt("按 COMMIT 计数；峰值 "+fmtNum(v.PeakTPS)+" 事务/秒 @"+nz(v.PeakTPSAt)))
			s.add(xc("COMMIT / ROLLBACK"), xc(fmtInt(v.Commits)+" / "+fmtInt(v.Rollbacks)), xt(fmt.Sprintf("回滚率 %.2f%%", v.RollbackPct)))
		}
		if !v.Mask29On {
			s.add(xc("锁等待（次）"), xc("不可判定"), xt("本批日志没有事务/锁事件行（TRX: / DLCK / LOCK_TID 全为 0），"+
				"判定 SQL_TRACE_MASK 缺 29 —— 这是「没采集到」，不是「没有锁竞争」"))
		} else {
			s.add(xc("锁等待（次）"), xi(v.LockN), xt(func() string {
				if v.LockN == 0 {
					return fmt.Sprintf("位号 29 已开（日志里有 %s 条事务事件），所以这个 0 可信：该时段确实无锁竞争",
						fmtInt(v.TrxEventN+v.TrxEndN))
				}
				return fmt.Sprintf("累计等待 %s，最长一次 %s，涉及 %d 张表（按对象 ID）",
					fmtDur(v.LockSumMS), fmtDur(v.LockMaxMS), v.LockTableN)
			}()))
		}
		if t := v.HistTotal(); t > 0 {
			s.add(xc("耗时分位 P50/P90"), xc(fmtDur(v.P50)+" / "+fmtDur(v.P90)), xt(fmt.Sprintf("P95 %s，P99 %s，最大 %s；P50 与 P99 差距越大，说明越少数语句在拖后腿",
				fmtDur(v.P95), fmtDur(v.P99), fmtDur(v.DurMax))))
		}
		s.blank()

		if t := v.HistTotal(); t > 0 {
			s.section("三、错误码分布（[ERR] 行）")
			if len(v.ErrCodes) == 0 {
				s.add(xnote("本次日志里没有 [ERR(...)] 行。"))
			} else {
				s.add(xnote("次数与耗时并列看：次数不多却吃掉大量耗时的错误码才是重点。" +
					"-608 = 会话请求超时 / 锁超时，它本身只说明超时，不能单凭它断定就是锁等待；" +
					"要定性需在库上核对 V$TRXWAIT / V$LOCK，或让采集侧 SQL_TRACE_MASK 补上 29。"))
				s.head("错误码", "次数", "占 [ERR] 次数", "累计耗时(ms)", "平均(ms)")
				for _, r := range v.ErrCodes {
					s.add(xc(r.Code), xi(r.Count), xp(pct(r.Count, v.ErrN)/100), xn(r.Sum), xn(r.Avg))
				}
			}
			s.blank()

			s.section("四、执行耗时分布")
			s.head("耗时区间", "条数", "占比")
			for i, n := range v.Hist {
				s.add(xc(histNames[i]), xi(n), xp(pct(n, t)/100))
			}
			s.blank()
		}

		if cr := configCheck(v); len(cr) > 0 {
			s.section("五、采集配置体检（据日志内容反推 sqllog.ini）")
			s.add(xnote("「分析不出锁等待 / 没有参数」这类问题，第一嫌疑是采集侧配置而不是解析器。" +
				"库上执行 SELECT PARA_NAME, PARA_VALUE FROM V$DM_SQLLOG_CONFIG; 可核对。"))
			s.head("检查项", "本次实测", "结论 / 怎么改")
			for _, r := range cr {
				s.add(xc(r.Item), xt(r.Value), xt(r.Advice))
			}
			s.blank()
		}

		s.section("六、口径与说明（读表前先看这几条）")
		s.head("项", "说明", "备注")
		notes := [][3]string{
			{"耗时单位", "表中所有耗时均为毫秒（ms），列名里已标注；不写单位的都是毫秒", "1s = 1000ms"},
			{"累计耗时", "该分组（模板/表/用户/时段）内所有语句执行耗时之和", "同一语句只计一次"},
			{"语句模板归一化", "字符串字面量 → '?'，数字 → #，连续空白压成一个空格；同模板语句合并统计", "所以「次数」是批量的量"},
			{"优化优先级规则", "按该模板占总耗时的比例分档：≥10% 标「优先」，3%~10% 标「次之」，其余「一般」", "占比高 = 改它收益最大"},
			{"SQL 明细行数", "由 -p 控制（Excel 模式下默认 200，可加 -p 500 提高）", "HTML 报告默认 10 行够看，交付要够改"},
			{"热表口径", "表名取自 SQL 文本（FROM/JOIN/INSERT INTO/UPDATE/DELETE FROM 等位置），已去 schema 并统一大写", "一条语句涉及多表时每表各计一次，故耗时占比之和可能超过 100%"},
			{"锁等待表名", "DM 的 SQL 日志只记对象 ID、不记表名；用 --obj-map 提供映射后才显示表名", "无映射时显示「对象ID nnnnn」"},
			{"未还原语句", "语句里仍带 ? 的是「采集侧没记 PARAMS 行」，会照常列出并可用 -X 过滤掉", "不是解析失败"},
			{"耗时占比", "各表「占比」列的分母不同：模板表看语句总耗时，热表看热表总耗时，锁表看锁等待总次数", "跨表别横向比较占比"},
		}
		for _, n := range notes {
			s.add(xc(n[0]), xt(n[1]), xt(n[2]))
		}
		if len(v.Hints) > 0 {
			s.blank()
			s.section("七、判读提示（工具据本次数据自动生成）")
			s.head("序号", "提示", "")
			for i, h := range v.Hints {
				r := len(s.rows)
				s.add(xi(int64(i+1)), xt(h))
				s.merge(r, 1, 2)
			}
		}
		out = append(out, s)
	}

	// ============ 2) SQL优化清单（核心） ============
	if len(v.Tpls) > 0 {
		s := newSheet("SQL优化清单", 6, 13, 10, 11, 11, 11, 11, 10, 110)
		s.head("序号", "累计耗时(ms)", "执行次数", "最快(ms)", "平均(ms)", "最大(ms)", "占总耗时", "优先级", "语句模板（样例为参数还原后的真实语句）")
		s.freeze = 1
		s.filter = true
		for i, r := range v.Tpls {
			share := 0.0
			if totalMS > 0 {
				share = r.Sum / totalMS
			}
			prio := "一般"
			switch {
			case share >= 0.10:
				prio = "优先"
			case share >= 0.03:
				prio = "次之"
			}
			// 🩸 与 HTML/终端/MD 保持同一口径（V2.10）：等锁受害者不算「优化对象」。
			// 原先这里自己按占比重算优先级，于是同一份交付件里
			// Excel 显示「优先」、HTML 显示「等锁」—— 两个视图打架。
			if ratio, _ := v.lockVictim(r.Sample, r.Sum); ratio > 0 {
				prio = "等锁"
			}
			s.add(xi(int64(i+1)), xn(r.Sum), xi(r.Count), xn(r.Min), xn(r.Avg), xn(r.Max),
				xp(share), xc(prio), xq(r.Sample))
		}
		s.blank()
		s.add(xnote("优先级规则：该模板累计耗时 ÷ 本次语句总耗时（" + fmtDur(totalMS) + "）≥10% 记「优先」，3%~10% 记「次之」，其余「一般」。"))
		s.add(xnote("「等锁」= 这条语句的累计耗时基本就是堵在某张表的锁上（同表锁等待累计 ≥ 该模板累计的 60%）。" +
			"此时**改 SQL 没有收益、EXPLAIN 也看不出问题** —— 单行 INSERT / 等值 UPDATE 本身不慢；" +
			"要动的是长时间持锁的**根事务**（见「锁等待」表）。"))
		s.add(xnote("同一模板的语句已合并（字面量与数字归一化），所以「执行次数」是这类语句出现的总次数 —— 次数多且平均高，通常是缺索引或写法问题。"))
		s.add(xnote("「最快」列与「平均」对比着看：两者接近 = 稳定慢（缺索引/写法问题，改了就好）；最快远小于平均 = 时快时慢（计划突变、数据倾斜或偶发锁等待），先查为什么不稳定。"))
		s.add(xnote("样例列是该模板参数还原后的一条真实语句，可直接复制到 disql 执行 EXPLAIN 看计划。行数由 -p 控制，加大即可获得更长清单。"))
		out = append(out, s)
	}

	// ============ 3) 慢SQL明细 ============
	if len(v.Slow) > 0 {
		s := newSheet("慢SQL明细", 6, 20, 12, 7, 8, 17, 15, 24, 110)
		s.head("序号", "执行时间", "耗时(ms)", "类型", "行数", "用户", "EXEC_ID", "来源日志", "SQL（参数已还原）")
		s.freeze = 1
		s.filter = true
		for i, r := range v.Slow {
			s.add(xi(int64(i+1)), xc(r.TS), xn(r.MS), xc(r.Op), xc(rowsDisp(r.Rows)),
				xc(nz(r.User)), xc(nz(r.ExecID)), xc(shortSrc(r.File)), xq(r.SQL))
		}
		s.blank()
		s.add(xnote("按耗时降序取前 " + strconv.Itoa(len(v.Slow)) + " 条（-p 控制行数）。行数显示「-」表示该语句在日志里没有 ROWCOUNT（[DDL]/[CAL] 一律不带），不是 0 行。"))
		if v.ExecIDSeen > 0 {
			s.add(xnote("拿 EXEC_ID 可下钻执行节点：SELECT * FROM V$SQL_NODE_HISTORY WHERE EXEC_ID = <上表值>; " +
				"其中 TIME_USED 是节点耗时（微秒），DLCK 节点正是日志里 DLCK used time 的来源。"))
		}
		out = append(out, s)
	}

	// ============ 4) 热表 ============
	if len(v.Tables) > 0 {
		s := newSheet("热表", 32, 11, 11, 11, 11, 14, 13, 12)
		s.head("表名", "语句数", "读次数", "写次数", "读写比", "累计耗时(ms)", "最大(ms)", "耗时占比")
		s.freeze = 1
		s.filter = true
		for _, r := range v.Tables {
			rw := r.RW
			if rw < 0 {
				rw = 0
			}
			s.add(xc(r.Table), xi(r.Count), xi(r.Reads), xi(r.Writes), xn(rw),
				xn(r.Sum), xn(r.Max), xp(r.Pct/100))
		}
		s.blank()
		s.add(xnote("表名取自 SQL 文本，已去 schema 并统一大写；一条语句涉及多张表时每张表各计一次，故耗时占比之和可能超过 100%。"))
		s.add(xnote("读写比很高（读远多于写）却依然慢的表，通常是缺合适索引；写为主且慢的表，看是否缺少批量提交或触发器开销。"))
		s.add(xnote("含数据字典视图与临时表（USER_/DBA_/V$/TMP_ 开头），不关心可用 -E 排除后重跑。"))
		out = append(out, s)
	}

	// ============ 5) 语句类型分布 ============
	if len(v.OpRows) > 0 {
		s := newSheet("语句类型分布", 11, 13, 12, 15, 12, 12, 12, 12)
		s.head("类型", "次数", "次数占比", "累计耗时(ms)", "耗时占比", "平均(ms)", "P95(ms)", "最大(ms)")
		s.freeze = 1
		s.filter = true
		for _, r := range v.OpRows {
			s.add(xc(r.Op), xi(r.Count), xp(r.Pct/100), xn(r.Sum),
				xp(r.SumPct/100), xn(r.Avg), xn(r.P95), xn(r.Max))
		}
		s.blank()
		s.add(xnote("次数占比与耗时占比偏离大时，说明该类型「次数不多但很慢」或「数量大但很轻」—— 优化收益看耗时占比，不看次数。"))
		out = append(out, s)
	}

	// ============ 6) 锁等待 ============
	if v.LockN > 0 || v.DlckN > 0 || !v.Mask29On {
		s := newSheet("锁等待", 6, 12, 9, 26, 17, 15, 17, 15, 12, 20)
		s.section("锁等待（SQL_TRACE_MASK 掩码 29）")
		if !v.Mask29On {
			s.add(xnote("⚠️ 本工作表没有数据，不等于没有锁等待：本批日志里 TRX: / DLCK / LOCK_TID " +
				"三类行全为 0，判定 SQL_TRACE_MASK 缺 29（位号 29 = 记录事务相关事件，含锁类型与锁等待时间）。" +
				"判据：29 一旦开启，事务事件行必然大量出现（实测现网库 394 万条 TRX: START、本机实例 30 万条 DLCK），" +
				"一条都没有只能是没开。要这一维度请开 29 后重新采集；短期替代：在库上查 V$TRXWAIT / V$LOCK。"))
		} else if v.LockN == 0 {
			s.add(xnote(fmt.Sprintf("未发现真实锁等待（无 LOCK_TID … wait for 行）；仅存在 %s 条 DLCK 锁操作计时行 —— "+
				"那是执行计划里锁节点的自身耗时，不是等待。", fmtInt(v.DlckN))))
		} else {
			s.kv("锁等待事件", fmt.Sprintf("%s 次", fmtInt(v.LockN)))
			s.kv("累计等待", fmt.Sprintf("%s（平均 %s）", fmtDur(v.LockSumMS), fmtDur(v.LockSumMS/float64(max64(v.LockN, 1)))))
			s.kv("最长一次等待", fmtDur(v.LockMaxMS))
			s.kv("涉及表数", fmt.Sprintf("%d 张（按对象 ID）", v.LockTableN))
			if v.LockPeakN > 0 {
				extra := ""
				if v.LockPeakIsTop {
					extra = "（正好是 QPS 峰值那一秒）"
				}
				s.kv("等待最密的一秒", fmt.Sprintf("%s：%d 次等待，该秒 QPS %d%s", v.LockPeakAt, v.LockPeakN, v.LockPeakQPS, extra))
			}
			s.blank()
			s.head("等待时长区间", "次数", "占比", "", "", "", "", "", "", "")
			var lt int64
			for _, n := range v.LockHist {
				lt += n
			}
			for i, n := range v.LockHist {
				r := len(s.rows)
				s.add(xc(lockNames[i]), xi(n), xp(pct(n, lt)/100))
				s.merge(r, 2, 9)
			}
			s.blank()
			if len(v.LockRows) > 0 {
				s.section(fmt.Sprintf("最久等待明细（全部 %d 条，按等待时长降序）", len(v.LockRows)))
				s.head("#", "等待(ms)", "锁模式", "对象", "等待方 trxid", "等待方用户", "持有方 trxid", "持有方用户", "被等事务数", "时间")
				for i, lk := range v.LockRows {
					s.add(xi(int64(i+1)), xn(lk.MS), xc(lk.Mode), xc(lockObj(lk.Table, lk.TableID)),
						xc(nz(lk.Waiter)), xc(nz(lk.WaiterU)), xc(nz(lk.Holder)), xc(nz(lk.HolderU)),
						xi(lk.Waiters), xc(lk.TS))
				}
				s.blank()
				s.add(xnote("持有方用户靠「事务号 → 用户」反查（日志的锁行只带等待方的会话信息），查不到显示为空。"))
			}
			if len(v.LockRowsAll) > 0 {
				s.section(fmt.Sprintf("锁等待双方的 SQL（V2.8；全量 %d 条，等待方 SQL 可得 %d / 持有方可得 %d）",
					v.LockTotalN, v.LockWaiterSQLN, v.LockHolderSQLN))
				s.head("#", "等待(ms)", "对象", "等待方 trxid", "等待方 SQL（参数已还原）",
					"持有方 trxid（链首）", "持有方结局", "持有方 SQL（该事务在日志里的语句）", "链长", "")
				for i, lk := range v.LockRowsAll {
					root := lk.HolderRoot
					if root == "" {
						root = lk.Holder
					}
					wsql := lk.WaiterSQL
					if wsql == "" {
						wsql = "（日志里没有可用 SQL 文本 —— 常见成因：语句很快被 MIN_EXEC_TIME 滤掉，或执行中被中止；都不是没执行）"
					} else {
						wsql = "[" + lk.WaiterOp + "] " + clipCell(wsql, 800)
					}
					hsql := "（日志里没有可用 SQL 文本 —— 常见成因：语句很快被 MIN_EXEC_TIME 滤掉，或执行中被中止；都不是没执行）"
					if len(lk.HolderStmts) > 0 {
						parts := make([]string, 0, len(lk.HolderStmts))
						for _, sm := range lk.HolderStmts {
							parts = append(parts, "["+sm.Op+"] "+clipCell(sm.SQL, 400))
						}
						hsql = strings.Join(parts, "  |  ")
						if lk.HolderSQLFromORA {
							hsql += "   ← 来源：[ORA] 原始语句行（掩码 27）；该语句执行很快，完成行被 MIN_EXEC_TIME 滤掉"
						}
					}
					kind := "未见 COMMIT/ROLLBACK"
					switch lk.HolderKind {
					case "ROLLBACK":
						kind = "回滚 " + shortTS(lk.HolderEndTS)
					case "COMMIT":
						kind = "提交 " + shortTS(lk.HolderEndTS)
					}
					s.add(xi(int64(i+1)), xn(lk.MS), xc(lockObj(lk.Table, lk.TableID)),
						xc(nz(lk.Waiter)), xc(wsql), xc(nz(root)), xc(kind), xc(hsql),
						xi(int64(len(lk.Chain))), xc(""))
				}
				s.blank()
				s.add(xnote("「持有方」取日志 trx[…] 列表的第一个 = 真正的持锁者，其余是排在它后面的等待者。" +
					"持有方 SQL 缺失不等于「没执行」：最常见成因是「语句执行很快、完成行被 MIN_EXEC_TIME 滤掉」" +
					"（133 构造实验实测），次因是「执行中被中止」；掩码含位 27 时本工具会自动从 [ORA] 行找回并标出来源。"))
			}
			if len(v.LockTables) > 0 {
				s.section(fmt.Sprintf("被争抢的表 Top%d（按累计等待）", len(v.LockTables)))
				s.head("对象", "次数", "累计等待(ms)", "最长(ms)", "锁模式", "等待方用户", "最长一次发生在", "", "", "")
				for _, r := range v.LockTables {
					s.add(xc(lockObj(r.Table, r.TableID)), xi(r.Count), xn(r.Sum), xn(r.Max),
						xc(r.Mode), xc(nz(r.Waiters)), xc(r.MaxAt))
				}
			}
			if v.RefSQL != "" {
				s.blank()
				s.add(xnote("DM 的 SQL 日志只记对象 ID、不记表名。复制执行下面这条即可反查，结果存成 UTF-8 文本后再加 --obj-map 文件名 重跑，报告就直接显示表名了："))
				s.add(xq(v.RefSQL))
			}
		}
		out = append(out, s)
	}

	// ============ 7) 长事务 ============
	if len(v.Trxs) > 0 || v.TrxOpenN > 0 {
		s := newSheet("长事务", 17, 19, 14, 16, 10, 10, 21, 21)
		s.head("trxid", "用户", "跨度(ms)", "SQL执行耗时(ms)", "利用率", "语句数", "起始", "结束")
		s.freeze = 1
		s.filter = true
		for _, r := range v.Trxs {
			s.add(xc(r.Trx), xc(nz(r.User)), xn(r.SpanMS), xn(r.ExecMS), xp(r.Util/100),
				xi(r.Count), xc(r.First), xc(r.Last))
		}
		s.blank()
		s.add(xnote("口径：同一 trxid 的首次事件 → 末次事件（事件 = 该事务的语句，以及掩码 29 的 TRX: START）。"))
		s.add(xnote("利用率 = 该事务内 SQL 的累计执行耗时 ÷（事务跨度 + 首条 SQL 耗时）。利用率低 = 占着事务不干活（长时间持锁、应用侧没提交），比「SQL 慢」更该先处理。"))
		if v.Commits+v.Rollbacks > 0 {
			s.add(xnote("注：COMMIT/ROLLBACK 行的 trxid 通常为 0，无法与 START 关联，故无法判定单个事务是否已提交，跨度只到该事务最后一条语句为止。"))
		}
		if v.TrxOpenN > 0 {
			s.add(xnote(fmt.Sprintf("另有 %s 个事务只见 TRX: START、后续无事件（可能未提交或日志被截断），未列入上表。", fmtInt(v.TrxOpenN))))
		}
		if v.TrxStmtN > 0 {
			s.blank()
			s.section(fmt.Sprintf("每事务语句数分布（共 %s 个事务，中位数 %d 条）", fmtInt(v.TrxStmtN), v.TrxStmtMed))
			s.head("每事务语句数", "事务数", "占比", "", "", "", "", "")
			for i, n := range v.TrxStmtHist {
				r := len(s.rows)
				s.add(xc(trxStmtNames[i]), xi(n), xp(pct(n, v.TrxStmtN)/100))
				s.merge(r, 2, 7)
			}
			s.add(xnote("「1 条」占比高 = 应用在逐条提交（批量导入慢的头号原因）；「>1000 条」= 大事务，注意 undo 与持锁。"))
		}
		out = append(out, s)
	}

	// ============ 8) 时段分布 ============
	if len(v.Buckets) > 0 {
		s := newSheet("时段分布", 24, 12, 12, 14, 12, 12, 11)
		s.section(fmt.Sprintf("负载时间分布（按%s，共 %d 个时段）", v.BucketUnit, v.BucketCount))
		s.add(xnote("这里是**完整时间轴**（报告里只画趋势图）—— 要按时间做柱状图/折线图、或按列排序筛选，直接用本表。"))
		s.head("时段", "SQL数", "平均QPS", "累计耗时(ms)", "COMMIT", "ROLLBACK", "占比")
		for _, b := range v.Buckets {
			s.add(xc(b.TS), xi(b.SQL), xn(b.QPS), xn(b.SumMS),
				xi(b.Commit), xi(b.Rollback), xp(b.Pct/100))
		}
		s.blank()
		s.add(xnote("看业务高峰直接把「SQL数」列降序排；空时段说明该时段没有 SQL 事件 —— 可能是业务低峰，也可能是采集中断。"))
		if v.PeakBucket != nil {
			s.add(xnote(fmt.Sprintf("峰值时段：%s（%s 条，平均 QPS %.2f）", v.PeakBucket.TS, fmtInt(v.PeakBucket.SQL), v.PeakBucket.QPS)))
		}
		if v.LongestIdle > 0 {
			s.add(xnote(fmt.Sprintf("最长静默空档：%s（起于 %s）—— 若与业务高峰无关，先怀疑采集中断。",
				fmtDur(v.LongestIdle*1000), v.LongestIdleAt)))
		}
		out = append(out, s)
	}

	// ============ 9) 用户与客户端 ============
	if len(v.Users) > 0 || len(v.Clients) > 0 {
		s := newSheet("用户与客户端", 32, 13, 14, 12, 12)
		s.section("用户排行（按语句数）")
		s.head("用户", "语句数", "累计耗时(ms)", "P95(ms)", "最大(ms)")
		for _, r := range v.Users {
			s.add(xc(r.User), xi(r.Count), xn(r.Sum), xn(r.P95), xn(r.Max))
		}
		s.blank()
		s.section("客户端排行（appname @ IP，按语句数）")
		s.add(xnote("生产日志里 appname 经常为空，此时按连接来源 IP 归类。"))
		s.head("客户端", "语句数", "累计耗时(ms)", "最大(ms)", "")
		for _, r := range v.Clients {
			rw := len(s.rows)
			s.add(xc(r.User), xi(r.Count), xn(r.Sum), xn(r.Max))
			s.merge(rw, 3, 4)
		}
		out = append(out, s)
	}

	// ============ 10) 结构变更与高危操作（有数据才出） ============
	if len(v.Dangers) > 0 || len(v.Changes) > 0 {
		s := newSheet("结构变更与高危操作", 6, 21, 12, 24, 18, 20, 11, 11, 100)
		s.section("结构变更与高危操作（性能劣化常紧跟一次 DDL，先看这里排除外力）")
		if len(v.SlowObjDDL) > 0 {
			s.add(xnote("最慢语句涉及的对象 → 该对象最近一次结构变更：「慢 SQL」的表的索引可能刚被改过。"))
			s.head("对象 → 最近一次结构变更", "", "", "", "", "", "", "", "")
			for _, r := range v.SlowObjDDL {
				rw := len(s.rows)
				s.add(xc(r.Name))
				s.merge(rw, 0, 8)
			}
			s.blank()
		}
		if len(v.Dangers) > 0 {
			ds, _ := auditSlice(v, opt)
			s.section(fmt.Sprintf("高危操作（共 %s 条，列出最近 %d 条，时间倒序）", fmtInt(v.DangerN), len(ds)))
			s.head("#", "时间", "类型", "对象", "用户", "客户端", "影响行数", "状态", "语句")
			for i, r := range ds {
				st := "已执行"
				if r.ORAOnly {
					st = "仅解析未执行"
				}
				s.add(xi(int64(i+1)), xc(auditTS(r.TS)), xc(r.Kind), xc(nz(r.Object)), xc(nz(r.User)),
					xc(nz(r.Client)), xc(rowsDisp(r.Rows)), xc(st), xq(r.AuditSQL))
			}
			s.blank()
			s.add(xnote("「仅解析未执行」= 语句到达服务器并完成语法解析、但没有执行行 —— 权限不足 / 超时 / 被取消都可能，本身即证据。"))
		}
		if len(v.Changes) > 0 {
			_, cs := auditSlice(v, opt)
			s.section(fmt.Sprintf("结构变更（共 %s 条，时间倒序）", fmtInt(v.ChangeN)))
			s.head("#", "时间", "类型", "对象", "用户", "客户端", "", "", "")
			for i, r := range cs {
				s.add(xi(int64(i+1)), xc(auditTS(r.TS)), xc(r.Kind), xc(nz(r.Object)), xc(nz(r.User)), xc(nz(r.Client)))
			}
		}
		out = append(out, s)
	}
	return out
}

// reportKindWord -r 落盘后的提示名词。.xlsx 不是"浏览器打开的报告"，别混着说。
func reportKindWord(path string) string {
	l := strings.ToLower(path)
	switch {
	case strings.HasSuffix(l, ".xlsx"):
		return "Excel 交付件"
	case strings.HasSuffix(l, ".html") || strings.HasSuffix(l, ".htm"):
		return "报告（HTML 浏览器直接打开）"
	case strings.HasSuffix(l, ".md") || strings.HasSuffix(l, ".markdown"):
		return "报告（Markdown）"
	}
	return "报告"
}

// defaultExcelName -e auto 时的交付件文件名：<日志名>_交付.xlsx
// 定期交付往往一月一份，文件名自带来源日志名，收件方一眼知道是哪份。
func defaultExcelName(files []string) string {
	base := ""
	if len(files) > 0 {
		base = filepath.Base(files[0])
	}
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" || base == "." {
		base = "dmsqlq"
	}
	return base + "_交付.xlsx"
}

func writeStatsFile(path string, v *statsView, opt *Options) error {
	l := strings.ToLower(path)
	// .xlsx 是个 zip 包，由独立写出器负责；不能共用下面这个 os.Create 的文件句柄
	if strings.HasSuffix(l, ".xlsx") {
		return writeExcelReport(path, v, opt)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	switch {
	case strings.HasSuffix(l, ".md") || strings.HasSuffix(l, ".markdown"):
		renderStatsMarkdown(f, v, opt)
	case strings.HasSuffix(l, ".html") || strings.HasSuffix(l, ".htm"):
		renderStatsHTML(f, v, opt)
	default:
		renderStatsText(f, v, opt)
	}
	return nil
}

// defaultReportName 纯 -s（未指定 -r）时的默认报告文件名。
//
// 取第一个输入文件做前缀，让"同一份日志的报告"天然聚在一起。
// 统一 .html —— 报告的价值大半在图表与交互上（点击展开/复制、条形图、KPI 卡片），
// 纯文本报告只适合在终端扫一眼，那正是 -S 的活。
func defaultReportName(files []string) string {
	base := ""
	if len(files) > 0 {
		base = filepath.Base(files[0])
	}
	// 剥扩展名；归档（.log.gz / .log.zip）要剥两次
	base = strings.TrimSuffix(base, filepath.Ext(base))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if base == "" || base == "." {
		base = "dmsqlq"
	}
	return base + "_报告.html"
}

// ---------------------------------------------------------------- 交付体验（对齐 dmmem-go 的设计约定）
//
// dmmem-go 是同一交付目录下的姊妹工具，它在「降低使用门槛」上有三条做法值得搬过来：
//   1. 产出了 HTML 就顺手用默认浏览器打开，用户不必自己去目录里找那个文件；
//   2. 从资源管理器双击运行时，结束前等一次回车，别让窗口一闪而过；
//   3. 终端只给「结论 + TOP5 表格」，够截图反馈，不刷屏。
// 前两条落在下面这几个函数里，第三条在 renderStatsBrief。
//
// 注意第 1 条会改变默认行为，所以配了 -Q/--no-open 开关：
// 批处理里连着跑十几份日志时，弹一屏浏览器窗口是很烦的。

// openers 各平台「用系统默认程序打开文件」的命令，按优先级排列。
func openers(abs string) [][]string {
	switch runtime.GOOS {
	case "windows":
		// explorer.exe 优先，两个理由：
		//   ① rundll32 是公认的 LOLBin，不少企业 EDR 会直接拦（本机沙箱这次就把它拦了）；
		//   ② 它不像 `cmd /c start` 那样闪一个黑窗口。
		// 注意 explorer.exe「打开成功时退出码也是 1」，所以绝不能拿退出码判成败 ——
		// 我们只判断进程能不能起来。
		return [][]string{
			{"explorer.exe", abs},
			{"rundll32.exe", "url.dll,FileProtocolHandler", abs},
		}
	case "darwin":
		return [][]string{{"open", abs}}
	default:
		// 桌面发行版优先 xdg-open；精简/老系统上没有它时退到 gio。
		return [][]string{{"xdg-open", abs}, {"gio", "open", abs}}
	}
}

// openWithSystem 用系统默认程序打开路径（HTML 报告）。best-effort：
// 打不开不算失败 —— 报告文件已经落盘，用户手动双击即可。
func openWithSystem(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	var lastErr error
	for _, argv := range openers(abs) {
		cmd := exec.Command(argv[0], argv[1:]...)
		// 打开器自身的输出一律丢弃：无桌面环境（SSH / 无 DISPLAY）下 xdg-open
		// 会往 stderr 吐一堆噪音，而我们只是「顺便打开」，不该污染终端。
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
		if err := cmd.Start(); err != nil {
			lastErr = err
			continue
		}
		go cmd.Wait() // 及时回收，别留僵尸进程
		return nil
	}
	return lastErr
}

// maybeOpenReport 报告落盘后自动用默认浏览器打开。
// 只对 HTML 生效 —— .md/.txt 没有「打开」的意义（它们本来就是给文档/终端看的）。
func maybeOpenReport(path string, opt *Options) {
	if opt.noOpen {
		return
	}
	l := strings.ToLower(path)
	if !strings.HasSuffix(l, ".html") && !strings.HasSuffix(l, ".htm") {
		return
	}
	if err := openWithSystem(path); err != nil && !opt.quiet {
		fmt.Fprintf(os.Stderr, "  （未能自动打开浏览器：%v；报告已生成，手动打开即可）\n", err)
	}
}

// isTerminal 判断文件是否连着终端（字符设备）。
// 用来区分「有人在屏幕前看」和「输出被重定向/接进管道」——只有前者才值得等待回车。
// 这也是个保护：`dmsqlq | grep …` 时 stdout 是管道，绝不会卡住。
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// watchStreams 决定 watch 的「数据」与「诊断」分别写到哪个流。
//
//	数据（记录本身）→ 永远 stdout：`dmsqlq watch … | grep x`、`> run.log` 拿到的都是干净的数据流；
//	诊断（横幅 / 表头 / 切换提示 / 汇总）→ stdout 是终端时也走 stdout（观感与以前完全一致），
//	  一旦 stdout 被重定向或接管道，就改走 stderr —— 否则 `| head -3` 的配额会被横幅吃掉、
//	  `> run.log` 里会混进表头和汇总。
//
// 判据用 isTerminal（字符设备）：Windows 控制台是字符设备，管道是 ModeNamedPipe，普通文件是普通文件。
func watchStreams() (data, diag io.Writer) {
	if isTerminal(os.Stdout) {
		return os.Stdout, os.Stdout
	}
	return os.Stdout, os.Stderr
}

// waitEnterIfDoubleClick Windows 上从资源管理器双击 exe 时，控制台窗口会在进程
// 结束的瞬间关闭，用户什么都来不及看（dmmem-go 明确记录过这个体验坑）。
//
// 只在「Windows + 无参数 + stdout 连着终端」时等待回车：
//   - 无参数 = 打印的是用法与引导，本来就该看完；
//   - Linux/macOS 从终端跑没有闪退问题，不必多此一举；
//   - 终端判断保证重定向/管道场景不会被拖住。
func waitEnterIfDoubleClick() {
	if runtime.GOOS != "windows" || !isTerminal(os.Stdout) {
		return
	}
	fmt.Fprint(os.Stdout, "\n按回车键退出 … ")
	// 直接读 1 字节（回车），不构造 bufio.Reader ——
	// 多处各自 new reader 会互相吞缓冲，dmmem-go / dmmem-monitor 都踩过。
	io.CopyN(io.Discard, os.Stdin, 1)
	fmt.Fprintln(os.Stdout)
}

// scanLogsHere 浅扫当前目录，看有没有本工具认识的日志。
// 无参数（多半是双击）时用它给出「照抄就能用」的下一步命令，
// 比让用户自己去 260 行的帮助里找入口友好得多。不递归 —— 双击场景下
// 日志通常就在 exe 旁边，递归扫大目录反而慢。
func scanLogsHere() (names []string, total int) {
	ents, err := os.ReadDir(".")
	if err != nil {
		return nil, 0
	}
	for _, e := range ents {
		if e.IsDir() || !isCandidate(e.Name(), false) {
			continue
		}
		total++
		if len(names) < 3 {
			names = append(names, e.Name())
		}
	}
	return names, total
}

// ExtraNote 命中等价说明
func (o *Options) ExtraNote() string {
	switch {
	case o.statsOnly:
		return "（--stats-only：只统计、未导出）"
	case o.topMS > 0:
		return fmt.Sprintf("（--top-ms：仅导出最慢 %d 条）", o.topMS)
	}
	return ""
}

// ═══════════════════════════════════════════════════════════════════ 实时监视（watch）
//
//   dmsqlq watch [目录或日志文件] [选项]
//
// 场景：想知道「点一下 DM 管理工具（manager.exe）的界面，它到底跑了什么 SQL」。
// 做法：跟随 sqllog.ini 指定的 SQL 日志目录，尾部增量读；每次轮询重扫目录，
//       出现更新的日志文件就切过去（SWITCH_MODE=2 是「按文件大小切换」，
//       新文件名自带时间戳），文件被截断/重建也能识别。
//
// 与批处理模式的边界：watch 有独立的参数集与独立的循环，不碰报告那条热路径；
// 入口只在 main() 开头拦一次。

const (
	watchPollDefault  = 200 * time.Millisecond
	watchWidthDefault = 150
	watchMinSQLCol    = 40
	watchSlowestKeep  = 5
	watchHeaderEvery  = 40   // 长跑时每 N 行重印一次列标题，免得滚上去后忘了每列是什么
	watchGapDefaultMS = 1000 // 同一批的最大间隔（毫秒）——实测一次点击带出的多条 SQL 间隔在百毫秒内
)

const (
	clrReset  = "\x1b[0m"
	clrDim    = "\x1b[2m"
	clrRed    = "\x1b[31m"
	clrGreen  = "\x1b[32m"
	clrYellow = "\x1b[33m"
	clrCyan   = "\x1b[36m"
)

// watchOpts 实时监视的选项（与批处理的 Options 完全分开，互不影响）
type watchOpts struct {
	app    string          // 只看该客户端（appname 子串，忽略大小写）
	ops    map[string]bool // 只看这些语句类型
	minMS  float64
	like   string
	all    bool   // 显示全部原始行（含 [ORA]、TRX、协议事件）
	dirArg string // -d/--dir：显式指定日志目录（等价于位置参数）
	pass   string // SYSDBA 口令（不给则读 $DM_PASS）

	// ---- 连远端实例（V2.21）----
	// 🩸 为什么需要：WSL2 是独立网络命名空间 + NAT，127.0.0.1 在 WSL 里指向 WSL 自己，
	//    连不上 Windows 主机上的达梦。从 WSL 连本机库必须用「Windows 主机 IP」；
	//    连虚拟机测试环境（192.168.16.x 等）同样要显式给地址。
	host      string // -H/--host：达梦实例地址（默认 127.0.0.1）
	port      string // -P/--port：达梦实例端口（默认读 dm.ini 的 PORT_NUM，否则 5236）
	syncLog   bool   // -Y：临时把 SQL 日志改成同步刷盘，退出自动还原
	showPaths bool   // 只列出自动找到的候选目录
	forget    bool   // 清掉记住的目录
	limit     int    // 输出满 N 条后退出（0 = 不限）
	tail      int    // 启动时回放最近 N 条
	poll      time.Duration
	width     int
	full      bool // SQL 不截断
	color     bool
	noHead    bool

	// ---- 批次聚合（V2.18）----
	gap    time.Duration // -g/--gap：同一批内两条记录的最大间隔；0 = 不聚合
	gapSet bool          // 用户是否显式给过 -g（显式则不管终端还是管道都照办）
	group  bool          // 是否启用批次聚合（终端默认开；重定向/接管道默认扁平）

	// ---- 只要 SQL（V2.19）----
	// 元信息行里的「耗时」是判断哪条慢的唯一线索，所以默认保留；
	// --sql-only 给「只想把 SQL 复制出去执行」的场景（看某个界面到底发了哪些 SQL）。
	sqlOnly bool // 只输出 SQL 原文：无元信息行/批次头/表头，不缩进、不截断
}

func watchUsage() func() {
	return func() {
		fmt.Fprint(os.Stdout, `dmsqlq watch ── 实时监视 SQL 日志（看客户端到底跑了什么 SQL）

用法
  dmsqlq watch [目录或日志文件] [选项]

  给目录 → 自动跟随目录里最新的 dmsql_*.log；
  给文件 → 跟随该文件，并自动切到同目录里更新的日志；
  ★ 都不给 → 自动定位（不用记路径）：
      ① $DMSQLQ_LOG_DIR  ② 上次用过的目录（记住）
      ③ 扫 DM 安装目录：各盘的 \dmdbms / \dm8 / \dameng / \dmdata 等，
         读其中 sqllog.ini 的 FILE_PATH（相对路径会逐个基准试，见下），
         Linux 上还扫 /opt /data /usr/local /home/<用户> 下的同名目录。
      多个候选时按「最近写过日志」挑，并在横幅里告诉你还发现了哪些、怎么换。

  ★ 日志会「切换」（SQLLOG.INI 的 SWITCH_MODE=2 是按大小切，默认 128MB 一个），
    本工具每次轮询都会重扫目录，新文件一出现就自动切过去，不用重开。

常用
  dmsqlq watch -a manager.exe
      自动定位日志目录，只看 DM 管理工具执行的 SQL。点界面 → SQL 立刻打到屏幕上。

  dmsqlq watch -a manager.exe -Y
      同上，并把 SQL 日志临时切成同步刷盘（退出自动还原）—— 口令取 $DM_PASS。

  dmsqlq watch --all
      连准备阶段（[ORA]）、事务起止、协议事件一起看 —— 排查「一条都没打出来」时用。

  dmsqlq watch --show-paths
      只列出自动找到的候选日志目录（含各自最近活动时间），确认它找对了没有。

  dmsqlq watch -d "D:\dmdbms\log" -m 100 -F
      显式给目录，只看执行超过 100ms 的，且 SQL 整条不截断。

选项
  -a, --app <名>        只看该客户端（appname 字段，子串匹配，忽略大小写；默认全部）
  -k, --op <类型列表>   只看这些语句类型，逗号分隔（SEL,INS,UPD,DEL,DML,DDL,CAL,ERR）
  -m, --min-ms <毫秒>   只显示耗时 ≥ 该值的语句
  -l, --like <子串>     只显示 SQL 含该子串的语句（忽略大小写）
  -A, --all             显示全部原始行，不做「只显示已执行语句」的过滤
  -T, --tail <条数>     启动时先回放该文件最近 N 条（默认 0：只看启动之后的新记录）
  -n, --limit <条数>    输出满 N 条后自动退出并打印汇总（默认 0：一直跑，Ctrl-C 停）
  -i, --interval <毫秒> 轮询间隔（默认 200，最小 20；--poll 为同义长名）
  -g, --gap <毫秒>      同一批的最大间隔（默认 1000）—— 同一会话、且与上一条的间隔不超过
                        它的连续记录聚成一批（点一次界面带出的十几条 SQL 会放在一起）。
                        0 = 不聚合，输出扁平表；重定向 / 接管道时自动就是这个模式。
      --sql-only        只输出 SQL 原文：不打印元信息行 / 批次头 / 表头，也不缩进、不截断。
                        **每条 SQL 之间空一行** —— 一批里有的语句不带分号（日志记的是客户端
                        发来的原文），一行挨一行会数不清是几条；批次之间空两行以示分组，
                        配 -g 0 则没有批次概念、统一一行一条。典型用法：
                            dmsqlq watch -a manager.exe --sql-only > click.sql
                        空行不影响 disql 执行（脚本执行默认忽略 SQL 之间的空行）。
  -d, --dir <目录>      显式指定日志目录（等价于位置参数）
  -p, --pass <口令>     SYSDBA 口令；不给则读环境变量 $DM_PASS。
  -H, --host <地址>   达梦实例地址（默认 127.0.0.1，也可用 $DM_HOST）。
                        ★ 从 WSL 连 Windows 本机的达梦：给 WSL 的网关地址（如 172.20.240.1）。
                        ★ 连虚拟机测试环境：给那台虚拟机的 IP（如 192.168.16.135）。
  -P, --port <端口>    实例端口（默认读 dm.ini 的 PORT_NUM，否则 5236）。
                        连远端库时建议显式给 —— 本机读不到远端的 dm.ini。
                        给了口令会顺手做一次「采集配置体检」（只读）。
  -Y, --sync-log        临时把 SQL 日志切成同步刷盘（ASYNC_FLUSH=0），
                        退出时自动还原。★要改数据库的 sqllog.ini，需口令。
      --show-paths      只列出自动找到的候选日志目录（含各自最近活动时间），不动
      --forget          清掉记住的日志目录
  -w, --width <列数>    输出总宽（默认取 $COLUMNS，否则 150）
  -F, --full            SQL 不截断，整条原样输出
      --color           彩色输出（Git Bash / Windows Terminal 下更好看；cmd.exe 请勿开）
      --no-header       不打印列标题
  -h, --help            本帮助

管道（把记录再往下游过滤）
  记录写在 stdout；诊断信息（横幅 / 表头 / 切换提示 / 汇总）在 stdout 被重定向或接管道时改走 stderr，
  所以下面这些拿到的都是「干净的数据流」：
    dmsqlq watch -a manager.exe | grep --line-buffered "insert into"
        ★ grep 的输出不是终端时会块缓冲，加 --line-buffered 才实时（不加要攒够 4KB 才吐一次）
    dmsqlq watch -a manager.exe > run.log      :: 文件里只有记录，没有横幅/表头/汇总
    dmsqlq watch -a manager.exe | head -3      :: 下游一关，工具在「下一次写出」时自己退出
        （Linux/macOS 会被 SIGPIPE 直接结束；Windows 没有 SIGPIPE，只能在写出时发现 ——
          所以下游关闭后若长时间没有新记录，它会继续跟随，按 Ctrl-C 即可）
  内置过滤仍是首选 —— 它懂语义：按客户端 / 语句类型 / 执行耗时 / SQL 子串，且能区分「SQL 文本」
  与列里的值；管道适合临时组合（多条 and/or、cut/awk、喂给别的工具）。
  例：-l 只匹配 SQL 文本，而 (| grep SYS) 会把「SYSDBA」这种列值也一起命中。

输出格式（默认：批次 + 紧凑表格）
  一次界面点击常带出十几条 SQL，它们的会话/客户端/用户/IP 完全相同 —— 逐条重复列出既占宽，
  也看不出「这些是同一次操作」。所以默认把「同一会话 + 间隔不超过 -g」的记录聚成一批：

    ── 批次 3 · 15:08:32.427 ──────────────────────────────────────────
      会话: 00000000348B71C8   客户端: DIsql.exe        ← 本批共用的字段（键: 值）
      用户: SYSDBA   线程号: 120096   IP: 127.0.0.1
      时间         类型 耗时      行数   事务号            ← 行内只留逐条变化的字段
      15:08:32.427 SEL       4 ms      1   4419259
        select user;
      15:08:32.489 SEL      54 ms   5781   4419260
        select sql_addr, sql_id, n_exec, cmd_type from v$sqltext;
      共 4 条 · 累计 59 ms · 跨度 62 ms                     ← 该批收尾（下批开始/静默超时/退出时打）

  · SQL 单独成行、缩进 4 空格 —— 想复制 SQL 就选这一行，不会带上时间与耗时。
  · 批次收尾里：累计 = 本批各条 EXECTIME 之和；跨度 = 本批最后一条减第一条的时间戳。
  · 批次头的线程号取自本批第一条 —— 同一条语句解析与执行可能落在不同线程，它会变。
  ★ 只想把 SQL 复制出去执行（例如「看某个界面到底发了哪些 SQL」）→ 加 --sql-only：
    只打 SQL 原文，没有元信息行、没有批次头，也不缩进不截断；**每条之间空一行**（一批里
    有的语句不带分号，挨着排会数不清），批次之间空两行。
    · 空行对执行无害：《DM8_DIsql 使用手册》里 SQL 以 ; 结束、语句块以 / 结束，
      而脚本执行**默认忽略 SQL 之间的空行**（SET CTRL_INFO 的 8 位才是「不忽略」）。
    · ⚠️ 但不带分号的语句粘进 disql **不会执行** —— 日志记的是客户端发来的原文，
      工具不替它补分号（末尾带 -- 注释时补 ; 会落进注释里），要跑请自己补。
    反过来，元信息行里的「耗时」是判断哪条慢的唯一线索 —— 所以默认保留，别为了好看丢掉它。
  · 时间    记录时刻（HH:MM:SS.mmm，服务端时钟）
  ★ 不加 -a 看全库时，多个会话交叉活动会让批次切得很碎（每切一次就是 3 行批头/批尾）：
    这时建议 -a 只看一个客户端，或用 -g 0 走扁平模式。
  · 耗时    EXECTIME；★包含等锁时间（一条等锁 25 秒的单行 INSERT 会显示 25 s，不是 1 ms）
  · 事务号  trxid；0 = 该语句当时没有活动事务（自动提交，或事务尚未开始）
  · 会话    sess 会话地址；拿它可以在库上关联到这条语句（见下）

  重定向 / 接管道时自动切成「扁平模式」（不加批次头与收尾）：
    第 1 行 = 元信息，对齐成表：时间 · 类型 · 耗时 · 行数 · 线程号 · 用户 · 事务号 · 应用名 · 会话 · IP
    第 2 行 = SQL 原文，缩进 2 空格、独占一行
    ★ 同一秒内执行的多条记录之间会空一行（时间戳一模一样，不空行会糊成一片）。
    终端不够宽会自动省略次要列（会话 → IP → 线程号 → 用户 → 事务号），用 -w 加宽即可全部显示。
   想让它带批次，显式给 -g 即可（例如 -g 1000）。

  未显示的两个字段（本次特意排除）：
    · 句柄号 stmt —— 实测没有可查的视图：V$OPEN_STMT 只给每会话的 STMT_ID（不是地址），
      唯一的地址列 STMT_DBG 只在调试会话时非空。
    · 执行节点 EP[n] —— 单机恒为 0，无信息量。
  拿着「会话」地址去库里查这条语句的实时状态：
    SELECT SESS_ADDR, SESSION#, STMT_ID, TYPE, SQL_STR FROM V$OPEN_STMT WHERE SESS_ADDR = '0x<会话>';
    再按 SESSION# 连 V$SESSIONS 看 SQL_TEXT / USER_NAME / TRX_ID / CLNT_IP / APPNAME / STATE。

为什么可能「一条都不打出来」
  ① SQLLOG.INI 的 MIN_EXEC_TIME 大于 0 —— 低于该值的语句不写「执行完成行」。
     本工具默认只显示已执行的语句，此时会看起来什么都没发生（用 --all 可看到 [ORA] 行）。
  ② dm.ini 的 SVR_LOG 没开（0=关，1=开）。
  ③ 异步刷盘有延迟：ASYNC_FLUSH=1 是异步刷盘，调试时建议临时设 0（= 实时刷盘）。

停止：Ctrl-C（退出时会打印本次观察的汇总）。
`)
	}
}

// envWidth 终端宽度：优先 $COLUMNS，否则用缺省值。
// 不做 ioctl —— 单文件要同时编 Windows/Linux，取终端尺寸得引平台特定代码，不值得。
func envWidth() int {
	if v := strings.TrimSpace(os.Getenv("COLUMNS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 60 {
			return n
		}
	}
	return watchWidthDefault
}

// watchRegroup 把「选项」与「位置参数（目录/文件）」分开。
// 必须自己做：Go 的 flag 包碰到第一个非选项参数就停止解析，
// 而本工具习惯写成 `dmsqlq watch <目录> -a xxx`（路径在前、选项在后），
// 不重排的话 -a xxx 会被整段当成位置参数。
// 判据是「这个选项收不收值」—— 收值的要连它的值一起搬走，漏一个就会把值吞掉。
func watchRegroup(args []string) (flagArgs, posArgs []string) {
	valNames := map[string]bool{
		"app": true, "a": true, "op": true, "k": true,
		"min-ms": true, "m": true, "like": true, "l": true,
		"tail": true, "T": true, "limit": true, "n": true,
		"interval": true, "i": true, "poll": true, "width": true, "w": true,
		"dir": true, "d": true, "pass": true, "p": true,
		"host": true, "H": true, "port": true, "P": true,
		// ★ 每加一个「收值」的选项都必须补进来 —— 漏了它就会把后面那个选项名当成自己的值
		//   （实测：漏了 gap，`-g 1000 -T 3000` 报 invalid value "-T" for flag -g）。
		//   V2.21 又踩一次同类：漏了 host，`-H 127.0.0.1` 里的 127.0.0.1 被当成位置参数
		//   （于是它变成了「日志目录」，反而报路径错误 —— 症状和参数名错完全不同，更难认）。
		"gap": true, "g": true,
	}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			posArgs = append(posArgs, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") || !valNames[name] {
				i++ // 布尔型，或已用 = 带值
				continue
			}
			if i+1 < len(args) {
				flagArgs = append(flagArgs, args[i+1])
				i += 2
				continue
			}
			i++
			continue
		}
		posArgs = append(posArgs, a)
		i++
	}
	return flagArgs, posArgs
}

func parseWatchArgs(args []string) (*watchOpts, string, error) {
	o := &watchOpts{poll: watchPollDefault}
	fs := flag.NewFlagSet("dmsqlq watch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {} // 自定义帮助自己打，不让 flag 包抢先

	var app, opList, like string
	var minMS float64
	var all, full, color, noHead, sqlOnly bool
	var limit, tail, width, pollMS int
	var dirArg, pass, host, portFlag string
	var syncLog, showPaths, forget bool
	var gapMS int

	fs.StringVar(&app, "app", "", "")
	fs.StringVar(&app, "a", "", "")
	fs.StringVar(&opList, "op", "", "")
	fs.StringVar(&opList, "k", "", "")
	fs.Float64Var(&minMS, "min-ms", 0, "")
	fs.Float64Var(&minMS, "m", 0, "")
	fs.StringVar(&like, "like", "", "")
	fs.StringVar(&like, "l", "", "")
	fs.BoolVar(&all, "all", false, "")
	fs.BoolVar(&all, "A", false, "")
	fs.IntVar(&tail, "tail", 0, "")
	fs.IntVar(&tail, "T", 0, "")
	fs.IntVar(&limit, "limit", 0, "")
	fs.IntVar(&limit, "n", 0, "")
	fs.IntVar(&pollMS, "interval", int(watchPollDefault/time.Millisecond), "")
	fs.IntVar(&pollMS, "i", int(watchPollDefault/time.Millisecond), "")
	fs.IntVar(&pollMS, "poll", int(watchPollDefault/time.Millisecond), "")
	fs.IntVar(&gapMS, "gap", watchGapDefaultMS, "")
	fs.IntVar(&gapMS, "g", watchGapDefaultMS, "")
	fs.StringVar(&dirArg, "dir", "", "")
	fs.StringVar(&dirArg, "d", "", "")
	fs.StringVar(&pass, "pass", "", "")
	fs.StringVar(&pass, "p", "", "")
	fs.StringVar(&host, "host", "", "")
	fs.StringVar(&host, "H", "", "")
	fs.StringVar(&portFlag, "port", "", "")
	fs.StringVar(&portFlag, "P", "", "")
	fs.BoolVar(&syncLog, "sync-log", false, "")
	fs.BoolVar(&syncLog, "Y", false, "")
	fs.BoolVar(&showPaths, "show-paths", false, "")
	fs.BoolVar(&forget, "forget", false, "")
	fs.IntVar(&width, "width", 0, "")
	fs.IntVar(&width, "w", 0, "")
	fs.BoolVar(&full, "full", false, "")
	fs.BoolVar(&full, "F", false, "")
	fs.BoolVar(&color, "color", false, "")
	fs.BoolVar(&noHead, "no-header", false, "")
	fs.BoolVar(&sqlOnly, "sql-only", false, "")

	flagArgs, posArgs := watchRegroup(args)
	if err := fs.Parse(flagArgs); err != nil {
		return nil, "", err
	}
	rest := posArgs
	if len(rest) > 1 {
		return nil, "", fmt.Errorf("最多给一个目录或文件，收到 %d 个：%v", len(rest), rest)
	}

	o.app = strings.TrimSpace(app)
	o.minMS = minMS
	o.like = strings.TrimSpace(like)
	o.all = all
	o.tail = tail
	if o.tail < 0 {
		o.tail = 0
	}
	o.limit = limit
	o.full = full
	o.color = color
	o.noHead = noHead
	o.dirArg = strings.TrimSpace(dirArg)
	o.pass = strings.TrimSpace(pass)
	o.host = strings.TrimSpace(host)
	o.port = strings.TrimSpace(portFlag)
	o.syncLog = syncLog
	o.showPaths = showPaths
	o.forget = forget
	o.sqlOnly = sqlOnly

	// 批次聚合：终端下默认开（一次点击的一批 SQL 聚在一起）；重定向/接管道时默认扁平输出，
	// 保证「数据流」是规整的行、方便 grep/awk。用户显式给了 -g 就照办。
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "gap" || f.Name == "g" {
			o.gapSet = true
		}
	})
	if gapMS < 0 {
		gapMS = 0
	}
	o.gap = time.Duration(gapMS) * time.Millisecond
	// --sql-only 也要走批次状态机（只为「批次之间空一行」这层分组信息），
	// 但批次头/行内列表头/收尾行都不打 —— 整份输出可以整段复制，不用删任何东西。
	o.group = o.gap > 0 && (o.sqlOnly || isTerminal(os.Stdout) || o.gapSet)
	if pollMS < 20 {
		pollMS = 20
	}
	o.poll = time.Duration(pollMS) * time.Millisecond
	o.width = width
	if o.width <= 0 {
		o.width = envWidth()
	}
	if o.width < 60 {
		o.width = 60
	}
	if opList != "" {
		o.ops = map[string]bool{}
		for _, p := range strings.Split(opList, ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			if p != "" {
				o.ops[p] = true
			}
		}
	}
	path := ""
	if len(rest) == 1 {
		path = rest[0]
	}
	return o, path, nil
}

// ------------------------------------------------------------ 跟随文件（含轮转）

var reWatchLogName = regexp.MustCompile(`_(\d{8})_(\d{6})\.log$`)

// newestLog 找目录里最新的 dmsql_*.log。
// 优先按文件名内嵌的时间戳比（DM 命名 dmsql_<实例>_<YYYYMMDD>_<HHMMSS>.log），
// 拿不到时间戳时退回按 mtime 比。
func newestLog(dir string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	best, bestKey := "", "\x00"
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, "dmsql_") || !strings.HasSuffix(n, ".log") {
			continue
		}
		m := reWatchLogName.FindStringSubmatch(n)
		if m == nil {
			continue
		}
		if key := m[1] + m[2]; key > bestKey {
			bestKey, best = key, filepath.Join(dir, n)
		}
	}
	if best != "" {
		return best
	}
	var bestT time.Time
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, "dmsql_") || !strings.HasSuffix(n, ".log") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if best == "" || fi.ModTime().After(bestT) {
			best, bestT = filepath.Join(dir, n), fi.ModTime()
		}
	}
	return best
}

func watchFileSize(path string) int64 {
	if st, err := os.Stat(path); err == nil && !st.IsDir() {
		return st.Size()
	}
	return 0
}

// follower 尾部增量读 + 轮转切换。
//
//	committed：已「消费」到的字节位置（只算完整行，末尾不完整的半行不计）
//	pending  ：末尾那半行，等下次读到换行再拼起来
type follower struct {
	dir       string
	cur       string
	committed int64
	pending   []byte
}

func (f *follower) readNew() []string {
	if f.cur == "" {
		return nil
	}
	fh, err := os.Open(f.cur)
	if err != nil {
		return nil
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return nil
	}
	size := fi.Size()
	if size < f.committed { // 同文件被截断/重建
		f.committed, f.pending = 0, nil
	}
	if size <= f.committed {
		return nil
	}
	start := f.committed
	buf := make([]byte, size-start)
	n, _ := fh.ReadAt(buf, start)
	if n <= 0 {
		return nil
	}
	buf = buf[:n]
	data := append(append([]byte(nil), f.pending...), buf...)
	f.pending = nil

	i := bytes.LastIndexByte(data, '\n')
	if i < 0 { // 还没凑出一条完整行
		f.pending = data
		f.committed = start + int64(n)
		return nil
	}
	f.pending = append([]byte(nil), data[i+1:]...)
	f.committed = start + int64(n) - int64(len(f.pending))
	return strings.Split(string(data[:i]), "\n")
}

// poll 每次轮询都重扫目录：出现更新的日志就先把旧文件读干净再切过去。
func (f *follower) poll() (lines []string, switched bool, newName string) {
	n := newestLog(f.dir)
	if n != "" && n != f.cur {
		var old []string
		if f.cur != "" {
			old = f.readNew()
		}
		f.cur, f.committed, f.pending = n, 0, nil
		return old, true, n
	}
	if f.cur == "" {
		return nil, false, ""
	}
	return f.readNew(), false, ""
}

// tailLines 只读文件末尾 N 行（从尾部按窗口往前扩，最多回退 32MB）
func tailLines(path string, n int) []string {
	if n <= 0 {
		return nil
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return nil
	}
	size := fi.Size()
	if size == 0 {
		return nil
	}
	window := int64(256 << 10)
	var data []byte
	var start int64
	for {
		if window > size {
			window = size
		}
		start = size - window
		buf := make([]byte, window)
		if _, err := fh.ReadAt(buf, start); err != nil && err != io.EOF {
			return nil
		}
		data = buf
		if start == 0 || bytes.Count(data, []byte("\n")) >= n+1 || window >= 32<<20 {
			break
		}
		window *= 4
	}
	lines := strings.Split(string(data), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // 首行是半截的
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// ------------------------------------------------------------ 行解析

type watchRow struct {
	Clock   string
	App     string // 客户端程序名（appname:）
	User    string // 登录用户名（user:）
	IP      string // 客户端 IP（ip:）
	Thrd    string // 服务端线程号（thrd:）
	Trx     string // 事务号（trxid:），0 = 当时无活动事务
	Sess    string // 会话地址（sess:）—— 可在库上按 V$OPEN_STMT.SESS_ADDR 关联
	Stmt    string // 语句句柄地址（stmt:）—— 无视图可查，暂不展示
	EP      string // 执行节点（EP[n:]），单机恒 0，暂不展示
	Op      string
	MS      float64
	HasMS   bool
	Rows    int64
	HasRows bool
	SQL     string
	IsStmt  bool
}

func watchHdrField(hdr, key string) string {
	i := strings.Index(hdr, key)
	if i < 0 {
		return ""
	}
	s := hdr[i+len(key):]
	if j := strings.IndexByte(s, ' '); j >= 0 {
		s = s[:j]
	}
	return strings.TrimSpace(s)
}

// watchEP 取 EP[n] 里的执行节点号（单机恒 0）。
func watchEP(hdr string) string {
	i := strings.Index(hdr, "EP[")
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(hdr[i:], ']')
	if j < 0 {
		return ""
	}
	return hdr[i+3 : i+j]
}

// tagIsStmt 判断方括号标签是不是「一条语句」。
// 已知：SEL/INS/UPD/DEL/DML/DDL/CAL/ORA/ERR(-NNNN)；LGN（登录）与 DLCK 是事件。
func tagIsStmt(tag string) bool {
	if strings.HasPrefix(tag, "ERR(") {
		return true
	}
	if tag == "LGN" || tag == "DLCK" {
		return false
	}
	if len(tag) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if tag[i] < 'A' || tag[i] > 'Z' {
			return false
		}
	}
	return true
}

func watchEventOp(body string) string {
	switch {
	case strings.HasPrefix(body, "trx["):
		return "pseg"
	case strings.HasPrefix(body, "DLCK"):
		return "DLCK"
	}
	if i := strings.IndexAny(body, " :"); i > 0 {
		return body[:i]
	}
	if len(body) > 7 {
		return body[:7]
	}
	return body
}

// watchSplitTail 把「SQL + EXECTIME: N(ms) + ROWCOUNT: N(rows) + EXEC_ID: N」拆开
func watchSplitTail(s string) (sql string, ms float64, hasMS bool, rows int64, hasRows bool) {
	cut := -1
	for _, m := range []string{" EXECTIME:", " ROWCOUNT:", " EXEC_ID:"} {
		if i := strings.Index(s, m); i >= 0 && (cut < 0 || i < cut) {
			cut = i
		}
	}
	if cut < 0 {
		return strings.TrimRight(s, " \t"), 0, false, 0, false
	}
	sql = strings.TrimRight(s[:cut], " \t")
	tail := s[cut:]
	if i := strings.Index(tail, "EXECTIME:"); i >= 0 {
		ms, hasMS = watchParseDur(tail[i+len("EXECTIME:"):])
	}
	if i := strings.Index(tail, "ROWCOUNT:"); i >= 0 {
		rows, hasRows = watchParseInt(tail[i+len("ROWCOUNT:"):])
	}
	return
}

func watchParseDur(s string) (float64, bool) {
	s = strings.TrimLeft(s, " \t")
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
		i++
	}
	if i == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, false
	}
	u := strings.ToLower(s[i:])
	switch {
	case strings.HasPrefix(u, "(us"):
		v /= 1000
	case strings.HasPrefix(u, "(ns"):
		v /= 1e6
	}
	return v, true
}

func watchParseInt(s string) (int64, bool) {
	s = strings.TrimLeft(s, " \t")
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	v, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// cleanWatchSQL 去掉客户端打的 /***Xxx***/ 标记（客户端列已经说明身份，这里重复）
func cleanWatchSQL(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "/***") {
		if i := strings.Index(s, "***/"); i >= 0 {
			s = strings.TrimSpace(s[i+4:])
		}
	}
	return s
}

func parseWatchLine(line string) (watchRow, bool) {
	var r watchRow
	if len(line) < 24 || line[4] != '-' || line[7] != '-' || line[10] != ' ' || line[13] != ':' {
		return r, false
	}
	r.Clock = line[11:23]
	close := strings.Index(line, ") ")
	if close < 24 {
		return r, false
	}
	hdr := line[:close]
	body := strings.TrimLeft(line[close+2:], " ")
	r.App = watchHdrField(hdr, "appname:")
	r.User = watchHdrField(hdr, "user:")
	r.IP = watchHdrField(hdr, "ip:")
	r.Thrd = watchHdrField(hdr, "thrd:")
	r.Trx = watchHdrField(hdr, "trxid:")
	r.Sess = watchHdrField(hdr, "sess:")
	r.Stmt = watchHdrField(hdr, "stmt:")
	r.EP = watchEP(hdr)

	if strings.HasPrefix(body, "[") {
		i := strings.IndexByte(body, ']')
		if i < 0 {
			return r, false
		}
		tag := body[1:i]
		rest := strings.TrimLeft(strings.TrimPrefix(body[i+1:], ":"), " ")
		r.IsStmt = tagIsStmt(tag)
		if strings.HasPrefix(tag, "ERR(") {
			r.Op = "ERR"
		} else {
			r.Op = tag
		}
		r.SQL, r.MS, r.HasMS, r.Rows, r.HasRows = watchSplitTail(rest)
		r.SQL = cleanWatchSQL(r.SQL)
		return r, true
	}

	r.Op = watchEventOp(body)
	r.SQL = body
	if strings.HasPrefix(body, "TRX: ") {
		r.SQL = strings.TrimSpace(body[5:])
	}
	return r, true
}

// ------------------------------------------------------------ 过滤与渲染

func (o *watchOpts) keep(r watchRow) bool {
	if o.app != "" && !strings.Contains(strings.ToLower(r.App), strings.ToLower(o.app)) {
		return false
	}
	if !o.all {
		// 默认只显示「真正执行过」的语句：有 EXECTIME 的执行完成行；ERR 始终显示。
		if !r.IsStmt || r.Op == "ORA" {
			return false
		}
		if !r.HasMS && r.Op != "ERR" {
			return false
		}
	}
	if len(o.ops) > 0 && !o.ops[r.Op] {
		return false
	}
	if o.minMS > 0 && (!r.HasMS || r.MS < o.minMS) {
		return false
	}
	if o.like != "" && !strings.Contains(strings.ToLower(r.SQL), strings.ToLower(o.like)) {
		return false
	}
	return true
}

func (o *watchOpts) filterDesc() string {
	parts := []string{}
	if o.all {
		parts = append(parts, "显示全部原始行")
	} else {
		parts = append(parts, "只显示已执行的语句")
	}
	if len(o.ops) > 0 {
		ks := make([]string, 0, len(o.ops))
		for k := range o.ops {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		parts = append(parts, "类型="+strings.Join(ks, "/"))
	}
	if o.minMS > 0 {
		parts = append(parts, "耗时≥"+watchDur(o.minMS))
	}
	if o.like != "" {
		parts = append(parts, "SQL 含「"+o.like+"」")
	}
	return strings.Join(parts, " · ")
}

func (o *watchOpts) paint(s, c string) string {
	if !o.color || c == "" {
		return s
	}
	return c + s + clrReset
}

func watchOpColor(op string) string {
	switch op {
	case "ERR":
		return clrRed
	case "SEL":
		return clrCyan
	case "INS", "UPD", "DEL", "DML", "DDL":
		return clrYellow
	case "CAL":
		return clrGreen
	case "ORA":
		return clrDim
	}
	return clrDim
}

func watchDur(ms float64) string {
	switch {
	case ms <= 0:
		return "<1 ms" // EXECTIME: 0(ms) 只说明不到 1 毫秒，别写成 0.0 us 那种假精度
	case ms < 1:
		return strconv.FormatFloat(ms*1000, 'f', 1, 64) + " us"
	case ms < 1000:
		return strconv.FormatFloat(ms, 'f', 0, 64) + " ms"
	case ms < 60000:
		return strconv.FormatFloat(ms/1000, 'f', 2, 64) + " s"
	default:
		return strconv.FormatFloat(ms/60000, 'f', 1, 64) + " m"
	}
}

// 元信息行的列。宽度不够时按 drop 值从小到大丢列（0 = 永不丢）。
type watchCol struct {
	key   string
	title string
	w     int
	right bool // 数值列右对齐
	drop  int  // 丢弃顺序：越小越先丢
}

func watchCols(showApp bool) []watchCol {
	cols := []watchCol{
		{key: "time", title: "时间", w: 12},
		{key: "op", title: "类型", w: 4},
		{key: "dur", title: "耗时", w: 9, right: true},
		{key: "rows", title: "行数", w: 6, right: true},
		{key: "thrd", title: "线程号", w: 7, right: true, drop: 3},
		{key: "user", title: "用户", w: 12, drop: 4},
		{key: "trx", title: "事务号", w: 13, right: true, drop: 5},
	}
	// 应用名总是显示：它是「谁在跑这条 SQL」的第一手信息。
	// 已经用 -a 过滤时这列是常量，所以宽度不够时优先丢它（drop=6）。
	appDrop := 0
	if !showApp {
		appDrop = 6
	}
	cols = append(cols, watchCol{key: "app", title: "应用名", w: 16, drop: appDrop})
	cols = append(cols,
		watchCol{key: "sess", title: "会话", w: 16, drop: 1},
		watchCol{key: "ip", title: "IP", w: 15, drop: 2},
	)
	return cols
}

// watchFit 按输出宽度裁列；返回可用列与被省略的列名（用 / 连接）。
func watchFit(o *watchOpts, showApp bool) ([]watchCol, string) {
	cols := watchCols(showApp)
	need := func(cs []watchCol) int {
		n := 0
		for _, c := range cs {
			n += c.w + 1
		}
		return n
	}
	var dropped []string
	for need(cols) > o.width {
		idx, best := -1, 1<<30
		for i, c := range cols {
			if c.drop > 0 && c.drop < best {
				idx, best = i, c.drop
			}
		}
		if idx < 0 {
			break
		}
		dropped = append(dropped, cols[idx].title)
		cols = append(cols[:idx:idx], cols[idx+1:]...)
	}
	return cols, strings.Join(dropped, "/")
}

func watchHeader(cols []watchCol) (head, sep string) {
	var h, s strings.Builder
	for _, c := range cols {
		t := c.title
		if c.right {
			t = lpad(t, c.w) // 数值列右对齐，标题跟着右对齐，免得标题与数字离得老远
		} else {
			t = pad(t, c.w)
		}
		h.WriteString(t + " ")
		s.WriteString(strings.Repeat("─", c.w) + " ")
	}
	return strings.TrimRight(h.String(), " "), strings.TrimRight(s.String(), " ")
}

// colText 取某列在一条记录上的显示值。空值统一显示成 "-"。
func (o *watchOpts) colText(r watchRow, key string) string {
	switch key {
	case "time":
		return r.Clock
	case "op":
		if r.Op == "" {
			return "?"
		}
		return r.Op
	case "dur":
		if !r.HasMS {
			return "-"
		}
		return watchDur(r.MS)
	case "rows":
		if !r.HasRows {
			return "-"
		}
		return strconv.FormatInt(r.Rows, 10)
	case "thrd":
		return dash(r.Thrd)
	case "user":
		return dash(r.User)
	case "trx":
		return dash(r.Trx)
	case "app":
		return dash(r.App)
	case "sess":
		return dash(r.Sess)
	case "ip":
		return dash(r.IP)
	}
	return ""
}

// renderRows 一条记录渲染成两行（扁平模式，SQL 缩进 2 空格）。见 renderRowsAt。
func (o *watchOpts) renderRows(r watchRow, cols []watchCol) []string {
	return o.renderRowsAt(r, cols, 2)
}

// renderRowsAt 一条记录渲染成两行：
//
//	① 元信息行（按 cols 对齐，方便横向扫读）
//	② SQL 原文行（独占一行，缩进 indent 个空格）—— 想复制 SQL 只选这一行即可，
//	   不会再连带时间与耗时（V2.15 之前是同一行，复制时被连坐）。
//
// 批次模式用 indent=4：批内比「会话: …」这类键值行再深一层，视觉上归到该条记录之下。
func (o *watchOpts) renderRowsAt(r watchRow, cols []watchCol, indent int) []string {
	if o.sqlOnly {
		// 这份输出的唯一用途就是「复制去执行」，所以：不缩进、不截断、不带任何元信息。
		sql := r.SQL
		if sql == "" {
			sql = r.Op
		}
		return []string{sql}
	}
	var b strings.Builder
	for i, c := range cols {
		v := clip(o.colText(r, c.key), c.w)
		if c.right {
			v = lpad(v, c.w)
		} else {
			v = pad(v, c.w)
		}
		if c.key == "op" {
			v = o.paint(v, watchOpColor(r.Op))
		}
		b.WriteString(v)
		if i != len(cols)-1 {
			b.WriteString(" ")
		}
	}
	sql := r.SQL
	if sql == "" {
		sql = r.Op
	}
	if !o.full {
		sql = clip(sql, o.width-indent)
	}
	return []string{strings.TrimRight(b.String(), " "), strings.Repeat(" ", indent) + sql}
}

// ══════════════════════════════════════════════ 批次聚合（V2.18）
//
// 为什么要聚合：一次界面点击（或一次 disql 执行）常带出十几条 SQL —— 它们的
// 会话/客户端/用户/IP 完全相同，逐条重复列出来既占宽度，也看不出「这些是同一次操作」。
//
// 判据：**同一会话 + 与上一条的间隔不超过 -g**（默认 1000ms）。
// 批次头用「键: 值」列出本批共用的字段，行内只留逐条变化的字段（时间/类型/耗时/行数/事务号）；
// 批次收尾（共 N 条 · 累计 · 跨度）在下批开始、静默超时或退出时打印。

// watchClockMS 把 "HH:MM:SS.mmm" 转成当天毫秒（-1 = 解析失败）。
func watchClockMS(c string) int64 {
	if len(c) < 8 {
		return -1
	}
	dig := func(a, b int) (int64, bool) {
		v := int64(0)
		for i := a; i < b; i++ {
			if c[i] < '0' || c[i] > '9' {
				return 0, false
			}
			v = v*10 + int64(c[i]-'0')
		}
		return v, true
	}
	hh, ok1 := dig(0, 2)
	mm, ok2 := dig(3, 5)
	ss, ok3 := dig(6, 8)
	if !ok1 || !ok2 || !ok3 {
		return -1
	}
	ms := int64(0)
	if len(c) >= 12 && c[8] == '.' {
		if v, ok := dig(9, 12); ok {
			ms = v
		}
	}
	return ((hh*60+mm)*60+ss)*1000 + ms
}

// watchGroupCols 批次模式的行内列：批次共用的字段已上提到批次头，这里只留逐条会变的。
// 合计 44 列（含间隔），任何终端都放得下，不需要丢列。
func watchGroupCols() []watchCol {
	return []watchCol{
		{key: "time", title: "时间", w: 12},
		{key: "op", title: "类型", w: 4},
		{key: "dur", title: "耗时", w: 9, right: true},
		{key: "rows", title: "行数", w: 6, right: true},
		{key: "trx", title: "事务号", w: 13, right: true, drop: 1},
	}
}

// watchGroup 一批记录的聚合状态。
type watchGroup struct {
	open     bool
	idx      int // 批次序号，从 1 开始
	key      string
	startMS  int64 // 批内第一条的「当天毫秒」
	lastMS   int64
	n        int
	sumMS    float64
	hasMS    bool
	lastWall time.Time // 最后一条记录到达的墙钟时刻（用于静默收尾）
}

// groupKey 判「是不是同一批」的键：优先会话；没有会话（--all 的事件行）时退到 客户端|IP。
func (o *watchOpts) groupKey(r watchRow) string {
	if r.Sess != "" {
		return r.Sess
	}
	if r.App != "" || r.IP != "" {
		return r.App + "|" + r.IP
	}
	return "-"
}

// belong 判断该记录是否还落在当前批次里；false 表示调用方应先 close 再 open1。
func (g *watchGroup) belong(o *watchOpts, key string, m int64) bool {
	if !g.open || key != g.key {
		return false
	}
	if m < 0 || g.lastMS < 0 {
		return true // 时间戳拿不到就不断批（宁可并在一起，也不要无意义地切开）
	}
	return m-g.lastMS <= int64(o.gap/time.Millisecond)
}

// open1 开一批：批次标题 + 本批共用的键值行 + 行内列表头。
func (g *watchGroup) open1(o *watchOpts, w io.Writer, r watchRow, rowHead string) {
	first := g.idx == 0
	g.open = true
	g.idx++
	g.key = o.groupKey(r)
	g.n, g.sumMS, g.hasMS = 0, 0, false
	g.startMS = watchClockMS(r.Clock)
	g.lastMS = g.startMS
	g.lastWall = time.Now()

	if o.sqlOnly {
		// 只出 SQL：批次头/键值行/行内列表头一律不打；空行分隔统一由 emit 处理
		// （这样「每条之间一行、每批之间两行」只有一个口径）。
		return
	}
	if !first {
		fmt.Fprintln(w) // 批次之间空一行，与批内的紧凑排布区分开
	}
	title := "── 批次 " + strconv.Itoa(g.idx) + " · " + r.Clock + " "
	rule := o.width
	if rule > 100 {
		rule = 100 // 150 列的终端下拉满太夸张，100 列足够当视觉边界
	}
	fill := rule - dispWidth(title)
	if fill < 4 {
		fill = 4
	}
	fmt.Fprintln(w, o.paint(title+strings.Repeat("─", fill), clrDim))
	fmt.Fprintf(w, "  会话: %s   客户端: %s\n", dash(r.Sess), dash(r.App))
	fmt.Fprintf(w, "  用户: %s   线程号: %s   IP: %s\n", dash(r.User), dash(r.Thrd), dash(r.IP))
	fmt.Fprintln(w, rowHead)
}

// close 收尾当前批次（下批开始 / 静默超时 / 退出时都会调；重复调用安全）。
func (g *watchGroup) close(o *watchOpts, w io.Writer) {
	if !g.open {
		return
	}
	if o.sqlOnly {
		g.open = false // 只出 SQL：不打收尾行
		return
	}
	span := g.lastMS - g.startMS
	if span < 0 {
		span = 0
	}
	sumTxt := "-"
	if g.hasMS {
		sumTxt = watchDur(g.sumMS)
	}
	fmt.Fprintln(w, o.paint("  共 "+strconv.Itoa(g.n)+" 条 · 累计 "+sumTxt+
		" · 跨度 "+watchDur(float64(span)), clrDim))
	g.open = false
}

// ------------------------------------------------------------ 汇总

type watchStat struct {
	start   time.Time
	n       int
	nGroup  int // 批次数量（批次模式）
	byOp    map[string]int
	slowest []watchRow
}

func (st *watchStat) note(r watchRow) {
	if !r.HasMS {
		return
	}
	if len(st.slowest) < watchSlowestKeep {
		st.slowest = append(st.slowest, r)
	} else if r.MS <= st.slowest[len(st.slowest)-1].MS {
		return
	} else {
		st.slowest[len(st.slowest)-1] = r
	}
	sort.SliceStable(st.slowest, func(i, j int) bool { return st.slowest[i].MS > st.slowest[j].MS })
}

func watchSummary(w io.Writer, st *watchStat) {
	fmt.Fprintln(w)
	sec(w, "本次观察汇总")
	fmt.Fprintf(w, "  %s %s\n", pad("观察时长:", 11), time.Since(st.start).Round(time.Second))
	fmt.Fprintf(w, "  %s %d\n", pad("输出条数:", 11), st.n)
	if st.nGroup > 0 {
		fmt.Fprintf(w, "  %s %d\n", pad("批次数量:", 11), st.nGroup)
	}
	if len(st.byOp) > 0 {
		keys := make([]string, 0, len(st.byOp))
		for k := range st.byOp {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if st.byOp[keys[i]] != st.byOp[keys[j]] {
				return st.byOp[keys[i]] > st.byOp[keys[j]]
			}
			return keys[i] < keys[j]
		})
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, st.byOp[k]))
		}
		fmt.Fprintf(w, "  %s %s\n", pad("按类型:", 11), strings.Join(parts, " · "))
	}
	if len(st.slowest) > 0 {
		fmt.Fprintf(w, "  %s\n", fmt.Sprintf("最慢 %d 条:", len(st.slowest)))
		for _, r := range st.slowest {
			fmt.Fprintf(w, "    %9s  %-7s  %s\n", watchDur(r.MS), r.Op, clip(r.SQL, 100))
		}
	}
	fmt.Fprintln(w)
}

// ------------------------------------------------------------ 入口

func watchMain(args []string) int {
	dataW, diagW := watchStreams()

	o, pathArg, err := parseWatchArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			watchUsage()()
			return 0
		}
		fmt.Fprintf(os.Stderr, "参数有误：%v\n\n", err)
		watchUsage()()
		return 2
	}

	dir, cur := "", ""
	if pathArg != "" {
		if st, e := os.Stat(pathArg); e == nil && st.IsDir() {
			dir = pathArg
		} else {
			cur = pathArg
			dir = filepath.Dir(pathArg)
		}
	}
	if pathArg == "" && o.dirArg != "" {
		// -d 给的是目录就当目录，是文件就当文件
		if st, e := os.Stat(o.dirArg); e == nil && !st.IsDir() {
			cur, dir = o.dirArg, filepath.Dir(o.dirArg)
		} else {
			dir = o.dirArg
		}
	}
	if o.forget {
		forgetWatchDir()
		fmt.Fprintln(os.Stdout, "已清掉记住的日志目录（下次会重新自动定位）。")
		return 0
	}

	loc := watchLoc{dir: dir}
	if dir == "" {
		loc = resolveWatchDir()
		dir = loc.dir
	} else {
		loc.why = "命令行指定"
	}
	if o.showPaths {
		printWatchPaths(loc)
		return 0
	}
	if dir == "" {
		fmt.Fprintln(os.Stderr, "没找到 SQL 日志目录。三种办法：")
		fmt.Fprintln(os.Stderr, "  1) 让工具自动找：确认 DM 装在常见位置（如 D:\\dmdbms），直接跑 dmsqlq watch")
		fmt.Fprintln(os.Stderr, "  2) 显式指定：dmsqlq watch \"D:\\dmdbms\\log\" -a manager.exe")
		fmt.Fprintln(os.Stderr, "  3) 设环境变量：set DMSQLQ_LOG_DIR=D:\\dmdbms\\log")
		fmt.Fprintln(os.Stderr, "（日志目录看 sqllog.ini 的 FILE_PATH；相对路径的基准是 dmserver 的工作目录，一般是 <安装目录>/bin）")
		fmt.Fprintln(os.Stderr, "想看都扫到了哪些候选，加 --show-paths。")
		return 2
	}
	if abs, e := filepath.Abs(dir); e == nil {
		dir = abs
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		fmt.Fprintf(os.Stderr, "目录不存在：%s\n", dir)
		return 2
	}
	if loc.why == "自动定位" {
		saveWatchDir(dir)
	}
	if cur != "" {
		if abs, e := filepath.Abs(cur); e == nil {
			cur = abs
		}
	} else {
		cur = newestLog(dir)
	}

	f := &follower{dir: dir}
	var replay []string
	if cur != "" {
		if o.tail > 0 {
			replay = tailLines(cur, o.tail)
		}
		f.cur, f.committed, f.pending = cur, watchFileSize(cur), nil
	}

	showApp := o.app == ""

	// ---- 可选：连库做体检 / 临时切成同步刷盘（-Y）
	if o.pass == "" {
		o.pass = strings.TrimSpace(os.Getenv("DM_PASS"))
	}
	var db *dmProbe
	var restore *syncRestore
	if o.pass != "" || o.syncLog {
		if o.pass == "" {
			fmt.Fprintln(os.Stderr, "-Y/--sync-log 需要 SYSDBA 口令：用 -p 给，或设环境变量 DM_PASS。")
			return 2
		}
		p, err := openDMProbe(loc, o.pass, o.host, o.port)
		if err != nil {
			if o.syncLog {
				fmt.Fprintf(os.Stderr, "连库失败（-Y 需要它）：%v\n", err)
				return 2
			}
			fmt.Fprintf(diagW, "  体检    跳过（%v）\n", err)
		} else {
			db = p
		}
	}
	if db != nil {
		// 先报体检（此时还是改动前的原值），再动手改 —— 顺序反过来会让人看到改完的值
		for _, ln := range db.report() {
			fmt.Fprintf(diagW, "  %s\n", ln)
		}
		if o.syncLog && !isLocalHost(db.host) {
			// 🩸 远端库不切同步刷盘（V2.21）。
			// 理由三条：① 同步刷盘对该库是实打实的性能开销，影响的不只是本工具；
			// ② 还原依赖网络 —— 进程被强杀或网络中断时，库里会永久停留在 ASYNC_FLUSH=0；
			// ③ 还原脚本落在本机临时目录，远端库出问题时现场未必找得到。
			// 只保留「只读体检」，把改动留给在那台机器上跑的原生 dmsqlq。
			fmt.Fprintf(diagW, "  %s\n", o.paint(
				"  ⚠️ -Y 已跳过：目标是远端实例（"+db.host+"）—— 远端不允许自动切同步刷盘（只读体检已照常执行）。", clrYellow))
			fmt.Fprintln(diagW, "     要切刷盘请到那台机器上用本机的 dmsqlq 执行；本工具只在 127.0.0.1 时才改动配置。")
		} else if o.syncLog {
			r, err := db.switchToSync()
			if err != nil {
				fmt.Fprintf(os.Stderr, "-Y 失败：%v\n", err)
				db.close()
				return 2
			}
			restore = r
		}
	}
	if restore != nil {
		defer func() {
			if restore.done {
				return
			}
			if err := db.restoreSync(restore); err != nil {
				fmt.Fprintf(diagW, "\n  ⚠️ 还原 ASYNC_FLUSH 失败：%v\n", err)
				fmt.Fprintf(diagW, "     请手工执行：%s\n", restore.script)
			} else {
				fmt.Fprintf(diagW, "\n  已还原 SQL 日志刷盘方式：ASYNC_FLUSH=%s ✓\n", restore.orig)
			}
		}()
	}

	fmt.Fprintf(diagW, "dmsqlq %s · 实时监视 SQL 日志\n", ver)
	if cur != "" {
		fmt.Fprintf(diagW, "  跟随:    %s\n", cur)
	} else {
		fmt.Fprintf(diagW, "  跟随:    %s（目录里还没有 dmsql_*.log，等它出现）\n", dir)
	}
	if loc.why != "" {
		fmt.Fprintf(diagW, "  路径:    %s   ← %s\n", dir, loc.why)
	}
	for _, h := range loc.hints {
		fmt.Fprintf(diagW, "  另发现:  %s\n", h)
	}
	if restore != nil {
		fmt.Fprintln(diagW)
		fmt.Fprintf(diagW, "  %s\n", o.paint("  ⚠️ 已临时把 SQL 日志改成「同步刷盘」（原值 "+restore.orig+"），退出时自动还原。", clrYellow))
		fmt.Fprintln(diagW, "     这是改数据库自己的 sqllog.ini（会写盘）—— 生产库请确认能接受同步刷盘的性能开销。")
		fmt.Fprintf(diagW, "     万一本进程被强杀，手工还原脚本已写到：%s\n", restore.script)
	}
	if showApp {
		fmt.Fprintf(diagW, "  过滤:    %s\n", o.filterDesc())
	} else {
		fmt.Fprintf(diagW, "  过滤:    客户端=%s · %s\n", o.app, o.filterDesc())
	}
	fmt.Fprintf(diagW, "  轮询:    %s · 输出宽 %d 列\n", o.poll, o.width)
	if o.sqlOnly {
		if o.group {
			fmt.Fprintf(diagW, "  批次:    同一会话 + 间隔 ≤ %s 视为同一批（批次之间空一行）\n", o.gap)
		}
		fmt.Fprintln(diagW, "  SQL:     只输出 SQL 原文（--sql-only）—— 无元信息行、不缩进、不截断，整段可直接复制")
	} else if o.group {
		fmt.Fprintf(diagW, "  批次:    同一会话 + 间隔 ≤ %s 视为同一批（改 -g 指定；0 = 不聚合）\n",
			o.gap)
	} else {
		fmt.Fprintf(diagW, "  批次:    不聚合（扁平输出）—— 用 -g 1000 可开启批次\n")
	}
	fmt.Fprintln(diagW)
	fmt.Fprintln(diagW, "  去点 DM 管理工具的界面，SQL 会实时打在下面。Ctrl-C 停止。")
	if !o.noHead {
		if o.sqlOnly {
			fmt.Fprintln(diagW, o.paint("  列说明:  只打印 SQL 原文 —— 不缩进、不截断（要粘贴执行就不该被截断）、"+
				"不带元信息行与批次头", clrDim))
			fmt.Fprintln(diagW, o.paint("           每条 SQL 之间空一行；批次之间空两行（配 -g 0 则统一一行一条）", clrDim))
			fmt.Fprintln(diagW, o.paint("           「哪条慢、什么类型、影响几行」这类判读信息在默认模式里（去掉 --sql-only）", clrDim))
		} else if o.group {
			fmt.Fprintln(diagW, o.paint("  列说明:  批次头 = 本批共用的字段（会话 / 客户端 / 用户 / 线程号 / IP）；行内 = 逐条变化的字段", clrDim))
			fmt.Fprintln(diagW, o.paint("           时间: 记录时刻 · 类型: 语句类型 · 耗时: EXECTIME（★含等锁时间）· 行数: ROWCOUNT · 事务号: trxid", clrDim))
			fmt.Fprintln(diagW, o.paint("           事务号 0 = 当时无活动事务；批次头的线程号取自本批第一条（同一语句可能换线程）", clrDim))
			fmt.Fprintln(diagW, o.paint("           SQL 单独成行、缩进 4 空格 —— 整行可直接复制；句柄号与执行节点已省略", clrDim))
			fmt.Fprintln(diagW, o.paint("           会话: sess 会话地址，可在库上按 V$OPEN_STMT.SESS_ADDR 关联（详见 -h）", clrDim))
		} else {
			fmt.Fprintln(diagW, o.paint("  列说明:  时间: 记录时刻 · 类型: 语句类型 · 耗时: EXECTIME（★含等锁时间）· 行数: ROWCOUNT", clrDim))
			fmt.Fprintln(diagW, o.paint("           线程号 / 用户 / 事务号 / 应用名 / IP: 取自日志头部；事务号 0 = 当时无活动事务", clrDim))
			fmt.Fprintln(diagW, o.paint("           会话: sess 会话地址，可在库上按 V$OPEN_STMT.SESS_ADDR 关联（详见 -h）", clrDim))
			fmt.Fprintln(diagW, o.paint("           SQL 单独成行、缩进 2 空格 —— 整行可直接复制；句柄号与执行节点已省略", clrDim))
		}
	}
	fmt.Fprintln(diagW)

	var cols []watchCol
	var droppedCols, head, sep, rowHead string
	if o.group {
		cols = watchGroupCols()
		rowHead, _ = watchHeader(cols) // 批次模式：行内列表头在每个批次头之后重印
	} else {
		cols, droppedCols = watchFit(o, showApp)
		head, sep = watchHeader(cols)
	}

	// 先把「回放」横幅打出来，再打表头 —— 否则横幅会夹在表头与记录之间。
	var replayKept []string
	for _, ln := range replay {
		if rr, ok := parseWatchLine(ln); ok && o.keep(rr) {
			replayKept = append(replayKept, ln)
		}
	}
	if len(replay) > 0 {
		if len(replayKept) > 0 {
			fmt.Fprintln(diagW, o.paint("  ── 回放最近 "+strconv.Itoa(len(replay))+
				" 行（匹配 "+strconv.Itoa(len(replayKept))+" 条）──", clrDim))
		} else {
			fmt.Fprintln(diagW, o.paint("  ── 回放最近 "+strconv.Itoa(len(replay))+
				" 行：没有匹配上面过滤条件的记录 ──", clrDim))
		}
	}
	if droppedCols != "" {
		fmt.Fprintf(diagW, "  （输出宽 %d 列放不下，已省略：%s —— 用 -w 加宽可显示）\n", o.width, droppedCols)
	}
	if !o.noHead && !o.group && !o.sqlOnly {
		fmt.Fprintln(diagW, head)
		fmt.Fprintln(diagW, sep)
	}

	st := &watchStat{start: time.Now(), byOp: map[string]int{}}
	lastSec := ""        // 扁平模式：上一条已输出记录的「秒」（HH:MM:SS）
	pipeBroken := false  // 下游（grep / head…）把管道关掉后置位
	grp := &watchGroup{} // 批次模式：当前批次的聚合状态

	// 记录一律走 dataW，且每次写入都查错：Windows 没有 SIGPIPE，管道被下游关闭时 write 只返回
	// 错误、进程不会自己死 —— 不查错的话 `dmsqlq watch … | head -3` 会留下一个永远轮询的孤儿进程。
	writeData := func(line string) bool {
		if _, err := fmt.Fprintln(dataW, line); err != nil {
			pipeBroken = true
			return false
		}
		return true
	}

	emit := func(lines []string) {
		for _, ln := range lines {
			r, ok := parseWatchLine(ln)
			if !ok || !o.keep(r) {
				continue
			}
			if o.group {
				// 批次模式：同一会话（且间隔不超过 -g）的记录聚成一批。
				m := watchClockMS(r.Clock)
				nb := !grp.belong(o, o.groupKey(r), m)
				if nb {
					grp.close(o, dataW)
					if pipeBroken {
						return
					}
					grp.open1(o, dataW, r, rowHead)
					if pipeBroken {
						return
					}
				}
				if o.sqlOnly {
					// 只出 SQL：**每条之间空一行** —— 一批里有的语句不带分号（日志记的是客户端发来的
					// 原文），一行挨一行会数不清是几条。换批再多空一行，保留「这批是同一次操作」。
					if st.n > 0 {
						if !writeData("") {
							return
						}
						if nb {
							if !writeData("") {
								return
							}
						}
					}
				}
				grp.n++
				if r.HasMS {
					grp.sumMS += r.MS
					grp.hasMS = true
				}
				if m >= 0 {
					grp.lastMS = m
				}
				grp.lastWall = time.Now()
				for _, l := range o.renderRowsAt(r, cols, 4) {
					if !writeData(l) {
						return
					}
				}
			} else {
				// 扁平模式：与 V2.17 相同的形态（10 列元信息行 + SQL 独占行）。
				// 同一秒内执行的多条语句（典型是一次界面点击带出十几条）时间戳一模一样，
				// 挨着排会糊成一片 —— 用空行把同一秒内的记录彼此隔开。
				sec := r.Clock
				if len(sec) > 8 {
					sec = sec[:8]
				}
				if o.sqlOnly {
					// 只出 SQL：每条之间空一行（-g 0 没有批次概念，就统一一行一条）
					if st.n > 0 {
						if !writeData("") {
							return
						}
					}
				} else if lastSec != "" && sec == lastSec {
					if !writeData("") {
						return
					}
				}
				lastSec = sec
				for _, l := range o.renderRows(r, cols) {
					if !writeData(l) {
						return
					}
				}
				if !o.noHead && !o.sqlOnly && st.n > 0 && st.n%watchHeaderEvery == 0 {
					fmt.Fprintln(diagW)
					fmt.Fprintln(diagW, head)
					fmt.Fprintln(diagW, sep)
				}
			}
			st.n++
			st.byOp[r.Op]++
			st.note(r)
			if o.limit > 0 && st.n >= o.limit {
				return
			}
		}
	}

	if len(replayKept) > 0 {
		emit(replayKept)
	}
	// finish 统一收尾：收掉未闭合的批次 → 打印汇总 → 还原 ASYNC_FLUSH。
	finish := func(note string) int {
		if note != "" {
			fmt.Fprintln(diagW, note)
		}
		if o.group {
			grp.close(o, dataW)
			st.nGroup = grp.idx
		}
		watchSummary(diagW, st)
		restoreNow(db, &restore)
		return 0
	}

	if pipeBroken {
		return finish("  下游已关闭（管道断开），退出。")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	ticker := time.NewTicker(o.poll)
	defer ticker.Stop()
	nudged := false
	for {
		select {
		case <-sigCh:
			return finish("")
		case <-ticker.C:
		}

		lines, switched, newName := f.poll()
		if switched && newName != "" {
			fmt.Fprintln(diagW, o.paint("  ── 日志切换 → "+filepath.Base(newName)+" ──", clrDim))
		}
		emit(lines)

		if pipeBroken {
			return finish("  下游已关闭（管道断开），退出。")
		}
		if o.limit > 0 && st.n >= o.limit {
			return finish("")
		}
		// 批次模式：静默超过一个批间隔就收掉当前批次 —— 否则最后一批的收尾行要等到
		// 下批开始（可能几分钟后）或退出时才出现，实时看会很懵。
		if o.group && grp.open && time.Since(grp.lastWall) >= o.gap {
			grp.close(o, dataW)
		}
		if !nudged && cur != "" && st.n == 0 && time.Since(st.start) > 8*time.Second {
			nudged = true
			fmt.Fprintln(diagW)
			fmt.Fprintln(diagW, o.paint("  提示：已跟随 8 秒，还没有「执行完成」的语句。若你确实点了界面，按顺序核对：", clrYellow))
			fmt.Fprintln(diagW, "        ① sqllog.ini 的 MIN_EXEC_TIME 是否为 0（大于 0 时快语句不写执行完成行）")
			fmt.Fprintln(diagW, "        ② dm.ini 的 SVR_LOG 是否为 1（SQL 日志总开关）")
			fmt.Fprintln(diagW, "        ③ 用 --all 连准备阶段的 [ORA] 行一起看")
			fmt.Fprintln(diagW)
		}
	}
}

// ══════════════════════════════════════════════ 自动定位日志目录（V2.14）
//
// 目标：`dmsqlq watch -a manager.exe` 就能跑，不用记路径。
// 思路：DM 的 SQL 日志目录写在 <数据目录>/sqllog.ini 的 FILE_PATH 里，
//       而 <数据目录> 一定是某个 DM 安装目录下的 data/<实例>/。
//       所以「扫 DM 安装目录 → 找 sqllog.ini → 取 FILE_PATH → 解析成绝对路径」。

type watchCand struct {
	dir    string
	why    string
	newest int64 // 目录里 dmsql_*.log 的最新 mtime（Unix 秒）
	count  int
}

func (c watchCand) ok() bool { return c.dir != "" && c.count > 0 }

// watchLoc 定位结果
type watchLoc struct {
	dir   string
	why   string
	ini   string // 找到的 sqllog.ini（可能为空）
	hints []string
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func isDirP(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// scanForDmsql 看一个目录里有没有 dmsql_*.log
func scanForDmsql(dir, why string) watchCand {
	c := watchCand{dir: filepath.Clean(dir), why: why}
	ents, err := os.ReadDir(c.dir)
	if err != nil {
		return c
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasPrefix(n, "dmsql_") || !strings.HasSuffix(n, ".log") {
			continue
		}
		c.count++
		if fi, err := e.Info(); err == nil {
			if t := fi.ModTime().Unix(); t > c.newest {
				c.newest = t
			}
		}
	}
	return c
}

// candFromSqllogIni 读 sqllog.ini 的 FILE_PATH，解析成真实的日志目录。
//
// 🩸 相对路径的基准不是 dm.ini 所在目录，而是「dmserver 的工作目录」（通常 <安装目录>/bin）。
// 手册原文：FILE_PATH「缺省生成在 DM 安装目录的 LOG 子目录下面」，而默认值正是 `../LOG` ——
// 只有在 <安装目录>/bin 下解析才会落在 <安装目录>/LOG。本机实测也是这个结论
// （sqllog.ini 在 D:\dmdbms\data\DAMENG，FILE_PATH=..\log，实际落在 D:\dmdbms\log）。
//
// 但实际部署里 bin 的位置不固定（数据目录可能在安装目录之外，如 133 的
// /home/dmdba/dmdata/DAMENG），所以这里**逐个试基准**：取第一个解析出来真实存在的目录；
// 若其中还有 dmsql_*.log 就更优先。
func candFromSqllogIni(iniPath string) (watchCand, bool) {
	b, err := os.ReadFile(iniPath)
	if err != nil {
		return watchCand{}, false
	}
	fp := ""
	for _, ln := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || t[0] == '#' || t[0] == ';' || t[0] == '[' {
			continue
		}
		i := strings.IndexByte(t, '=')
		if i <= 0 {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(t[:i])) != "FILE_PATH" {
			continue
		}
		v := strings.TrimSpace(t[i+1:])
		if j := strings.IndexAny(v, "#\t "); j >= 0 {
			v = strings.TrimSpace(v[:j])
		}
		if v != "" {
			fp = v
			break
		}
	}
	if fp == "" {
		return watchCand{}, false
	}

	why := "sqllog.ini 的 FILE_PATH（" + iniPath + "）"
	if filepath.IsAbs(fp) {
		c := scanForDmsql(fp, why)
		if !c.ok() && isDirP(fp) {
			c = watchCand{dir: filepath.Clean(fp), count: 1,
				why: why[:strings.LastIndex(why, "（")] + "（" + iniPath + "，目录暂空）"}
		}
		return c, true
	}

	// 逐个试基准：ini 所在目录、它的各级祖先、各祖先下的 bin、以及已知 DM 安装根
	base := filepath.Dir(iniPath)
	bases := []string{base}
	d := base
	for i := 0; i < 4; i++ {
		bases = append(bases, filepath.Join(d, "bin"))
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
		bases = append(bases, d)
	}
	for _, r := range dmRoots() {
		bases = append(bases, r.path, filepath.Join(r.path, "bin"))
	}

	var empty watchCand
	for _, b := range bases {
		p := filepath.Join(b, fp)
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		if c := scanForDmsql(p, why); c.ok() {
			return c, true
		}
		if empty.dir == "" && isDirP(p) {
			empty = watchCand{dir: filepath.Clean(p), count: 1,
				why: why[:strings.LastIndex(why, "（")] + "（" + iniPath + "，目录暂空）"}
		}
	}
	if empty.dir != "" {
		return empty, true
	}
	return watchCand{}, true
}

// dmRootSpec 一个待扫描的根目录 + 扫描深度
type dmRootSpec struct {
	path  string
	depth int
}

// dmRoots 列出「DM 装在哪」的常见位置。
// 注意：**绝不**把盘符根/家目录本身当根去递归 —— 那会扫到几千个目录。
func dmRoots() []dmRootSpec {
	var out []dmRootSpec
	seen := map[string]bool{}
	add := func(p string, depth int) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		p = filepath.Clean(p)
		if !isDirP(p) {
			return
		}
		k := strings.ToLower(p)
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, dmRootSpec{p, depth})
	}
	names := []string{"dmdbms", "dm8", "dameng", "dmdata", "DM"}
	if runtime.GOOS == "windows" {
		for _, d := range "CDEFGHIJ" {
			for _, n := range names {
				add(string(d)+":\\"+n, 2)
			}
		}
	} else {
		for _, b := range []string{"/opt", "/data", "/usr/local", "/dmdbms"} {
			for _, n := range names {
				add(filepath.Join(b, n), 2)
			}
		}
		add("/dm8", 2)
		if ents, err := os.ReadDir("/home"); err == nil {
			for _, e := range ents {
				if !e.IsDir() {
					continue
				}
				u := filepath.Join("/home", e.Name())
				add(filepath.Join(u, "dmdbms"), 2)
				add(filepath.Join(u, "dmdata"), 2)
			}
		}
	}
	// 当前目录 / 可执行文件旁：只看一层（log / sqllog），不深挖
	shallow := []string{}
	if wd, err := os.Getwd(); err == nil {
		shallow = append(shallow, wd, filepath.Join(wd, "log"), filepath.Join(wd, "sqllog"))
	}
	if exe, err := os.Executable(); err == nil {
		d := filepath.Dir(exe)
		shallow = append(shallow, d, filepath.Join(d, "log"), filepath.Join(d, "sqllog"))
	}
	for _, d := range shallow {
		add(d, 1)
	}
	return out
}

// scanOneRoot 扫一个根：它自己 + depth 层子目录，找 sqllog.ini 与 dmsql_*.log
func scanOneRoot(r dmRootSpec) []watchCand {
	var out []watchCand
	dirs := []string{r.path}
	cur := []string{r.path}
	for lv := 0; lv < r.depth; lv++ {
		var next []string
		for _, p := range cur {
			ents, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			for _, e := range ents {
				if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
					continue
				}
				next = append(next, filepath.Join(p, e.Name()))
			}
		}
		dirs = append(dirs, next...)
		cur = next
		if len(dirs) > 400 { // 防御：异常目录结构不至于卡死
			break
		}
	}
	for _, d := range dirs {
		if ini := filepath.Join(d, "sqllog.ini"); fileExists(ini) {
			if c, ok := candFromSqllogIni(ini); ok {
				out = append(out, c)
			}
			continue
		}
		if c := scanForDmsql(d, ""); c.ok() {
			out = append(out, c)
		}
	}
	return out
}

// watchMemFile 记住上次用的目录（省得每次重扫）
func watchMemFile() string {
	d, err := os.UserConfigDir()
	if err != nil || d == "" {
		return ""
	}
	return filepath.Join(d, "dmsqlq", "watch-dir.txt")
}

func loadWatchDir() string {
	p := watchMemFile()
	if p == "" {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func saveWatchDir(dir string) {
	p := watchMemFile()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	_ = os.WriteFile(p, []byte(dir+"\n"), 0o644)
}

func forgetWatchDir() {
	if p := watchMemFile(); p != "" {
		_ = os.Remove(p)
	}
}

// resolveWatchDir 自动定位 SQL 日志目录。
func resolveWatchDir() watchLoc {
	var loc watchLoc
	if d := strings.TrimSpace(os.Getenv("DMSQLQ_LOG_DIR")); d != "" && isDirP(d) {
		loc.dir, loc.why = d, "环境变量 DMSQLQ_LOG_DIR"
		return loc
	}

	var all []watchCand
	for _, r := range dmRoots() {
		all = append(all, scanOneRoot(r)...)
	}
	// 按目录去重（保留 count/newest 更大的那份，why 用先出现的）
	byDir := map[string]int{}
	var uniq []watchCand
	for _, c := range all {
		k := strings.ToLower(c.dir)
		if i, ok := byDir[k]; ok {
			if c.count > uniq[i].count || c.newest > uniq[i].newest {
				keep := uniq[i].why
				uniq[i] = c
				if uniq[i].why == "" {
					uniq[i].why = keep
				}
			}
			continue
		}
		byDir[k] = len(uniq)
		uniq = append(uniq, c)
	}
	sort.SliceStable(uniq, func(i, j int) bool {
		if uniq[i].newest != uniq[j].newest {
			return uniq[i].newest > uniq[j].newest
		}
		return uniq[i].count > uniq[j].count
	})

	// 记住的目录：有效就优先（稳定），但若别处明显更新则提示
	mem := loadWatchDir()
	pick := -1
	if mem != "" {
		for i := range uniq {
			if strings.EqualFold(uniq[i].dir, mem) {
				pick = i
				break
			}
		}
		if pick < 0 && isDirP(mem) {
			c := scanForDmsql(mem, "记住的路径")
			if c.ok() {
				uniq = append(uniq, c)
				pick = len(uniq) - 1
			}
		}
	}
	if pick < 0 && len(uniq) > 0 {
		pick = 0
	}
	if pick < 0 {
		return loc
	}

	loc.dir = uniq[pick].dir
	if mem != "" && strings.EqualFold(uniq[pick].dir, mem) {
		loc.why = "记住的路径（改路径用 -d 指定，或 --forget 清掉）"
	} else {
		loc.why = "自动定位"
	}
	if uniq[pick].why != "" {
		loc.why = "自动定位 · " + uniq[pick].why
	}
	if ini := filepath.Join(loc.dir, "sqllog.ini"); fileExists(ini) {
		loc.ini = ini
	}
	// 还有别的候选且比选中的更新 → 告诉用户
	n := 0
	for i := range uniq {
		if i == pick {
			continue
		}
		if uniq[i].newest > uniq[pick].newest {
			loc.hints = append(loc.hints, fmt.Sprintf("%s（最近 %s）—— 换用加 -d",
				uniq[i].dir, time.Unix(uniq[i].newest, 0).Format("01-02 15:04")))
			n++
			if n >= 3 {
				break
			}
		}
	}
	return loc
}

func printWatchPaths(loc watchLoc) {
	w := os.Stdout
	fmt.Fprintln(w, "自动定位找到的 SQL 日志目录候选（按最近写过日志排序）：")
	fmt.Fprintln(w)
	if loc.dir != "" {
		fmt.Fprintf(w, "  ★ 本次会选   %s\n", loc.dir)
	}
	sel := loc.dir
	var all []watchCand
	for _, r := range dmRoots() {
		all = append(all, scanOneRoot(r)...)
	}
	seen := map[string]bool{}
	rows := []watchCand{}
	for _, c := range all {
		k := strings.ToLower(c.dir)
		if seen[k] {
			continue
		}
		seen[k] = true
		rows = append(rows, c)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].newest != rows[j].newest {
			return rows[i].newest > rows[j].newest
		}
		return rows[i].count > rows[j].count
	})
	if mem := loadWatchDir(); mem != "" {
		fmt.Fprintf(w, "  记住的路径   %s\n", mem)
	}
	fmt.Fprintf(w, "  %-44s %-6s %-8s %s\n", "目录", "日志数", "最近写入", "来源")
	fmt.Fprintf(w, "  %s %s %s %s\n", strings.Repeat("─", 44), "──────", "────────", strings.Repeat("─", 30))
	shown := 0
	for _, c := range rows {
		if shown >= 12 {
			fmt.Fprintf(w, "  …另有 %d 个\n", len(rows)-shown)
			break
		}
		mark := " "
		if sel != "" && strings.EqualFold(c.dir, sel) {
			mark = "★"
		}
		last := "-"
		if c.newest > 0 {
			last = time.Unix(c.newest, 0).Format("01-02 15:04")
		}
		why := c.why
		if why == "" {
			why = "目录里有 dmsql_*.log"
		}
		fmt.Fprintf(w, "  %s %-43s %-8d %-10s %s\n", mark, clip(c.dir, 43), c.count, last, clip(why, 60))
		shown++
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "  （没找到。可用 -d 指定，或设 DMSQLQ_LOG_DIR）")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "指定方式：dmsqlq watch -d <目录>  或  dmsqlq watch \"<目录>\"")
}

// ══════════════════════════════════════════════ 连库（体检 / 切同步刷盘）
//
// 不引第三方驱动：改用 DM 自带的 disql。口令走 stdin（/NOLOG + conn），
// 不进命令行 —— 否则会出现在进程列表里。

type dmProbe struct {
	disql    string
	host     string // 实例地址（-H/--host），默认 127.0.0.1；还原脚本要用它
	conn     string
	mode     string // V$DM_SQLLOG_CONFIG 报出的模式名（可能是 <DEFAULT>）
	iniMode  string // sqllog.ini 里的段名（如 SLOG_ALL），仅作候选
	prefix   string // SP_SET_SQLLOG_INI 实测生效的写法前缀："[模式]" 或 ""（不带模式名）
	prefixOK bool   // prefix 是否已经验证过（还原时优先沿用）
}

// dmqMark 结果行的唯一标记。
//
// 🩸 disql 会把输入的 SQL 原样回显到输出里 —— 如果标记直接写在 SQL 文本中，
// 回显行也会命中，解析出来的「值」就变成 SQL 片段（实测踩过）。
// 所以 SQL 里把标记拆成两个字符串常量拼接：文本中不存在连续标记，只有结果行才有。
const dmqMark = "##DMQ7F3A##"

func dmqSel(v string) string { return "'##DMQ'||'7F3A##'||" + v }

type syncRestore struct {
	mode   string // 模式名（仅用于提示）
	prefix string // 实际生效的写法前缀（还原时照用）
	orig   string
	script string
	done   bool
}

// findDisqlNear 从「数据目录 / DM 安装根」附近找 disql
func findDisqlNear(loc watchLoc) string {
	bin := "disql"
	if runtime.GOOS == "windows" {
		bin = "disql.exe"
	}
	var cands []string
	if v := strings.TrimSpace(os.Getenv("DMSQLQ_DISQL")); v != "" {
		cands = append(cands, v)
	}
	starts := []string{}
	if loc.ini != "" {
		starts = append(starts, filepath.Dir(loc.ini))
	}
	if loc.dir != "" {
		starts = append(starts, loc.dir)
	}
	for _, st := range starts {
		d := st
		for i := 0; i < 4 && d != ""; i++ { // 往上找 4 层，每层试 bin/
			cands = append(cands, filepath.Join(d, "bin", bin))
			parent := filepath.Dir(d)
			if parent == d {
				break
			}
			d = parent
		}
	}
	for _, r := range dmRoots() {
		cands = append(cands, filepath.Join(r.path, "bin", bin))
	}
	if p, err := exec.LookPath(bin); err == nil {
		cands = append(cands, p)
	}
	for _, c := range cands {
		if fileExists(c) {
			return c
		}
	}
	return ""
}

// dmIniPort 从数据目录的 dm.ini 读 PORT_NUM
func dmIniPort(dataDir string) string {
	b, err := os.ReadFile(filepath.Join(dataDir, "dm.ini"))
	if err != nil {
		return "5236"
	}
	for _, ln := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(ln)
		i := strings.IndexByte(t, '=')
		if i <= 0 {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(t[:i])) != "PORT_NUM" {
			continue
		}
		v := strings.TrimSpace(t[i+1:])
		if j := strings.IndexAny(v, "#\t "); j >= 0 {
			v = strings.TrimSpace(v[:j])
		}
		if v != "" {
			return v
		}
	}
	return "5236"
}

// isLocalHost 判断实例地址是否指向本机。
//
// 判据只认回环地址与常见的本机别名 —— 不解析真实网卡 IP：
//
//	· 从 WSL 连 Windows 本机时，给的是「Windows 主机 IP」（如 172.20.240.1），
//	  从工具视角看它**就是远端**，按远端处理（拒绝改动配置）才是正确取舍；
//	· localhost / 127.x / ::1 / 空 都算本机。
func isLocalHost(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	switch h {
	case "", "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	if strings.HasPrefix(h, "127.") {
		return true
	}
	return false
}

func openDMProbe(loc watchLoc, pass, host, portArg string) (*dmProbe, error) {
	d := findDisqlNear(loc)
	if d == "" {
		return nil, errors.New("没找到 disql（可用环境变量 DMSQLQ_DISQL 指定完整路径）")
	}
	dataDir := ""
	if loc.ini != "" {
		dataDir = filepath.Dir(loc.ini)
	} else {
		dataDir = loc.dir
	}
	// 端口优先级：命令行 -P > dm.ini 的 PORT_NUM > 5236
	port := strings.TrimSpace(portArg)
	if port == "" {
		port = dmIniPort(dataDir)
	}
	// 地址优先级：命令行 -H > $DM_HOST > 127.0.0.1
	if host == "" {
		host = strings.TrimSpace(os.Getenv("DM_HOST"))
	}
	if host == "" {
		host = "127.0.0.1"
	}
	p := &dmProbe{disql: d, host: host, conn: fmt.Sprintf("SYSDBA/%s@%s:%s", pass, host, port)}
	// 🩸 远端库不能沿用本机的 dm.ini 端口兜底 —— 若用户没给 -P 且 dm.ini 又不在手边，
	//    5236 只是假定值；连不上时提示用 -P 指定。
	if loc.ini != "" {
		p.iniMode = sqllogMode(loc.ini)
	}
	// 模式名以 V$DM_SQLLOG_CONFIG **实际报的**为准 —— 它不等于 sqllog.ini 里的段名。
	// 🩸 本机实测：报的是 <DEFAULT>，而文件里写的是 [SLOG_ALL]；
	//    用 [SLOG_ALL] 只改到磁盘、内存不生效，必须用「不带模式名」才真的生效。
	rows, err := p.query("select " + dmqSel("MODE_NAME||'|'||NVL(PARA_VALUE,'')") +
		" from V$DM_SQLLOG_CONFIG where PARA_NAME='ASYNC_FLUSH';")
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errors.New("V$DM_SQLLOG_CONFIG 里没有 ASYNC_FLUSH 行")
	}
	if i := strings.IndexByte(rows[0], '|'); i >= 0 {
		p.mode = strings.TrimSpace(rows[0][:i])
	}
	return p, nil
}

// sqllogMode 取 sqllog.ini 里「含 ASYNC_FLUSH 的那一段」的段名（仅作候选）
func sqllogMode(iniPath string) string {
	b, err := os.ReadFile(iniPath)
	if err != nil {
		return ""
	}
	cur := ""
	for _, ln := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		if t[0] == '[' {
			if j := strings.IndexByte(t, ']'); j > 0 {
				cur = t[1:j]
			}
			continue
		}
		i := strings.IndexByte(t, '=')
		if i <= 0 {
			continue
		}
		if strings.ToUpper(strings.TrimSpace(t[:i])) == "ASYNC_FLUSH" {
			return cur
		}
	}
	return ""
}

// prefixCands SP_SET_SQLLOG_INI 的候选写法，按「先可信」排序。
// 已验证过的写法排最前；正常模式名带 [模式]；否则/其次用不带模式名（全局配置区）。
func (p *dmProbe) prefixCands() []string {
	var out []string
	add := func(s string) {
		for _, x := range out {
			if x == s {
				return
			}
		}
		out = append(out, s)
	}
	if p.prefixOK {
		add(p.prefix)
	}
	if p.mode != "" && !strings.HasPrefix(p.mode, "<") {
		add("[" + p.mode + "]")
	}
	add("")
	if p.iniMode != "" && !strings.EqualFold(p.iniMode, p.mode) {
		add("[" + p.iniMode + "]")
	}
	return out
}

func (p *dmProbe) close() {}

// query 跑一条 SQL，返回所有含 ##DMQ## 标记的值
func (p *dmProbe) query(sql string) ([]string, error) {
	cmd := exec.Command(p.disql, "/NOLOG")
	cmd.Stdin = strings.NewReader("conn " + p.conn + "\nset echo off\n" + sql + "\nexit\n")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	env := os.Environ()
	if runtime.GOOS != "windows" {
		env = append(env, "LD_LIBRARY_PATH="+filepath.Dir(p.disql))
	}
	cmd.Env = env
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		return nil, errors.New("disql 超时（20s）")
	case <-done:
	}
	out := buf.String()
	if os.Getenv("DMSQLQ_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "---- disql 原始输出 ----\n%s\n------------------------\n", out)
	}
	var vals []string
	for _, ln := range strings.Split(out, "\n") {
		i := strings.Index(ln, dmqMark)
		if i < 0 {
			continue
		}
		v := ln[i+len(dmqMark):]
		// 值后面可能跟着 disql 的提示符/空格，取到行尾再清理
		v = strings.TrimRight(v, " \t\r")
		if j := strings.Index(v, "SQL>"); j >= 0 {
			v = strings.TrimSpace(v[:j])
		}
		vals = append(vals, v)
	}
	if len(vals) == 0 {
		if strings.Contains(out, "用户名或密码错误") || strings.Contains(out, "invalid password") {
			return nil, errors.New("登录失败（口令不对？）")
		}
		return nil, errors.New("查询无结果（设 DMSQLQ_DEBUG=1 可看 disql 原始输出）")
	}
	return vals, nil
}

func (p *dmProbe) cfgValue(name string) string {
	rows, err := p.query("select " + dmqSel("NVL(PARA_VALUE,'')") +
		" from V$DM_SQLLOG_CONFIG where PARA_NAME='" + name + "';")
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0]
}

// report 只读体检：把采集侧的四个关键项列出来
func (p *dmProbe) report() []string {
	var out []string
	line := "体检    "
	if p.mode != "" {
		line += "模式=" + p.mode + " · "
	}
	if v := p.cfgValue("SQL_TRACE_MASK"); v != "" {
		line += "掩码=" + v
		if !hasBit(v, "27") {
			line += "（不含位 27，拿不到被 MIN_EXEC_TIME 滤掉的语句）"
		}
	} else {
		line += "掩码=读不到"
	}
	if v := p.cfgValue("MIN_EXEC_TIME"); v != "" {
		line += " · MIN_EXEC_TIME=" + v
		if v != "0" {
			line += "（>0：快语句不写「执行完成行」，可用 --all 看 [ORA]）"
		}
	}
	if v := p.cfgValue("ASYNC_FLUSH"); v != "" {
		line += " · ASYNC_FLUSH=" + v
		if v == "1" {
			line += "（异步刷盘；要最实时用 -Y 临时切同步）"
		}
	}
	out = append(out, line)
	if sv := p.iniValue("SVR_LOG"); sv != "" && sv != "1" && sv != "2" && sv != "3" {
		out = append(out, "体检    ⚠️ dm.ini 的 SVR_LOG="+sv+"（0=关闭）—— SQL 日志总开关没开，watch 看不到东西")
	}
	return out
}

func (p *dmProbe) iniValue(name string) string {
	rows, err := p.query("select " + dmqSel("NVL(PARA_VALUE,'')") +
		" from V$DM_INI where PARA_NAME='" + name + "';")
	if err != nil || len(rows) == 0 {
		return ""
	}
	return rows[0]
}

// hasBit 判断「2:3:25:28」这种掩码串里有没有某一位
func hasBit(mask, bit string) bool {
	for _, p := range strings.Split(mask, ":") {
		if strings.TrimSpace(p) == bit {
			return true
		}
	}
	return false
}

func (p *dmProbe) setAsyncFlush(v string) error {
	_, err := p.query("SP_SET_SQLLOG_INI('" + p.prefix + "ASYNC_FLUSH=" + v +
		"');SP_REFRESH_SVR_LOG_CONFIG();select " + dmqSel("'ok'") + " as x;")
	return err
}

// applyFlush 设置 ASYNC_FLUSH，逐个候选写法试到「回读一致」为止，并记下真正生效的那个。
// 🩸 只看「过程执行成功」不够：本机实测 [SLOG_ALL] 写法过程成功、磁盘也改了，但内存值没变。
func (p *dmProbe) applyFlush(v string) error {
	var last string
	for _, pre := range p.prefixCands() {
		p.prefix, p.prefixOK = pre, false
		_ = p.setAsyncFlush(v)
		if now := p.cfgValue("ASYNC_FLUSH"); now == v {
			p.prefixOK = true
			return nil
		} else {
			last = now
		}
	}
	return fmt.Errorf("改不动 ASYNC_FLUSH：回读是 %s，期望 %s —— 模式名 %s 与「不带模式名」两种写法都试过了",
		last, v, p.mode)
}

// switchToSync 把 ASYNC_FLUSH 从 1 改成 0（原本就是 0 则不动）。
//
// 🩸 顺序很重要：**先写还原脚本、再动数据库**。反过来会出现「已改成功、
// 但还没登记还原就出错退出」—— 库被留在同步刷盘上（实测踩过）。
// 回读校验失败时也立即回滚，绝不把改动留在库里。
func (p *dmProbe) switchToSync() (*syncRestore, error) {
	orig := p.cfgValue("ASYNC_FLUSH")
	if orig == "" {
		return nil, errors.New("读不到 ASYNC_FLUSH（V$DM_SQLLOG_CONFIG 没这一项？）")
	}
	if orig == "0" {
		return nil, nil // 本来就是同步刷盘，不需要动，也不需要还原
	}
	r := &syncRestore{mode: p.mode, orig: orig}
	// ★ 先把还原脚本落盘（用首选写法），再动数据库；等确定生效写法后再改写一次
	cands := p.prefixCands()
	if len(cands) > 0 {
		r.prefix = cands[0]
	}
	r.script = writeRestoreScript(p, r)
	if err := p.applyFlush("0"); err != nil {
		rb := p.applyFlush(orig) // 可能改了一半，尽量回滚
		if rb != nil {
			return nil, fmt.Errorf("%v；且回滚也失败：%v —— 请执行 %s", err, rb, r.script)
		}
		return nil, fmt.Errorf("%v（已回滚为 %s）", err, orig)
	}
	r.prefix = p.prefix
	r.script = writeRestoreScript(p, r) // 用实测生效的写法改写
	return r, nil
}

func (p *dmProbe) restoreSync(r *syncRestore) error {
	if r == nil || r.done {
		return nil
	}
	p.prefix, p.prefixOK = r.prefix, true
	if err := p.applyFlush(r.orig); err != nil {
		return err
	}
	now := p.cfgValue("ASYNC_FLUSH")
	if now != r.orig {
		return fmt.Errorf("回读是 %s，期望 %s", now, r.orig)
	}
	r.done = true
	return nil
}

// restoreNow 供退出路径调用（无库/无还原登记时静默）
func restoreNow(db *dmProbe, r **syncRestore) {
	if db == nil || *r == nil {
		return
	}
	rr := *r
	if rr.done {
		return
	}
	if err := db.restoreSync(rr); err != nil {
		fmt.Fprintf(os.Stdout, "\n  ⚠️ 还原 ASYNC_FLUSH 失败：%v\n     请手工执行：%s\n", err, rr.script)
		return
	}
	fmt.Fprintf(os.Stdout, "\n  已还原 SQL 日志刷盘方式：ASYNC_FLUSH=%s ✓\n", rr.orig)
}

// writeRestoreScript 写一份「没有口令」的手工还原脚本，防强杀
func writeRestoreScript(p *dmProbe, r *syncRestore) string {
	pth := filepath.Join(os.TempDir(), "dmsqlq_restore_async_flush.sql")
	host := p.host
	if host == "" {
		host = "127.0.0.1"
	}
	port := ""
	if i := strings.LastIndexByte(p.conn, ':'); i > 0 {
		port = p.conn[i+1:]
	}
	if port == "" {
		port = "5236"
	}
	txt := "-- dmsqlq watch 自动生成：手工还原 SQL 日志刷盘方式\n" +
		"--（日志模式 " + r.mode + "，写法 '" + r.prefix + "ASYNC_FLUSH=" + r.orig + "'）\n" +
		"-- 用途：万一 dmsqlq 被强杀、没来得及自动还原，手工跑这个即可。\n" +
		"-- 用法：把下面的 <口令> 换成 SYSDBA 口令，然后\n" +
		"--        disql /NOLOG < " + pth + "\n" +
		"conn SYSDBA/<口令>@" + host + ":" + port + "\n" +
		"SP_SET_SQLLOG_INI('" + r.prefix + "ASYNC_FLUSH=" + r.orig + "');\n" +
		"SP_REFRESH_SVR_LOG_CONFIG();\n" +
		"select PARA_NAME, PARA_VALUE from V$DM_SQLLOG_CONFIG where PARA_NAME='ASYNC_FLUSH';\n" +
		"exit\n"
	if err := os.WriteFile(pth, []byte(txt), 0o644); err != nil {
		return "(写还原脚本失败：" + err.Error() + ")"
	}
	return pth
}
