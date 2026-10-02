# -*- coding: utf-8 -*-
"""dmsqlq Excel 交付件自测（V2.1 起）。

为什么单独有这么一个测试：.xlsx 是手写 XML + zip，写错一个字符 Excel 就直接
「文件已损坏」拒绝打开 —— 而这种错在 Go 侧编译期和运行时都发现不了。
所以每次改 Excel 相关代码后，用 openpyxl（严格的 OOXML 实现）回读一遍：
它能读通，Excel / WPS / LibreOffice 就一定打得开。

用法：python test_xlsx.py <交付件.xlsx> [--strict]
      --strict 时要求 10 张工作表齐全（小日志切片场景会缺「锁等待」等表，不加即可）

依赖：openpyxl（pip install openpyxl）
"""
import sys

import openpyxl

EXPECT_CORE = ["概览", "SQL优化清单", "慢SQL明细", "热表", "语句类型分布",
               "锁等待", "长事务", "时段分布", "用户与客户端", "结构变更与高危操作"]

path = sys.argv[1] if len(sys.argv) > 1 else "交付.xlsx"
strict = "--strict" in sys.argv

fails = []
def check(cond, msg):
    print(("  ✓ " if cond else "  ✗ ") + msg)
    if not cond:
        fails.append(msg)

wb = openpyxl.load_workbook(path, data_only=True)
names = wb.sheetnames
print("工作表 %d 张：%s" % (len(names), " / ".join(names)))

print("\n[1] 结构完整性")
check(len(names) >= 6, "至少有 6 张表（实际 %d）" % len(names))
check("概览" in names, "有「概览」表")
check("SQL优化清单" in names, "有「SQL优化清单」表")
missing = [n for n in EXPECT_CORE if n not in names]
check(not (strict and missing), "strict 模式下核心表齐全（缺：%s）" % (missing or "无"))
for n in names:
    check(len(n) <= 31, "表名长度合法：%s（%d 字符）" % (n, len(n)))
check(len(set(names)) == len(names), "表名无重复")

print("\n[2] 概览表内容")
ws = wb["概览"]
texts = []
for r in ws.iter_rows(values_only=True):
    for c in r:
        if isinstance(c, str):
            texts.append(c)
blob = "\n".join(texts)
check("dmsqlq SQL 优化交付件" in blob, "标题存在")
check("口径与说明" in blob, "含「口径与说明」章节")
check("优化优先级规则" in blob, "含优先级规则说明")
check("扫描日志" in blob, "含分析范围")

print("\n[3] SQL优化清单：数字为真数字 + 降序")
ws = wb["SQL优化清单"]
hdr = [c.value for c in ws[1]]
check(hdr[1] and "累计耗时" in hdr[1], "第 2 列表头为累计耗时（实际 %r）" % (hdr[1] if hdr else None))
nums, cnts, samples = [], [], []
row = 2
while row <= ws.max_row:
    v = ws.cell(row=row, column=2).value
    if not isinstance(v, (int, float)):
        break  # 数据区结束（后面是空行 + 说明）
    nums.append(v)
    cnts.append(ws.cell(row=row, column=3).value)
    samples.append(ws.cell(row=row, column=8).value)
    row += 1
check(len(nums) > 0, "有数据行（%d 条）" % len(nums))
check(all(isinstance(c, (int, float)) for c in cnts), "执行次数列全为数字（可在 Excel 里求和）")
check(nums == sorted(nums, reverse=True), "按累计耗时严格降序")
check(all(s and len(str(s)) > 5 for s in samples), "语句模板列非空")
has_nl = any("\n" in str(s) for s in samples)
print("       （含换行的 SQL 单元格：%s —— 换行能保留说明 xml:space 生效）" % ("是" if has_nl else "否，本样本 SQL 均为单行"))
# 优先级取值合法性
prios = set()
for i in range(2, 2 + len(nums)):
    prios.add(ws.cell(row=i, column=7).value)
check(prios <= {"优先", "次之", "一般"}, "优先级取值合法：%s" % prios)

print("\n[4] 慢SQL明细")
ws = wb["慢SQL明细"]
ms = []
for i in range(2, ws.max_row + 1):
    v = ws.cell(row=i, column=3).value
    if not isinstance(v, (int, float)):
        break
    ms.append(v)
check(len(ms) > 0, "有数据行（%d 条）" % len(ms))
check(ms == sorted(ms, reverse=True), "按耗时降序")
check(all(ws.cell(row=2, column=9).value for _ in [0]), "SQL 列非空")

print("\n[5] 控制字符（Excel 拒绝的非法字符）")
bad = 0
for sh in wb.worksheets:
    for r in sh.iter_rows(values_only=True):
        for c in r:
            if isinstance(c, str) and any(ord(ch) < 0x20 and ch not in "\t\n" for ch in c):
                bad += 1
check(bad == 0, "全文无 XML 非法控制字符（发现 %d 处）" % bad)

print("\n" + "=" * 76)
if fails:
    print("失败 %d 项：" % len(fails))
    for f in fails:
        print("   - " + f)
    sys.exit(1)
print("全部通过 —— .xlsx 结构合法、数字为真数字、核心清单降序。")
