# -*- coding: utf-8 -*-
"""extract_core 自测 —— 构造真实压缩包（含嵌套/错后缀/无后缀/加密/恶意包）逐项验证。

运行：venv\\Scripts\\python.exe src\\selftest_core.py
"""
from __future__ import annotations

import gzip
import io
import os
import shutil
import sys
import tarfile
import threading
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from extract_core import (  # noqa: E402
    Extractor, Options, archive_stem, fix_zip_name, human_size, safe_join, sanitize_rel, sniff,
)

PASS = 0
FAIL = 0
FAILS: list[str] = []


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        FAILS.append(name)
        print(f"  [FAIL] {name}  {extra}")


def section(t: str) -> None:
    print(f"\n=== {t} ===")


# ---------------------------------------------------------------- 造样本

def mkzip(path, entries, crypt=None, aes=False):
    """entries: [(name, bytes|None)]，None 表示目录条目。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if crypt:
        import pyzipper
        with pyzipper.AESZipFile(path, "w", compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as z:
            z.setpassword(crypt.encode())
            z.setencryption(pyzipper.WZ_AES, nbits=128)
            for name, data in entries:
                z.writestr(name, b"" if data is None else data)
        return
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, b"" if data is None else data)


# ---- ZipCrypto（传统加密）手写实现：pyzipper 只能写 AES，造 ZipCrypto 样本得自己来 ----

def _crc_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if c & 1 else 0)
        t.append(c)
    return t


_ZC_TABLE = _crc_table()


class _ZC:
    """PKWARE ZipCrypto：密钥流 = f(key2)，每字节用**明文**更新密钥。"""

    def __init__(self, pwd: bytes):
        self.k0, self.k1, self.k2 = 0x12345678, 0x23456789, 0x34567890
        for b in pwd:
            self.update(b)

    def update(self, b: int) -> None:
        t = _ZC_TABLE
        self.k0 = (self.k0 >> 8) ^ t[(self.k0 ^ b) & 0xFF]
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & 0xFFFFFFFF
        self.k1 = (self.k1 * 134775813 + 1) & 0xFFFFFFFF
        self.k2 = (self.k2 >> 8) ^ t[(self.k2 ^ ((self.k1 >> 24) & 0xFF)) & 0xFF]

    def byte(self) -> int:
        t = (self.k2 | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for b in data:
            out.append(b ^ self.byte())
            self.update(b)
        return bytes(out)


def _raw_deflate(data: bytes) -> bytes:
    import zlib
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


def mkzip_zipcrypto(path, entries, pwd):
    """手工构造 ZipCrypto 加密 zip（flag 位 0x1，12 字节加密头）。"""
    import struct
    import time as _t
    import zlib

    os.makedirs(os.path.dirname(path), exist_ok=True)
    pw = pwd.encode() if isinstance(pwd, str) else pwd
    dt = _t.localtime()
    dos_time = (dt.tm_hour << 11) | (dt.tm_min << 5) | (dt.tm_sec // 2)
    dos_date = ((dt.tm_year - 1980) << 9) | (dt.tm_mon << 5) | dt.tm_mday
    local = b""
    central = b""
    offset = 0
    for name, data in entries:
        nb = name.encode("utf-8")
        raw = data
        crc = zlib.crc32(raw) & 0xFFFFFFFF
        comp = _raw_deflate(raw)
        hdr = os.urandom(11) + bytes([(crc >> 24) & 0xFF])
        zc = _ZC(pw)
        payload = zc.encrypt(hdr) + zc.encrypt(comp)
        lfh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x0001, 8, dos_time, dos_date,
                          crc, len(payload), len(raw), len(nb), 0)
        local += lfh + nb + payload
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0x0001, 8,
                               dos_time, dos_date, crc, len(payload), len(raw), len(nb),
                               0, 0, 0, 0, 0, offset) + nb
        offset += len(lfh) + len(nb) + len(payload)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
                       len(central), len(local), 0)
    with open(path, "wb") as f:
        f.write(local + central + eocd)


def mkzip_gbk(path, entries):
    """手工构造"老式"zip：不带 UTF-8 标志位，文件名是 GBK 原始字节。

    （Python 3.12 的 zipfile 写非 ASCII 名会自动置 UTF-8 位，造不出老式包，只能手写字节。）
    """
    import struct
    import time as _t
    import zlib

    os.makedirs(os.path.dirname(path), exist_ok=True)
    dt = _t.localtime()
    dos_time = (dt.tm_hour << 11) | (dt.tm_min << 5) | (dt.tm_sec // 2)
    dos_date = ((dt.tm_year - 1980) << 9) | (dt.tm_mon << 5) | dt.tm_mday
    local = b""
    central = b""
    offset = 0
    for name, data in entries:
        nb = name.encode("gbk") if isinstance(name, str) else name
        raw = data if isinstance(data, bytes) else data.encode()
        crc = zlib.crc32(raw) & 0xFFFFFFFF
        comp = _raw_deflate(raw)
        lfh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, dos_time, dos_date,
                          crc, len(comp), len(raw), len(nb), 0)
        local += lfh + nb + comp
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 8,
                               dos_time, dos_date, crc, len(comp), len(raw), len(nb),
                               0, 0, 0, 0, 0, offset) + nb
        offset += len(lfh) + len(nb) + len(comp)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
                       len(central), len(local), 0)
    with open(path, "wb") as f:
        f.write(local + central + eocd)


def mkzip_raw(path, raw_entries, extra_entries=()):
    """raw_entries: [(zipinfo_name, bytes)] 原样写入（用于造假路径）。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in raw_entries:
            z.writestr(zipfile.ZipInfo(name), data)
        for name, data in extra_entries:
            z.writestr(name, data)


def mkzip_symlink(path, link_name, target):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        zi = zipfile.ZipInfo(link_name)
        zi.create_system = 3
        zi.external_attr = (0o120777 << 16)
        z.writestr(zi, target)


def mktar(path, entries, mode="w:gz", symlink=None, evil=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with tarfile.open(path, mode) as tf:
        for name, data in entries:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        if symlink:
            ti = tarfile.TarInfo(symlink[0])
            ti.type = tarfile.SYMTYPE
            ti.linkname = symlink[1]
            tf.addfile(ti)
        if evil:
            data = b"pwned"
            ti = tarfile.TarInfo(evil)
            ti.size = len(data)
            ti.type = tarfile.REGTYPE
            tf.addfile(ti, io.BytesIO(data))


def mk7z(path, entries, password=None):
    import py7zr
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with py7zr.SevenZipFile(path, "w", password=password) as z:
        for name, data in entries:
            z.writestr(data, arcname=name)


def mkraw(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)


def rmtree(p):
    shutil.rmtree(p, ignore_errors=True)


def run_extract(src, **kw):
    logs: list[tuple[str, str]] = []
    opt = Options(**kw)
    ex = Extractor([src], opt, log=lambda lv, m: logs.append((lv, m)))
    stats = ex.run()
    return ex, stats, logs


# ---------------------------------------------------------------- 主流程

def main() -> int:
    root = os.path.join(os.path.dirname(HERE), "tmp", "selftest")
    rmtree(root)
    os.makedirs(root, exist_ok=True)
    print(f"临时根目录：{root}")

    # ---------------- T1 嵌套递归
    section("T1 zip 基本 + 三层嵌套递归")
    d = os.path.join(root, "t1")
    tmp = os.path.join(root, "_t1_stage")                   # 中间包放这儿，别污染源目录
    c = os.path.join(tmp, "c.zip")
    mkzip(c, [("finally.txt", b"deep")])
    c_data = open(c, "rb").read()
    b = os.path.join(tmp, "b.zip")
    mkzip(b, [("hello.txt", b"mid"), ("deep.zip", c_data)])
    b_data = open(b, "rb").read()
    rmtree(tmp)
    a = os.path.join(d, "a.zip")
    mkzip(a, [("inner/hello.txt", b"top"), ("b.zip", b_data)])
    ex, st, logs = run_extract(d)
    check("a.zip → a\\ 目录存在", os.path.isdir(os.path.join(d, "a")))
    check("顶层文件解出", os.path.isfile(os.path.join(d, "a", "inner", "hello.txt")))
    check("第 2 层嵌套解出", os.path.isfile(os.path.join(d, "a", "b", "hello.txt")))
    check("第 3 层嵌套解出", os.path.isfile(os.path.join(d, "a", "b", "deep", "finally.txt")))
    check("3 个包全部成功", st.archives_done == 3, f"done={st.archives_done} failed={st.archives_failed}")
    with open(os.path.join(d, "a", "b", "deep", "finally.txt"), "rb") as f:
        check("深层内容正确", f.read() == b"deep")

    # ---------------- T2 无后缀 + 错后缀
    section("T2 后缀名不可信（无后缀 / 错后缀）")
    d = os.path.join(root, "t2")
    mkraw(os.path.join(d, "noext"), b"")
    mkzip(os.path.join(d, "noext"), [("x.txt", b"zip-no-ext")])
    gz = os.path.join(d, "_stage.tar.gz")
    mktar(gz, [("y.txt", b"tar-mislabeled")])
    os.replace(gz, os.path.join(d, "mislabel.7z"))          # 后缀 .7z，实际是 tar.gz
    z7 = os.path.join(d, "_stage.7z")
    mk7z(z7, [("z.txt", b"real-7z")])
    os.replace(z7, os.path.join(d, "wrong.zip"))            # 后缀 .zip，实际是 7z
    ex, st, logs = run_extract(d)
    check("无后缀文件被识别为 zip 并解出",
          os.path.isfile(os.path.join(d, "noext_extracted", "x.txt")))
    check(".7z 实为 tar.gz 解出", os.path.isfile(os.path.join(d, "mislabel", "y.txt")))
    check(".zip 实为 7z 解出", os.path.isfile(os.path.join(d, "wrong", "z.txt")))
    check("三种都成功", st.archives_done == 3, f"done={st.archives_done} fail={st.archives_failed}")

    # ---------------- T3 中文名
    section("T3 老式中文名 zip（cp437 → GBK）")
    d = os.path.join(root, "t3")
    p = os.path.join(d, "cn.zip")
    mkzip_gbk(p, [("中文目录/文件.txt", b"cn")])
    with zipfile.ZipFile(p) as z:
        info = z.infolist()[0]
        check("夹具确实是老式编码", not (info.flag_bits & 0x800), f"flag={info.flag_bits}")
        check("fix_zip_name 还原中文", fix_zip_name(info) == "中文目录/文件.txt", fix_zip_name(info))
    ex, st, logs = run_extract(d)
    check("中文路径落盘正确", os.path.isfile(os.path.join(d, "cn", "中文目录", "文件.txt")))

    d2 = os.path.join(root, "t3b")
    fake = "假标记/文件.txt".encode("gbk").decode("cp437")
    p2 = os.path.join(d2, "fakeutf8.zip")
    mkzip(p2, [(fake, b"fake")])            # Python 写非 ASCII 名会自动打 UTF-8 标记
    with zipfile.ZipFile(p2) as z:
        i = z.infolist()[0]
        check("夹具确实带（假）UTF-8 标记", bool(i.flag_bits & 0x800), hex(i.flag_bits))
        check("假标记也能还原中文", fix_zip_name(i) == "假标记/文件.txt", repr(fix_zip_name(i)))
    ex, st, logs = run_extract(d2)
    check("假标记中文名落盘正确", os.path.isfile(os.path.join(d2, "fakeutf8", "假标记", "文件.txt")))

    # ---------------- T4 zip-slip
    section("T4 恶意路径（zip-slip / 绝对路径）")
    d = os.path.join(root, "t4")
    p = os.path.join(d, "evil.zip")
    mkzip_raw(p, [("../../pwned.txt", b"pwned"),
                  ("/abs_pwned.txt", b"pwned"),
                  ("a/../../b_pwned.txt", b"pwned")],
              extra_entries=[("good.txt", b"good")])
    ex, st, logs = run_extract(d)
    check("正常文件仍解出", os.path.isfile(os.path.join(d, "evil", "good.txt")))
    check("上级目录未被写入", not os.path.exists(os.path.join(root, "pwned.txt")))
    check("磁盘根未写入", not os.path.exists(os.path.splitdrive(root)[0] + os.sep + "abs_pwned.txt"))
    check("b_pwned 未落地", not os.path.exists(os.path.join(d, "evil", "b_pwned.txt")))
    check("恶意条目被日志记录", any("不安全路径" in m for _lv, m in logs))

    # ---------------- T5 zip 符号链接
    section("T5 zip 符号链接应跳过")
    d = os.path.join(root, "t5")
    p = os.path.join(d, "link.zip")
    mkzip_symlink(p, "link_to_system", r"C:\Windows")
    with zipfile.ZipFile(p, "a") as z:
        z.writestr("ok.txt", b"ok")
    ex, st, logs = run_extract(d)
    check("普通文件解出", os.path.isfile(os.path.join(d, "link", "ok.txt")))
    check("符号链接未创建", not os.path.exists(os.path.join(d, "link", "link_to_system")))

    # ---------------- T6 tar 系列
    section("T6 tar.gz / symlink / tar 内部 ../ 攻击")
    d = os.path.join(root, "t6")
    mktar(os.path.join(d, "t.tar.gz"), [("dir/f.txt", b"tar")], symlink=("lnk", r"C:\Windows"))
    mktar(os.path.join(d, "bad.tar"), [("ok.txt", b"ok")], mode="w", evil="../tar_pwned.txt")
    ex, st, logs = run_extract(d)
    check("tar 内文件解出", os.path.isfile(os.path.join(d, "t", "dir", "f.txt")))
    check("tar 符号链接未创建", not os.path.exists(os.path.join(d, "t", "lnk")))
    check("正常 tar 文件解出", os.path.isfile(os.path.join(d, "bad", "ok.txt")))
    check("tar 的 ../ 未逃逸", not os.path.exists(os.path.join(root, "tar_pwned.txt")))

    # ---------------- T7 7z 与密码
    section("T7 7z：明文 / 加密")
    d = os.path.join(root, "t7")
    mk7z(os.path.join(d, "plain.7z"), [("p.txt", b"plain7z")])
    mk7z(os.path.join(d, "secret.7z"), [("s.txt", b"topsecret")], password="pw123")

    ex, st, logs = run_extract(d, password="")
    check("无密码时明文 7z 照常解出", os.path.isfile(os.path.join(d, "plain", "p.txt")))
    check("无密码时加密 7z 被跳过（不是失败崩溃）", st.archives_skipped >= 1, f"skip={st.archives_skipped}")
    check("无密码时不产生加密包目录内容",
          not os.path.isfile(os.path.join(d, "secret", "s.txt")))

    d2 = os.path.join(root, "t7b")
    mk7z(os.path.join(d2, "plain.7z"), [("p.txt", b"plain7z")])
    mk7z(os.path.join(d2, "secret.7z"), [("s.txt", b"topsecret")], password="pw123")
    ex, st, logs = run_extract(d2, password="pw123")
    check("一次密码，明文包不受影响", os.path.isfile(os.path.join(d2, "plain", "p.txt")))
    check("一次密码，加密包解出", os.path.isfile(os.path.join(d2, "secret", "s.txt")))
    check("两个都成功", st.archives_done == 2, f"done={st.archives_done} fails={st.archives_failed}")

    d3 = os.path.join(root, "t7c")
    mk7z(os.path.join(d3, "secret.7z"), [("s.txt", b"x")], password="pw123")
    ex, st, logs = run_extract(d3, password="WRONG")
    check("错误密码 → 失败而不是静默成功", st.archives_failed == 1, f"failed={st.archives_failed}")
    check("错误密码未留下文件", not os.path.isfile(os.path.join(d3, "secret", "s.txt")))

    # ---------------- T8 zip 加密
    section("T8 zip：ZipCrypto 加密 / WinZip AES")
    d = os.path.join(root, "t8")
    mkzip(os.path.join(d, "plain.zip"), [("p.txt", b"plain")])
    mkzip_zipcrypto(os.path.join(d, "zc.zip"), [("s.txt", b"zipcrypto")], "pw123")
    # 夹具自证：Python 自带 zipfile 能解开，说明样本本身是合格的 ZipCrypto zip
    with zipfile.ZipFile(os.path.join(d, "zc.zip")) as z:
        check("夹具自证：zipfile 能用密码读出",
              z.read("s.txt", pwd=b"pw123") == b"zipcrypto")
    ex, st, logs = run_extract(d, password="pw123")
    check("明文 zip 正常", os.path.isfile(os.path.join(d, "plain", "p.txt")))
    check("ZipCrypto 用密码解开", os.path.isfile(os.path.join(d, "zc", "s.txt")))
    with open(os.path.join(d, "zc", "s.txt"), "rb") as f:
        check("ZipCrypto 内容正确", f.read() == b"zipcrypto")

    d2 = os.path.join(root, "t8b")
    mkzip_zipcrypto(os.path.join(d2, "zc.zip"), [("s.txt", b"x")], "pw123")
    ex, st, logs = run_extract(d2, password="")
    check("无密码时 ZipCrypto 被跳过", st.archives_skipped == 1 and st.archives_failed == 0,
          f"skip={st.archives_skipped} fail={st.archives_failed}")

    d3 = os.path.join(root, "t8c")
    mkzip(os.path.join(d3, "aes.zip"), [("s.txt", b"aes-secret")], crypt="pw123")
    ex, st, logs = run_extract(d3, password="pw123")
    ok_aes = os.path.isfile(os.path.join(d3, "aes", "s.txt"))
    check("WinZip AES 走 bsdtar 兜底解出", ok_aes,
          f"done={st.archives_done} fail={st.archives_failed} note={[r.note for r in ex.results]}")

    # ---------------- T9 深度限制
    section("T9 最大嵌套深度")
    d = os.path.join(root, "t9")
    lv3 = os.path.join(d, "_l3.zip")
    mkzip(lv3, [("l3.txt", b"3")])
    lv2 = os.path.join(d, "_l2.zip")
    mkzip(lv2, [("l2.txt", b"2"), ("l3.zip", open(lv3, "rb").read())])
    lv1 = os.path.join(d, "_l1.zip")
    mkzip(lv1, [("l1.txt", b"1"), ("l2.zip", open(lv2, "rb").read())])
    for f in (lv3, lv2):
        os.remove(f)
    ex, st, logs = run_extract(d, max_depth=1)
    check("第 1 层解出", os.path.isfile(os.path.join(d, "_l1", "l1.txt")))
    check("第 2 层解出（在深度内）", os.path.isfile(os.path.join(d, "_l1", "l2", "l2.txt")))
    check("第 3 层被深度限制挡下", not os.path.isfile(os.path.join(d, "_l1", "l2", "l3", "l3.txt")))
    check("深度跳过有日志", any("最大嵌套深度" in m for _lv, m in logs))

    # ---------------- T10 覆盖策略
    section("T10 同名冲突策略")
    d = os.path.join(root, "t10")
    mkzip(os.path.join(d, "a.zip"), [("f.txt", b"1")])
    run_extract(d)
    ex, st, logs = run_extract(d, overwrite="rename")
    check("rename：第二次生成 a (2)", os.path.isdir(os.path.join(d, "a (2)")))
    check("原目录内容未被覆盖", open(os.path.join(d, "a", "f.txt"), "rb").read() == b"1")
    d2 = os.path.join(root, "t10b")
    mkzip(os.path.join(d2, "a.zip"), [("f.txt", b"new")])
    run_extract(d2)
    ex, st, logs = run_extract(d2, overwrite="overwrite")
    check("overwrite：内容被覆盖", open(os.path.join(d2, "a", "f.txt"), "rb").read() == b"new")

    # ---------------- T11 炸弹阈值
    section("T11 压缩炸弹防护（阈值触发）")
    d = os.path.join(root, "t11")
    mkzip(os.path.join(d, "big.zip"), [("big.bin", b"\0" * (3 << 20))])
    ex, st, logs = run_extract(d, max_total_bytes=1 << 20)
    check("声明总量超限 → 整包拒绝", st.archives_failed == 1, f"fail={st.archives_failed}")
    d2 = os.path.join(root, "t11b")
    mkzip(os.path.join(d2, "big.zip"), [("big.bin", b"\0" * (3 << 20))])
    ex, st, logs = run_extract(d2, max_file_bytes=1 << 20)
    check("单文件超限 → 失败", st.archives_failed == 1, f"fail={st.archives_failed}")
    check("超限不留半截文件", not os.path.exists(os.path.join(d2, "big", "big.bin")))

    # ---------------- T12 布局
    section("T12 三种输出布局")
    src = os.path.join(root, "t12")
    mkzip(os.path.join(src, "sub", "x.zip"), [("f.txt", b"X")])
    ex, st, logs = run_extract(src, layout="beside_flat")
    check("beside_flat：铺在包旁边", os.path.isfile(os.path.join(src, "sub", "f.txt")))
    out = os.path.join(root, "t12-out")
    ex, st, logs = run_extract(src, layout="out_dir", out_dir=out)
    check("out_dir：按包名建子目录", os.path.isfile(os.path.join(out, "sub", "x", "f.txt")))
    out2 = os.path.join(root, "t12-out2")
    ex, st, logs = run_extract(src, layout="out_dir_flat", out_dir=out2)
    check("out_dir_flat：平铺到输出目录", os.path.isfile(os.path.join(out2, "sub", "f.txt")))

    # ---------------- T13 删除源包
    section("T13 解压后删除原包")
    d = os.path.join(root, "t13")
    p = os.path.join(d, "del.zip")
    mkzip(p, [("f.txt", b"d")])
    ex, st, logs = run_extract(d, delete_source=True)
    check("原包已删除", not os.path.exists(p))
    check("内容仍在", os.path.isfile(os.path.join(d, "del", "f.txt")))

    # ---------------- T14 单文件压缩流
    section("T14 单文件 gz / 无扩展名 gz")
    d = os.path.join(root, "t14")
    os.makedirs(d, exist_ok=True)
    with gzip.open(os.path.join(d, "log.txt.gz"), "wb") as f:
        f.write(b"hello gz")
    with open(os.path.join(d, "odd"), "wb") as f:
        f.write(gzip.compress(b"no ext gz"))
    ex, st, logs = run_extract(d)
    check("log.txt.gz → log.txt", os.path.isfile(os.path.join(d, "log", "log.txt")))
    check("单文件 gz 内容正确", open(os.path.join(d, "log", "log.txt"), "rb").read() == b"hello gz")
    check("无扩展名 gz 也解出", os.path.isfile(os.path.join(d, "odd_extracted", "odd_out")))

    # ---------------- T15 Windows 非法名 / 保留名
    section("T15 保留名与非法字符")
    d = os.path.join(root, "t15")
    mkzip(os.path.join(d, "n.zip"), [("CON.txt", b"c"), ("a:b.txt", b"b"), ("trail. ", b"t")])
    ex, st, logs = run_extract(d)
    got = os.listdir(os.path.join(d, "n"))
    check("保留名被改写后落盘", os.path.isfile(os.path.join(d, "n", "_CON.txt")), str(got))
    check("非法字符被替换", os.path.isfile(os.path.join(d, "n", "a_b.txt")), str(got))
    check("全部条目成功（无丢失）", st.archives_failed == 0)

    # ---------------- T16 空包 / 坏包
    section("T16 空 zip 与损坏文件")
    d = os.path.join(root, "t16")
    mkzip(os.path.join(d, "empty.zip"), [])
    mkraw(os.path.join(d, "broken.zip"), b"PK\x03\x04" + b"\x00" * 100)
    ex, st, logs = run_extract(d)
    res = {os.path.basename(r.path): r.status for r in ex.results}
    check("空 zip → ok", res.get("empty.zip") == "ok", str(res))
    check("损坏 zip → failed（不崩全局）", res.get("broken.zip") == "failed", str(res))

    # ---------------- T16b 自动输出目录（解压文件YY_MM_DD_HHMM）
    section("T16b 全部解压到同一文件夹（自动时间戳目录）")
    d = os.path.join(root, "t16b")
    mkzip(os.path.join(d, "1.zip"), [("one.txt", b"1")])
    mkzip(os.path.join(d, "2.7z"), [("two.txt", b"2")])
    import extract_core as ec
    stamp = ec.auto_out_dir_name()
    ex, st, logs = run_extract(d, layout="out_dir")         # 不给 out_dir → 自动生成
    auto = os.path.join(d, stamp)
    check(f"自动创建 {stamp}", os.path.isdir(auto), str(os.listdir(d)))
    check("两个包各自建子目录", os.path.isfile(os.path.join(auto, "1", "one.txt"))
          and os.path.isfile(os.path.join(auto, "2", "two.txt")))
    check("时间戳格式正确", len(stamp) == len("解压文件26_09_22_0926"), stamp)

    # ---------------- T16c 并行度
    section("T16c 并行解压")
    d = os.path.join(root, "t16c")
    for i in range(12):
        mkzip(os.path.join(d, f"p{i:02d}.zip"),
              [(f"f{j}.txt", b"y" * 8192) for j in range(60)])
    t0 = time.time()
    ex, st, logs = run_extract(d, workers=6)
    t_par = time.time() - t0
    check("并行 6 路 12 个包全部成功", st.archives_done == 12,
          f"done={st.archives_done} fail={st.archives_failed}")
    check("并行结果完整（720 个文件）",
          sum(len(os.listdir(os.path.join(d, f"p{i:02d}"))) for i in range(12)) == 12 * 60)
    print(f"        （并行 6 路耗时 {t_par:.2f}s，仅作记录）")
    d2 = os.path.join(root, "t16d")
    for i in range(12):
        mkzip(os.path.join(d2, f"p{i:02d}.zip"),
              [(f"f{j}.txt", b"y" * 8192) for j in range(60)])
    t0 = time.time()
    ex, st, logs = run_extract(d2, workers=1)
    t_seq = time.time() - t0
    check("串行 12 个包全部成功", st.archives_done == 12, f"done={st.archives_done}")
    print(f"        （串行耗时 {t_seq:.2f}s；加速比 {t_seq / max(t_par, 0.001):.2f}x）")

    # ---------------- T17 取消
    section("T17 取消")
    d = os.path.join(root, "t17")
    for i in range(15):
        mkzip(os.path.join(d, f"p{i:02d}.zip"),
              [(f"f{j}.txt", b"x" * 4096) for j in range(120)])
    cancel = threading.Event()
    logs: list = []

    def on_log(lv, m):
        logs.append((lv, m))
        if m.startswith("✔") and not cancel.is_set():
            cancel.set()

    opt = Options()
    ex = Extractor([d], opt, log=on_log, cancel=cancel)
    t0 = time.time()
    st = ex.run()
    el = time.time() - t0
    check("取消后能及时返回（宽松阈值，受杀毒/磁盘抖动影响）", el < 30, f"{el:.1f}s")
    check("取消后未跑完全部", st.archives_done < 15, f"done={st.archives_done}")
    check("取消有日志", any("取消" in m for _lv, m in logs))

    # ---------------- T18 单元函数
    section("T18 工具函数")
    check("sanitize 拒绝 ..", sanitize_rel("../x") is None)
    check("sanitize 拒绝绝对", sanitize_rel("/etc/passwd") is None)
    check("sanitize 拒绝盘符", sanitize_rel("C:\\Windows\\x") is None)
    check("sanitize 冒号按非法字符处理（不丢文件）", sanitize_rel("a:b.txt") == "a_b.txt",
          str(sanitize_rel("a:b.txt")))
    check("sanitize 正常路径", sanitize_rel("a/b/c.txt") == "a/b/c.txt")
    check("sanitize 反斜杠归一", sanitize_rel("a\\b.txt") == "a/b.txt")
    check("archive_stem: a.tar.gz → a", archive_stem("a.tar.gz") == "a")
    check("archive_stem: b.7z → b", archive_stem("b.7z") == "b")
    check("archive_stem: 无后缀 → 加 _extracted", archive_stem("nodot") == "nodot_extracted",
          archive_stem("nodot"))
    check("archive_stem: log.txt.gz → log", archive_stem("log.txt.gz") == "log",
          archive_stem("log.txt.gz"))
    check("human_size", human_size(1536).endswith("KB"))
    try:
        safe_join(root, "a/b")
        check("safe_join 正常", True)
    except Exception as exc:                                # noqa: BLE001
        check("safe_join 正常", False, str(exc))
    check("sniff 对普通文本返回 None", sniff(os.path.join(HERE, "selftest_core.py")) is None)

    # ---------------- T19 失败标记 / 报告 / 空目录清理
    section("T19 .failed 标记 / 处理报告 / 空目录清理")
    d = os.path.join(root, "t19")
    mkraw(os.path.join(d, "broken.zip"), b"PK\x03\x04" + b"\x00" * 100)
    mkzip(os.path.join(d, "good.zip"), [("g.txt", b"ok")])
    ex, st, logs = run_extract(d, mark_failed=True)
    check(".failed 标记生效", os.path.exists(os.path.join(d, "broken.zip.failed")))
    check("原文件已改名", not os.path.exists(os.path.join(d, "broken.zip")))
    reports = [f for f in os.listdir(d) if f.startswith("解压报告")]
    check("处理报告已写出", len(reports) == 1, str(os.listdir(d)))
    if reports:
        body = open(os.path.join(d, reports[0]), encoding="utf-8-sig").read()
        check("报告含失败条目与原因", "broken.zip" in body and "失败" in body, body[:200])
        check("报告含成功条目", "good.zip" in body)
    d2 = os.path.join(root, "t19b")
    mkzip(os.path.join(d2, "empty.zip"), [])
    ex, st, logs = run_extract(d2, clean_empty_dirs=True, report=False)
    check("空包目录被清理", not os.path.isdir(os.path.join(d2, "empty")))

    # ---------------- T20 并行度自动探测
    section("T20 并行度自动探测")
    import extract_core as ec
    check("detect_workers 中档 = 线程数×0.75（16 线程 ⇒ 12 路）", ec.detect_workers(16) == 12,
          str(ec.detect_workers(16)))
    check("三档换算：高 1.0 / 中 0.75 / 低 0.5（16 线程 ⇒ 16/12/8）",
          (ec.detect_workers("high", 16), ec.detect_workers("mid", 16), ec.detect_workers("low", 16))
          == (16, 12, 8),
          f'{ec.detect_workers("high", 16)}/{ec.detect_workers("mid", 16)}/{ec.detect_workers("low", 16)}')
    check("最低保底 1（不取到 0）", ec.detect_workers(2) == 1 and ec.detect_workers(1) == 1,
          f"{ec.detect_workers(2)}/{ec.detect_workers(1)}")
    check("大核数封顶 64", ec.detect_workers(128) == 64, str(ec.detect_workers(128)))
    check("options.workers=1 时确实串行", ec.Extractor(["."], ec.Options(workers=1))._workers() == 1)

    # ---------------- 汇总
    print("\n" + "=" * 60)
    print(f"自测结果：PASS {PASS} / FAIL {FAIL}")
    if FAILS:
        print("失败项：")
        for f in FAILS:
            print(f"  - {f}")
    print("=" * 60)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
