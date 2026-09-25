# -*- coding: utf-8 -*-
"""extract_core —— 递归解压引擎（与 GUI 解耦，可独立测试）

v1.1.0：按三路对抗性审查（路径逃逸 / 解析炸弹与并发 / 副作用统计）的发现重构。

★ 两处架构改造（一次解决了最严重的一批问题）
  A. **按包账本**：每个包记录自己写了哪些文件/建了哪些目录；
     回滚只删自己的、统计只算自己的 —— 不再对整个目标目录拍快照做差集
     （旧实现会在并发共享目录时删掉别的线程刚写好的文件，且统计虚报数倍）。
  B. **沙箱通道**：7z 与外部工具（bsdtar：rar/iso/cab/AES-zip）先解到本包私有暂存目录，
     再逐个经 `sanitize_rel → safe_join(realpath 校验) → _prepare_target(覆盖策略)` 搬进目标，
     搬移用 `os.replace` 原子落盘。⇒ 覆盖策略对**所有格式**生效、外部工具不再能写到目标之外、
     取消与炸弹检查有响应点、失败不留半成品。

其余设计：魔数识别格式（含 tar header checksum 校验）、BFS 分层递归 + 同层并行、
按需密码（先无密码试，需要才用密码重试）、`os.walk` 不跟随 junction、dry-run 零落盘。
"""
from __future__ import annotations

import bz2
import gzip
import lzma
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import sys
import threading
import time
import zipfile
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

APP_NAME = "递归解压"
VERSION = "1.5.7"
COPY_BUF = 1024 * 1024
SANDBOX_PREFIX = ".rc-sbx-"
# 🩸 沙箱目录里的"这是我建的"标记文件。旧清扫逻辑**只按名字**判（严格匹配
# `.rc-sbx-<pid>-<8位>` 且 pid 已死就 rmtree），于是用户自己的同名目录会被整棵删掉
# （不可逆）；`beside_flat` 布局下沙箱基目录还是**用户没选的那个父目录**。
# 现在只有带本标记的目录才敢删 —— 标记不存在就一个字节都不碰。
SANDBOX_OWNER = ".rc-sbx-owner"

# 进度回调节流间隔（秒）：解压主循环检查点很密，不节流会把 GUI 消息队列打爆
# 进度回调节流间隔（秒）：解压主循环检查点很密，不节流会把 GUI 消息队列打爆。
# 🩸 「解压大量文件偶发未响应」：0.1s（10 次/秒）在十几万文件的规模下仍然偏密 ——
# 每次快照 GUI 都要刷新总条 + 16 个槽位条。人眼 4 次/秒完全够，降到 0.25s。
PROGRESS_THROTTLE = 0.25
# 沙箱体积轮询间隔（秒）：rar/iso/cab 的"已解出字节"只能靠扫沙箱得到
SBX_POLL_INTERVAL = 0.5

# 只清**严格符合我们自己命名格式**的残留（旧实现只判前缀，
# 会把用户的 `.rc-sbx-notes` / `.rc-sbx-12345670-old` 连内容一起删掉）
_SANDBOX_NAME_RE = re.compile(r"\.rc-sbx-(?:7zsfx-)?(\d+)-[0-9a-z_]{8}(?:\.7z)?")
PART_SUFFIX = ".rc-part"
# 🩸 「解压大量文件偶发未响应」：沙箱体积轮询的**单次扫描时间预算**（秒）与**最大间隔**。
# 文件多时不让全量 scandir 长时间占着 GIL（Tk 主线程会被饿死 ⇒ 窗口变「未响应」）。
SBX_SCAN_BUDGET = 0.25
SBX_POLL_MAX = 4.0
# 🩸 覆盖用户已有文件前，先把原文件改名成这个后缀的**同目录备份**；
# 包成功结束时删掉、失败回滚时还原（避免"回滚反而删掉用户原文件"）。
PART_BACKUP = ".rc-bak-"
# 🩸 运行期压缩比闸的起算体积（tar / 裸流拿不到整包声明值时用）。
RATIO_RUNTIME_FLOOR = 64 << 20

DEFAULT_MAX_DEPTH = 5
DEFAULT_MAX_FILE_BYTES = 8 << 30
DEFAULT_MAX_TOTAL_BYTES = 512 << 30
DEFAULT_MAX_ENTRIES = 200_000
DEFAULT_BOMB_RATIO = 5000.0
BOMB_MIN_BYTES = 512 << 20

_ILLEGAL_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_TAR_SUFFIXES = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst",
                 ".tgz", ".tbz2", ".tbz", ".txz")

# Office / 其它"内部就是 zip"的文档格式：--delete 时不许当压缩包删掉
_DOC_EXTS = {
    ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".vsdx", ".odt", ".ods",
    ".odp", ".odg", ".epub", ".jar", ".apk", ".ipa", ".xpi", ".crx", ".nupkg",
    ".whl", ".one", ".vsz", ".sb3", ".sketch", ".zmx",
}


class ExtractError(Exception):
    """解压过程中的可预期错误（记日志后继续下一个包）。"""


class UnsafePath(ExtractError):
    """成员路径逃逸，拒绝该条目。"""


class BombDetected(ExtractError):
    """疑似压缩炸弹，中止该包。"""


class Cancelled(ExtractError):
    """用户取消。"""


class NeedPassword(ExtractError):
    """加密压缩包，无密码。"""


class UseExternal(ExtractError):
    """内置实现干不了（如 WinZip AES 加密 zip），转交外部工具。"""


@dataclass
class Options:
    layout: str = "beside_folder"     # beside_folder | beside_flat | out_dir | out_dir_flat
    out_dir: str = ""
    overwrite: str = "rename"         # skip | overwrite | rename
    max_depth: int = DEFAULT_MAX_DEPTH
    delete_source: bool = False
    password: str = ""
    workers: int = 0                  # >0 时直接用它；0 = 按 worker_level 自动
    worker_level: str = "mid"         # high / mid / low ⇒ 线程数 × 1.0 / 0.75 / 0.5
    mark_failed: bool = False
    clean_empty_dirs: bool = False
    report: bool = True
    dry_run: bool = False
    smart_extract: bool = True       # Bandizip 式"智能解压"：剥掉与包同名的单层顶层文件夹
    scan_exe: bool = True            # 尝试解开 .exe 外壳（自解压包）里的压缩本体（只读，绝不运行）
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_entries: int = DEFAULT_MAX_ENTRIES
    bomb_ratio: float = DEFAULT_BOMB_RATIO
    bomb_min_bytes: int = BOMB_MIN_BYTES   # 压缩比判据的起算体积（低于它不套 ratio，防小文件误报）


@dataclass
class ArchiveResult:
    path: str
    kind: str = ""
    dest: str = ""
    status: str = "pending"           # ok | failed | skipped
    files: int = 0
    bytes: int = 0
    note: str = ""
    depth: int = 0
    skipped_members: int = 0          # 包内被跳过的条目数（有它就不该删源包）


@dataclass
class Stats:
    archives_found: int = 0
    archives_done: int = 0
    archives_failed: int = 0
    archives_skipped: int = 0
    files_written: int = 0
    bytes_written: int = 0
    deleted: int = 0
    empty_dirs_removed: int = 0
    started_at: float = 0.0
    elapsed: float = 0.0

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["elapsed"] = round(self.elapsed, 2)
        return d


@dataclass
class Job:
    path: str
    depth: int
    src_root: str


class _Ledger:
    """单个压缩包的产物账本（改造 A）。

    只记"这个包自己写出去的东西"，回滚与统计都以此为准 ——
    绝不再用"目标目录前后快照差集"，那样会在并发共享目录时误删邻居的成果。
    """

    __slots__ = ("paths", "bytes", "dirs", "replaced")

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.bytes: int = 0
        self.dirs: list[str] = []
        # [(最终路径, 用户原文件的备份路径)] —— 覆盖（overwrite）档专用
        self.replaced: list[tuple[str, str]] = []

    def add_replaced(self, final: str, backup: str) -> None:
        self.replaced.append((final, backup))

    def drop_backups(self) -> None:
        """包**成功**处理完时调用：新内容已就位，覆盖前留的用户原文件备份可以删了。"""
        for _final, bak in self.replaced:
            try:
                os.remove(bak)
            except OSError:
                pass
        self.replaced.clear()

    def add_file(self, path: str, size: int) -> None:
        self.paths.append(path)
        self.bytes += size

    def add_dir(self, path: str) -> None:
        self.dirs.append(path)

    @property
    def files(self) -> int:
        return len(self.paths)


# ---------------------------------------------------------------- 格式识别

_MAGIC = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07\x01\x00", "rar5"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"MSCF", "cab"),
)


_PE_SCAN_BYTES = 32 << 20            # 扫 PE 外壳内嵌段时最多读前 32 MB

# PE（自解压 exe）内部嵌着的压缩数据签名 —— 命中即说明"这个 exe 只是个外壳"
_EMBED_MAGIC = (
    (b"Rar!\x1a\x07\x01\x00", "rar5"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"PK\x03\x04", "zip"),
)


def _tar_header_ok(head: bytes) -> bool:
    """校验 tar 头（512 字节）。

    只看偏移 257 的 `ustar` 会把**恰好撞上这 5 个字节的普通二进制**误判成 tar
    （被误判后会报失败，开了 mark_failed 还会把用户正常文件改名成 .failed）。
    这里补上权威判据：header 的八进制校验和必须对得上（checksum 字段按 8 个空格算）。
    """
    if len(head) < 512 or head[257:262] != b"ustar":
        return False
    raw = head[148:156].split(b"\0")[0].strip()
    if not raw:
        return False
    try:
        declared = int(raw, 8)
    except ValueError:
        return False
    calc = sum(head[:148]) + 32 * 8 + sum(head[156:512])
    return declared == calc


def _usable_exe(path: str, min_bytes: int = 64 * 1024) -> bool:
    """这个路径上是不是一个**真能跑**的 exe（存在 + 大小过关 + PE 头 `MZ`）。

    只判 `os.path.isfile()` 会把 0 字节/坏文件当成可用 ⇒ 启动后
    `[WinError 193]` 直接失败、**不会回落到还能用的 bsdtar**。
    """
    try:
        if not os.path.isfile(path):
            return False
        if os.path.getsize(path) < min_bytes:
            return False
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def is_pe_shell(path: str) -> bool:
    """这个文件是不是 PE（.exe/.dll）外壳 —— 用来保证 --delete 不会删掉自解压 exe。"""
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except OSError:
        return False


def _sniff_pe(path: str) -> tuple[Optional[str], int]:
    """在 PE（.exe/.dll）外壳里找内嵌压缩段；返回 (kind, 偏移)。找不到返回 (None, 0)。

    ★ **只把 exe 当数据读，绝不执行它**（不 CreateProcess、不 ShellExecute、不 Shell）。
    RAR / 7z 的签名有 8 / 6 字节，撞车概率可忽略；`PK\\x03\\x04` 只有 4 字节，
    所以 zip 还要求**真的能被 zipfile 打开**才算数（Python 的 zipfile 原生支持 SFX 前置数据）。
    """
    try:
        with open(path, "rb") as f:
            blob = f.read(_PE_SCAN_BYTES)
    except OSError:
        return (None, 0)
    if not blob.startswith(b"MZ"):
        return (None, 0)
    # 旧实现只取"最早命中"的签名，一旦它是个假 zip 就**整体放弃**
    # ⇒ 真 SFX 被静默漏判（在 7za.exe / MRT.exe / imagehelp.dll 上实测到）；
    # 现在**收集所有候选、按偏移升序逐个验证**，第一个通过的就是它。
    cands: list[tuple[int, str]] = []
    for magic, kind in _EMBED_MAGIC:
        start = 2
        while len(cands) < 64:                              # 上限：防病态 PE 里候选刷屏
            i = blob.find(magic, start)
            if i <= 0:
                break
            cands.append((i, kind))
            start = i + 1
    for off, kind in sorted(cands):
        # ★ **每种格式都要真伪校验**（只靠"签名长度"不够 —— `7za.exe` / `MRT.exe`
        #   这类含签名字符串的普通 exe 立刻会变成误报）。下面四条判据都对真样本实测过：
        #   rar4: 签名 7 字节后 = 2 字节 CRC + `0x73`(MAIN_HEAD)
        #   rar5: 签名 8 字节后 = 4 字节 CRC + header size + header type（1=MAIN / 4=HEAD_CRYPT）
        #   7z  : 签名 6 字节后 = 版本 `00 04`
        #   zip : 必须真的能被 zipfile 打开
        if kind == "rar" and blob[off + 9:off + 10] == b"\x73":
            return (kind, off)
        # 实测：签名(8) + CRC(4) + size(vint) + type；MAIN_HEAD 的 size 很小 ⇒ type 在 +13
        # （size 占 2 字节时在 +14，两种都收）
        if kind == "rar5" and (blob[off + 13:off + 14] in (b"\x01", b"\x04")
                               or blob[off + 14:off + 15] in (b"\x01", b"\x04")):
            return (kind, off)
        if kind == "7z" and blob[off + 6:off + 8] == b"\x00\x04":
            return (kind, off)
        if kind == "zip":
            try:
                with zipfile.ZipFile(path) as zf:
                    zf.infolist()
                return (kind, off)
            except Exception:                               # noqa: BLE001
                continue                                    # 假 zip ⇒ 继续看后面还有没有真 SFX
    return (None, 0)


def sniff_ex(path: str, allow_pe: bool = True) -> tuple[Optional[str], int]:
    """识别格式；第二项 > 0 表示"这是 PE 外壳，压缩数据从该偏移开始"。

    `allow_pe=False` = 不做 PE 内嵌扫描（用户关掉「解开 .exe 外壳」开关时走这条）。
    """
    try:
        with open(path, "rb") as f:
            head = f.read(512)
            if not head:
                return (None, 0)
            for magic, kind in _MAGIC:
                if head.startswith(magic):
                    return (kind, 0)
            if _tar_header_ok(head):
                return ("tar", 0)
            if allow_pe and head.startswith(b"MZ"):
                return _sniff_pe(path)
            if len(head) < 512:
                return (None, 0)
            f.seek(0x8001)
            iso = f.read(5)
    except OSError:
        return (None, 0)
    return ("iso", 0) if iso == b"CD001" else (None, 0)


def sniff(path: str) -> Optional[str]:
    """按文件头识别压缩格式（含 .exe 外壳）；不是压缩包则返回 None。"""
    return sniff_ex(path)[0]


def _cp437_mojibake_fix(name: str) -> Optional[str]:
    """有些工具会给 cp437 乱码名打上 UTF-8 标记；四条严判据都满足才还原。"""
    if re.search(r"[\u4e00-\u9fff]", name):
        return None
    try:
        raw = name.encode("cp437")
    except UnicodeEncodeError:
        return None
    try:
        cand = raw.decode("gbk")
    except UnicodeDecodeError:
        return None
    return cand if re.search(r"[\u4e00-\u9fff]", cand) else None


def fix_zip_name(info: zipfile.ZipInfo) -> str:
    """还原被错误编码的 zip 文件名。"""
    name = info.filename
    if info.flag_bits & 0x0800:
        return _cp437_mojibake_fix(name) or name
    try:
        raw = name.encode("cp437")
    except UnicodeEncodeError:
        return name
    for enc in ("gbk", "utf-8"):
        try:
            cand = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if cand != name:
            return cand
    return name


def sanitize_rel(name: str) -> Optional[str]:
    """把压缩包内的成员名规范成安全的相对路径（`/` 分隔）；危险则返回 None。

    注意：`a:b.txt` 这类"驱动器相对/ADS 写法"**不整条拒绝**，冒号会按非法字符替换成 `_`
    （否则会静默丢文件）；只有 `C:/...`、`/x`、`../x` 这类才是真危险。
    """
    if not name:
        return None
    s = name.replace("\\", "/")
    if s.startswith("/"):
        return None
    if re.match(r"^[A-Za-z]:/", s):
        return None
    parts = []
    for part in s.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        part = _ILLEGAL_CHARS.sub("_", part)
        part = part.rstrip(" .")
        if not part:
            continue
        if part.split(".")[0].upper() in _RESERVED_NAMES:
            part = "_" + part
        parts.append(part)
    return "/".join(parts) if parts else None


def _same_rel(name: str) -> Optional[str]:
    """要求成员名**原样安全**（规范化后不变）才返回它，否则 None。

    教训：旧代码 `[n for n in names if sanitize_rel(n)]` 把 sanitize 只当布尔用、
    丢掉了返回值，结果传给 py7zr 的还是原名 ⇒ `ads.txt:evil` 直接建出 NTFS 隐藏流。
    """
    rel = sanitize_rel(name)
    if rel is None:
        return None
    return name if rel == name.replace("\\", "/") else None


_LONG_PREFIX = "\\\\?\\"
_UNC_PREFIX = "\\\\?\\UNC\\"


def _real_norm(path: str) -> str:
    """`realpath` + **规范化**（剥掉 Windows 长路径前缀）后 `normcase`。

    🩸 v1.4.2 修的真缺陷：`os.path.realpath()` 在**路径不存在**时**偶发**返回带 `\\\\?\\`
    前缀的形式 —— 实测同一进程里 `realpath(out)` 不带前缀、`realpath(out\\d1)` 却带前缀
    （"目录尚未创建的那些条目"首当其冲）。直接拿两者 `startswith` 比较，就会把**合法路径
    误判成路径逃逸** ⇒ 整包失败并回滚：默认的"多包并行解到同一目录"场景实测 **20%~45%** 中招。
    修法 = 比较前统一剥前缀 + normcase（所有 realpath 比较点都用它，别再自己拼）。
    """
    p = os.path.realpath(path)
    if p.startswith(_UNC_PREFIX):
        p = "\\\\" + p[len(_UNC_PREFIX):]        # \\?\UNC\srv\share → \\srv\share
    elif p.startswith(_LONG_PREFIX):
        p = p[len(_LONG_PREFIX):]                # \\?\D:\x → D:\x
    return os.path.normcase(p)


def safe_join(root: str, rel: str) -> str:
    """把相对路径拼到 root 下，并校验不会逃逸（realpath 级校验）。"""
    root_abs = os.path.abspath(root)
    # 🩸 先挡掉字符串层面就不该出现的 `..` / 绝对路径 —— 旧实现只看
    # `dirname(cand)` 的 realpath，`rel=".."` 拼出 `root\..`、dirname 归一化后恰好等于 root
    # ⇒ 判据被绕过（当前调用方都先过 `sanitize_rel` 所以不可达，这里补上防将来漏掉）。
    if os.path.isabs(rel) or os.path.splitdrive(rel)[0]:
        raise UnsafePath(f"路径逃逸被拒绝: {rel}")
    if any(p == ".." for p in rel.replace("\\", "/").split("/")):
        raise UnsafePath(f"路径逃逸被拒绝: {rel}")
    cand = os.path.join(root_abs, *rel.split("/"))
    real_root = _real_norm(root_abs)
    real_parent = _real_norm(os.path.dirname(cand))
    if real_parent != real_root and not real_parent.startswith(real_root + os.sep):
        raise UnsafePath(f"路径逃逸被拒绝: {rel}")
    return cand


def _is_reparse(path: str) -> bool:
    """判断是否符号链接 / junction。

    Windows 上 `os.path.islink()` 对 **junction 返回 False**，而 `os.walk` 会跟着 junction
    跑进外部目录，所以这里补上 reparse tag 判据。
    """
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return bool(getattr(st, "st_reparse_tag", 0))


def _rmtree_force(path: str) -> bool:
    """尽力删掉整棵目录树：**先摘只读属性再删**，删不掉也如实返回 False。

    🩸 Python 的 `shutil.rmtree` 在 Windows 上遇到**只读目录**会抛
    `PermissionError [WinError 5]`；旧代码一律 `ignore_errors=True` ⇒ 失败被静默吞掉，
    沙箱目录在用户源目录里**只增不减**（ISO 解出来的 D1/D2 带 ReadOnly，实测每次留一个，
    连下次启动的 `_sweep_sandboxes` 兜底也删不掉）。这里改成：
    ① 先按标准 `onerror` 回调给失败项补写权限再重试；② 整体仍失败时递归清只读位再试一轮；
    ③ 返回真实结果，让调用方能记一条 warn 而不是假装清理过。
    """
    if not os.path.exists(path):
        return True

    def _onerror(func, p, _exc):                        # noqa: ANN001
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass

    for _ in range(3):
        try:
            shutil.rmtree(path, onerror=_onerror)
        except OSError:
            pass
        if not os.path.exists(path):
            return True
        for root, dirs, files in os.walk(path):
            for n in list(dirs) + list(files):
                try:
                    os.chmod(os.path.join(root, n), stat.S_IWRITE | stat.S_IREAD)
                except OSError:
                    pass
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass
    return not os.path.exists(path)


def _sbx_entries(sbx: str) -> list[str]:
    """沙箱里**除标记文件之外**的条目（判"有没有解出东西"要用它，别把标记算成产物）。"""
    try:
        return [n for n in os.listdir(sbx) if n != SANDBOX_OWNER]
    except OSError:
        return []


_JOB_HANDLE: Optional[int] = None


def _job_handle() -> Optional[int]:
    """取（或创建）本进程的 Job Object，带 `KILL_ON_JOB_CLOSE`。

    🩸 实测发现：点了「停止」界面显示已停止，**后台 11 个 UnRAR 还在解**。
    只靠"worker 走到检查点再 terminate"不够 —— 程序被强杀/崩溃/异常退出时子进程会**变孤儿**，
    一直占 CPU 与磁盘。绑进 Job 之后：**本进程一死，里面所有子进程一起死**。
    """
    global _JOB_HANDLE
    if os.name != "nt" or _JOB_HANDLE is not None:
        return _JOB_HANDLE or None
    try:
        import ctypes
        from ctypes import wintypes
        k = ctypes.windll.kernel32
        h = k.CreateJobObjectW(None, None)
        if not h:
            _JOB_HANDLE = 0
            return None

        class _IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in
                        ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                         "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class _BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class _EXT(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", _BASIC), ("IoInfo", _IO),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        info = _EXT()
        info.BasicLimitInformation.LimitFlags = 0x2000      # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        k.SetInformationJobObject(h, 9, ctypes.byref(info), ctypes.sizeof(info))
        _JOB_HANDLE = h
        return h
    except Exception:                                       # noqa: BLE001
        _JOB_HANDLE = 0
        return None


def _assign_to_job(proc) -> None:
    """把刚起的子进程绑进 Job（拿不到句柄就算了，不影响功能）。"""
    h = _job_handle()
    if not h:
        return
    try:
        import ctypes
        ctypes.windll.kernel32.AssignProcessToJobObject(h, int(proc._handle))
    except Exception:                                       # noqa: BLE001
        pass


def _suspend_proc(proc) -> bool:
    """挂起外部解压进程（Windows `NtSuspendProcess`）；返回是否真的挂上了。

    🩸 `_wait_if_paused()` 只挂住 **Python 线程**，而 UnRAR / bsdtar 是独立进程，
    会**继续写盘**（实测 cab 暂停后 3.36 秒沙箱仍涨 1125 MiB）⇒ 对 rar/iso/cab 来说暂停等于没停。
    挂起只影响那个子进程；取消/超时时 `terminate()` 对挂起的进程照样有效，不会挂死。
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.OpenProcess(0x0800, False, proc.pid)          # PROCESS_SUSPEND_RESUME
        if not h:
            return False
        try:
            ctypes.windll.ntdll.NtSuspendProcess(h)
            return True
        finally:
            k.CloseHandle(h)
    except Exception:                                       # noqa: BLE001
        return False


def _resume_proc(proc) -> None:
    """恢复被 `_suspend_proc` 挂起的外部进程。"""
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.OpenProcess(0x0800, False, proc.pid)
        if not h:
            return
        try:
            ctypes.windll.ntdll.NtResumeProcess(h)
        finally:
            k.CloseHandle(h)
    except Exception:                                       # noqa: BLE001
        pass


def archive_stem(path: str) -> str:
    """取"去掉压缩后缀"的名字：a.tar.gz → a，b.7z → b。"""
    name = os.path.basename(path)
    lower = name.lower()
    for suffix in _TAR_SUFFIXES:
        if lower.endswith(suffix):
            return name[: -len(suffix)]
    stem, ext = os.path.splitext(name)
    if not ext:
        return name + "_extracted"
    if ext.lower() in (".gz", ".bz2", ".xz", ".zst", ".zstd"):
        stem2, _ext2 = os.path.splitext(stem)
        return stem2 or stem
    return stem if stem else name


def auto_out_dir_name(now: Optional[time.struct_time] = None) -> str:
    """「全部解压到同一文件夹」时自动生成的目录名：解压文件26_09_22_0926"""
    return "解压文件" + time.strftime("%y_%m_%d_%H%M", now or time.localtime())


# 并行优先级 ⇒ 倍率
WORKER_RATIO = {"high": 1.0, "mid": 0.75, "low": 0.5}
WORKER_LEVEL_CN = {"high": "高", "mid": "中", "low": "低"}


def detect_workers(level: str | int = "mid", cpu_count: Optional[int] = None) -> int:
    """按**优先级档位**算并行度：高 = 线程数×1.0、中 = ×0.75、低 = ×0.5。

    **向下取整、最低 1**（规格明确：按**超线程后的逻辑线程数**算，向下取整、最低 1、别取到 0）
    ⇒ 用 `int()` 截断、`max(1, …)` 保底。
    这里的 `os.cpu_count()` 返回的正是**逻辑处理器数**（本机 16 = 8 物理核开了超线程）。

    背景：解压是"每个包一个 worker" ⇒ 同层包越多越能吃到多线程；**单个大包永远单线程**
    （LZMA/deflate 不支持并行解码）。内存代价可忽略（实测 8 路并行工作集 21→53 MiB），
    真正的瓶颈是磁盘 —— 机械盘建议选"低"。
    """
    if isinstance(level, int):                 # 兼容旧签名 detect_workers(16)
        level, cpu_count = "mid", level
    n = cpu_count or os.cpu_count() or 4
    ratio = WORKER_RATIO.get((level or "mid").lower(), 0.5)
    return max(1, min(64, int(n * ratio)))


def _pid_alive(pid: int) -> bool:
    """判断进程是否还活着（用来决定能不能清掉它留下的沙箱目录）。"""
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            h = k.OpenProcess(0x1000, False, pid)           # QUERY_LIMITED_INFORMATION
            if not h:
                return False
            try:
                code = ctypes.c_ulong()
                if k.GetExitCodeProcess(h, ctypes.byref(code)):
                    return code.value == 259                # STILL_ACTIVE
                return True                                 # 不确定就当活着，宁可不删
            finally:
                k.CloseHandle(h)
        except Exception:                                   # noqa: BLE001
            return True
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
    except Exception:                                       # noqa: BLE001
        return True


def is_document_like(path: str) -> bool:
    """Office / epub / jar 这类"内部是 zip"的文档（--delete 时要放过）。"""
    return os.path.splitext(path)[1].lower() in _DOC_EXTS


_REASON_KEYS = ("error", "incorrect", "cannot", "corrupt", "checksum", "missing",
                "unsupported", "password", "encrypted", "jlink", "skipping", "not found")


def _pick_reason(lines: list[str]) -> str:
    """从工具输出里挑一句"像原因"的话。

    旧实现取 `lines[-1]`，缺分卷那种场景最后一行的 "checksum error" 会把真原因顶掉。
    """
    for ln in reversed(lines):
        low = ln.lower()
        if any(k in low for k in _REASON_KEYS):
            return ln.strip()
    return lines[-1].strip() if lines else ""


def human_size(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} TB"


# ---------------------------------------------------------------- 引擎

class Extractor:
    """递归解压引擎。

    src_dirs / options / log(level,msg) / progress(snapshot) / cancel(Event) / pause(Event)

    `cancel` = 取消（不可逆，按"账本回滚半成品"语义）；
    `pause`  = 暂停（可恢复：置位后引擎在下一个检查点原地等待，清除即继续）。
    """

    def __init__(
        self,
        src_dirs: Iterable[str],
        options: Optional[Options] = None,
        log: Optional[Callable[[str, str], None]] = None,
        progress: Optional[Callable[[dict], None]] = None,
        cancel: Optional[threading.Event] = None,
        pause: Optional[threading.Event] = None,
        force_stop: Optional[threading.Event] = None,
    ) -> None:
        self.src_dirs = [os.path.abspath(d) for d in src_dirs]
        self.opt = options or Options()
        self._log = log or (lambda lv, msg: None)
        self._progress = progress or (lambda snap: None)
        self.cancel = cancel or threading.Event()
        self.pause = pause or threading.Event()
        # 「强制停」：置位时取消**不回滚**已解出的内容（只清临时文件）——
        # 取舍：不回滚，直接 kill + 删临时文件夹即可，下次重新解压就行。
        self.force_stop = force_stop or threading.Event()
        self._tool_procs: list = []        # 本程序起过的外部解压工具（点"停止"时直接杀）
        # 🩸 **被我们主动杀过**的工具 pid。Windows 上 `Popen.terminate()` 的
        # 退出码恒为 1，与 UnRAR 的"部分成功（rc=1）"语义完全撞车 ⇒ 被强杀的那次会被记成
        # 成功（还可能与 `--delete` 联立删源包）。返回前查这张表，一律抛 Cancelled。
        self._killed_pids: set = set()
        self.stats = Stats()
        self.results: list[ArchiveResult] = []
        self._seen: set[str] = set()
        self._lock = threading.Lock()
        self._name_lock = threading.Lock()
        self._claimed: set[str] = set()
        self._auto_out: dict[str, str] = {}
        self._made_auto: list[str] = []
        self._all_dirs: list[str] = []
        self._known_dirs: set[str] = set()
        self._scratch: dict[str, list[str]] = {}   # 按**包**隔离的临时文件（7z-SFX 裁切段等）
        self._source_paths: set[str] = set()   # 本次待处理的源包（不许被解压产物覆盖）
        # ---- v1.4.0 进度 / 暂停
        self._tls = threading.local()      # 每个工作线程"当前正在解的包 key"（进度上报用）
        self._active: dict[str, dict] = {}  # 并行中每个包的进度（UI 显示"本包"进度）
        self._pkg_seq = 0
        self._last_emit = 0.0
        self._paused_logged = False
        self._rate_win: deque[tuple[float, int]] = deque(maxlen=32)
        self._rate_key = ""
        # "实时已解出"的单调保护：包刚完成、stats 还没记账的那一瞬，和值会短暂回落
        self._live_bytes_max = 0
        self._live_files_max = 0

    # -------------------------------------------------- 进度 / 暂停（v1.4.0）

    def _begin_pkg(self, key: str) -> None:
        """登记"这个包开始处理了"，并把它记进本线程的当前包（进度上报用）。"""
        self._tls.pkg = key
        try:
            self._tls.pkg_size = os.path.getsize(key)     # 运行期压缩比闸要用
        except OSError:
            self._tls.pkg_size = 0
        with self._lock:
            self._pkg_seq += 1
            self._active[key] = {"name": os.path.basename(key), "total": 0,
                                 "done": 0, "file": "", "file_total": 0, "file_done": 0,
                                 "file_pct": -1.0, "seq": self._pkg_seq, "note": "", "files": 0,
                                 # "下一个文件"先挂起，等真的写出第一个 chunk 再顶上 ——
                                 # 否则小文件（照片包那种）会让第二条进度条在 0%↔100% 之间狂闪
                                 "pending": None}

    def _end_pkg(self, key: str, discarded: bool = False) -> None:
        """注销本包；`discarded=True` 表示它的产物已经回滚 ⇒ 从"实时已解出"里扣回去。

        🩸 `_live_*_max` 是终身单调的，包失败回滚后状态栏会一直虚报
        "已解出 93.8 MiB / 1501 个文件"，而磁盘上其实一个字节都没留下。
        """
        with self._lock:
            d = self._active.pop(key, None)
            if d is not None and discarded:
                self._live_bytes_max = max(self.stats.bytes_written,
                                           self._live_bytes_max - int(d["done"]))
                self._live_files_max = max(self.stats.files_written,
                                           self._live_files_max - int(d["files"]))
        if getattr(self._tls, "pkg", "") == key:
            self._tls.pkg = ""

    def _file_begin(self, name: str, size: Optional[int] = None,
                    pct: Optional[float] = None, key: str = "", defer: bool = False) -> None:
        """开始解包内某个文件 ⇒ 重置"单文件进度"（Bandizip 式的第二条进度条）。

        `size` 未知（裸压缩流 / 外部工具）时给 0 ⇒ UI 退回用本包进度顶上；
        `pct` 用于能从工具输出直接读到百分比的格式（UnRAR 会打 `Extracting x  45%`）。

        `defer=True`（zip/tar 这类逐文件流式写的通路）：**先挂起**，等第一个 chunk 真写下去
        （`_file_advance`）才切换显示 —— 否则几毫秒一个的小文件会让进度条不停闪回 0%。
        """
        k = key or getattr(self._tls, "pkg", "")
        if not k:
            return
        info = {"name": os.path.basename(name) if name else "", "total": int(size) if size else 0,
                "pct": float(pct) if pct is not None else -1.0}
        with self._lock:
            d = self._active.get(k)
            if d is None:
                return
            if defer:
                d["pending"] = info
            else:
                d["pending"] = None
                d["file"] = info["name"]
                d["file_total"] = info["total"]
                d["file_done"] = 0
                d["file_pct"] = info["pct"]
        self._emit()                     # 锁外推送（_emit 自带节流）

    def _pkg_file_add(self, key: str = "") -> None:
        """本包又写出一个文件（供状态栏的"实时已解出文件数"）。"""
        k = key or getattr(self._tls, "pkg", "")
        if not k:
            return
        with self._lock:
            d = self._active.get(k)
            if d is not None:
                d["files"] += 1

    def _file_clear(self, key: str = "") -> None:
        """本包进入"无单文件粒度"的阶段（如沙箱搬移）⇒ 清掉单文件进度。"""
        self._file_begin("", None, None, key=key)

    def _file_advance(self, n: int, key: str = "") -> None:
        k = key or getattr(self._tls, "pkg", "")
        if not k or not n:
            return
        with self._lock:
            d = self._active.get(k)
            if d is None:
                return
            pend = d.get("pending")
            if pend:                                  # 第一个 chunk 落地 ⇒ 这时才切显示
                d["file"] = pend["name"]
                d["file_total"] = pend["total"]
                d["file_pct"] = pend["pct"]
                d["file_done"] = 0
                d["pending"] = None
            d["file_done"] += int(n)

    def _pkg_total(self, total: int, key: str = "") -> None:
        """设置"本包声明解压总量"（字节）。0 = 无法预知 ⇒ UI 走不确定态。"""
        k = key or getattr(self._tls, "pkg", "")
        if not k or total <= 0:
            return
        with self._lock:
            d = self._active.get(k)
            if d is not None:
                d["total"] = int(total)
        self._emit()                         # 锁外推送（_emit 自带节流）

    def _pkg_note(self, note: str, key: str = "") -> None:
        """给"本包"附一句说明（如"分 3 批提取"），UI 会显示。"""
        k = key or getattr(self._tls, "pkg", "")
        if not k:
            return
        with self._lock:
            d = self._active.get(k)
            if d is not None:
                d["note"] = note
        self._emit()                         # 锁外推送（_emit 自带节流）

    def _pkg_advance(self, *, counter_bytes: Optional[int] = None,
                     sbx_bytes: Optional[int] = None,
                     cur_file: Optional[str] = None, key: str = "") -> None:
        """推进"本包已完成字节"。**单调不减**（取 max）：沙箱阶段用沙箱体积、
        搬移阶段用已写出字节，两个量纲在阶段交界处会重叠，取 max 才不会让进度条倒退。"""
        k = key or getattr(self._tls, "pkg", "")
        if not k:
            return
        with self._lock:
            d = self._active.get(k)
            if d is None:
                return
            if counter_bytes is not None and counter_bytes > d["done"]:
                d["done"] = int(counter_bytes)
            if sbx_bytes is not None and sbx_bytes > d["done"]:
                d["done"] = int(sbx_bytes)
            if cur_file:
                d["file"] = os.path.basename(cur_file)
        # ⚠️ 必须在这里推送：解压途中没有别的 emit 点，否则 GUI 只在"每个包结束时"跳一格
        self._emit()                         # 锁外调用（_emit 自带 100ms 节流）

    def _wait_if_paused(self) -> bool:
        """暂停闸门：已请求暂停就原地等待（可被"取消"立刻打断）。

        返回 True 表示**已取消** —— 调用方按自己原有的取消语义收手（break 或抛 Cancelled）。
        ⚠️ 每个"取消检查点"都必须换成它，否则暂停时那一路会继续跑（表现为"点了暂停还在写"）。
        """
        if self.pause.is_set():
            if not self._paused_logged:
                self._paused_logged = True
                self._log("info", "解压已暂停。当前文件写入完成后停止，点击「继续」可恢复。")
                self._emit(force=True)
            while self.pause.is_set() and not self.cancel.is_set():
                time.sleep(0.05)
            if self._paused_logged:
                self._paused_logged = False
                if not self.cancel.is_set():
                    self._log("info", "解压已恢复。")
                # 速率窗口不能跨暂停 —— 否则恢复后第一帧会拿"暂停前后的字节差
                # 除以墙钟时间"，算出 2.8 MiB/s（真值 58.5）这种假速度、ETA 也随之乱跳。
                self._rate_win.clear()
                self._rate_key = ""
                self._emit(force=True)
        return self.cancel.is_set()

    @staticmethod
    def _dir_size(root: str, budget: float = 0.0) -> int:
        """统计目录内文件总字节（**不跟随 reparse 点**，与 _adopt 的剪枝判据一致）。

        🩸 「解压大量文件偶发未响应」（实测的界面假死）元凶之一：
        沙箱里有几万个文件时，**单次全量 scandir 要 1~3 秒**，而 8 路并行各自在轮询
        （`_tick_sbx` 每 0.5s 一次）⇒ Python 层循环长时间占着 GIL、磁盘也被打满，
        Tk 主线程抢不到 GIL ⇒ 窗口变「未响应」。
        现在加**时间预算**：单次调用有上界，超预算就收工返回已累计值（进度本来就是估算）。
        """
        total = 0
        deadline = (time.time() + budget) if budget > 0 else 0.0
        stack = [root]
        n = 0
        while stack:
            if deadline and (n & 0x3F) == 0 and time.time() > deadline:
                break                                   # 每 64 个条目查一次表，别把预算花在 clock 上
            n += 1
            cur = stack.pop()
            try:
                with os.scandir(cur) as it:
                    for e in it:
                        try:
                            if e.is_symlink():
                                continue
                            if e.is_dir(follow_symlinks=False):
                                if not _is_reparse(e.path):
                                    stack.append(e.path)
                            elif e.is_file(follow_symlinks=False):
                                total += e.stat(follow_symlinks=False).st_size
                        except OSError:
                            pass
            except OSError:
                pass
        return total

    def _cur_sbx(self) -> str:
        """本线程当前包的沙箱目录（供轮询体积用）。"""
        return getattr(self._tls, "sbx", "") or ""

    def _tick_sbx(self) -> None:
        """把"沙箱里已解出多少字节"上报成本包进度（rar / bsdtar 那类外部工具用）。

        🩸 见 `_dir_size` 的说明：这里再做一层**自适应节流** —— 一次扫描用满时间预算
        （说明沙箱很大、扫不动）就把下次的间隔翻倍（上限 4 秒），否则回到 0.5 秒。
        这样"几万个文件"的包不会让 8 路并行反复去做全量遍历。
        """
        sbx = self._cur_sbx()
        if not sbx:
            return
        now = time.time()
        iv = float(getattr(self._tls, "sbx_iv", SBX_POLL_INTERVAL) or SBX_POLL_INTERVAL)
        if now - float(getattr(self._tls, "sbx_last", 0.0) or 0.0) < iv:
            return
        t0 = time.time()
        total = self._dir_size(sbx, budget=SBX_SCAN_BUDGET)
        spent = time.time() - t0
        if spent >= SBX_SCAN_BUDGET * 0.85:
            self._tls.sbx_iv = min(SBX_POLL_MAX, max(SBX_POLL_INTERVAL, iv * 2))
        else:
            self._tls.sbx_iv = SBX_POLL_INTERVAL
        self._tls.sbx_last = now
        self._pkg_advance(sbx_bytes=total)


    # -------------------------------------------------- 对外入口

    def _settle_one(self, job: Job, new_files: list[str], res: ArchiveResult,
                    queue: deque) -> None:
        """一个包跑完就**立刻**记账 + 上报。

        🩸 用例「明明解压完这么多了，进度条只有 6 个」：旧实现把这段逻辑
        放在 `for fut in as_completed(...)` **循环之外** —— 整层 126 个包**全部解完之前
        一个都不 `_record`**，进度条的"已完成包数"整层纹丝不动（写着 `0/126`，旁边却是
        "已解出 40 GB"），用户当然以为卡住了。现在每完成一个包就记账 + 推一次快照。
        """
        self._record(res)
        # 🩸 本轮只要**杀过外部工具**（或整轮被取消/强停过），就一律
        # 不删源包。被强杀的那一次退出码是 1，与"部分成功"撞车、可能"看起来成功"，
        # 而删源不可逆 —— 保守优先。
        aborted = (bool(self._killed_pids) or self.cancel.is_set()
                   or self.force_stop.is_set())
        if res.status == "ok" and self.opt.delete_source and aborted:
            self._log("warn", f"本轮发生过取消或强制停止，为安全起见不删原包：{job.path}")
        elif res.status == "ok" and self.opt.delete_source:
            if res.files <= 0:
                # 条目全因"已存在"被跳过（写出 0 个文件）时**绝不能删源包**
                self._log("warn", f"本次没有写出任何文件（条目都已存在），为安全起见不删原包：{job.path}")
            elif res.skipped_members:
                # 包里有条目被跳过（不安全路径/链接等）⇒ 别删原包，留个可复核的源
                self._log("warn", f"包内有 {res.skipped_members} 个条目被跳过，"
                                  f"为安全起见不删原包：{job.path}")
            else:
                self._delete_source(job.path)
        elif res.status == "failed" and self.opt.mark_failed:
            self._mark_failed(job.path)
        for f in new_files:
            if self._wait_if_paused():
                break
            if self._candidate(f) and not self._doc_guarded(f):
                self._log("info", f"  ↳ 发现嵌套包裹（第 {job.depth + 1} 层）：{f}")
                queue.append(Job(path=f, depth=job.depth + 1, src_root=job.src_root))
                # 🩸 **嵌套包也要登记**进"本次待处理的源包"集合。
                # 以前只登记顶层包，于是 `overwrite=overwrite` 时嵌套包的内容会被同批
                # 另一个包的同名成员顶掉（原内容永不落地），配合 `--delete` 连包一起删。
                with self._lock:
                    self._source_paths.add(_real_norm(f))
                with self._lock:
                    self.stats.archives_found += 1
        self._emit()

    def run(self) -> Stats:
        self.stats.started_at = time.time()
        queue: deque[Job] = deque()

        for root in self.src_dirs:
            if not os.path.isdir(root):
                self._log("error", f"源目录不存在：{root}")
                continue
            if self.opt.layout in ("out_dir", "out_dir_flat") and not self.opt.out_dir \
                    and not self.opt.dry_run:
                auto = os.path.join(root, auto_out_dir_name())
                self._auto_out[root] = auto
                try:
                    os.makedirs(auto, exist_ok=True)
                    self._made_auto.append(auto)
                    self._log("info", f"统一输出目录（自动创建）：{auto}")
                except OSError as exc:
                    self._log("error", f"无法创建输出目录 {auto}：{exc}")
            self._log("info", f"扫描目录：{root}")
            for p in self._iter_files(root):
                if self._wait_if_paused():
                    break
                if self._candidate(p) and not self._doc_guarded(p):
                    self._source_paths.add(_real_norm(p))
                    queue.append(Job(path=p, depth=0, src_root=root))

        self.stats.archives_found = len(queue)
        nw = self._workers()
        self._nw = nw                      # 本次并行度（GUI 用它决定"每个包一条"的槽位数）
        self._log("info", f"共发现 {len(queue)} 个压缩包（顶层）；并行度 {nw}"
                          f"（CPU 逻辑核 {os.cpu_count()}）")
        self._emit()

        while queue:
            if self._wait_if_paused():
                break
            layer, queue = list(queue), deque()
            jobs: list[Job] = []
            for job in layer:
                key = _real_norm(job.path)
                if key in self._seen:
                    continue
                self._seen.add(key)
                if job.depth > self.opt.max_depth:
                    self._log("warn", f"超过最大嵌套深度 {self.opt.max_depth}，跳过：{job.path}")
                    self._record(ArchiveResult(path=job.path, status="skipped",
                                               note=f"超过深度 {self.opt.max_depth}",
                                               depth=job.depth))
                    continue
                if self.opt.dry_run:
                    self._log("info", f"[dry-run] 深度 {job.depth}：{job.path}")
                    self._record(ArchiveResult(path=job.path, status="skipped",
                                               note="dry-run", depth=job.depth))
                    continue
                jobs.append(job)
            if not jobs:
                continue

            if nw <= 1 or len(jobs) == 1:
                for job in jobs:
                    if self._wait_if_paused():
                        break
                    try:
                        self._settle_one(*self._run_one(job), queue)
                    except Cancelled:
                        self.cancel.set()
                        self._record(ArchiveResult(path=job.path, status="skipped",
                                                   note="已取消", depth=job.depth))
                        break
            else:
                with ThreadPoolExecutor(max_workers=min(nw, len(jobs))) as pool:
                    futs = {pool.submit(self._run_one, j): j for j in jobs}
                    for fut in as_completed(futs):
                        try:
                            # ⚠️ 必须**在这里**就记账（见 `_settle_one` 的说明）
                            self._settle_one(*fut.result(), queue)
                        except Cancelled:
                            self.cancel.set()
                            self._record(ArchiveResult(path=futs[fut].path, status="skipped",
                                                       note="已取消", depth=futs[fut].depth))
                        except Exception as exc:            # noqa: BLE001
                            self._log("error", f"线程异常：{type(exc).__name__}: {exc}")

        if self.cancel.is_set():
            self._log("warn", "已取消，停止处理剩余压缩包")

        if self.opt.clean_empty_dirs:
            n = self._clean_dirs()
            self.stats.empty_dirs_removed = n
            if n:
                self._log("info", f"清理空目录 {n} 个")

        self.stats.elapsed = time.time() - self.stats.started_at
        self._log("info", f"完成：成功 {self.stats.archives_done} · 失败 {self.stats.archives_failed} · "
                          f"跳过 {self.stats.archives_skipped}；写出 {self.stats.files_written} 个文件 / "
                          f"{human_size(self.stats.bytes_written)}，耗时 {self.stats.elapsed:.1f} 秒")
        if self.opt.report and not self.opt.dry_run:
            self._write_report()
        self._emit(done=True)
        return self.stats

    def _workers(self) -> int:
        if self.opt.workers and self.opt.workers > 0:
            return max(1, min(int(self.opt.workers), 64))      # 显式数字优先
        return detect_workers(self.opt.worker_level)

    def _run_one(self, job: Job) -> tuple[Job, list[str], ArchiveResult]:
        self._begin_pkg(job.path)
        res: Optional[ArchiveResult] = None
        try:
            new_files, res = self._handle(job)
        except Cancelled:
            raise
        except Exception as exc:                            # noqa: BLE001
            new_files = []
            res = ArchiveResult(path=job.path, dest="", status="failed",
                                note=f"{type(exc).__name__}: {exc}", depth=job.depth)
            self._log("error", f"处理失败：{job.path} —— {res.note}")
        finally:
            # **任何**路径（炸弹/密码/取消/沙箱内失败）都要清掉本包的临时文件，
            # 否则 7z-SFX 的裁切段会残留在用户源目录旁，下次运行还会被当成压缩包重复处理。
            self._cleanup_scratch(job.path)
            # v1.4.0：**先把本包最后一次进度强制推出去，再注销它** ——
            # 否则节流（100ms）会把"最后一帧"吞掉，UI 上表现为进度条停在 9x% 就跳走。
            self._emit(force=True)
            # 失败/取消的包产物已回滚 ⇒ 让实时计数把它扣掉
            self._end_pkg(job.path, discarded=(res is None or res.status != "ok"))
        return job, new_files, res

    def _cleanup_scratch(self, key: str = "") -> None:
        """清掉**这个包**的临时文件。

        🩸 旧实现是**实例级**列表 + 无条件 `clear()` —— 并行时 B 的收尾会把
        A 的记账一起清掉，于是 A 被取消后它的 7z-SFX 裁切段残留在用户源目录旁边。
        """
        k = key or getattr(self._tls, "pkg", "")
        with self._lock:
            items = self._scratch.pop(k, [])
        for p in items:
            try:
                os.remove(p)
            except OSError:
                pass

    def _add_scratch(self, path: str) -> None:
        """登记本包的临时文件（按包 key 隔离，见 `_cleanup_scratch`）。"""
        k = getattr(self._tls, "pkg", "")
        with self._lock:
            self._scratch.setdefault(k, []).append(path)

    def _record(self, res: ArchiveResult) -> None:
        with self._lock:
            self.results.append(res)
            if res.status == "ok":
                self.stats.archives_done += 1
            elif res.status == "skipped":
                self.stats.archives_skipped += 1
            else:
                self.stats.archives_failed += 1
            self.stats.files_written += res.files
            self.stats.bytes_written += res.bytes

    # -------------------------------------------------- 单个压缩包

    def _handle(self, job: Job) -> tuple[list[str], ArchiveResult]:
        kind, sfx = self._detect(job.path)
        res = ArchiveResult(path=job.path, kind=kind, depth=job.depth)
        dest = self._dest_for(job)
        res.dest = dest

        ledger = _Ledger()
        counter = {"bytes": 0}
        status, note = "ok", ""

        try:
            self._dispatch(kind, job.path, dest, counter, "", ledger, sfx)
        except NeedPassword as exc:
            if not self.opt.password:
                status, note = "skipped", f"加密压缩包，未输入密码：{exc}"
            else:
                self._log("info", f"  ※ 需要密码，改用输入的密码重试：{os.path.basename(job.path)}")
                self._rollback_guarded(ledger)
                ledger = _Ledger()
                counter = {"bytes": 0}
                try:
                    self._dispatch(kind, job.path, dest, counter, self.opt.password, ledger, sfx)
                except Cancelled:
                    self._rollback_guarded(ledger)
                    raise
                except NeedPassword as exc2:
                    status, note = "failed", f"密码不正确或不支持该加密方式：{exc2}"
                except BombDetected as exc2:
                    status, note = "failed", f"疑似压缩炸弹：{exc2}"
                except (ExtractError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc2:
                    status, note = "failed", f"{type(exc2).__name__}: {exc2}"
        except Cancelled:
            self._rollback_guarded(ledger)
            raise
        except BombDetected as exc:
            status, note = "failed", f"疑似压缩炸弹：{exc}"
        except UnsafePath as exc:
            status, note = "failed", str(exc)
        except ExtractError as exc:
            status, note = "failed", str(exc)
        except (zipfile.BadZipFile, tarfile.TarError, EOFError) as exc:
            status, note = "failed", f"压缩包损坏：{type(exc).__name__}: {exc}"
        except OSError as exc:
            status, note = "failed", f"系统错误：{exc}"
        except Exception as exc:                            # noqa: BLE001
            status, note = "failed", f"{type(exc).__name__}: {exc}"

        res.status = status
        res.note = note
        res.skipped_members = counter.get("skipped", 0) + counter.get("skip_existing", 0)

        # 🩸 「解压大量文件偶发未响应」：`_inside` 是 **realpath 级**校验，旧实现对
        # **每一个产物文件**都调一次 ⇒ 几万文件时就是几万次 realpath，而 `py-spy dump`
        # 显示多个 worker 线程同时卡在 `realpath` 上抢 GIL，主线程的 Tk 调用抢不过 ⇒ 假死。
        # 这些路径本来就经过 `safe_join(dest, …)`（realpath 校验过），这里是第二道闸：
        # 先用**廉价的字符串前缀**过滤，只有可疑的才升级到 realpath 复核。
        escaped = []
        _root_abs = os.path.abspath(dest)
        for p in ledger.paths:
            if p == _root_abs or p.startswith(_root_abs + os.sep):
                continue
            if not self._inside(dest, p):
                escaped.append(p)
        if escaped:
            res.status = "failed"
            res.note = (note + " | " if note else "") + f"落盘越界 {len(escaped)} 处：{escaped[0]}"
            status = res.status

        if res.status != "ok" and ledger.paths:
            # 失败/跳过都回滚自己写出去的东西；只删账本里的路径（改造 A）
            self._rollback_guarded(ledger)
            res.note = (res.note + " " if res.note else "") + "（产物已回滚）"

        if res.status == "ok":
            ledger.drop_backups()               # 成功 ⇒ 覆盖前留的备份可以删了
            res.files = ledger.files
            res.bytes = ledger.bytes
            with self._lock:
                self._all_dirs.extend(ledger.dirs)
        else:
            res.files = 0
            res.bytes = 0

        new_files = list(ledger.paths) if res.status == "ok" else []

        if res.status == "ok":
            self._log("ok", f"✔ {os.path.basename(job.path)} → {dest}"
                            f"（{res.files} 个文件，{human_size(res.bytes)}）")
        elif res.status == "skipped":
            self._log("warn", f"⚠ 跳过 {os.path.basename(job.path)}：{note}")
        else:
            self._log("error", f"✘ 失败 {os.path.basename(job.path)}：{res.note}")
        return new_files, res

    def _dispatch(self, kind: str, path: str, dest: str, counter: dict,
                  password: str, ledger: _Ledger, sfx: int = 0) -> None:
        if kind == "zip":
            try:
                self._extract_zip(path, dest, counter, password, ledger)
            except UseExternal as exc:
                self._log("info", f"  改用外部工具处理（{exc}）")
                self._extract_external(path, dest, "zip", password, counter, ledger)
        elif kind == "7z":
            self._extract_7z(path, dest, counter, password, ledger, sfx)
        elif kind in ("tar", "gzip", "bzip2", "xz", "zstd"):
            self._extract_tar_or_single(path, kind, dest, counter, ledger)
        elif kind in ("rar", "rar5"):
            # rar 优先用内置的官方 UnRAR：能解 rar5、加密包、以及自解压 exe 外壳；
            # 没有它才回落到系统 tar.exe（libarchive，**不支持** rar 加密）
            if self._unrar():
                self._extract_rar(path, dest, counter, ledger, password)
            else:
                self._log("warn", "  没有可用的内置 UnRAR（bin\\UnRAR.exe 缺失或损坏）⇒ 改用系统 "
                                  "tar.exe；**它不支持加密 rar，加密包一定会失败**")
                self._extract_external(path, dest, kind, password, counter, ledger)
        elif kind in ("iso", "cab"):
            self._extract_external(path, dest, kind, password, counter, ledger)
        else:
            raise ExtractError(f"不认识的格式：{kind}")

    def _doc_guarded(self, path: str) -> bool:
        """Office/epub/jar 这类文档不当作压缩包处理（它们内部确实是 zip）。"""
        return is_document_like(path)

    def _candidate(self, path: str) -> bool:
        """这个文件要不要当压缩包处理（.exe 外壳算不算，看 scan_exe 开关）。"""
        return sniff_ex(path, allow_pe=self.opt.scan_exe)[0] is not None

    def _detect(self, path: str) -> tuple[str, int]:
        """返回 (kind, sfx 偏移)；sfx > 0 表示这是 PE 外壳。"""
        kind, sfx = sniff_ex(path, allow_pe=self.opt.scan_exe)
        return (kind or "unknown"), sfx

    @staticmethod
    def _unrar() -> Optional[str]:
        """找**内置的**官方 UnRAR.exe（打包态 `_MEIPASS/bin`，源码态引擎同级 `bin`）。

        🩸 两条判据都收紧过：
        ① **不再回落到 PATH / CWD** —— Py3.12 的 `shutil.which()` 会命中当前工作目录，
           只要在落点目录放个同名 exe 就能劫持我们的调用（实测能真的把它启动起来）；
        ② **不只判 isfile** —— 文件坏成 0 字节/非 PE 时仍会被选中并 WinError 193，
           而且不再回落到还能用的 bsdtar ⇒ 改用 `_usable_exe()`。
        """
        cands: list[str] = []
        base = getattr(sys, "_MEIPASS", "")
        if base:
            cands.append(os.path.join(base, "bin", "UnRAR.exe"))
        here = os.path.dirname(os.path.abspath(__file__))
        cands.append(os.path.join(here, "bin", "UnRAR.exe"))
        cands.append(os.path.join(os.path.dirname(here), "src", "bin", "UnRAR.exe"))
        for c in cands:
            if _usable_exe(c):
                return c
        return None

    def _extract_rar(self, path: str, dest: str, counter: dict,
                     ledger: _Ledger, password: str) -> None:
        """rar / rar5 / 自解压 exe：交给官方 UnRAR 解到沙箱，再逐个校验搬移（改造 B）。

        UnRAR 原生就能读自解压 SFX（它自己会跳过前面的 PE 头），所以 exe 外壳不用另作处理。
        """
        if not self._unrar():
            raise ExtractError("找不到 UnRAR.exe")

        # rar 此前**没有任何预检**（7z 有 names/ratio 预检 + 分批核账）——
        # 400 MB 全 0 的单成员 rar（压缩比 2.4 万:1）在 bomb_ratio=50 下照样写出。
        # 这里先用 `unrar lt` 拿声明值拦一道；列不出来（损坏/加密文件名没密码）就不拦，
        # 交给真正解压时报错。沙箱核账仍然是第二道闸。
        n_entries, total_bytes, unsafe_names, lt_ok = self._rar_entries_bytes(path, password)
        if not lt_ok:
            # 🩸 `unrar lt` 失败（包损坏/不可读）时旧代码直接 `return (0,0,0)`，
            # 于是条目数/声明总量/压缩比**三道预检被整体跳过**（实测 25 KB 的 600 MiB 炸弹包
            # 照写 600 MB）。而现在：预检拿不到 ⇒ 明确按"可能不完整"处理，**禁止删源包**。
            self._log("warn", "  无法列出成员清单（压缩包可能损坏或不完整）。"
                              "本次将保守处理：不删除原压缩包。")
            counter["skipped"] = counter.get("skipped", 0) + 1
        if total_bytes:
            self._pkg_total(total_bytes)         # 声明解压量 ⇒ 本包进度条有了分母
        if unsafe_names:
            self._log("warn", f"  包内有 {unsafe_names} 个条目名不安全（unrar 会自动改名，已记入跳过）")
            counter["skipped"] = counter.get("skipped", 0) + unsafe_names
        if n_entries and total_bytes:
            if n_entries > self.opt.max_entries:
                raise BombDetected(f"条目数 {n_entries} 超过上限 {self.opt.max_entries}")
            if total_bytes > self.opt.max_total_bytes:
                raise BombDetected(f"声明解压量 {human_size(total_bytes)} 超过上限 "
                                   f"{human_size(self.opt.max_total_bytes)}")
            pkg_size = max(1, os.path.getsize(path))
            ratio = total_bytes / pkg_size
            if total_bytes > self.opt.bomb_min_bytes and ratio > self.opt.bomb_ratio:
                raise BombDetected(f"声明压缩比 {ratio:.0f}:1 异常（{human_size(total_bytes)}"
                                   f" / {human_size(pkg_size)}）")

        def runner(sbx: str) -> None:
            skipped = self._run_unrar(path, sbx, password)
            if skipped:
                # unrar 会静默跳过不安全成员（如 jlink）并返回 rc=1
                # ⇒ 必须计进 skipped，否则 585-591 的"有跳过就不删源包"保护不触发
                counter["skipped"] = counter.get("skipped", 0) + skipped

        moved = self._sandbox_extract(path, dest, counter, ledger, runner, "rar")

        # 🩸 第二层：**成员数核对** —— `unrar lt` 声明的文件条目数 vs 实际搬出数。
        # 实测尾部截断 64 B 的 solid rar：`x` 返回 rc=1、一行 `Skipping` 都不打、10 个成员
        # 只解出 8 个 ⇒ 旧逻辑记 status=ok/files=8/skipped=0 ⇒ 源包被删、缺的内容永久丢失。
        # 这里把"没出来的成员"如实计进 skipped，让"有跳过就不删源包"那道闸生效。
        if lt_ok and n_entries:
            missing = n_entries - moved - counter.get("skip_existing", 0)
            if missing > 0:
                counter["skipped"] = counter.get("skipped", 0) + missing
                self._log("warn", f"  成员数与清单不符：清单 {n_entries} 个、实际写出 {moved} 个"
                                  f"（缺 {missing} 个）。本次将保守处理：不删除原压缩包。")

    def _rar_entries_bytes(self, path: str, password: str) -> tuple[int, int, int, bool]:
        """`unrar lt` 预检：返回 (条目数, 声明解压总量, **命名不安全的条目数**, 清单是否可用)。

        unrar 会**静默清洗** `..\\evil\\payload.txt` 这类名字（rc=0、零警告）
        ⇒ 引擎侧 `skipped_members` 恒 0 ⇒ "有跳过就不删源包"的保护不触发、源包照删。
        这里先用 `sanitize_rel` 把声明的名字审一遍。

        🩸 `rc` 只有 0 才算"清单可用"；但 **rc=1（部分可读）也要继续解析**，
        否则尾部损坏的包会让三道炸弹预检整体失效。返回的 `ok=False` 由调用方转成
        "禁止删源"的保守处理。
        """
        exe = self._unrar()
        if not exe:
            return (0, 0, 0, False)
        rc, lines, _ = self._run_tool_streaming(
            [exe, "lt", "-p" + (password or "-"), path],
            label="UnRAR 列表", collect_all=True)
        ok = rc == 0
        if rc not in (0, 1):
            return (0, 0, 0, False)
        n, total, unsafe = 0, 0, 0
        for ln in lines:
            s = ln.strip()
            if s.startswith("Type:") and "File" in s:
                n += 1
            elif s.startswith("Name:"):
                nm = s.split(":", 1)[1].strip()
                if nm and sanitize_rel(nm) is None:
                    unsafe += 1
            elif s.startswith("Size:"):
                try:
                    total += int(s.split(":", 1)[1].strip())
                except ValueError:
                    pass
        return (n, total, unsafe, ok)

    def _run_tool_streaming(self, cmd: list[str], *, label: str,
                            timeout: float = 3600.0,
                            collect_all: bool = False,
                            stdin_data: Optional[str] = None,
                            on_tick: Optional[Callable[[], None]] = None,
                            on_line: Optional[Callable[[str], None]] = None) -> tuple[int, list[str], int]:
        """跑外部工具：**必须边跑边把输出抽走**，否则 Windows 管道写满会死锁。

        🩸 旧写法 `Popen(stdout=PIPE, stderr=PIPE)` 全程不读、只在结束时
        `communicate()` —— unrar 的进度输出约 4 KiB 就把管道写满、它自己阻塞在 write、
        永不退出，引擎只能干等 3600s 才报超时（实测：20 成员 0.25s 通过，
        30/40/100/600 成员**永不返回**；同命令改成边读边跑后 600 成员 0.56s 完成）。

        返回 `(returncode, 输出的尾部若干行（`collect_all=True` 时给全部行）, 含 "Skipping"/"cannot open" 的行数)`。
        """
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE if stdin_data is not None else None,
                text=True, errors="replace", bufsize=1)
        except OSError as exc:
            raise ExtractError(f"无法启动{label}：{exc}") from exc
        _assign_to_job(proc)                                # 防孤儿：父进程死则子进程一起死
        with self._lock:
            self._tool_procs.append(proc)                   # 供"立即停止"直接杀（持锁登记）
        # ⚠️ 这里**不能**"启动瞬间写完就 close"：unrar 的 `Enter password` 提示在几百毫秒之后，
        # 那时 stdin 已经 EOF、写入被吞掉 ⇒ 密码根本没送进去（v1.3.6 第一版就是这么回归的）。
        # 改成由下面的 reader 线程**看到提示再现喂**，并且不 close（避免问到第 N 次时已 EOF 而挂住）。
        tail: deque[str] = deque(maxlen=80)
        all_lines: list[str] = []
        state = {"skipped": 0}
        feed = {"n": 0}                                     # 交互喂料次数（防无限问答）
        lock = threading.Lock()

        def _reader() -> None:
            try:
                for raw in proc.stdout:                 # 迭代到 EOF —— 关键：持续抽走
                    line = raw.rstrip()
                    low = line.lower()
                    with lock:
                        tail.append(line)
                        if collect_all:
                            all_lines.append(line)
                        if "skipping" in low or "cannot open" in low:
                            state["skipped"] += 1
                    if on_line is not None:
                        try:
                            on_line(line)                   # 解析工具输出（如 UnRAR 的单文件进度）
                        except Exception:                   # noqa: BLE001
                            pass
                    if stdin_data is not None and proc.stdin is not None and "password" in low:
                        # ⚠️ unrar 有两种询问，必须分别回答，否则**无限问答**（实测卡 10 分钟）：
                        #   `Enter password ...`       ⇒ 喂密码
                        #   `x.txt - use current password?` ⇒ 喂 y
                        ans = stdin_data if "enter password" in low else "y\n"
                        try:
                            proc.stdin.write(ans)
                            proc.stdin.flush()
                        except Exception:                   # noqa: BLE001
                            pass
                        with lock:
                            feed["n"] += 1
                            too_many = feed["n"] > 64
                        if too_many:                        # 兜底：绝不无限问答
                            try:
                                proc.kill()
                            except Exception:               # noqa: BLE001
                                pass
            except Exception:                           # noqa: BLE001
                pass

        th = threading.Thread(target=_reader, daemon=True)
        th.start()
        killed = ""
        t0 = time.time()
        last_tick = 0.0
        suspended = False
        while proc.poll() is None:
            if self.pause.is_set():
                # 🩸 必须把**外部进程本身**挂住 —— 只挂 Python 线程的话它还在写盘
                if not suspended:
                    suspended = _suspend_proc(proc)
                if self._wait_if_paused():          # 在这里阻塞，直到"继续"或"取消"
                    killed = "cancel"
                    break
                if suspended:
                    _resume_proc(proc)
                    suspended = False
                continue
            # 🩸 v1.4.11 修 v1.4.9 引入的回归：**正常轮询分支也必须看 cancel**。
            # 旧写法只在 `if self.pause.is_set()` 分支里检查 ⇒ 用户点「停止」（只置 cancel、
            # 不置 pause）时，正在跑的外部工具**完全不理会**，一直解到包结束 ——
            # 就是实测的「界面显示已停止、后台还在解」。
            if self.cancel.is_set():
                killed = "cancel"
                break
            now = time.time()
            if on_tick is not None and now - last_tick >= SBX_POLL_INTERVAL:
                last_tick = now
                try:
                    on_tick()                               # 轮询"沙箱里已解出多少"
                except Exception:                           # noqa: BLE001
                    pass
            if now - t0 > timeout:
                killed = "timeout"
                break
            time.sleep(0.15)
        if killed:
            if suspended:
                _resume_proc(proc)                  # 先恢复再终止（避免任何边缘情况）
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        th.join(timeout=5)
        with lock:
            lines = list(all_lines) if collect_all else list(tail)
            skipped = state["skipped"]
        # 🩸 本轮跑完就**注销**这个 Popen 并关掉它的 stdout ——
        # 旧实现只在 `kill_tools()` 里清理，一轮跑几百个包时会强引用成百上千个
        # 进程/管道句柄（实测 ≈4 个句柄/次，40 次调用 +164 个句柄）。
        with self._lock:
            self._tool_procs[:] = [p for p in self._tool_procs if p is not proc]
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except Exception:                                   # noqa: BLE001
            pass
        # 🩸 **被我们杀过**的进程绝不能落到 rc 分支 —— 强杀的退出码是 1，
        # 与 UnRAR 的"部分成功"撞车，会被记成成功（叠上 --delete 就删源包）。
        if killed == "cancel" or proc.pid in self._killed_pids:
            raise Cancelled(f"用户取消（{label} 已终止）")
        if killed == "timeout":
            raise ExtractError(f"{label} 解压超时（超过 {int(timeout / 60)} 分钟）")
        return proc.returncode, lines, skipped

    def _run_unrar(self, path: str, sbx: str, password: str) -> int:
        """跑 UnRAR，返回**被跳过的成员数**。`-p-` = "没有密码，别提示"。

        退出码语义（修正）：
        - `0` 成功；`1` = **部分成功**（有成员被跳过，如不安全的 jlink）⇒ 返回跳过数、
          让上层禁止删源包；
        - `11` = 密码错/缺密码 ⇒ NeedPassword；
        - **`3` = 校验/CRC 错 = 包损坏 ⇒ 报"损坏"，绝不能再当"需要密码"**
          （旧实现把 3 与 11 一起映射成密码语义：非加密损坏包被报成"加密未输密码"、
          密码正确但数据坏被冤枉成"密码不正确"）。
        """
        exe = self._unrar()
        if not exe:
            raise ExtractError("找不到 UnRAR.exe")
        # ⚠️ 口令只能走命令行（`-p<pwd>`）。实测确实"同机进程能读到它"，
        # 但**改用 stdin 交互喂密码实测两次卡死**（unrar 的询问措辞会变，读不到就死等）
        # ⇒ 明确选择不修这条：**卡死的危害 > 本地命令行泄露**。缓解：不把密码写进
        # 日志/报告/settings.json，并在使用说明里写明风险。
        cmd = [exe, "x", "-o+", "-y", "-p" + (password or "-"), path, sbx + os.sep]
        key = getattr(self._tls, "pkg", "")
        rc, lines, skipped = self._run_tool_streaming(
            cmd, label="UnRAR", on_line=lambda ln: self._unrar_line(ln, key),
            on_tick=self._tick_sbx)
        if rc == 0:
            return skipped
        brief = _pick_reason(lines)
        if rc == 11:
            raise NeedPassword(brief or "需要密码")
        if rc == 1:
            if skipped:
                self._log("warn", f"  UnRAR 跳过了 {skipped} 个成员（不安全或不支持）")
            else:
                # 🩸 rc=1 = **部分成功**，但有些情况下 UnRAR **一行 Skipping 都不打**
                # （实测尾部截断 64 B：10 个成员只解出 8 个、Skipping 行 = 0）。旧代码据此
                # 返回 0 ⇒ 上层当"完全成功"⇒ 配合 --delete 直接删源包，缺的内容永久丢失。
                # 没有跳过行时也必须记成"有成员没出来"，让删源闸门拦住。
                self._log("warn", "  UnRAR 报告部分成功（rc=1），可能有个别成员未能解出")
                skipped = 1
            return skipped
        if rc == 3:
            raise ExtractError(f"压缩包损坏或校验失败（rc=3）：{brief}")
        if rc == 2 and any(k in brief.lower() for k in ("password", "encrypted", "crypt")):
            raise NeedPassword(brief)
        raise ExtractError(f"UnRAR 失败（rc={rc}）：{brief}")

    def _unrar_line(self, line: str, key: str) -> None:
        """解析 UnRAR 的 stdout，拿到「当前文件 + 单文件百分比」。

        v1.4.0 新增：UnRAR 每处理一个文件都会打
        `Extracting  <路径>                                        OK ` 或 `...  45%`，
        正好是 Bandizip 式"单文件进度条"要的东西（不用 `-idq` 才有 —— 我们本来就没加）。
        """
        s = (line or "").strip()
        if len(s) < 12 or not s.lower().startswith("extracting"):
            return
        body = s[len("Extracting"):].strip()
        pct: Optional[float] = None
        m = re.search(r"(\d{1,3})%\s*$", body)
        if m:
            pct = float(m.group(1))
            body = body[:m.start()].strip()
        elif body.upper().endswith("OK"):
            pct = 100.0
            body = body[:-2].strip()
        if body:
            self._file_begin(body, None, pct, key=key)

    @staticmethod
    def _strip_prefix(name: str, prefix: str) -> str:
        """剥掉智能解压的那一层前缀（没配到就原样返回）。"""
        if not prefix:
            return name
        s = name.replace("\\", "/")
        return s[len(prefix):] if s.startswith(prefix) else name

    def _smart_prefix_names(self, pkg_path: str, names: Iterable[str]) -> str:
        """Bandizip 式「智能解压」：包内只有一个顶层**文件夹**、且它与压缩包同名时，返回要剥掉的前缀。

        场景：`A.7z` 里只有 `A/文件` ⇒ 解到 `A\\` 之后不该再套一层变成 `A\\A\\文件`，
        而应该就是 `A\\文件`。返回 `"A/"` 表示落盘时去掉这个前缀；返回 `""` 表示不剥。

        判据故意收得很紧（三条全满足才剥），避免误伤：
          ① 顶层条目**只有一个**；
          ② 它**确实是文件夹**（存在以 `它/` 开头的子条目）；
          ③ 它与压缩包去后缀后的名字**同名**（忽略大小写与首尾空格）。
        """
        if not self.opt.smart_extract:
            return ""
        norm = []
        for n in names:
            s = (n or "").replace("\\", "/").strip("/")
            if s:
                norm.append(s)
        if not norm:
            return ""
        tops = {s.split("/")[0] for s in norm}
        if len(tops) != 1:
            return ""
        only = tops.pop()
        if not any(s.startswith(only + "/") for s in norm):
            return ""
        if only.strip().lower() != archive_stem(pkg_path).strip().lower():
            return ""
        return only + "/"

    def _smart_prefix_dir(self, sbx: str, pkg_path: str) -> str:
        """沙箱版：看沙箱根下是不是只有一个与包同名的文件夹。"""
        if not self.opt.smart_extract or not pkg_path:
            return ""
        try:
            # ⚠️ 必须排除我们自己的沙箱标记文件（`_sbx_entries`），否则沙箱根下永远
            # "有两个条目"、智能解压判据恒不成立（引入 owner 标记时踩到过）。
            entries = _sbx_entries(sbx)
        except OSError:
            return ""
        if len(entries) != 1:
            return ""
        only = entries[0]
        if not os.path.isdir(os.path.join(sbx, only)):
            return ""
        if only.strip().lower() != archive_stem(pkg_path).strip().lower():
            return ""
        return only + "/"

    def _out_base(self, job: Job) -> str:
        return self.opt.out_dir or self._auto_out.get(job.src_root) or job.src_root

    def _dest_for(self, job: Job) -> str:
        if self.opt.layout == "beside_flat":
            return os.path.dirname(job.path) or job.src_root
        if self.opt.layout in ("out_dir", "out_dir_flat"):
            base = self._out_base(job)
            try:
                rel_dir = os.path.dirname(os.path.relpath(job.path, job.src_root))
            except ValueError:
                rel_dir = ""
            parent = base if rel_dir in (".", "") else os.path.join(base, *rel_dir.split(os.sep))
            if self.opt.layout == "out_dir_flat":
                return parent
            return self._unique_dir(os.path.join(parent, archive_stem(job.path)))
        return self._unique_dir(os.path.join(os.path.dirname(job.path), archive_stem(job.path)))

    def _unique_dir(self, base: str) -> str:
        """给包挑一个独占的目标目录名。

        ★ 必须加锁 + 登记 `_claimed`：两个包（如 `same.zip` 与 `same.tar.gz`）并发解压时，
        旧实现会在同一瞬间都判断"`same` 不存在"⇒ 双双选中同一个目录，内容混在一起
        （实测命中）。
        """
        with self._name_lock:
            key = os.path.normcase(base)
            if not os.path.exists(base) and key not in self._claimed:
                self._claimed.add(key)
                return base
            for i in range(2, 9999):
                cand = f"{base} ({i})"
                ck = os.path.normcase(cand)
                if not os.path.exists(cand) and ck not in self._claimed:
                    self._claimed.add(ck)
                    return cand
            raise ExtractError(f"无法为 {base} 找到可用目录名")

    @staticmethod
    def _inside(root: str, path: str) -> bool:
        real_root = _real_norm(root)
        real = _real_norm(path)
        return real == real_root or real.startswith(real_root + os.sep)

    # -------------------------------------------------- 目录遍历（不跟随 junction）

    def _iter_files(self, root: str):
        for dp, dirnames, filenames in os.walk(root, topdown=True):
            # junction / 符号链接目录一律不跟随（Windows 上 islink 对 junction 为 False）
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(SANDBOX_PREFIX)
                           and not _is_reparse(os.path.join(dp, d))]
            for fn in filenames:
                if fn.startswith(SANDBOX_PREFIX):
                    # 🩸 7z-SFX 的裁切段（`.rc-sbx-7zsfx-*.7z`）是**临时文件**，
                    # 旧实现只过滤了目录名 ⇒ 残留物会被下一轮当压缩包再解一遍。
                    continue
                yield os.path.join(dp, fn)

    def kill_tools(self) -> int:
        """**立刻**终止本程序起过的所有外部解压工具（返回杀掉的个数）。

        🩸 实测发现：点「停止」后界面显示已停止，但后台 UnRAR 还在解。
        根因是停止只置了 `cancel`，而外部工具要等 worker **走到检查点**才被 terminate ——
        期间它照旧满速解压。现在点停止**直接杀**，不必等。
        """
        n = 0
        with self._lock:
            procs = list(self._tool_procs)
            # 🩸 旧写法"先快照 → 再 `self._tool_procs = [...快照过滤...]`"——
            # 快照之后 worker 新 append 的 Popen 会被这次**整体赋值抹掉**：既没被杀，也从此
            # 不在名单里 ⇒ **之后任何一次「停止」都杀不到它**（界面显示已停止、它继续解）。
            # 现在持锁、基于**当前列表**过滤，绝不丢新登记项。
            self._tool_procs[:] = [p for p in self._tool_procs if p.poll() is None]
        for p in procs:
            try:
                if p.poll() is None:
                    _resume_proc(p)          # 万一正被挂起，先恢复再杀
                    p.terminate()
                    self._killed_pids.add(p.pid)    # 记住"这是我们杀的"
                    n += 1
            except Exception:                   # noqa: BLE001
                pass
        return n

    def _rollback_guarded(self, ledger: _Ledger) -> None:
        """取消/失败时的回滚开关。

        **强制停**（`force_stop` 置位）⇒ **不回滚**：已解出的内容保留，只清临时文件
        （沙箱与 `.rc-part` 由各自的 finally 负责）。取舍是：
        不回滚，直接 kill + 删临时文件夹就行 —— **下次重新解压就行**。
        反正重跑本来就会重解，不必为了"干净"去删已经解好的东西。
        其余情况（失败、密码错、普通取消）照旧回滚。
        """
        if self.force_stop.is_set():
            self._log("warn", "已按强制停止处理：已解出内容保留，未执行回滚。")
            return
        self._rollback(ledger)

    def _rollback(self, ledger: _Ledger) -> None:
        """只回滚**本包账本里**写出去的文件与新建目录（改造 A）。

        🩸 本包**覆盖掉**的那些路径要先**还原用户原文件的备份**，再删真正的
        新增产物 —— 旧实现无差别 `os.remove`，把"覆盖前就存在的用户文件"一起删了，
        等于用"回滚"制造了一次数据丢失。
        """
        restored = set()
        for final, bak in ledger.replaced:
            try:
                if os.path.exists(bak):
                    os.replace(bak, final)          # 把用户原文件放回原位
                    restored.add(final)
            except OSError:
                pass
        for p in reversed(ledger.paths):
            if p in restored:
                continue                             # 已还原成本包覆盖前的用户文件，不能删
            try:
                os.remove(p)
            except OSError:
                pass
        for d in sorted(ledger.dirs, key=len, reverse=True):
            try:
                if os.path.isdir(d) and not os.listdir(d):
                    os.rmdir(d)
            except OSError:
                pass
        ledger.paths.clear()
        ledger.dirs.clear()
        ledger.replaced.clear()
        ledger.bytes = 0

    def _clean_dirs(self) -> int:
        """清理解压产生的空目录：只动**本包账本里记录过的**目录。

        教训：旧实现遍历整个源树找空目录，会把**用户自己原有的空目录**一起删掉
        （源码注释当时还声称"绝不动"，实际不成立）。
        """
        removed = 0
        with self._lock:
            cands = sorted(set(self._all_dirs), key=len, reverse=True)
        for d in cands:
            try:
                if os.path.isdir(d) and not os.listdir(d):
                    os.rmdir(d)
                    removed += 1
            except OSError:
                pass
        return removed

    def _delete_source(self, path: str) -> None:
        if is_document_like(path):
            self._log("info", f"原文件像 Office/文档类（内部也是 zip），不删：{path}")
            return
        if is_pe_shell(path):
            # 自解压 exe：解出来的是安装包内容，原 exe 往往还要用（家人场景更不能替他们删）
            self._log("warn", f"原文件是 .exe 外壳（自解压包），为安全起见不删：{path}")
            return
        try:
            os.remove(path)
            self.stats.deleted += 1
            self._log("info", f"已删除原压缩包：{path}")
        except OSError as exc:
            self._log("warn", f"删除原压缩包失败：{path} —— {exc}")

    def _mark_failed(self, path: str) -> None:
        base = os.path.basename(path)
        if ".failed" in base:
            return                                          # 别每轮再叠一层 .failed
        if is_pe_shell(path):
            # 普通 exe 尾巴碰巧含压缩签名时会被判"失败"，改名会破坏用户的程序
            self._log("warn", f"原文件是 .exe，不添加 .failed 标记：{base}")
            return
        target = path + ".failed"
        i = 1
        while os.path.exists(target):
            target = f"{path}.failed.{i}"
            i += 1
        try:
            os.rename(path, target)
            self._log("info", f"已标记失败：{os.path.basename(target)}")
        except OSError as exc:
            self._log("warn", f"标记失败文件出错：{path} —— {exc}")

    # -------------------------------------------------- 写盘原语

    def _prepare_target(self, target: str, counter: Optional[dict] = None) -> Optional[str]:
        """按覆盖策略决定最终写入路径；返回 None 表示跳过。

        加锁 + `_claimed`：并行时同层不同包可能往同一目录写同名文件。

        🩸 **不可逆**：跳过数以前记在**实例级** `self._skip_existing` 上，
        而 `_handle` 每个包开头都把它清 0 ⇒ 并行时 A 的计数会被 B 清零 ⇒ A 的
        `skipped_members` 报成 0 ⇒ "有跳过就不删源包"的保护失效 ⇒ **源包被真删掉**。
        现在改成写进**本包的 counter**（每包独立，杜绝串扰）。
        """
        def _bump() -> None:
            if counter is not None:
                counter["skip_existing"] = counter.get("skip_existing", 0) + 1

        with self._name_lock:
            key = os.path.normcase(target)
            if not os.path.exists(target) and key not in self._claimed:
                self._claimed.add(key)
                return target
            if self.opt.overwrite == "skip":
                _bump()
                return None
            if self.opt.overwrite == "overwrite" and os.path.isfile(target) \
                    and not _is_reparse(target):
                # 🩸 `beside_flat` + overwrite 时，包里一个叫 `x.zip` 的成员
                # 会把**同目录里另一个待处理的源压缩包**覆盖掉（源包被毁、报告计数也不自洽）
                if _real_norm(target) in self._source_paths:
                    self._log("warn", f"  目标是本次待处理的压缩包，拒绝覆盖：{os.path.basename(target)}")
                    _bump()
                    return None
                return target
            root, ext = os.path.splitext(target)
            for i in range(2, 9999):
                cand = f"{root} ({i}){ext}"
                ck = os.path.normcase(cand)
                if not os.path.exists(cand) and ck not in self._claimed:
                    self._claimed.add(ck)
                    return cand
            return None

    def _mkdirs(self, path: str, ledger: Optional[_Ledger] = None) -> None:
        """建目录；把**新建的**那几层登记进账本（供回滚与 --clean 只删自己建的）。

        带"已知存在"缓存：每个文件都重走一遍 `isdir` 会让大包明显变慢。
        """
        if not path:
            return
        key = os.path.normcase(path)
        if key in self._known_dirs:
            return
        if os.path.isdir(path):
            self._known_dirs.add(key)
            return
        missing = []
        cur = path
        while cur and not os.path.isdir(cur):
            missing.append(cur)
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        os.makedirs(path, exist_ok=True)
        self._known_dirs.add(key)
        if ledger is not None:
            ledger.dirs.extend(reversed(missing))

    def _write_stream(self, src, target: str, counter: dict, ledger: _Ledger,
                      file_size: Optional[int] = None, ratio_guard: bool = False) -> None:
        """流式写盘：**先写同目录临时文件再原子 replace**。

        这样 `--overwrite overwrite` 中途失败也不会把用户原文件删掉 / 清成 0 字节。
        v1.4.0：顺手维护"单文件进度"（`file_size` 已知时，UI 才能画第二条进度条）。

        🩸 `overwrite` 档下 target 可能**就是用户原有的文件**，`os.replace` 一执行
        原内容就没了；旧代码又把这个路径记进账本，包一旦失败回滚就 `os.remove(target)` ⇒
        **"回滚"把用户原文件删掉了**（与代码自己的承诺相反）。现在覆盖前先把原文件改名成
        同目录备份并记进账本：成功结束删备份、失败回滚**还原备份**。

        🩸 `ratio_guard=True` 时叠加**运行期压缩比闸**（tar / 裸流拿不到整包
        声明值时用）—— 旧代码在这条路上完全没有比闸，305 KB 的 tar.xz 能静默写出 2 GiB。
        """
        self._file_begin(os.path.basename(target), file_size, defer=True)
        parent = os.path.dirname(target)
        self._mkdirs(parent, ledger)
        tmp = target + PART_SUFFIX
        bak = ""
        written = 0
        try:
            with open(tmp, "wb") as dst:
                while True:
                    if self._wait_if_paused():
                        raise Cancelled("用户取消")
                    chunk = src.read(COPY_BUF)
                    if not chunk:
                        break
                    written += len(chunk)
                    counter["bytes"] += len(chunk)
                    self._file_advance(len(chunk))
                    self._pkg_advance(counter_bytes=counter["bytes"])
                    if written > self.opt.max_file_bytes:
                        raise BombDetected(f"单文件超过 {human_size(self.opt.max_file_bytes)}")
                    if counter["bytes"] > self.opt.max_total_bytes:
                        raise BombDetected(f"单包总解压量超过 {human_size(self.opt.max_total_bytes)}")
                    if ratio_guard and counter["bytes"] > RATIO_RUNTIME_FLOOR:
                        ps = int(getattr(self._tls, "pkg_size", 0) or 0)
                        if ps > 0 and counter["bytes"] / ps > self.opt.bomb_ratio:
                            raise BombDetected(
                                f"实际解压量 {human_size(counter['bytes'])} 相对源包 "
                                f"{human_size(ps)} 已达 {counter['bytes'] / ps:.0f}:1（超出上限）")
                    dst.write(chunk)
            if os.path.lexists(target):
                # 覆盖前先保住用户原文件（失败要能还原，见 docstring）
                bak = f"{target}{PART_BACKUP}{os.getpid()}-{os.urandom(4).hex()}"
                try:
                    os.replace(target, bak)
                except OSError:
                    bak = ""
            os.replace(tmp, target)
        except BaseException:
            try:
                os.remove(tmp)
            except OSError:
                pass
            if bak:                                 # 把用户原文件放回去
                try:
                    os.replace(bak, target)
                except OSError:
                    pass
            raise
        ledger.add_file(target, written)
        if bak:
            ledger.add_replaced(target, bak)
        self._pkg_file_add()

    # -------------------------------------------------- zip

    def _extract_zip(self, path: str, dest: str, counter: dict,
                     password: str, ledger: _Ledger) -> None:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > self.opt.max_entries:
                raise BombDetected(f"条目数 {len(infos)} 超过上限 {self.opt.max_entries}")
            prefix = self._smart_prefix_names(path, [fix_zip_name(i) for i in infos])
            self._pkg_total(sum(max(0, i.file_size) for i in infos))
            encrypted = any(i.flag_bits & 0x0001 for i in infos)
            if any(i.compress_type == 99 for i in infos):
                # WinZip AES：zipfile 解不了。优先用 pyzipper（能处理非 ASCII 密码），
                # 没有才退回外部 bsdtar —— 后者读不了中文密码。
                try:
                    import pyzipper   # noqa: F401
                except ImportError:
                    raise UseExternal("WinZip AES 加密（无 pyzipper）") from None
                self._extract_zip_aes(path, dest, counter, password, ledger)
                return
            pwd = None
            if encrypted:
                if not password:
                    raise NeedPassword("该 zip 有加密条目")
                pwd = password.encode("utf-8", "surrogateescape")
            for info in infos:
                if self._wait_if_paused():
                    raise Cancelled("用户取消")
                name = self._strip_prefix(fix_zip_name(info), prefix)
                if info.is_dir() or name.endswith("/"):
                    rel = sanitize_rel(name)
                    if rel:
                        self._mkdirs(safe_join(dest, rel), ledger)
                    else:
                        # 🩸 目录条目被丢弃时**也要计 skipped** —— 否则
                        # `skipped_members==0` 会让"有跳过就不删源包"那道闸失效（照样删源）。
                        self._log("warn", f"  跳过不安全的目录条目：{name!r}")
                        counter["skipped"] = counter.get("skipped", 0) + 1
                    continue
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    self._log("warn", f"  跳过符号链接：{name}")
                    counter["skipped"] = counter.get("skipped", 0) + 1
                    continue
                if info.compress_size > 0 and info.file_size > self.opt.bomb_min_bytes:
                    ratio = info.file_size / info.compress_size
                    if ratio > self.opt.bomb_ratio:
                        raise BombDetected(f"{name} 压缩比 {ratio:.0f}:1 异常")
                rel = sanitize_rel(name)
                if rel is None:
                    self._log("warn", f"  跳过不安全路径：{name!r}")
                    counter["skipped"] = counter.get("skipped", 0) + 1
                    continue
                target = self._prepare_target(safe_join(dest, rel), counter)
                if target is None:
                    self._log("info", f"  已存在，跳过：{rel}")
                    continue
                try:
                    with zf.open(info, pwd=pwd) as src:
                        self._write_stream(src, target, counter, ledger, file_size=info.file_size)
                except (RuntimeError, zipfile.BadZipFile) as exc:
                    if "password" in str(exc).lower():
                        raise NeedPassword(str(exc)) from exc
                    raise

    def _extract_zip_aes(self, path: str, dest: str, counter: dict,
                         password: str, ledger: _Ledger) -> None:
        """WinZip AES 加密 zip —— 走 pyzipper（bsdtar 读不了非 ASCII 密码）。"""
        import pyzipper
        if not password:
            raise NeedPassword("该 zip 是 WinZip AES 加密")
        with pyzipper.AESZipFile(path) as zf:
            zf.setpassword(password.encode("utf-8", "surrogateescape"))
            infos = zf.infolist()
            prefix = self._smart_prefix_names(path, [fix_zip_name(i) for i in infos])
            self._pkg_total(sum(max(0, i.file_size) for i in infos))
            for info in infos:
                if self._wait_if_paused():
                    raise Cancelled("用户取消")
                name = self._strip_prefix(fix_zip_name(info), prefix)
                if info.is_dir() or name.endswith("/"):
                    rel = sanitize_rel(name)
                    if rel:
                        self._mkdirs(safe_join(dest, rel), ledger)
                    else:
                        # 🩸 目录条目被丢弃时**也要计 skipped** —— 否则
                        # `skipped_members==0` 会让"有跳过就不删源包"那道闸失效（照样删源）。
                        self._log("warn", f"  跳过不安全的目录条目：{name!r}")
                        counter["skipped"] = counter.get("skipped", 0) + 1
                    continue
                rel = sanitize_rel(name)
                if rel is None:
                    self._log("warn", f"  跳过不安全路径：{name!r}")
                    counter["skipped"] = counter.get("skipped", 0) + 1
                    continue
                target = self._prepare_target(safe_join(dest, rel), counter)
                if target is None:
                    self._log("info", f"  已存在，跳过：{rel}")
                    continue
                try:
                    with zf.open(info) as src:
                        self._write_stream(src, target, counter, ledger, file_size=info.file_size)
                except Exception as exc:                    # noqa: BLE001
                    if "password" in str(exc).lower():
                        raise NeedPassword(str(exc)) from exc
                    raise

    # -------------------------------------------------- 沙箱通道（7z / 外部工具）

    def _make_sandbox(self, dest: str) -> str:
        """建本包私有的暂存目录（放在目标目录的父目录里 ⇒ 同盘，搬移用 os.replace 才快）。

        名字带 pid，方便下次启动时把"上次被强杀留下的"沙箱扫掉（见 `_sweep_sandboxes`）。
        """
        base = os.path.dirname(os.path.abspath(dest)) or os.path.abspath(dest)
        os.makedirs(base, exist_ok=True)
        self._sweep_sandboxes(base)
        sbx = tempfile.mkdtemp(prefix=f"{SANDBOX_PREFIX}{os.getpid()}-", dir=base)
        # 留"本沙箱是程序建的"证据（含 pid / 建立时间 / 版本），供清扫与排查用。
        try:
            with open(os.path.join(sbx, SANDBOX_OWNER), "w", encoding="utf-8") as f:
                f.write(f"{os.getpid()}\n{int(time.time())}\n{APP_NAME} {VERSION}\n")
        except OSError:
            pass
        return sbx

    @staticmethod
    def _sweep_sandboxes(base: str) -> None:
        """清掉**已经没有活进程**在用的沙箱残留（目录 + 7z-SFX 裁切出来的文件）。

        正常路径都会清理干净；只有进程被强杀/断电才会留下。按 pid 判活，绝不误删别的实例在用的。

        🩸 **名字必须严格匹配我们自己的格式**才敢删 ——
        旧实现只判 `.rc-sbx-` 前缀，实测会把用户的 `.rc-sbx-notes`、`.rc-sbx-12345670-old`
        连内容一起 rmtree 掉（不可逆）。我们的格式是：
        `.rc-sbx-<pid>-<8位随机>`（目录）与 `.rc-sbx-7zsfx-<pid>-<8位hex>.7z`（文件）。
        顺带修掉"只认目录"的问题：7z-SFX 残留是**文件**，旧逻辑永远清不掉。

        🩸 名字对了也还不够 —— 实测用户自己放一个严格同名的目录就会被整棵删掉。
        现在**目录必须带 `SANDBOX_OWNER` 标记文件**才删（我们每个沙箱都写一个），
        没有标记就跳过，一个字节都不碰。
        """
        try:
            names = os.listdir(base)
        except OSError:
            return
        for n in names:
            m = _SANDBOX_NAME_RE.fullmatch(n)
            if not m:
                continue                                # 不是我们的命名 ⇒ 一个字节都不碰
            pid = int(m.group(1))
            if pid == os.getpid() or _pid_alive(pid):
                continue
            full = os.path.join(base, n)
            try:
                if os.path.isdir(full) and not _is_reparse(full):
                    if not os.path.isfile(os.path.join(full, SANDBOX_OWNER)):
                        continue                        # 不是我们建的 ⇒ 绝不 rmtree
                    _rmtree_force(full)
                elif os.path.isfile(full):
                    os.remove(full)
            except OSError:
                pass

    def _adopt(self, sbx: str, dest: str, counter: dict, ledger: _Ledger,
               pkg_path: str = "") -> int:
        """把沙箱里的产物逐个搬进 dest。

        每个条目都过：**拒绝链接** → `sanitize_rel` → `safe_join`（realpath 越界校验，
        外部工具此前完全没有这层）→ `_prepare_target`（走覆盖策略）
        → `os.replace` 原子搬移。返回搬出的文件数。

        智能解压（Bandizip 式）：沙箱根下若只有一个与包同名的文件夹，搬移时把这一层剥掉。
        """
        prefix = self._smart_prefix_dir(sbx, pkg_path)
        only = prefix.rstrip("/")

        def _adj(rel: str) -> str:
            if not prefix:
                return rel
            if rel == only:
                return ""                       # 顶层那个同名文件夹本身 ⇒ 不搬
            return rel[len(prefix):] if rel.startswith(prefix) else rel

        dirs: list[tuple[str, str]] = []
        files: list[tuple[str, str]] = []
        for dp, dirnames, filenames in os.walk(sbx):
            # 🩸 Windows 上 junction 的 `is_dir(follow_symlinks=False)` 也是 True、
            # `islink()` 也是 False ⇒ 光判文件不够，**必须把 reparse 目录从遍历里剪掉**，
            # 否则 walk 会走进 junction，把沙箱外的文件搬进输出目录（真机 6/6 命中）。
            dirnames[:] = [d for d in dirnames if not _is_reparse(os.path.join(dp, d))]
            for d in dirnames:
                full = os.path.join(dp, d)
                rel = _adj(os.path.relpath(full, sbx).replace(os.sep, "/"))
                if rel:
                    dirs.append((full, rel))
            for fn in filenames:
                if fn == SANDBOX_OWNER:
                    continue                    # 这是我们自己的沙箱标记，不是产物
                full = os.path.join(dp, fn)
                # 再对每个文件做一遍 realpath 复核（万一还有别的换道方式）
                if not self._inside(sbx, full):
                    self._log("warn", f"  跳过越出沙箱的条目：{fn}")
                    counter["skipped"] = counter.get("skipped", 0) + 1
                    continue
                rel = _adj(os.path.relpath(full, sbx).replace(os.sep, "/"))
                if rel:
                    files.append((full, rel))

        dropped = 0
        for _full, rel in dirs:
            safe = sanitize_rel(rel)
            if safe is None:
                dropped += 1
                continue
            self._mkdirs(safe_join(dest, safe), ledger)
        if dropped:
            self._log("warn", f"  跳过 {dropped} 个不安全的目录条目")
            counter["skipped"] = counter.get("skipped", 0) + dropped

        moved = 0
        self._file_clear()          # 搬移阶段没有"单文件进度"（os.replace 是瞬时的）
        for full, rel in files:
            if self._wait_if_paused():
                raise Cancelled("用户取消")
            if _is_reparse(full):
                self._log("warn", f"  跳过链接条目：{rel}")
                counter["skipped"] = counter.get("skipped", 0) + 1
                continue
            safe = sanitize_rel(rel)
            if safe is None:
                self._log("warn", f"  跳过不安全路径：{rel!r}")
                counter["skipped"] = counter.get("skipped", 0) + 1
                continue
            target = safe_join(dest, safe)
            if os.path.lexists(target) and _is_reparse(target):
                self._log("warn", f"  目标是链接，跳过（不写穿）：{safe}")
                counter["skipped"] = counter.get("skipped", 0) + 1
                continue
            final = self._prepare_target(target, counter)
            if final is None:
                self._log("info", f"  已存在，跳过：{safe}")
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            if size > self.opt.max_file_bytes:
                raise BombDetected(f"单文件超过 {human_size(self.opt.max_file_bytes)}")
            counter["bytes"] += size
            self._pkg_advance(counter_bytes=counter["bytes"])
            if counter["bytes"] > self.opt.max_total_bytes:
                raise BombDetected(f"单包总解压量超过 {human_size(self.opt.max_total_bytes)}")
            self._mkdirs(os.path.dirname(final), ledger)
            os.replace(full, final)
            ledger.add_file(final, size)
            self._pkg_file_add()
            moved += 1
        return moved

    def _sandbox_extract(self, path: str, dest: str, counter: dict, ledger: _Ledger,
                         runner: Callable[[str], None], label: str) -> int:
        sbx = self._make_sandbox(dest)
        prev_sbx = getattr(self._tls, "sbx", "")
        self._tls.sbx = sbx                      # 供 _tick_sbx 轮询"已解出多少字节"
        try:
            runner(sbx)
            moved = self._adopt(sbx, dest, counter, ledger, path)
            if moved == 0 and not _sbx_entries(sbx):
                raise ExtractError(f"{label} 没有解出任何内容")
            return moved
        finally:
            self._tls.sbx = prev_sbx
            # 🩸 ISO 解出来的目录带 ReadOnly ⇒ `rmtree(ignore_errors=True)` 在
            # Windows 上静默失败、沙箱在用户源目录里只增不减。改用会摘只读位的版本，并把
            # "确实删不掉"如实写进日志（不再假装清理过）。
            if not _rmtree_force(sbx):
                self._log("warn", f"临时目录未能删除（可能被别的程序占用）：{sbx}")

    # -------------------------------------------------- 7z

    def _extract_7z(self, path: str, dest: str, counter: dict,
                    password: str, ledger: _Ledger, sfx: int = 0) -> None:
        try:
            import py7zr
        except ImportError as exc:                          # pragma: no cover
            raise ExtractError(f"缺少 py7zr，无法解 7z：{exc}") from exc

        # 自解压 7z 外壳：py7zr 从文件头找签名，所以要先把压缩数据段裁出来。
        # 裁切文件用沙箱同款前缀放在目标旁边 ⇒ 万一异常残留，下次运行会被按 pid 判活清扫。
        src, part = path, ""
        if sfx > 0:
            base = os.path.dirname(dest) or dest
            # 🩸 `out_dir` + 子目录时父目录可能还不存在 ⇒ 旧写法直接 open 会失败，
            # 嵌套的自解压 7z **必然**解不开（平坦布局下恰好父目录存在所以没暴露）。
            os.makedirs(base, exist_ok=True)
            part = os.path.join(base, f"{SANDBOX_PREFIX}7zsfx-{os.getpid()}-{os.urandom(4).hex()}.7z")
            try:
                with open(path, "rb") as fi, open(part, "wb") as fo:
                    fi.seek(sfx)
                    shutil.copyfileobj(fi, fo, 1 << 20)
            except OSError as exc:
                raise ExtractError(f"读取自解压外壳失败：{exc}") from exc
            src = part
            self._add_scratch(part)             # 交给 _run_one 的 finally 兜底清理（按包隔离）

        def _drop_part() -> None:
            if part:
                try:
                    os.remove(part)
                except OSError:
                    pass

        try:
            zf = py7zr.SevenZipFile(src, mode="r", password=password or None)
        except Exception as exc:                            # noqa: BLE001
            _drop_part()
            self._raise_pwd_or_original(exc, bool(password))
            return
        with zf:
            names = list(zf.getnames())
            if len(names) > self.opt.max_entries:
                raise BombDetected(f"条目数 {len(names)} 超过上限 {self.opt.max_entries}")
            fi_list = list(zf.list())               # 与 names 同序（下面按 index 取声明大小）
            pairs, pair_sizes, unsafe = [], [], 0
            for idx, n in enumerate(names):
                if not _same_rel(n):
                    unsafe += 1
                    continue
                pairs.append(n)
                u = getattr(fi_list[idx], "uncompressed", None) if idx < len(fi_list) else None
                pair_sizes.append(u if isinstance(u, int) and u > 0 else 0)
            if unsafe:
                self._log("warn", f"  跳过 {unsafe} 条不安全/畸形路径条目")
                counter["skipped"] = counter.get("skipped", 0) + unsafe
            if not pairs:
                raise ExtractError("包内没有可安全解出的条目")
            # 压缩比判据（另一半：max_file_bytes 已由沙箱核账兜住，
            # bomb_ratio 需要在这里按声明值预检）
            self._pkg_total(sum(fi.uncompressed for fi in fi_list
                                if isinstance(getattr(fi, "uncompressed", None), int)))
            for fi in fi_list:
                usize = getattr(fi, "uncompressed", None)
                csize = getattr(fi, "compressed", None)
                if isinstance(usize, int) and isinstance(csize, int) \
                        and usize > self.opt.bomb_min_bytes and csize > 0:
                    ratio = usize / csize
                    if ratio > self.opt.bomb_ratio:
                        fn = getattr(fi, "filename", "?")
                        raise BombDetected(f"{fn} 压缩比 {ratio:.0f}:1 异常")
            try:
                needs = bool(zf.needs_password())
            except Exception:                               # noqa: BLE001
                needs = False
            if needs and not password:
                raise NeedPassword("该 7z 已加密")

            # 分批：**既按条目数、也按声明字节**切。
            # 旧实现固定 32 条目 —— 若这 32 个恰好都是大文件，批内要写出 900 MiB 才轮到
            # 检查点，暂停/取消都"按不住"（实测暂停后仍写 901.9 MiB 才收手）。
            # 现在任何一批的声明总量都不超过 32 MiB。
            batches: list[tuple[list[str], int]] = []
            cur: list[str] = []
            acc = 0
            for nm, sz in zip(pairs, pair_sizes):
                cur.append(nm)
                acc += sz
                if len(cur) >= 32 or acc >= (32 << 20):
                    batches.append((cur, acc))
                    cur, acc = [], 0
            if cur:
                batches.append((cur, acc))
            # 🩸 与「解压大量文件偶发未响应」同源：旧实现**每批之后都 `_dir_size(sbx)`
            # 全量遍历沙箱** ⇒ 成员多时是 O(条目数²)（几万文件时每批 1~3 秒、还把 GIL 占满）。
            # 现在直接用**声明字节累加**推进度；只有 py7zr 给不出任何声明大小时才退回遍历。
            have_sizes = any(sz > 0 for sz in pair_sizes)

            def runner(sbx: str) -> None:
                # 小批提取 + 批间核账 ⇒ 取消与炸弹都有响应点
                done = 0
                declared_done = 0
                for i, (chunk, chunk_bytes) in enumerate(batches):
                    if self._wait_if_paused():
                        raise Cancelled("用户取消")
                    try:
                        zf.extract(path=sbx, targets=chunk)
                    except Exception as exc:                # noqa: BLE001
                        if i == 0:
                            zf.extractall(path=sbx)         # 分批不被支持则退回一次性
                            break
                        self._raise_pwd_or_original(exc, bool(password))
                    finally:
                        # 🩸 **每批之后必须 reset()** —— py7zr 的
                        # `extract(targets=…)` 用完不 reset，下一批在 **solid** 包上会永久卡死
                        # （实测：solid ≤32 条目 OK，33/34/41/101 条目 25 秒内不返回；
                        # `-ms=off` 的非 solid 包不卡）。旧实现的 `if i == 0` 兜底只管第一批。
                        try:
                            zf.reset()
                        except Exception:                    # noqa: BLE001
                            pass
                    done += len(chunk)
                    if have_sizes:
                        declared_done += chunk_bytes
                        total = declared_done
                    else:
                        total = self._dir_size(sbx, budget=SBX_SCAN_BUDGET)
                    # 7z 没有"逐文件"回调 ⇒ 只报本包字节进度，UI 会自动回退到包级显示。
                    self._pkg_advance(sbx_bytes=total)
                    self._pkg_note(f"分批提取 {done}/{len(pairs)} 个条目")
                    if total > self.opt.max_total_bytes:
                        raise BombDetected(f"实际解压量超过 {human_size(self.opt.max_total_bytes)}")
                if done == 0 and not _sbx_entries(sbx):
                    raise ExtractError("7z 未解出任何内容")

            self._sandbox_extract(path, dest, counter, ledger, runner, "7z")
        _drop_part()

    @staticmethod
    def _raise_pwd_or_original(exc: Exception, password_used: bool) -> None:
        """把"需要密码/密码错"的异常统一转成 NeedPassword。

        ★ 只在**确实用过密码**时才把 Crc/LZMA 错误当成密码问题
        （旧实现见 crc 就转 NeedPassword，把未加密的损坏 7z 误判成"需要密码"，
        于是跳过 + 半成品残留）。
        """
        name = type(exc).__name__
        msg = str(exc)
        low = msg.lower()
        if "password" in low or "Password" in name:
            raise NeedPassword(f"{name}: {msg}") from exc
        if password_used and ("crc" in low or "Crc" in name or "lzma" in name.lower()):
            raise NeedPassword(f"密码不正确或文件损坏（{name}: {msg}）") from exc
        raise exc

    # -------------------------------------------------- tar / 单文件压缩

    def _extract_tar_or_single(self, path: str, kind: str, dest: str,
                               counter: dict, ledger: _Ledger) -> None:
        try:
            self._extract_tar(path, dest, counter, ledger)
            return
        except (tarfile.ReadError, tarfile.CompressionError, tarfile.StreamError):
            if kind == "tar":
                raise ExtractError("tar 解析失败（文件可能损坏）") from None
        self._extract_single(path, kind, dest, counter, ledger)

    def _extract_tar(self, path: str, dest: str, counter: dict, ledger: _Ledger) -> None:
        with tarfile.open(path, "r:*") as tf:
            members = tf.getmembers()
            if len(members) > self.opt.max_entries:
                raise BombDetected(f"条目数 {len(members)} 超过上限 {self.opt.max_entries}")
            prefix = self._smart_prefix_names(path, [m.name for m in members])
            declared = sum(max(0, m.size or 0) for m in members if m.isfile())
            self._pkg_total(declared)
            # 🩸 tar 通路此前**完全没有压缩比闸** —— 实测 305 KB 的 tar.xz
            # （单个 2 GiB 全 0 成员，声明比 6871:1）被原样写出。这里按声明总量与包体积判。
            if declared > self.opt.bomb_min_bytes:
                pkg_size = max(1, os.path.getsize(path))
                ratio = declared / pkg_size
                if ratio > self.opt.bomb_ratio:
                    raise BombDetected(f"声明压缩比 {ratio:.0f}:1 异常（{human_size(declared)}"
                                       f" / {human_size(pkg_size)}）")
            skipped = 0
            done = 0
            for m in members:
                if self._wait_if_paused():
                    raise Cancelled("用户取消")
                mname = self._strip_prefix(m.name, prefix)
                if m.isdir():
                    rel = sanitize_rel(mname)
                    if rel:
                        self._mkdirs(safe_join(dest, rel), ledger)
                    else:
                        # 目录条目被丢弃同样算"有跳过"（否则删源包闸失效）
                        self._log("warn", f"  跳过不安全的目录条目：{mname!r}")
                        skipped += 1
                    continue
                if m.issym() or m.islnk():
                    self._log("warn", f"  跳过链接条目：{mname}")
                    skipped += 1
                    continue
                if not m.isfile():
                    self._log("warn", f"  跳过特殊条目：{mname}")
                    skipped += 1
                    continue
                rel = sanitize_rel(mname)
                if rel is None:
                    self._log("warn", f"  跳过不安全路径：{mname!r}")
                    skipped += 1
                    continue
                target = self._prepare_target(safe_join(dest, rel), counter)
                if target is None:
                    self._log("info", f"  已存在，跳过：{rel}")
                    continue
                src = tf.extractfile(m)
                if src is None:
                    skipped += 1
                    continue
                with src:
                    self._write_stream(src, target, counter, ledger, file_size=m.size,
                                       ratio_guard=True)
                done += 1
            counter["skipped"] = counter.get("skipped", 0) + skipped
            if done == 0 and skipped:
                raise ExtractError(f"tar 内 {skipped} 个条目全部被跳过，没有可解出的内容")

    def _extract_single(self, path: str, kind: str, dest: str,
                        counter: dict, ledger: _Ledger) -> None:
        base = os.path.basename(path)
        out_name, ext = os.path.splitext(base)
        ext_l = ext.lower()
        if not out_name or ext_l not in (".gz", ".bz2", ".xz", ".zst", ".zstd",
                                         ".tgz", ".tbz", ".tbz2", ".txz"):
            out_name = base + "_out"
        if kind == "gzip" or ext_l in (".gz", ".tgz"):
            src = gzip.open(path, "rb")
        elif kind == "bzip2" or ext_l in (".bz2", ".tbz", ".tbz2"):
            src = bz2.open(path, "rb")
        elif kind == "xz" or ext_l in (".xz", ".txz"):
            src = lzma.open(path, "rb")
        elif kind == "zstd" or ext_l in (".zst", ".zstd"):
            src = self._open_zstd(path)
        else:
            raise ExtractError(f"不支持的裸压缩流：{base}（识别为 {kind}）")
        rel = sanitize_rel(out_name) or (base + "_out")
        # 🩸 裸压缩流此前没有任何比闸。gzip 尾部带 ISIZE（原始长度），
        # 先按它做声明值预检；其余（bz2/xz/zst）交给 _write_stream 的运行期闸。
        if kind == "gzip" or ext_l in (".gz", ".tgz"):
            declared = self._gzip_isize(path)
            if declared > self.opt.bomb_min_bytes:
                pkg_size = max(1, os.path.getsize(path))
                ratio = declared / pkg_size
                if ratio > self.opt.bomb_ratio:
                    raise BombDetected(f"声明压缩比 {ratio:.0f}:1 异常（{human_size(declared)}"
                                       f" / {human_size(pkg_size)}）")
        target = self._prepare_target(safe_join(dest, rel), counter)
        if target is None:
            self._log("info", f"  已存在，跳过：{out_name}")
            src.close()
            return
        with src:
            self._write_stream(src, target, counter, ledger, ratio_guard=True)

    @staticmethod
    def _gzip_isize(path: str) -> int:
        """读 gzip 尾 4 字节 ISIZE（原始长度 mod 2^32），供裸流声明值预检用。

        取不到就返回 0（调用方据此跳过预检）；ISIZE 回绕时数值会很小，同样不会误触发。
        """
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                if f.tell() < 4:
                    return 0
                f.seek(-4, os.SEEK_END)
                raw = f.read(4)
        except OSError:
            return 0
        return int.from_bytes(raw, "little") if len(raw) == 4 else 0

    @staticmethod
    def _open_zstd(path: str):
        try:
            import pyzstd
            return pyzstd.open(path, "rb")
        except ImportError:
            pass
        try:
            import zstandard
            return zstandard.ZstdDecompressor().stream_reader(open(path, "rb"))
        except ImportError as exc:                          # pragma: no cover
            raise ExtractError(f"缺少 zstd 解压库（pyzstd/zstandard）：{exc}") from exc

    # -------------------------------------------------- 外部工具（rar / iso / cab / AES-zip）

    @staticmethod
    def _bsdtar() -> Optional[str]:
        exe = shutil.which("tar")
        if exe:
            return exe
        cand = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "tar.exe")
        return cand if os.path.exists(cand) else None

    def _run_external(self, args: list[str], password: str,
                      on_tick: Optional[Callable[[], None]] = None) -> None:
        """跑外部解压工具（bsdtar）。

        **同族死锁一起修**：这里原来也是 `Popen(stdout=PIPE, stderr=PIPE)` 不读管道
        （bsdtar 的文件列表/警告同样能把 4 KiB 管道写满），现在统一走 `_run_tool_streaming`。
        """
        exe = self._bsdtar()
        if not exe:
            raise ExtractError("系统没有 tar.exe")
        cmd = [exe, *args]
        if password:
            cmd += ["--passphrase", password]
        rc, lines, _skipped = self._run_tool_streaming(cmd, label="外部解压工具", on_tick=on_tick)
        if rc == 0:
            return
        msg = _pick_reason(lines)[:300]
        low = msg.lower()
        if any(k in low for k in ("passphrase", "password", "encrypted")):
            raise NeedPassword(msg or "需要密码")
        raise ExtractError(f"外部解压失败（rc={rc}）：{msg}")

    def _extract_external(self, path: str, dest: str, kind: str, password: str,
                          counter: dict, ledger: _Ledger) -> None:
        """rar / iso / cab / AES-zip：解到沙箱 → 逐文件校验搬移（改造 B）。

        旧实现是 `bsdtar -xf` 直接往目标目录写，**完全没有 realpath 校验** ——
        目标目录里预置一个 junction 就能写到外面，还会覆盖外部已有文件。
        """
        if not self._bsdtar():
            raise ExtractError(f"系统没有 tar.exe，无法解 {kind}")

        def runner(sbx: str) -> None:
            self._run_external(["-xf", path, "-C", sbx, "--no-same-owner"], password,
                               on_tick=self._tick_sbx)

        self._sandbox_extract(path, dest, counter, ledger, runner, kind)

    # -------------------------------------------------- 报告

    def _write_report(self) -> None:
        base = self.opt.out_dir or next(iter(self._auto_out.values()), "") or \
            (self.src_dirs[0] if self.src_dirs else os.getcwd())
        path = os.path.join(base, "解压报告" + time.strftime("%y_%m_%d_%H%M%S") + ".txt")
        ok = [r for r in self.results if r.status == "ok"]
        bad = [r for r in self.results if r.status == "failed"]
        skip = [r for r in self.results if r.status == "skipped"]
        layout_text = {
            "beside_folder": "每个压缩包 → 它旁边的同名文件夹",
            "beside_flat": "解压到压缩包所在文件夹（内容铺开）",
            "out_dir": "全部解压到同一文件夹（每个包一个子目录）",
            "out_dir_flat": "全部解压到同一文件夹（内容铺开）",
        }.get(self.opt.layout, self.opt.layout)

        lines = [
            "递归解压 · 处理报告",
            "=" * 52,
            f"时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"源目录：{'；'.join(self.src_dirs)}",
            f"输出方式：{layout_text}",
            f"并行度：{self._workers()}",
            f"密码：{'已填写（仅用于需要密码的包）' if self.opt.password else '未填写'}",
        ]
        if self.cancel.is_set():
            lines.append("⚠ 本次运行被用户取消，以下为取消前的结果")
        lines += [
            "",
            f"发现压缩包 {self.stats.archives_found} 个（含嵌套）",
            f"成功 {self.stats.archives_done} · 失败 {self.stats.archives_failed} · 跳过 {self.stats.archives_skipped}",
            f"写出 {self.stats.files_written} 个文件 / {human_size(self.stats.bytes_written)}",
            f"删除原包 {self.stats.deleted} 个 · 清理空目录 {self.stats.empty_dirs_removed} 个",
            f"耗时 {self.stats.elapsed:.1f} 秒",
            "",
        ]
        if bad:
            lines += [f"--- 失败 {len(bad)} 个（需要处理）---"]
            for r in bad:
                lines.append(f"[失败] {r.path}")
                lines.append(f"       原因：{r.note}")
            lines.append("")
        if skip:
            lines += [f"--- 跳过 {len(skip)} 个 ---"]
            for r in skip:
                lines.append(f"[跳过] {r.path}（{r.note}）")
            lines.append("")
        if ok:
            lines += [f"--- 成功 {len(ok)} 个 ---"]
            for r in ok:
                extra = f"｜跳过 {r.skipped_members} 个条目" if r.skipped_members else ""
                lines.append(f"[成功] {r.path} → {r.dest}（{r.kind or '?'}｜{r.files} 个文件，"
                             f"{human_size(r.bytes)}{extra}）")
            lines.append("")
        try:
            with open(path, "w", encoding="utf-8-sig") as f:
                f.write("\n".join(lines) + "\n")
            self._log("info", f"处理报告已写出：{path}")
        except OSError as exc:
            self._log("warn", f"处理报告写不出来：{exc}")

    def _emit(self, done: bool = False, force: bool = False) -> None:
        """把当前进度推给 UI（**节流 ~10 次/秒**；`done`/`force` 立即发）。

        快照分两层，对应 GUI 那两条进度条：
        - 总体：`found` / `done+failed+skipped`（按**包数**，稳定、不会倒退）；
        - 单文件：`file_name` / `file_total` / `file_done` / `file_pct`，
          取不到单文件粒度时 `file_name` 为空 ⇒ GUI 回退用本包（`pkg_*`）画第二条。
        """
        now = time.time()
        if not done and not force and now - self._last_emit < PROGRESS_THROTTLE:
            return
        self._last_emit = now

        with self._lock:
            act = sorted(self._active.values(), key=lambda d: d["seq"])
            cur = act[0] if act else None
            n_act = len(act)
            pkg = dict(cur) if cur else None
            # ★ partial：活跃包各自的完成比例之和。**没有它总进度条在"包很大"时会卡住**——
            # 实测 3 个包并行解 148 MB 时，纯按包数的总条整整 8 秒不动（真机截图暴露）。
            partial = 0.0
            live_bytes = self.stats.bytes_written
            live_files = self.stats.files_written
            slots: list[dict] = []          # 每一个"正在解压的包"一条（"每个包一个进度条"）
            for d in act:
                if d["total"] > 0:
                    partial += min(1.0, d["done"] / d["total"])
                live_bytes += d["done"]
                live_files += d["files"]
                tot = int(d["total"])
                slots.append({
                    "name": d["name"],
                    "file": d["file"],
                    "known": tot > 0,
                    "pct": round(min(100.0, 100.0 * d["done"] / tot), 1) if tot > 0 else 0.0,
                    "done": int(d["done"]),
                    "total": tot,
                })
            # 速率窗口按"当前展示的包"算（切包即清空，否则跨包速率毫无意义）
            key = pkg["name"] if pkg else ""
            if key != self._rate_key:
                self._rate_key = key
                self._rate_win.clear()
            if pkg is not None:
                self._rate_win.append((now, pkg["done"]))
            rate = 0.0
            if len(self._rate_win) >= 3:
                t0, b0 = self._rate_win[0]
                t1, b1 = self._rate_win[-1]
                dt = t1 - t0
                if dt >= 0.6 and b1 > b0:
                    rate = (b1 - b0) / dt
        self._live_bytes_max = max(self._live_bytes_max, live_bytes)
        self._live_files_max = max(self._live_files_max, live_files)
        paused = self.pause.is_set()
        eta = 0.0
        if pkg and pkg["total"] > 0 and rate > 0 and not paused:
            remain = max(0, pkg["total"] - pkg["done"])
            eta = remain / rate

        snap = {
            "found": self.stats.archives_found,
            "done": self.stats.archives_done,
            "failed": self.stats.archives_failed,
            "skipped": self.stats.archives_skipped,
            "files": self.stats.files_written,
            "bytes": self.stats.bytes_written,
            "files_live": self._live_files_max,
            "bytes_live": self._live_bytes_max,
            "partial": round(partial, 3),
            "deleted": self.stats.deleted,
            "done_flag": done,
            "paused": paused,
            "active": n_act,
            "workers": getattr(self, "_nw", 0),
            "slots": slots,
            "pkg_name": pkg["name"] if pkg else "",
            "pkg_total": pkg["total"] if pkg else 0,
            "pkg_done": pkg["done"] if pkg else 0,
            "pkg_note": pkg["note"] if pkg else "",
            "file_name": pkg["file"] if pkg else "",
            "file_total": pkg["file_total"] if pkg else 0,
            "file_done": pkg["file_done"] if pkg else 0,
            "file_pct": pkg["file_pct"] if pkg else -1.0,
            "rate": 0.0 if paused else rate,
            "eta": 0.0 if paused else eta,
        }
        try:
            self._progress(snap)
        except Exception:                                   # noqa: BLE001
            pass


def is_archive(path: str) -> bool:
    return sniff(path) is not None


__all__ = [
    "Extractor", "Options", "Stats", "ArchiveResult", "Job", "VERSION",
    "ExtractError", "UnsafePath", "BombDetected", "Cancelled", "NeedPassword", "UseExternal",
    "sniff", "sanitize_rel", "safe_join", "fix_zip_name", "archive_stem", "human_size",
    "auto_out_dir_name", "detect_workers", "is_document_like",
]
