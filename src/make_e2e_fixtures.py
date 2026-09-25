# -*- coding: utf-8 -*-
"""造 e2e 样本 + 校验产物（用真 exe 跑：RecursiveExtract.exe --cli <src> --password pw123）

    python make_e2e_fixtures.py make      # 造样本
    python make_e2e_fixtures.py verify    # 校验
"""
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from selftest_core import mk7z, mkraw, mktar, mkzip, mkzip_gbk, mkzip_zipcrypto  # noqa: E402

ROOT = os.path.join(os.path.dirname(HERE), "tmp", "e2e")
SRC = os.path.join(ROOT, "src")


def make():
    shutil.rmtree(ROOT, ignore_errors=True)
    os.makedirs(SRC, exist_ok=True)

    # 1) 明文 7z
    mk7z(os.path.join(SRC, "1.7z"), [("docs/a.txt", b"seven-zip")])
    # 2) 老式中文名 zip + 嵌套 zip
    inner = os.path.join(ROOT, "_inner.zip")
    mkzip(inner, [("inner.txt", b"inner-ok")])
    inner_data = open(inner, "rb").read()
    mkzip_gbk(os.path.join(SRC, "2.zip"),
              [("中文目录/文件.txt", b"chinese"), ("inner.zip", inner_data)])
    os.remove(inner)
    # 3) tar.gz
    mktar(os.path.join(SRC, "3.tar.gz"), [("sub/b.txt", b"targz")])
    # 4) 裸 gz
    import gzip
    with gzip.open(os.path.join(SRC, "4.gz"), "wb") as f:
        f.write(b"plain gzip payload")
    # 5) 同一个文件夹里：一个没密码 + 一个要密码（验证"输入一次密码，两个都能解"）
    os.makedirs(os.path.join(SRC, "5-mixed"), exist_ok=True)
    mkzip(os.path.join(SRC, "5-mixed", "plain.zip"), [("p.txt", b"no-pwd")])
    mk7z(os.path.join(SRC, "5-mixed", "secret.7z"), [("s.txt", b"topsecret")], password="pw123")
    # 6) ZipCrypto 加密 zip
    mkzip_zipcrypto(os.path.join(SRC, "6-zipcrypto.zip"), [("s.txt", b"zipcrypto-ok")], "pw123")
    # 7) 后缀骗人：.tar 其实是 zip；无后缀其实是 7z
    mkzip(os.path.join(SRC, "mislabel.tar"), [("mislabeled.txt", b"actually-zip")])
    mk7z(os.path.join(SRC, "_ne.7z"), [("ne.txt", b"actually-7z")])
    os.replace(os.path.join(SRC, "_ne.7z"), os.path.join(SRC, "noext"))
    # 7b) 假 UTF-8 标记的中文名（Python zipfile 往老式包追加时会写出这种包）
    mkzip(os.path.join(SRC, "7b-fakeutf8.zip"),
          [("假标记/文件.txt".encode("gbk").decode("cp437"), b"fake-utf8-flag")])
    # 8) 三层嵌套
    l3 = os.path.join(ROOT, "_l3.zip")
    mkzip(l3, [("l3.txt", b"level-3")])
    l2 = os.path.join(ROOT, "_l2.zip")
    mkzip(l2, [("l2.txt", b"level-2"), ("9.zip", open(l3, "rb").read())])
    mkzip(os.path.join(SRC, "7-deep.zip"),
          [("l1.txt", b"level-1"), ("8.zip", open(l2, "rb").read())])
    os.remove(l3)
    os.remove(l2)
    # 9) 一个解不开的坏包（验证失败路径不拖垮全批）
    mkraw(os.path.join(SRC, "8-broken.zip"), b"PK\x03\x04" + b"\x00" * 64)
    # 10) WinZip AES 加密（**中文密码**，该通路的回归用例）+ zstd 单文件
    import pyzipper
    import pyzstd
    os.makedirs(os.path.join(SRC, "9-cn"), exist_ok=True)
    with pyzipper.AESZipFile(os.path.join(SRC, "9-cn", "aes-cn.zip"), "w",
                             compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as z:
        z.setpassword("中文密码".encode())
        z.setencryption(pyzipper.WZ_AES, nbits=128)
        z.writestr("aes.txt", b"aes-chinese-pwd")
    with open(os.path.join(SRC, "10.zst"), "wb") as f:
        f.write(pyzstd.compress(b"zstd payload"))

    print("样本已生成：", SRC)
    for dp, _dn, fn in os.walk(SRC):
        for f in sorted(fn):
            print("   ", os.path.relpath(os.path.join(dp, f), SRC))


CASES = [
    ("1.7z 明文", "1/docs/a.txt", b"seven-zip"),
    ("中文 zip（老式 GBK）", "2/中文目录/文件.txt", b"chinese"),
    ("嵌套 inner.zip", "2/inner/inner.txt", b"inner-ok"),
    ("tar.gz", "3/sub/b.txt", b"targz"),
    ("裸 gz", "4/4", b"plain gzip payload"),
    ("混装：无密码包", "5-mixed/plain/p.txt", b"no-pwd"),
    ("混装：有密码包（同一次运行）", "5-mixed/secret/s.txt", b"topsecret"),
    ("ZipCrypto 加密 zip", "6-zipcrypto/s.txt", b"zipcrypto-ok"),
    ("后缀骗人 .tar 实为 zip", "mislabel/mislabeled.txt", b"actually-zip"),
    ("无后缀实为 7z", "noext_extracted/ne.txt", b"actually-7z"),
    ("假 UTF-8 标记的中文名", "7b-fakeutf8/假标记/文件.txt", b"fake-utf8-flag"),
    ("zstd 单文件", "10/10", b"zstd payload"),
    ("WinZip AES · 中文密码", "9-cn/aes-cn/aes.txt", b"aes-chinese-pwd"),
    ("三层嵌套 L1", "7-deep/l1.txt", b"level-1"),    ("三层嵌套 L2", "7-deep/8/l2.txt", b"level-2"),
    ("三层嵌套 L3", "7-deep/8/9/l3.txt", b"level-3"),
]


def verify():
    bad = 0
    for name, rel, want in CASES:
        p = os.path.join(SRC, *rel.split("/"))
        if not os.path.isfile(p):
            print(f"[FAIL] {name}：文件不存在 {rel}")
            bad += 1
            continue
        got = open(p, "rb").read()
        if got != want:
            print(f"[FAIL] {name}：内容不对 {rel} -> {got!r}")
            bad += 1
            continue
        print(f"[PASS] {name}")
    report = [f for f in os.listdir(SRC) if f.startswith("解压报告")]
    if report:
        print(f"[PASS] 处理报告已生成：{report[0]}")
    else:
        print("[FAIL] 没有生成处理报告")
        bad += 1
    print(f"\n结果：{'全部通过' if bad == 0 else str(bad) + ' 项失败'}")
    return 1 if bad else 0


if __name__ == "__main__":
    act = sys.argv[1] if len(sys.argv) > 1 else "make"
    sys.exit(verify() if act == "verify" else (make() or 0))
