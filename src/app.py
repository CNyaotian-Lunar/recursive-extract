# -*- coding: utf-8 -*-
"""递归解压 —— 图形界面（tkinter，简洁扁平风）

默认策略：每个压缩包解到「它旁边的同名文件夹」里（如 a.zip → a\\）。
可选：解压到压缩包所在文件夹；或全部解压到指定文件夹。
密码：留空即可；填了以后只对需要密码的包生效，未加密的包不受影响。
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from extract_core import APP_NAME, VERSION, Extractor, Options, detect_workers, human_size

# ---------------------------------------------------------------- 配色

BG = "#f3f4f6"
CARD = "#ffffff"
BORDER = "#e5e7eb"
ACCENT = "#2563eb"
ACCENT_D = "#1d4ed8"
ACCENT_L = "#eff6ff"
DANGER = "#ef4444"
DANGER_D = "#dc2626"
TEXT = "#111827"
MUTED = "#6b7280"
LOG_BG = "#0f172a"
LOG_FG = "#cbd5e1"
OK_FG = "#4ade80"
WARN_FG = "#fbbf24"
ERR_FG = "#f87171"
INFO_FG = "#93c5fd"

FONT = ("Microsoft YaHei UI", 9)
FONT_B = ("Microsoft YaHei UI", 9, "bold")
FONT_TITLE = ("Microsoft YaHei UI", 14, "bold")
FONT_SUB = ("Microsoft YaHei UI", 9)
FONT_LOG = ("Consolas", 9)

CFG_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "RecursiveExtract")
CFG_PATH = os.path.join(CFG_DIR, "settings.json")


def _btn(parent, text, cmd, kind="primary", width=None):
    if kind == "primary":
        b = tk.Button(parent, text=text, command=cmd, bg=ACCENT, fg="white",
                      activebackground=ACCENT_D, activeforeground="white",
                      relief="flat", bd=0, padx=16, pady=7, cursor="hand2",
                      font=FONT_B, disabledforeground="#dbeafe")
        b.bind("<Enter>", lambda e: b.config(bg=ACCENT_D) if b["state"] == "normal" else None)
        b.bind("<Leave>", lambda e: b.config(bg=ACCENT) if b["state"] == "normal" else None)
    elif kind == "ghost":
        b = tk.Button(parent, text=text, command=cmd, bg=CARD, fg=TEXT,
                      activebackground=ACCENT_L, activeforeground=ACCENT,
                      disabledforeground="#9ca3af",
                      relief="solid", bd=1, padx=14, pady=6, cursor="hand2", font=FONT)
        b.config(highlightbackground=BORDER)
        b.bind("<Enter>", lambda e: b.config(bg=ACCENT_L) if b["state"] == "normal" else None)
        b.bind("<Leave>", lambda e: b.config(bg=CARD) if b["state"] == "normal" else None)
    else:  # danger
        b = tk.Button(parent, text=text, command=cmd, bg=DANGER, fg="white",
                      activebackground=DANGER_D, activeforeground="white",
                      relief="flat", bd=0, padx=16, pady=7, cursor="hand2", font=FONT_B)
    if width:
        b.config(width=width)
    return b


def _fmt_eta(sec: float) -> str:
    """剩余时间说成人话（"45 秒" / "3 分 20 秒" / "1 小时 05 分"）。"""
    sec = int(max(0.0, sec))
    if sec < 60:
        return f"{sec} 秒"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m} 分 {s:02d} 秒"
    h, m = divmod(m, 60)
    return f"{h} 小时 {m:02d} 分"


def _proc_image(pid: int) -> str:
    """取某个进程的可执行文件路径（拿不到就返回空串）。"""
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.OpenProcess(0x1000, False, pid)               # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return ""
        try:
            size = ctypes.c_uint(32768)
            buf = ctypes.create_unicode_buffer(size.value)
            if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                return buf.value
            return ""
        finally:
            k.CloseHandle(h)
    except Exception:                                       # noqa: BLE001
        return ""


def hide_own_console() -> None:
    """双击 exe 时那个黑控制台要藏掉，但**绝不能藏掉用户自己的终端**。

    教训：onefile 打包后 bootloader 父进程 + 真程序子进程会共享同一个新建控制台，
    所以"控制台里只有 1 个进程"这个判据**永不成立** ⇒ 旧实现是死代码、双击必留黑窗口。
    改成看控制台里**有没有不属于本程序的进程**：全是自己人才隐藏；只要有一个别人的
    （从 cmd/pwsh 启动时那个就是用户的窗口）就一个都不动。
    """
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        hwnd = k.GetConsoleWindow()
        if not hwnd:
            return
        buf = (ctypes.c_uint * 64)()
        n = k.GetConsoleProcessList(buf, 64)
        if n <= 0:
            return
        me = os.path.normcase(os.path.abspath(sys.executable))
        for i in range(min(n, 64)):
            if os.path.normcase(_proc_image(buf[i])) != me:
                return                                      # 有别人的进程（用户终端）⇒ 不动
        ctypes.windll.user32.ShowWindow(hwnd, 0)            # SW_HIDE
    except Exception:                                       # noqa: BLE001
        pass


def _ellipsize(text, limit: int = 46) -> str:
    """超长名字截断。

    3000 字符的包名会让 Label 的请求宽度涨到 7 万像素，把同一行其它控件挤爆、看着像花屏。
    """
    t = str(text or "")
    return t if len(t) <= limit else t[: limit - 1] + "…"


def _check_images(master=None):
    """自绘复选框图标：未选 = 灰框，已选 = 蓝底白勾。

    不用 ttk 主题自带的 indicator —— clam 主题下它画的是「✕」，容易被误读成"已取消"。

    ⚠️ `master` 必须显式给（传 App 实例）：`tk.PhotoImage` 默认挂在**默认 root** 上，
    而验收脚本会在同一进程里建多个 Tk 实例 ⇒ 第一个被 destroy 后，后面的复选框会抛
    `TclError: image "pyimageN" doesn't exist`（实测把整段验收脚本打断）。
    """
    size = 14
    off = tk.PhotoImage(master=master, width=size, height=size)
    on = tk.PhotoImage(master=master, width=size, height=size)
    for y in range(size):
        for x in range(size):
            edge = x in (0, size - 1) or y in (0, size - 1)
            off.put("#9ca3af" if edge else "#ffffff", (x, y))
            on.put(ACCENT, (x, y))

    def line(img, x0, y0, x1, y1, color, width=2):
        steps = max(abs(x1 - x0), abs(y1 - y0))
        for i in range(steps + 1):
            x = round(x0 + (x1 - x0) * i / steps)
            y = round(y0 + (y1 - y0) * i / steps)
            for dx in range(width):
                for dy in range(width):
                    px, py = x + dx, y + dy
                    if 0 <= px < size and 0 <= py < size:
                        img.put(color, (px, py))

    # 禁用版：整张降饱和。勾用**中灰画在浅灰底上**（不是白勾画淡蓝底 —— 14px 下白勾
    # 几乎看不出，容易被当成"没勾"，正是最容易被误读的那类歧义）。
    off_dis = tk.PhotoImage(master=master, width=size, height=size)
    on_dis = tk.PhotoImage(master=master, width=size, height=size)
    for y in range(size):
        for x in range(size):
            edge = x in (0, size - 1) or y in (0, size - 1)
            off_dis.put("#d1d5db" if edge else "#f9fafb", (x, y))
            on_dis.put("#e5e7eb", (x, y))

    line(on, 3, 7, 6, 10, "#ffffff", 2)
    line(on, 6, 10, 11, 3, "#ffffff", 2)
    line(on_dis, 3, 7, 6, 10, "#8b93a1", 2)
    line(on_dis, 6, 10, 11, 3, "#8b93a1", 2)
    return off, on, off_dis, on_dis


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} · 递归解开文件夹里所有压缩包")
        self.configure(bg=BG)

        self.logq: queue.Queue = queue.Queue()
        self.cancel = threading.Event()
        self.pause = threading.Event()          # v1.4.0：暂停（置位=暂停，清除=继续）
        self.force_stop = threading.Event()     # v1.4.9：强制停（置位 ⇒ 取消时不回滚）
        # 🩸 **每个任务一套全新的 Event 对象**，并按任务记账。
        # 旧实现复用同一批 Event 且 `_start` 里 `engine_box.clear()`：旧 worker 收尾时的级联
        # `cancel.set()` 会把刚起步的新任务一起取消（界面显示"完成 0/0 个压缩包"），
        # 同时旧 Extractor 从名单里消失 ⇒ 之后再点「停止」杀不到它起的外部工具。
        self.jobs: list[dict] = []              # [{ex, cancel, pause, force_stop, worker, seq}]
        self._task_seq = 0                      # 任务令牌：旧任务的收尾消息不许改新任务的界面
        self._stopped = False                   # 本次任务是否被用户主动停止（决定收尾文案）
        self.engine_box: list = []              # 活着的 Extractor（"停止"时直接杀外部工具）
        self.worker: threading.Thread | None = None
        self.last_out_dir = ""
        self._pkg_mode = ""                     # 第二条进度条当前模式（determinate/indeterminate）
        self._alive = True                      # 窗口还活着吗（destroy 后不再排期）
        self._afters: set[str] = set()          # 在飞的 after 回调（退出时统一取消）
        self._user_sized = False                # 用户是否手动调过窗口（别顶掉）
        self._fitting = False                   # 正在由程序自己设窗口尺寸（区分用户操作）
        self._first_fit_done = False            # 首次自动定尺寸是否已稳定（之后才开始记用户操作）
        self._last_canvas_w = 0                 # canvas 上次的宽度（宽度没变就不重排 body）
        self._last_bbox = None                  # canvas 上次的内容范围（没变就不改 scrollregion）
        self._ui_last: dict = {}                # 上次真正写进 Tk 的显示值（`_set_var`/`_set_pb` 的本地缓存）
        self._last_cfg_t = 0.0                  # 上次 Configure 的时刻（识别"正在拖动窗口"）
        self._cfg_burst = 0                     # 连续 Configure 次数（≥3 才算真的在拖）
        self._dragging_until = 0.0              # 拖到这个时刻为止，`_drain` 让路给输入与重绘
        self._log_lines = 0                     # 日志区当前行数（超限就裁开头，见 _log）
        self._log_follow = True                 # 日志是否自动跟随底部（用户自己滚过就交给 `_log_scrolled`）
        self._pending: list = []                # 上轮没处理完的消息（时间预算到点时留的，见 _drain）

        self._init_style()
        self.chk_off, self.chk_on, self.chk_off_dis, self.chk_on_dis = _check_images(self)
        self._build()
        # 🩸 用例：窗口开得太小，挂满 16 个线程时就短了 ——
        # 初始化时**按最高并行档把槽位先建好**，窗口才会一次按"16 路"（8 行）的高度定下来。
        # 否则 `_fit_window()` 是按当时 1 行槽位算的 —— 挂满 16 路时下半截会超出窗口、
        # 得滚动才看得见（v1.5.3/1.5.4 就是这样）。
        try:
            self._build_slots(detect_workers("high"))
            self._set_var("slots_head", self.var_slots, "（未开始）")
        except Exception:                       # noqa: BLE001
            pass
        self._fit_window()                      # ⚠️ 必须在 _build 之后：按内容实际需求定窗
        self._load_cfg()
        self._after(80, self._drain)
        self.bind("<Configure>", self._on_configure)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _after(self, ms: int, fn) -> None:
        """登记 after 回调，退出时能统一取消。

        🩸 窗口 destroy 之后，**已经在飞的** after 回调会以 Tcl 错误吐出来
        （`invalid command name "..._drain"`）—— 那时回调根本没机会执行，所以只能在退出前取消。
        """
        holder: list[str] = []

        def _wrap() -> None:
            if holder:
                self._afters.discard(holder[0])
            fn()

        try:
            holder.append(self.after(ms, _wrap))
        except tk.TclError:
            return
        self._afters.add(holder[0])

    # -------------------------------------------------- 滚动主区

    def _on_body_configure(self, _e=None) -> None:
        """内容尺寸变了 ⇒ 更新滚动范围。

        🩸 「移动窗口/滚动日志只有 3fps」（在 v1.5.2 上实测）：
        旧实现除了设 scrollregion，还**按需 `pack` / `pack_forget` 滚动条** —— 而滚动条
        一出现/消失就改变 canvas 宽度 ⇒ 触发 `_on_canvas_configure` ⇒ 改 body 宽度 ⇒
        又触发本函数 ⇒ **几何反馈环**，拖一下窗口就是几十轮全量重排（3fps 就是这么来的）。
        现在：① 滚动条**常驻**（不再切换显隐）；② 用 `bbox("all")` 取内容范围，
        不再调 `winfo_reqheight()`（后者要递归计算整个 body 的请求尺寸）。
        """
        try:
            bbox = self.canvas.bbox("all")
            if bbox and bbox != self._last_bbox:    # 值没变就别碰 canvas（拖动窗口时会狂触发）
                self._last_bbox = bbox
                self.canvas.configure(scrollregion=bbox)
        except tk.TclError:
            pass

    def _on_canvas_configure(self, e) -> None:
        """让内容宽度跟随窗口宽度（否则窗口变宽时内容还按初始宽度排）。"""
        if e.widget is not self.canvas:
            return
        if e.width == self._last_canvas_w:
            return                      # 宽度没变就别碰（打断上面那个反馈环的另一半）
        self._last_canvas_w = e.width
        try:
            self.canvas.itemconfigure(self._body_win, width=max(1, e.width))
        except tk.TclError:
            pass

    def _on_wheel(self, e) -> None:
        """滚轮滚动主区。鼠标在日志框里时让它自己滚，别抢（日志有自己的滚动条）。"""
        if isinstance(getattr(e, "widget", None), tk.Text):
            return
        try:
            bbox = self.canvas.bbox("all")
            if not bbox or bbox[3] <= self.canvas.winfo_height():
                return
            self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")
        except tk.TclError:
            pass

    def _on_configure(self, e) -> None:
        """记下"用户手动调过窗口"（之后别再被程序顶回去）。

        同时识别"正在拖动/缩放窗口"：短时间内的连续 Configure ⇒ 让 `_drain` **整体让路**
        （否则消息处理会把鼠标拖动/重绘消息压在队列里，手感变成"延迟 1.5 秒"）。
        """
        if e.widget is not self or self._fitting:
            return
        now = time.time()
        if now - self._last_cfg_t < 0.25:
            self._cfg_burst += 1
            # ⚠️ 必须**连续多次**才算"用户在拖窗口"：只 1~2 次 Configure（程序自己改尺寸、
            # 验收脚本调 `geometry()`）也让路的话，`_drain` 会被误停 0.4 秒 ⇒ 消息不处理
            #（踩到过：让界面验收脚本当场变红）。
            if self._cfg_burst >= 3:
                self._dragging_until = now + 0.4
        else:
            self._cfg_burst = 0
        self._last_cfg_t = now
        if self._first_fit_done:
            self._user_sized = True

    def _mark_first_fit(self) -> None:
        self._first_fit_done = True

    def _fit_window(self, force: bool = False) -> None:
        """按**内容实际需要多大**来定窗口大小。

        🩸 v1.4.0 踩到：旧代码把窗高硬顶在 `min(880, 屏高×0.8)`，而加了两条进度条之后
        内容需要 **943×977** ⇒ 高差 97px、宽差 63px，**日志区被挤成一条缝**（肉眼一眼可见）。
        现在改成：先让 Tk 把内容算出来（`update_idletasks()` + `winfo_req*`），
        再取「内容想要的」和「屏幕给得起的」两者的小值。

        🩸 主内容已经在**可滚动容器**里（`self.body`）⇒
        ① 尺寸要按 `body` 的需求算，不能再按 canvas；② 窗口下限可以放低（装不下能滚）；
        ③ **用户手动调过窗口之后就不再自动改尺寸**（以前点「开始解压」会把他拉好的窗口
        弹回"内容所需尺寸 + 屏幕 1/3 处"）。
        """
        self.update_idletasks()
        try:
            sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        except tk.TclError:
            sw, sh = 1280, 800
        # +24/+20 是给窗口边框与滚动条留的余量：不然"其实装得下"也会冒出一条滚动条
        w = max(960, self.body.winfo_reqwidth() + 24)
        h = max(640, self.body.winfo_reqheight() + 24)
        w = min(w, max(760, sw - 40))
        h = min(h, max(560, sh - 60))
        self.minsize(min(760, w), min(420, h))
        if self._user_sized and not force:
            return
        self._fitting = True
        try:
            self.geometry(f"{w}x{h}+{max(16, (sw - w) // 3)}+{max(12, (sh - h) // 8)}")
        finally:
            self._fitting = False
        if not self._first_fit_done:
            self._after(400, self._mark_first_fit)      # 等初始窗口稳定再开始记"用户改过"

    # -------------------------------------------------- 样式

    def _init_style(self) -> None:
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=TEXT, font=FONT)
        st.configure("Card.TFrame", background=CARD)
        st.configure("Card.TLabel", background=CARD, foreground=TEXT, font=FONT)
        st.configure("CardMuted.TLabel", background=CARD, foreground=MUTED, font=FONT_SUB)
        st.configure("TRadiobutton", background=CARD, foreground=TEXT, font=FONT,
                     focuscolor=CARD)
        st.map("TRadiobutton", background=[("active", CARD)])
        st.configure("TCheckbutton", background=CARD, foreground=TEXT, font=FONT, focuscolor=CARD)
        st.map("TCheckbutton", background=[("active", CARD)])
        st.configure("TEntry", fieldbackground="white", bordercolor=BORDER,
                     lightcolor=BORDER, darkcolor=BORDER, padding=5, insertcolor=TEXT)
        st.configure("TCombobox", fieldbackground="white", background="white",
                     bordercolor=BORDER, arrowcolor=MUTED, padding=4)
        st.configure("TProgressbar", troughcolor="#e5e7eb", background=ACCENT,
                     thickness=10, borderwidth=0, bordercolor=BG,
                     lightcolor=ACCENT, darkcolor=ACCENT)
        # v1.4.0 两条进度条：**总体条明显一些**（更粗 + 主色），单文件条细一号、浅蓝。
        st.configure("All.Horizontal.TProgressbar", troughcolor="#e5e7eb", background=ACCENT,
                     thickness=18, borderwidth=0, bordercolor=BG,
                     lightcolor=ACCENT, darkcolor=ACCENT)
        st.configure("File.Horizontal.TProgressbar", troughcolor="#eef0f3", background="#60a5fa",
                     thickness=8, borderwidth=0, bordercolor=BG,
                     lightcolor="#60a5fa", darkcolor="#60a5fa")
        st.configure("TSpinbox", fieldbackground="white", bordercolor=BORDER, padding=4)

    # -------------------------------------------------- 布局

    def _card(self, parent, title: str):
        wrap = tk.Frame(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
        wrap.pack(fill="x", padx=16, pady=(0, 10))
        inner = tk.Frame(wrap, bg=CARD)
        inner.pack(fill="x", padx=14, pady=(10, 12))
        tk.Label(inner, text=title, bg=CARD, fg=MUTED, font=FONT_B).pack(anchor="w", pady=(0, 8))
        return inner

    def _check(self, parent, text, var, command=None, bg=CARD):
        """带 √ 的自绘复选框（不受 ttk 主题影响）。"""
        cb = tk.Checkbutton(parent, text=text, variable=var, command=command,
                            image=self.chk_off, selectimage=self.chk_on,
                            indicatoron=False, compound="left", anchor="w",
                            bg=bg, fg=TEXT, activebackground=bg, activeforeground=TEXT,
                            font=FONT, bd=0, highlightthickness=0, padx=0, pady=1,
                            cursor="hand2", takefocus=0)
        return cb

    def _build(self) -> None:
        # 🩸 小屏（1366×768）或用户把窗口拖到最小尺寸时，Tk 的 `pack` 在空间
        # 不足时会把**靠后的控件整块不映射**（实测 900×520 连「开始解压」都点不到、
        # 960×708 时进度区/槽位区/日志区全是 1×1）——不是裁掉一条边，是整个消失。
        # 现在整个主内容放进**可滚动容器**：窗口再小也能滚着看到，不会再"点不到"。
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(outer, bg=BG, highlightthickness=0, bd=0, takefocus=0)
        self.vsb = ttk.Scrollbar(outer, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        # ⚠️ 滚动条**常驻**：旧实现"内容超出才 pack、不超出就 pack_forget"，而显隐会改 canvas
        # 宽度 ⇒ 触发 Configure ⇒ 又判断 ⇒ 几何反馈环（拖窗口掉到 3fps，实测）。
        self.vsb.pack(side="right", fill="y")
        self.body = tk.Frame(self.canvas, bg=BG)
        self._body_win = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._on_body_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.bind_all("<MouseWheel>", self._on_wheel)

        # ---- 顶部标题
        head = tk.Frame(self.body, bg=BG)
        head.pack(fill="x", padx=16, pady=(14, 12))
        tk.Label(head, text="递归解压", bg=BG, fg=TEXT, font=FONT_TITLE).pack(side="left")
        tk.Label(head, text="    自动识别压缩包真实格式；嵌套压缩包将逐层解压",
                 bg=BG, fg=MUTED, font=FONT_SUB).pack(side="left")

        # ---- 源文件夹
        c1 = self._card(self.body, "源文件夹（里面的压缩包会被递归解开）")
        row = tk.Frame(c1, bg=CARD)
        row.pack(fill="x")
        self.var_src = tk.StringVar()
        ttk.Entry(row, textvariable=self.var_src).pack(side="left", fill="x", expand=True)
        _btn(row, "浏览…", self._pick_src, "ghost").pack(side="left", padx=(8, 0))

        # ---- 解压方式
        c2 = self._card(self.body, "解压方式")
        self.var_layout = tk.StringVar(value="beside_folder")
        ttk.Radiobutton(c2, text="每个压缩包解压到同目录下的同名文件夹（推荐）",
                        variable=self.var_layout, value="beside_folder").pack(anchor="w")
        ttk.Radiobutton(c2, text="解压到压缩包所在文件夹（内容直接展开）",
                        variable=self.var_layout, value="beside_flat").pack(anchor="w", pady=(4, 0))

        row2 = tk.Frame(c2, bg=CARD)
        row2.pack(fill="x", pady=(4, 0))
        ttk.Radiobutton(row2, text="全部解压到：", variable=self.var_layout,
                        value="out_dir").pack(side="left")
        self.var_out = tk.StringVar()
        self.ent_out = ttk.Entry(row2, textvariable=self.var_out)
        self.ent_out.pack(side="left", fill="x", expand=True, padx=(4, 8))
        self.btn_out = _btn(row2, "浏览…", self._pick_out, "ghost")
        self.btn_out.pack(side="left")

        self.var_sub = tk.BooleanVar(value=True)
        self.chk_sub = self._check(c2, "每个压缩包单独建立子文件夹（避免同名文件相互覆盖）",
                                   self.var_sub)
        self.chk_sub.pack(anchor="w", pady=(6, 0))
        self.lbl_out_hint = tk.Label(
            c2, text="输出文件夹留空时，自动在源文件夹中创建「解压文件26_09_22_0926」时间戳目录",
            bg=CARD, fg=MUTED, font=FONT_SUB)
        self.lbl_out_hint.pack(anchor="w", pady=(4, 0))
        self.var_layout.trace_add("write", lambda *_a: self._sync_layout())
        # 勾选状态也影响禁用态用哪张灰图（勾着 ⇒ 灰勾，没勾 ⇒ 灰空框）
        self.var_sub.trace_add("write", lambda *_a: self._sync_layout())
        self._sync_layout()

        # ---- 密码
        c3 = self._card(self.body, "密码（可留空）")
        row3 = tk.Frame(c3, bg=CARD)
        row3.pack(fill="x")
        self.var_pwd = tk.StringVar()
        self.ent_pwd = ttk.Entry(row3, textvariable=self.var_pwd, show="●", width=28)
        self.ent_pwd.pack(side="left")
        self.var_show = tk.BooleanVar(value=False)
        self._check(row3, "显示", self.var_show, command=self._toggle_pwd).pack(side="left", padx=(8, 0))
        tk.Label(row3, text="   仅对已加密的压缩包生效；未加密的压缩包不受影响",
                 bg=CARD, fg=MUTED, font=FONT_SUB).pack(side="left")

        # ---- 高级
        c4 = self._card(self.body, "高级选项")
        row4 = tk.Frame(c4, bg=CARD)
        row4.pack(fill="x")
        tk.Label(row4, text="同名文件：", bg=CARD, fg=TEXT, font=FONT).pack(side="left")
        self.var_ow = tk.StringVar(value="rename")
        ttk.Combobox(row4, textvariable=self.var_ow, width=9, state="readonly",
                     values=["rename", "skip", "overwrite"]).pack(side="left", padx=(4, 16))
        tk.Label(row4, text="最大嵌套层数：", bg=CARD, fg=TEXT, font=FONT).pack(side="left")
        self.var_depth = tk.IntVar(value=5)
        # 保存引用：清空后 `IntVar.get()` 会抛 TclError，读 Spinbox 自己的字符串更稳
        # （见 `_depth_value`）
        self.spin_depth = ttk.Spinbox(row4, from_=1, to=30, width=4, textvariable=self.var_depth)
        self.spin_depth.pack(side="left", padx=(4, 16))
        tk.Label(row4, text="并行解压：", bg=CARD, fg=TEXT, font=FONT).pack(side="left")
        self.var_workers = tk.StringVar(value="中")
        ttk.Combobox(row4, textvariable=self.var_workers, width=4, state="readonly",
                     values=["高", "中", "低"]).pack(side="left", padx=(4, 6))
        cpu = os.cpu_count() or 4
        tk.Label(row4,
                 text=f"（本机 {cpu} 线程 ⇒ 高 {detect_workers('high')} / 中 {detect_workers('mid')}"
                      f" / 低 {detect_workers('low')} 路；单个压缩包本身只能单线程解）",
                 bg=CARD, fg=MUTED, font=FONT_SUB).pack(side="left")

        row5 = tk.Frame(c4, bg=CARD)
        row5.pack(fill="x", pady=(8, 0))
        self.var_del = tk.BooleanVar(value=False)
        self._check(row5, "解压成功后删除原压缩包", self.var_del).pack(side="left")
        self.var_markfail = tk.BooleanVar(value=False)
        self._check(row5, "解压失败的原包添加 .failed 标记", self.var_markfail).pack(side="left", padx=(16, 0))
        self.var_clean = tk.BooleanVar(value=False)
        self._check(row5, "清理本次解压产生的空目录", self.var_clean).pack(side="left", padx=(16, 0))
        self.var_report = tk.BooleanVar(value=True)
        self._check(row5, "生成处理报告", self.var_report).pack(side="left", padx=(16, 0))
        self.var_smart = tk.BooleanVar(value=True)
        self._check(c4, "智能解压：压缩包内仅有一个与压缩包同名的文件夹时，去除该层目录",
                    self.var_smart).pack(anchor="w", pady=(6, 0))
        self.var_exe = tk.BooleanVar(value=True)
        self._check(c4, "尝试解开 .exe 外壳中的压缩包（部分安装程序是自解压包；只读取，不运行程序）",
                    self.var_exe).pack(anchor="w", pady=(6, 0))
        tk.Label(c4, text="rename=保留两份　skip=跳过已存在　overwrite=覆盖　｜　"
                          "解压为 CPU 密集型任务：多路并行约提速 2 倍，不使用 GPU",
                 bg=CARD, fg=MUTED, font=FONT_SUB).pack(anchor="w", pady=(6, 0))

        # ---- 操作栏
        bar = tk.Frame(self.body, bg=BG)
        bar.pack(fill="x", padx=16, pady=(2, 8))
        # 一个按钮两种身份：空闲「开始解压」⇄ 运行中「停止」
        # （原来两个并排按钮，按了开始之后看不出来按上没有）
        self._run_bg, self._run_bg_hover = ACCENT, ACCENT_D
        self.btn_run = _btn(bar, "开始解压", self._start, "primary")
        self.btn_run.pack(side="left")
        self.btn_run.bind("<Enter>", lambda _e: self._run_hover(True))
        self.btn_run.bind("<Leave>", lambda _e: self._run_hover(False))
        # v1.4.0：暂停 / 继续。**空闲时禁用而不是隐藏**（位置不跳，也让"有这个功能"看得见）。
        self.btn_pause = _btn(bar, "暂停", self._toggle_pause, "ghost")
        self.btn_pause.pack(side="left", padx=(8, 0))
        self.btn_pause.config(state="disabled", cursor="")
        _btn(bar, "打开输出位置", self._open_out, "ghost").pack(side="left", padx=(8, 0))

        self.var_stat = tk.StringVar(value="就绪")
        tk.Label(bar, textvariable=self.var_stat, bg=BG, fg=MUTED, font=FONT).pack(side="right")

        # ---- 进度（Bandizip 式：总体条 + 单文件条，总体更醒目）
        pin = tk.Frame(self.body, bg=BG)
        pin.pack(fill="x", padx=16, pady=(0, 10))

        r_all = tk.Frame(pin, bg=BG)
        r_all.pack(fill="x")
        tk.Label(r_all, text="总体进度", bg=BG, fg=TEXT, font=FONT_B).pack(side="left")
        self.var_all = tk.StringVar(value="等待开始")
        tk.Label(r_all, textvariable=self.var_all, bg=BG, fg=MUTED, font=FONT).pack(side="right")
        # ⚠️ clam 主题下水平 ttk.Progressbar **忽略 thickness**（给 8/18/40 都画 18px），
        # 所以"总体条更粗"必须靠**定高容器**夹住控件才真生效（实测：
        # 8px 容器 ⇒ 8px、18px 容器 ⇒ 18px）。需求是"总体进度条明显一些"。
        allbox = tk.Frame(pin, bg=BG, height=18)
        allbox.pack(fill="x", pady=(4, 10))
        allbox.pack_propagate(False)
        self.pb_all = ttk.Progressbar(allbox, style="All.Horizontal.TProgressbar",
                                      mode="determinate", maximum=100)
        self.pb_all.pack(fill="both", expand=True)

        # ---- 并行槽位：**每个正在解的包一条进度条**（需求：
        #      在并行度下面按"每个包一个"列出进度条）
        self.slots_head = tk.Frame(pin, bg=BG)
        self.slots_head.pack(fill="x")
        tk.Label(self.slots_head, text="并行进度", bg=BG, fg=TEXT, font=FONT_B).pack(side="left")
        self.var_slots = tk.StringVar(value="（未开始）")
        tk.Label(self.slots_head, textvariable=self.var_slots, bg=BG, fg=MUTED,
                 font=FONT_SUB).pack(side="right")
        self.slots_box = tk.Frame(pin, bg=BG)
        self.slots_box.pack(fill="x", pady=(4, 0))
        self.slot_rows: list[tuple] = []        # [(文件名 StringVar, Progressbar, 百分比 StringVar)]
        self._slot_n = 0

        # ---- 日志
        logwrap = tk.Frame(self.body, bg=LOG_BG, highlightbackground=BORDER, highlightthickness=1)
        logwrap.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.txt = tk.Text(logwrap, bg=LOG_BG, fg=LOG_FG, insertbackground=LOG_FG,
                           relief="flat", bd=0, font=FONT_LOG, wrap="none", padx=10, pady=8,
                           state="disabled", height=10)
        sb = ttk.Scrollbar(logwrap, command=self._log_scroll_cmd)
        self.txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.txt.pack(side="left", fill="both", expand=True)
        # 🩸 日志"自动跟随底部"的语义要靠**用户有没有自己滚过**来判断（判据见 `_log_scrolled`）：
        # 不能拿"插入之后的 yview"去猜 —— 插入会让总行数变、视口比例跟着变，判据必然失真。
        self.txt.bind("<MouseWheel>", self._log_scrolled)
        self.txt.bind("<KeyPress>", self._log_scrolled)
        self.txt.bind("<ButtonRelease-1>", self._log_scrolled)
        self.txt.tag_configure("info", foreground=INFO_FG)
        self.txt.tag_configure("ok", foreground=OK_FG)
        self.txt.tag_configure("warn", foreground=WARN_FG)
        self.txt.tag_configure("error", foreground=ERR_FG)
        self._log("info", f"{APP_NAME} 就绪。请选择源文件夹，然后点击「开始解压」。")

    # -------------------------------------------------- 交互

    def _run_hover(self, on: bool) -> None:
        """主按钮的悬停色：随"当前身份"变（禁用时不动）。"""
        if str(self.btn_run["state"]) != "normal":
            return
        self.btn_run.config(bg=self._run_bg_hover if on else self._run_bg)

    def _set_run_state(self, running: bool) -> None:
        """空闲「开始解压」⇄ 运行中「停止」；暂停按钮随运行态启用/禁用。"""
        if running:
            self._run_bg, self._run_bg_hover = DANGER, DANGER_D
            self.btn_run.config(text="停止", command=self._stop, bg=DANGER,
                                activebackground=DANGER_D, state="normal", cursor="hand2")
            self.btn_pause.config(text="暂停", command=self._toggle_pause,
                                  state="normal", cursor="hand2")
        else:
            self._run_bg, self._run_bg_hover = ACCENT, ACCENT_D
            self.btn_run.config(text="开始解压", command=self._start, bg=ACCENT,
                                activebackground=ACCENT_D, state="normal", cursor="hand2")
            self.btn_pause.config(text="暂停", state="disabled", cursor="")

    def _toggle_pause(self) -> None:
        """暂停 / 继续。

        ⚠️ 暂停是**在检查点生效**的：正在写的那个文件会先写完，然后原地停住；
        多路并行时每一路都会各自停在自己的检查点上。
        """
        if self.pause.is_set():
            self.pause.clear()
            self.btn_pause.config(text="暂停")
            self._log("info", "解压已恢复。")
            self._set_var("stat", self.var_stat, "继续中…")
        else:
            self.pause.set()
            self.btn_pause.config(text="继续")
            self._log("info", "正在暂停：当前文件写入完成后生效。")
            self._set_var("stat", self.var_stat, "暂停中…")

    def _toggle_pwd(self) -> None:
        self.ent_pwd.config(show="" if self.var_show.get() else "●")

    def _sync_layout(self) -> None:
        """按当前「解压方式」同步从属控件的可用状态。

        只有选中「全部解压到」时，输出文件夹输入框 / 浏览按钮 / 「每个压缩包单独建立
        子文件夹」才参与本次解压；其余档位下它们不生效，统一置灰，避免误以为设置有效。
        """
        on = self.var_layout.get() == "out_dir"
        self.ent_out.config(state="normal" if on else "disabled")
        self.btn_out.config(state="normal" if on else "disabled")
        # 自绘复选框不随主题变灰，这里显式换成禁用版图标。
        # ⚠️ 经典 tk.Checkbutton **没有 disabledimage**（那是 ttk 的选项），而且禁用态下
        # 它只画 image、不按 selectimage 走 ⇒ 必须把两张图都指向"当前勾没勾"对应的那张
        # 灰图，否则勾着的项会画成灰空框、看着像"被取消了"（禁用时反正点不动，不影响交互）。
        if on:
            self.chk_sub.config(state="normal", image=self.chk_off, selectimage=self.chk_on,
                                fg=TEXT, cursor="hand2")
        else:
            dis = self.chk_on_dis if self.var_sub.get() else self.chk_off_dis
            self.chk_sub.config(state="disabled", image=dis, selectimage=dis,
                                fg="#b4b8bf", cursor="")
        self.lbl_out_hint.config(fg=MUTED if on else "#c3c7cd")

    def _depth_value(self) -> int:
        """读「最大嵌套层数」，**任何异常都回默认 5 并夹到 1..30**。

        `ttk.Spinbox` 是可编辑的：全选删除后 `IntVar.get()` 抛 `TclError`，而打包版是
        windowed（没有 stderr）⇒ Tk 默认只把 traceback 打到 stderr，用户看到的就是
        「点了开始解压没反应」。畸形配置里的 `Infinity` / `1e999` 则抛 `OverflowError`。
        """
        raw = ""
        try:
            # ⚠️ 用 `self.__dict__.get` 而不是 `getattr(self, ...)`：在**未初始化的假实例**上
            # （验收探针会 `App.__new__` 造壳直接调 `_start`），`getattr` 会落进 tkinter 的
            # `Misc.__getattr__` 无限递归（RecursionError），把探针整段打断。
            spin = self.__dict__.get("spin_depth")
            raw = spin.get() if spin is not None else self.var_depth.get()
        except (tk.TclError, ValueError, AttributeError, RecursionError):
            raw = ""
        try:
            v = int(float(str(raw).strip() or 5))
        except (TypeError, ValueError, OverflowError):
            v = 5
        return max(1, min(30, v))

    @staticmethod
    def _as_bool(v, default: bool = False) -> bool:
        """严格布尔解析。

        `bool("false")` 是 **True** —— 手工编辑/被别的工具改过的 `settings.json` 里
        一旦写成字符串 `"false"`，**破坏性开关「解压成功后删除原压缩包」会被静默打开**。
        现在只认真正的布尔值与明确的真值字符串，其余一律回默认。
        """
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "on"):
                return True
            if s in ("0", "false", "no", "off", ""):
                return False
            return default
        if isinstance(v, (int, float)):
            return bool(v)
        return default

    def report_callback_exception(self, exc, val, tb) -> None:      # noqa: ANN001
        """任何界面回调抛异常都必须**留痕**。

        打包版没有 stderr，Tk 默认的 traceback 用户永远看不到 —— 表现就是"点了没反应"。
        这里写进日志区并弹一次提示，让问题至少看得见。
        """
        name = getattr(exc, "__name__", str(exc))
        try:
            import traceback
            detail = "".join(traceback.format_exception(exc, val, tb))
            self._log("error", f"界面操作出错（已忽略本次操作）：{name}: {val}")
            self._log("error", detail[-1200:].rstrip())
        except Exception:                           # noqa: BLE001
            pass
        try:
            messagebox.showerror(APP_NAME, f"操作失败：\n{name}: {val}")
        except Exception:                           # noqa: BLE001
            pass

    def _pick_src(self) -> None:
        d = filedialog.askdirectory(title="选择要处理的文件夹")
        if d:
            self.var_src.set(os.path.normpath(d))

    def _pick_out(self) -> None:
        d = filedialog.askdirectory(title="选择统一输出文件夹")
        if d:
            self.var_out.set(os.path.normpath(d))
            self.var_layout.set("out_dir")

    def _open_out(self) -> None:
        target = self.last_out_dir or self.var_out.get() or self.var_src.get()
        if target and os.path.isdir(target):
            os.startfile(target)                            # noqa: S606
        else:
            messagebox.showinfo(APP_NAME, "尚无可打开的文件夹。")

    def _log_scroll_cmd(self, *args) -> None:
        """日志滚动条被拖动：先滚动，再重新判定"还要不要自动跟随底部"。"""
        try:
            self.txt.yview(*args)
        except tk.TclError:
            return
        self._log_scrolled()

    def _log_scrolled(self, _e=None) -> None:
        """用户自己滚动了日志 ⇒ 重新判定跟随状态。

        🩸 用例「日志不会自动向下滚，需要手动拉」：旧写法是在**插入之后**
        用 `yview()[1] > 0.999` 判断"用户在不在底部" —— 插入让总行数变多、视口比例随即变小，
        刚插一行就判成"用户离开了底部" ⇒ 从此一次都不自动滚。改成：
        **只在用户自己滚动时更新这个标志**，`_log` 只管按标志跟随。
        """
        try:
            first, last = self.txt.yview()
            self._log_follow = last >= 0.999 or (last - first) >= 1.0
        except tk.TclError:
            pass

    def _log(self, level: str, msg: str) -> None:
        self.txt.configure(state="normal")
        self.txt.insert("end", msg + "\n", level)
        # 🩸 「解压大量文件偶发未响应」：日志行数不设上限时，Text 的插入/重排会越来越慢
        # —— 解压几万个文件（尤其反复跳过"已存在"的条目）时日志能堆到几万行，
        # 那时每插一行都要重算布局 + `see("end")` 强制滚动，主线程（Tk）直接被拖死。
        # 只保留最近约 4200 行，超出就从开头裁掉 1200 行。
        self._log_lines += 1
        if self._log_lines > 4200:
            try:
                self.txt.delete("1.0", "1200.0")
            except tk.TclError:
                pass
            self._log_lines -= 1200
        # 🩸 `see("end")` 是这条路径上**最贵**的调用（实测 0.08ms/行，是 insert 的 20 倍，
        # 因为每次都触发重排 + 滚动）。只在"跟随中"才调 —— 用户自己往上翻看历史时，
        # 既不抢他的滚动位置，也省掉这笔开销（跟随状态由 `_log_scrolled` 维护）。
        if self._log_follow:
            try:
                self.txt.see("end")
            except tk.TclError:
                pass
        self.txt.configure(state="disabled")

    # -------------------------------------------------- 运行

    def _start(self) -> None:
        src = self.var_src.get().strip().strip('"')
        if not src or not os.path.isdir(src):
            messagebox.showwarning(APP_NAME, "请先选择一个有效的源文件夹。")
            return
        layout = self.var_layout.get()
        out_dir = self.var_out.get().strip().strip('"')
        if layout == "out_dir" and out_dir:
            try:
                os.makedirs(out_dir, exist_ok=True)
            except OSError as exc:
                messagebox.showerror(APP_NAME, f"输出文件夹不可用：\n{out_dir}\n\n{exc}")
                return
            if not os.path.isdir(out_dir):
                messagebox.showerror(APP_NAME, f"该路径不是文件夹（可能指向一个文件）：\n{out_dir}")
                return
        if self.var_del.get():
            if not messagebox.askyesno(APP_NAME, "解压成功后将删除原压缩包，该操作不可撤销。\n\n是否继续？"):
                return

        if layout == "out_dir":
            opt_layout = "out_dir" if self.var_sub.get() else "out_dir_flat"
        else:
            opt_layout = layout
        level = {"高": "high", "中": "mid", "低": "low"}.get(self.var_workers.get(), "mid")
        opt = Options(
            layout=opt_layout,
            out_dir=out_dir,
            overwrite=self.var_ow.get() or "rename",
            max_depth=self._depth_value(),
            delete_source=bool(self.var_del.get()),
            password=self.var_pwd.get(),
            workers=0, worker_level=level,
            mark_failed=bool(self.var_markfail.get()),
            clean_empty_dirs=bool(self.var_clean.get()),
            report=bool(self.var_report.get()),
            smart_extract=bool(self.var_smart.get()),
            scan_exe=bool(self.var_exe.get()),
        )

        self._save_cfg()
        # 🩸 **每次任务换一套全新的 Event 对象**（不是 clear() 复用）——
        # 旧 worker 收尾时会走 `except Cancelled: self.cancel.set()` 的级联路径，
        # 复用同一批对象时那一刀会砍到刚起步的新任务上（实测界面显示"完成 0/0 个压缩包"，
        # 而这条"停止后立刻重开"的路径正是"停止立刻复位界面"设计鼓励的）。旧 worker 拿的是
        # 旧对象，级联 set() 落不到新任务上；同时下面先把旧任务补一刀，免得它和新任务抢文件。
        if self.worker is not None and self.worker.is_alive():
            self._signal_stop(only_alive=True)
        self.cancel = threading.Event()
        self.pause = threading.Event()
        self.force_stop = threading.Event()
        ev_cancel, ev_pause, ev_force = self.cancel, self.pause, self.force_stop
        self._task_seq += 1
        seq = self._task_seq
        self._stopped = False
        self.results = []
        self._set_run_state(True)
        self.pb_all.config(value=0, maximum=100)
        # 不把槽位行数重置成 0：那会让窗口先缩再长（点一次开始跳两次）。
        # 这里直接**按本次并行度预建**（此刻还没有 worker 抢 GIL，建控件是干净的）——
        # 否则等第一条快照到达时才建 16 行，那一下正好撞上 16 路解压，主线程可能被拖住。
        self._apply_slots({"slots": [], "workers": max(1, detect_workers(level))})
        self._set_var("slots_head", self.var_slots, "（未开始）")
        self._set_var("all_txt", self.var_all, "正在扫描…")
        self._set_var("stat", self.var_stat, "扫描中…")
        self._log("info", "─" * 68)
        self._log("info", f"开始处理：{src}")

        def job():
            ex = Extractor([src], opt,
                           log=lambda lv, m: self.logq.put(("log", seq, lv, m)),
                           progress=lambda s: self.logq.put(("prog", seq, s)),
                           cancel=ev_cancel, pause=ev_pause,
                           force_stop=ev_force)
            rec = {"ex": ex, "cancel": ev_cancel, "pause": ev_pause,
                   "force_stop": ev_force, "worker": threading.current_thread(), "seq": seq}
            self.jobs.append(rec)               # 按任务记账，别 clear() 弄丢旧任务
            self.engine_box = [j["ex"] for j in self.jobs]
            try:
                stats = ex.run()
                if seq == self._task_seq:
                    self.results = ex.results
                self.logq.put(("done", seq, stats))
            except Exception as exc:                        # noqa: BLE001
                self.logq.put(("fatal", seq, f"{type(exc).__name__}: {exc}"))

        self.worker = threading.Thread(target=job, daemon=True)
        self.worker.start()

    def _signal_stop(self, only_alive: bool = True) -> int:
        """给任务发**强制停止**信号，并直接杀掉它们起的外部解压工具（返回杀掉的进程数）。

        🩸 停止必须对**所有还活着的任务**生效（包括"停止→立刻重开"
        时仍在收尾的上一个任务），并且不能因为 `_start()` 清空名单而失联。
        """
        killed = 0
        for j in list(self.jobs):
            if only_alive and not j["worker"].is_alive():
                continue
            try:
                j["force_stop"].set()           # 强制停：取消时不回滚已解出的内容
                j["cancel"].set()
                j["pause"].clear()
                killed += j["ex"].kill_tools()
            except Exception:                   # noqa: BLE001
                pass
        self.jobs = [j for j in self.jobs if j["worker"].is_alive()]
        self.engine_box = [j["ex"] for j in self.jobs]
        return killed

    def _stop(self) -> None:
        """停止 = **强制停 + 清理**（取舍：停止与暂停的逻辑其实不一样，
        强制停就可以了）。

        与**暂停**的区别：暂停是"原地等、可继续、保留现场"；停止是**终止 + 清理**。
        所以这里**不再摆「正在停止…」慢慢等优雅收尾**：立刻取消、立刻把界面交还给用户，
        剩下的收尾（杀外部解压工具、删沙箱与 .rc-part、按账本回滚正在解的那个包）由 worker
        在后台自己完成（`_run_one` 的 finally 一定会清）。
        """
        self._stopped = True                        # 收尾时别改口说"已完成"
        self.pause.clear()
        # 🩸 关键：**立刻杀掉外部解压工具**（UnRAR / bsdtar），不再等 worker 走到检查点 ——
        # 实测过"界面显示已停止、后台还在解"（11 个 UnRAR 在跑）。
        killed = self._signal_stop(only_alive=False)
        if not self.jobs:
            # 没有登记在册的任务（例如界面刚起来、或被直接调用）也要把当前信号置上，
            # 保证"界面显示已停止"与信号状态一致。
            self.force_stop.set()
            self.cancel.set()
        self._set_run_state(False)                  # ⚡ 立刻复位（按钮马上能再点）
        self._apply_slots({"slots": [], "workers": self._slot_n})
        self._set_var("slots_head", self.var_slots, "（已停止）")
        self._set_var("stat", self.var_stat, "已停止")
        tail = f"（已终止 {killed} 个外部解压进程）" if killed else ""
        self._log("warn", f"已停止解压任务：已解出的文件保留，临时文件由程序自动清理。{tail}")

    def _settle_after_stop(self) -> None:
        """停止兜底：worker 已经不在跑了，界面却还停在「正在停止…」⇒ 直接归位。"""
        if not self._alive:
            return
        if self.worker is not None and self.worker.is_alive():
            return
        if str(self.btn_run["text"]) == "正在停止…":
            self._set_run_state(False)
            self._set_var("stat", self.var_stat, "已停止")

    def _drain(self) -> None:
        """把 worker 线程放进队列的消息搬到界面上。

        🩸 旧写法只 `except queue.Empty` —— 只要有一条消息处理时抛异常，
        异常就会冒出去、**`after(80, self._drain)` 不再排期**，整个 UI 消息处理永久停摆
        （进度不动、日志不涨、按钮可能永远停在「正在停止…」，还没有任何报错线索）。
        现在：**单条消息各自 try/except + 整体 finally 一定重排期**。
        """
        try:
            # 🩸 「解压大量文件偶发未响应」（实测，`py-spy dump` 抓到主线程
            # 长期卡在 `_drain → _apply_slots → configure`）：
            #   ① 旧写法 `while True` 把队列**一次抽干**，十几万文件时队列能积压上千条；
            #   ② 更贵的是：**进度快照会被后来的完全覆盖**，处理中间那些纯属白烧主线程时间。
            # 现在：先**廉价**地把消息搬出来（最多 2000 条），同一批里只保留**最后一条**
            # `prog`；日志照旧全处理，但加 25ms 时间预算，超了就留给下一轮 ——
            # 主线程每轮最多占用几十毫秒，界面就不会再「未响应」。
            #
            # 🩸 「拖动窗口/交互不跟手、延迟约 1.5 秒」（在 v1.5.3 上实测）：
            # 帧率不低，但**输入要等** —— 因为主线程被这里长时间占着（25ms 预算 + 40ms 排期
            # ≈ 60% 的时间在处理消息），Windows 的鼠标拖动/重绘消息只能排队；拖动时更糟
            # （Configure 事件与 after 抢同一条队列）。现在：① 拖动期间**整体让路**；
            # ② 每轮预算 25ms → **8ms**；③ 排期 30ms（占用率降到 ~25%，而进度本来只有 4 次/秒）。
            if time.time() < self._dragging_until:
                return
            items: list = self._pending
            self._pending = []
            while len(items) < 2000:
                try:
                    items.append(self.logq.get_nowait())
                except queue.Empty:
                    break
            if not items:
                return
            last_prog = -1
            for i, it in enumerate(items):
                # ⚠️ 预扫描也要容错：验收脚本会故意喂各种坏消息（非元组、长度不足…），
                # 这里一句裸 `it[0]` 就会把整个 _drain 抛出去（老坑）。
                try:
                    if it[0] == "prog":
                        last_prog = i
                except Exception:                   # noqa: BLE001
                    pass
            t_start = time.time()
            for i, item in enumerate(items):
                try:
                    is_prog = item[0] == "prog"
                except Exception:                   # noqa: BLE001
                    is_prog = False
                if is_prog and i != last_prog:
                    continue                    # 被更晚的快照覆盖了，直接丢
                try:
                    self._handle_msg(item)
                except Exception as exc:                # noqa: BLE001
                    try:
                        self._log("error", "界面刷新出错（已忽略，不影响解压）："
                                           f"{type(exc).__name__}: {exc}")
                    except Exception:                   # noqa: BLE001
                        pass
                if time.time() - t_start > 0.008:
                    # 时间预算到点：剩下的**留在下轮**（绝不丢消息 —— 日志与终态消息都不能少）
                    self._pending = items[i + 1:]
                    break
        finally:
            if self._alive:
                self._after(30, self._drain)

    def _handle_msg(self, item) -> None:
        """处理 worker 消息。

        ⚠️ 新格式带**任务令牌** `seq`：`("log", seq, lv, m)` / `("prog", seq, s)` /
        `("done", seq, stats)` / `("fatal", seq, msg)`；同时兼容不带 seq 的旧两段格式
        （验收脚本会直接构造消息）。**旧任务的收尾消息一律丢弃** ——
        否则「停止 → 立刻重开」后，上一个任务的 `done` 会把新任务界面改口成
        「已完成」，用户分不清是自己停的还是跑完了。
        """
        seq = None
        if len(item) >= 3 and isinstance(item[1], int):
            seq, kind, payload = item[1], item[0], list(item[2:])
        else:
            kind, payload = item[0], list(item[1:])
        if seq is not None and seq != self._task_seq:
            return
        if kind == "log":
            self._log(payload[0], payload[1])
        elif kind == "prog":
            self._apply_progress(payload[0])
        elif kind == "done":
            st = payload[0]
            self.pause.clear()                      # 收尾别把"暂停中"残留着
            self._apply_slots({"slots": [], "workers": max(1, self._slot_n)})
            self._set_run_state(False)
            if self._stopped:
                # 用户自己停的 ⇒ 收尾文案必须还是"已停止"，不能说"已完成"
                self._set_var("all_txt", self.var_all, f"已停止：本次共处理 {st.archives_done + st.archives_failed} 个压缩包")
                self._set_var("slots_head", self.var_slots, "（已停止）")
                self._set_var("stat", self.var_stat, f"已停止：成功 {st.archives_done} · 失败 {st.archives_failed} · "
                                  f"跳过 {st.archives_skipped}　|　{human_size(st.bytes_written)}")
                return
            self.pb_all.config(value=self.pb_all["maximum"])
            self._set_var("all_txt", self.var_all, f"完成：{st.archives_done}/{st.archives_found} 个压缩包")
            self._set_var("slots_head", self.var_slots, "已完成")
            self._set_var("stat", self.var_stat, f"完成：成功 {st.archives_done} · 失败 {st.archives_failed} · "
                              f"跳过 {st.archives_skipped}　|　{human_size(st.bytes_written)}")
            if st.archives_failed:
                self._log("warn", f"有 {st.archives_failed} 个压缩包未能解开，请查看上方日志了解原因。")
        elif kind == "fatal":
            self._log("error", f"程序异常：{payload[0]}")
            self.pause.clear()
            self._apply_slots({"slots": [], "workers": max(1, self._slot_n)})
            self._set_run_state(False)

    # -------------------------------------------------- 进度显示

    def _set_var(self, key: str, var, value: str) -> None:
        """内容没变就不碰 Tk（见 `_apply_progress` 的性能说明）。

        🩸 **必须用本地缓存比较，绝不能用 `var.get()` 比**：`get()` 本身是一次 Tcl 往返、
        同样要抢 GIL —— `py-spy` 在 v1.5.2 上抓到的未响应现场，主线程正是卡在
        `_set_var → Variable.get` 上（旁边 4 个 worker 正在 realpath 抢 GIL）。
        ⚠️ 用缓存的前提是：**所有**写这几个变量的地方都走本函数，不能有裸 `var.set()`。
        """
        if self._ui_last.get(key) == value:
            return
        self._ui_last[key] = value
        var.set(value)

    def _set_pb(self, key: str, pb, value: float, maximum: float = 0.0) -> None:
        """数值没变就不 `config()` —— `Progressbar.config` 会触发重绘，是这条路径上最贵的。

        同理**不读 `pb["value"]`**（那也是一次 Tcl 往返），只跟本地缓存比。
        """
        if maximum and self._ui_last.get(key + ":max") != maximum:
            self._ui_last[key + ":max"] = maximum
            pb.config(maximum=maximum)
        if self._ui_last.get(key) == value:
            return
        self._ui_last[key] = value
        pb.config(value=value)

    def _apply_progress(self, s: dict) -> None:
        """第一条（总体）进度条：按**包数**算 —— 递归解压时"总量"会一直变，
        按包数才稳定、不倒退；百分比后面附已解出体积，信息量够。

        🩸 「解压大量文件偶发未响应」（实测；`py-spy dump` 抓到主线程
        **长期卡在 `_apply_slots → configure`**）：旧实现**每个快照都无条件**去 config
        总条 + 16 个槽位条 + 3 个 StringVar —— 每秒 ~10 个快照 ⇒ 每秒近 200 次 Tk 调用，
        而每个 Tk 调用都要抢 GIL；同时多个 worker 线程正在跑 `realpath`（同样要 GIL），
        主线程抢不过 ⇒ 消息越积越多、`_drain` 出不去 ⇒ 界面「未响应」。
        现在全部走 `_set_var` / `_set_pb`：**只有显示内容真的变了才碰 Tk**。
        """
        found = int(s.get("found", 0) or 0)
        fin = int(s.get("done", 0)) + int(s.get("failed", 0)) + int(s.get("skipped", 0))
        # ★ 光按包数会"一格不动"：大包在解的时候 fin 不变（真机实测 8 秒没动）⇒
        # 再叠上"活跃包各自的完成比例之和"（partial），总条才会平滑往前爬。
        val = min(float(max(found, 1)), fin + float(s.get("partial", 0.0) or 0.0))
        # 进度条只按 0.5% 的粒度更新（人眼分辨不出更细，但 Tk 调用少一个数量级）
        self._set_pb("all", self.pb_all, round(val * 2) / 2.0, maximum=float(max(found, 1)))
        pct = (100.0 * val / found) if found else 0.0
        head = f"{fin}/{found} 个压缩包 · {pct:.0f}%"
        bl = int(s.get("bytes_live", s.get("bytes", 0)) or 0)
        if bl:
            head += f"　已解出 {human_size(bl)}"
        if int(s.get("active", 0)) > 1:
            head += f"　（{s['active']} 路并行）"
        self._set_var("all_txt", self.var_all, head)

        self._apply_slots(s)

        fl = int(s.get("files_live", s.get("files", 0)) or 0)
        stat = (f"成功 {s['done']} · 失败 {s['failed']} · 跳过 {s['skipped']}"
                f"　|　已解出 {human_size(bl)}（{fl} 个文件）")
        if s.get("paused"):
            stat = "已暂停　|　" + stat
        self._set_var("stat", self.var_stat, stat)

    def _build_slots(self, n: int) -> None:
        """建并行槽位：**每行两个**（左 a 任务条、右 b 任务条，然后换行）。

        需求：在并行度下面按"每个包一个"列出进度条，
        并且**每行两个**：左 a 任务条、右 b 任务条，回车换行后是 c 任务条……。
        两列之后 16 路只占 8 行，窗口高度也不至于顶到屏幕上沿。
        """
        for w in self.slots_box.winfo_children():
            w.destroy()
        self.slot_rows = []
        self._slot_n = n
        for r in range((n + 1) // 2):               # 每行两个
            line = tk.Frame(self.slots_box, bg=BG)
            line.pack(fill="x", pady=0)
            # 🩸 两列必须**等宽**：两侧都用 pack(expand=True) 时，Tk 会按"内容请求宽度"
            # 分配空间 ⇒ 名字长的那半更宽 ⇒ 两边的进度条位置对不上（需求：
            # 进度条要对齐）。改成 grid + `uniform` 强制两列同宽。
            line.columnconfigure(0, weight=1, uniform="slotcol")
            line.columnconfigure(1, weight=1, uniform="slotcol")
            for c in range(2):
                i = r * 2 + c
                half = tk.Frame(line, bg=BG)
                half.grid(row=0, column=c, sticky="ew", padx=(0, 10))
                if i >= n:                          # 奇数个槽位 ⇒ 右下角留空占位
                    continue
                tk.Label(half, text=f"{i + 1:>2}", bg=BG, fg=MUTED, font=FONT_SUB,
                         width=3, anchor="e").pack(side="left")
                nm = tk.StringVar(value="空闲")
                tk.Label(half, textvariable=nm, bg=BG, fg=TEXT, font=FONT_SUB,
                         anchor="w").pack(side="left", fill="x", expand=True, padx=(4, 6))
                pct = tk.StringVar(value="")
                tk.Label(half, textvariable=pct, bg=BG, fg=MUTED, font=FONT_SUB,
                         width=5, anchor="e").pack(side="right")
                # 和**总体进度条同款**（同色同高：18px 主色）：要的是和总体进度一样的条，
                # 不是文字进度条
                box = tk.Frame(half, bg=BG, height=18, width=130)
                box.pack(side="right", padx=(6, 0))
                box.pack_propagate(False)
                pb = ttk.Progressbar(box, style="All.Horizontal.TProgressbar",
                                     mode="determinate", maximum=100)
                pb.pack(fill="both", expand=True)
                self.slot_rows.append((nm, pb, pct))
        # 重建了控件 ⇒ 清掉槽位的本地显示缓存（否则新控件会沿用旧缓存而不再刷新）
        for k in [k for k in self._ui_last if k.startswith("slot")]:
            self._ui_last.pop(k, None)
        # ⚠️ 这里**不再**调 `_fit_window()`：槽位数变化（1 行 → 16 行）时改窗口尺寸会触发
        # 整窗口重排 + 重绘，而那一刻 16 路 UnRAR 正在抢 GIL ⇒ 主线程可能被拖住十几秒
        # （v1.5.2 真机实测：开局流畅，进入解压那一刻出现一次 **30 秒**未响应）。
        # 内容放不下时由外层滚动容器兜底（`_on_body_configure` 自动出滚动条）。

    def _apply_slots(self, s: dict) -> None:
        """按"每个正在解的包一条"刷新槽位；没有活跃包的槽位显示"空闲"。"""
        slots = s.get("slots") or []
        try:
            n = int(s.get("workers", 0) or 0)
        except (TypeError, ValueError):
            n = 0
        if n <= 0:
            # 扫描阶段 `_nw` 还没设（=0）⇒ 保持当前行数，别缩成 1 行再涨回来
            n = max(1, self._slot_n or len(slots) or 1)
        n = min(n, 64)              # 怪值别建出上千行（一行要 ~4ms）
        if n != self._slot_n:
            self._build_slots(n)
        busy = len(slots)
        if self.slot_rows:
            self._set_var("slots_head", self.var_slots,
                          f"{busy} 路在跑 / 共 {len(self.slot_rows)} 路")
        for i, (nm, pb, pct) in enumerate(self.slot_rows):
            if i < busy:
                d = slots[i] if isinstance(slots[i], dict) else {}
                # 显示的是**压缩包名称**（一个线程 ↔ 一个包），不是包内的文件名 ——
                # 需求：每个线程对应一个压缩包，显示这个压缩包的名称和解压到多少
                self._set_var(f"slot{i}:name", nm,
                              _ellipsize(d.get("name") or d.get("file") or ""))
                known = bool(d.get("known"))
                try:
                    p = float(d.get("pct", 0.0) or 0.0)
                except (TypeError, ValueError):
                    p = 0.0
                # 进度条按 **1%** 粒度更新（0.1% 的精度人眼看不出来，但 Tk 调用量差 10 倍；
                # 再配上"快照 10→4 次/秒"，总调用量降了一个数量级）
                p = round(p) if known else 0.0
                self._set_pb(f"slot{i}", pb, p)
                self._set_var(f"slot{i}:pct", pct, f"{p:.0f}%" if known else "—")
            else:
                self._set_var(f"slot{i}:name", nm, "空闲")
                self._set_pb(f"slot{i}", pb, 0.0)
                self._set_var(f"slot{i}:pct", pct, "")

    # -------------------------------------------------- 配置持久化

    def _save_cfg(self) -> None:
        # ⚠️ 有意**不保存**「源文件夹」与「输出目录」：把软件给家里人时，
        # 一打开就露出"上次解压了啥 / 解到哪"很尴尬。
        # 其余设置照旧持久化。
        data = {
            "layout": self.var_layout.get(),
            "sub": bool(self.var_sub.get()),
            "overwrite": self.var_ow.get(), "depth": self._depth_value(),
            "delete": bool(self.var_del.get()), "workers": self.var_workers.get(),
            "markfail": bool(self.var_markfail.get()),
            "clean": bool(self.var_clean.get()),
            "report": bool(self.var_report.get()),
            "smart": bool(self.var_smart.get()),
            "exe": bool(self.var_exe.get()),
        }
        try:
            os.makedirs(CFG_DIR, exist_ok=True)
            with open(CFG_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except OSError as exc:
            # 写不进去（目录只读、路径被占）时别静默 —— 用户改了设置却没保存
            # 是"静默失效"，必须留一行线索。
            self._log("warn", f"设置未能保存（{type(exc).__name__}: {exc}）。本次修改只在本次运行有效。")

    def _load_cfg(self) -> None:
        """读取配置。**任何异常都回默认**，绝不让一个坏文件把窗口挡在门外。

        🩸 旧实现只捕 `(OSError, ValueError)` 与 `(TypeError, ValueError)`，
        漏掉 `OverflowError`（`{"depth": Infinity}` / `1e999`）与 `RecursionError`
        （几千层嵌套的 JSON）⇒ `App.__init__` 抛异常、**窗口根本不出现、零提示**，
        用户只会觉得"软件打不开了"。
        """
        try:
            with open(CFG_PATH, encoding="utf-8") as f:
                data = json.load(f)
        except RecursionError:
            self._quarantine_cfg("配置内容嵌套过深")
            return
        except (OSError, ValueError, UnicodeDecodeError):
            return                      # 文件不存在 / 不是合法 JSON ⇒ 静默回默认
        if not isinstance(data, dict):
            # 合法 JSON 但不是对象（[]/null/"x"/123）时，旧代码在 data.get 上抛
            # AttributeError ⇒ 窗口都不出现。
            return
        try:
            self._apply_cfg(data)
        except Exception as exc:                    # noqa: BLE001
            self._quarantine_cfg(f"{type(exc).__name__}: {exc}")

    def _quarantine_cfg(self, why: str) -> None:
        """把读不动的 `settings.json` 改名保留并回默认，免得用户每次打开都撞同一面墙。"""
        bad = ""
        try:
            bad = f"{CFG_PATH}.bad-{time.strftime('%Y%m%d-%H%M%S')}"
            os.replace(CFG_PATH, bad)
        except OSError:
            bad = ""
        self._log("warn", f"设置文件无法读取（{why}），已按默认设置启动。")
        if bad:
            self._log("info", f"原文件已重命名保留：{bad}")

    def _apply_cfg(self, data: dict) -> None:
        # 不读 src / out：打开时保持干净（原因见 _save_cfg）
        # 🩸 也**不读 layout**：默认应是"每个压缩包解压到同目录下的同名文件夹"，
        # 而读回来的可能是"全部解压到 xx" —— 解压方式每次打开都回到**默认第一档**。
        # 🩸 同样**不读 delete**：「解压成功后删除原压缩包」是
        # 破坏性开关，勾一次就永久生效会放大任何解压缺陷的后果（对抗性审查里正是这样被放大的）
        # ⇒ 每次打开都回到"不删源包"。其余选项照旧记住。
        self.var_sub.set(self._as_bool(data.get("sub", True), True))
        ow = data.get("overwrite", "rename")
        self.var_ow.set(ow if ow in ("rename", "skip", "overwrite") else "rename")
        try:
            d = int(data.get("depth", 5))
        except (TypeError, ValueError, OverflowError):
            d = 5
        self.var_depth.set(max(1, min(30, d)))
        self.var_del.set(False)
        _wk = str(data.get("workers", "中"))
        self.var_workers.set(_wk if _wk in ("高", "中", "低") else "中")   # 兼容旧配置里的"自动"/数字
        self.var_markfail.set(self._as_bool(data.get("markfail", False)))
        self.var_clean.set(self._as_bool(data.get("clean", False)))
        self.var_report.set(self._as_bool(data.get("report", True), True))
        self.var_smart.set(self._as_bool(data.get("smart", True), True))
        self.var_exe.set(self._as_bool(data.get("exe", True), True))
        self._sync_layout()

    def _on_close(self) -> None:
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno(APP_NAME, "解压仍在进行，是否确认退出？"):
                return
            self.cancel.set()
            self.pause.clear()
            self.force_stop.set()
            # 🩸 关窗前先**直接杀掉外部解压工具**（否则 worker 要等检查点），
            # 并把等待时间放宽到 12 秒 —— 大沙箱（上万个文件）的 rmtree 实测要 14 秒，
            # 旧代码 `join(6)` 超时后进程带着 daemon 线程退出 ⇒ 源目录残留 `.rc-sbx-*`。
            try:
                self._signal_stop(only_alive=False)
            except Exception:                       # noqa: BLE001
                pass
            # 🩸 直接 destroy 会连 daemon 线程一起带走 ⇒ 已经写出去的文件来不及
            # 回滚（实测残留 251 个文件 / 16.4 MB）。这里先给它最多 12 秒收尾并提示。
            self._set_var("stat", self.var_stat, "正在收尾…")
            try:
                self.update()
            except tk.TclError:
                pass
            self.worker.join(timeout=12.0)
        self._alive = False
        for aid in list(self._afters):              # 销毁前撤掉在飞的 after
            try:
                self.after_cancel(aid)
            except Exception:                       # noqa: BLE001
                pass
        self._afters.clear()
        self.destroy()


def run_cli(argv: list[str]) -> int:
    """命令行模式（打包成 exe 后也用它做真机 e2e）：递归解压 --cli <目录>"""
    import argparse
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:                                       # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(prog="递归解压", description="递归解开文件夹里所有压缩包（含嵌套）")
    ap.add_argument("src", help="要处理的文件夹")
    ap.add_argument("-p", "--password", default="", help="密码（只对需要密码的包生效）")
    ap.add_argument("--layout", default="beside_folder",
                    choices=["beside_folder", "beside_flat", "out_dir", "out_dir_flat"])
    ap.add_argument("--out", default="", help="统一输出目录（留空=自动时间戳目录）")
    ap.add_argument("--depth", type=int, default=5, help="最大嵌套层数")
    ap.add_argument("--workers", type=int, default=0,
                    help="并行度（显式数字，优先于 --level；0=按 --level 自动）")
    ap.add_argument("--level", default="mid", choices=["high", "mid", "low"],
                    help="并行优先级：high=线程数×1.0 / mid=×0.75 / low=×0.5")
    ap.add_argument("--overwrite", default="rename", choices=["rename", "skip", "overwrite"])
    ap.add_argument("--delete", action="store_true", help="解压成功后删除原压缩包")
    ap.add_argument("--mark-failed", action="store_true", help="失败的原压缩包添加 .failed 标记")
    ap.add_argument("--clean", action="store_true", help="清理解压产生的空目录")
    ap.add_argument("--no-smart-extract", action="store_true",
                    help="关闭智能解压（不剥掉与包同名的单层顶层文件夹）")
    ap.add_argument("--no-exe", action="store_true",
                    help="不尝试解开 .exe 外壳（自解压包）里的压缩本体")
    ap.add_argument("--no-report", action="store_true", help="不生成处理报告")
    ap.add_argument("--dry-run", action="store_true", help="只扫描不解压")
    a = ap.parse_args(argv)
    if a.depth < 1:
        ap.error("--depth 必须 ≥ 1（它的含义是：最多往下解几层包）")

    opt = Options(layout=a.layout, out_dir=a.out, overwrite=a.overwrite, max_depth=a.depth,
                  delete_source=a.delete, password=a.password, workers=a.workers,
                  worker_level=a.level,
                  mark_failed=a.mark_failed, clean_empty_dirs=a.clean,
                  report=not a.no_report, dry_run=a.dry_run,
                  smart_extract=not a.no_smart_extract, scan_exe=not a.no_exe)
    ex = Extractor([a.src], opt, log=lambda lv, m: print(f"[{lv}] {m}", flush=True))
    st = ex.run()
    return 0 if st.archives_failed == 0 else 2


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] in ("--cli", "-c"):
        sys.exit(run_cli(argv[1:]))
    if argv and argv[0] in ("--version", "-V"):
        print(f"{APP_NAME} {VERSION}")
        return
    hide_own_console()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
