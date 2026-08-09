/*
 * utui.c — Universal TUI engine.  A "make menuconfig" (lxdialog) style terminal
 *          UI toolkit in C99.  Consumers describe a UtItem tree + a UtApp and
 *          call ut_run()/ut_main() (see utui.h); this file is the reusable
 *          engine (terminal layer, cell renderer, input parser, widgets:
 *          menu/msgbox/yesno/inputbox/textview, .config save/load, search).
 *
 *   Language   : C99 (-std=c99 -pedantic)
 *   Portability: POSIX (Linux/macOS/BSD; termios+poll) and pure Windows
 *                (Win32 Console API).  Rendering is direct VT100/xterm escapes;
 *                Windows uses ENABLE_VIRTUAL_TERMINAL_PROCESSING for output and
 *                ReadConsoleInputW -> VT translation for input (works on Win7+
 *                and Wine, not just Win10 VT-input).
 *   Dependency : none.  Only libc and the OS terminal API (no ncurses).
 *
 *   License: Apache-2.0.
 */
#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <io.h>
#else
#  define _POSIX_C_SOURCE 200809L
#  include <poll.h>
#  include <signal.h>
#  include <sys/ioctl.h>
#  include <termios.h>
#  include <unistd.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utui.h"

/* ---------------------------------------------------------------- 定数 */

#define MIN_COLS      80
#define MIN_ROWS      19
#define MAX_DEPTH     16
#define MAX_LABEL     256
#define MAX_RESULTS   64
#define PASTE_MAX     1024

enum { C_BLACK, C_RED, C_GREEN, C_YELLOW, C_BLUE, C_MAGENTA, C_CYAN, C_WHITE };

enum {                                   /* getkey() の返す仮想キー */
    K_NONE = 0x1000, K_UP, K_DOWN, K_LEFT, K_RIGHT, K_ENTER, K_ESC, K_TAB,
    K_BTAB, K_PGUP, K_PGDN, K_HOME, K_END, K_BS, K_DEL, K_RESIZE, K_QUIT,
    K_MOUSE, K_PASTE
};

typedef struct { int type; int mb, mx, my, mpress; } Key;

static int  g_rows = 24, g_cols = 80;
static int  g_ascii = 0;                 /* 1 なら罫線を +-| で描く */
static char g_paste[PASTE_MAX];
static const UtApp *g_app = NULL;   /* 実行中のアプリ記述 */
static UtItem *g_root_ptr = NULL;    /* ルートメニュー */

/* 早期宣言 (プラットフォーム層から使う) */
static void buf_resize(void);

/* =====================================================================
 *  プラットフォーム抽象層  (端末 raw 化 / 入力 1 バイト / サイズ / 出力)
 * ===================================================================== */

static volatile sig_atomic_t g_quit = 0, g_resized = 0;

/* --- 生バイト出力 (部分書き込みに強い) --- */
static void wrs_n(const char *s, size_t n)
{
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD done = 0, off = 0;
    while (off < n) {
        if (!WriteFile(h, s + off, (DWORD)(n - off), &done, NULL) || done == 0)
            break;
        off += done;
    }
#else
    size_t off = 0;
    while (off < n) {
        long w = (long)write(STDOUT_FILENO, s + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; return; }
        off += (size_t)w;
    }
#endif
}
static void wrs(const char *s) { wrs_n(s, strlen(s)); }

#if defined(_WIN32)
/* ---------------------------- Windows 実装 ---------------------------- */
static HANDLE g_hin, g_hout;
static DWORD  g_inmode_old, g_outmode_old;
static UINT   g_cp_old, g_cpout_old;
static int    g_rawon = 0;

static void term_getsize(void)
{
    CONSOLE_SCREEN_BUFFER_INFO ci;
    if (GetConsoleScreenBufferInfo(g_hout, &ci)) {
        int w = ci.srWindow.Right - ci.srWindow.Left + 1;
        int h = ci.srWindow.Bottom - ci.srWindow.Top + 1;
        if (w > 0) g_cols = w;
        if (h > 0) g_rows = h;
    }
}

static void term_restore(void)
{
    if (!g_rawon) return;
    g_rawon = 0;
    wrs("\x1b[?1000l\x1b[?1006l\x1b[?2004l\x1b[0m\x1b[?25h\x1b[?1049l");
    SetConsoleMode(g_hin, g_inmode_old);
    SetConsoleMode(g_hout, g_outmode_old);
    SetConsoleCP(g_cp_old);
    SetConsoleOutputCP(g_cpout_old);
}

static BOOL WINAPI ctrl_handler(DWORD t)
{
    (void)t; g_quit = 1; return TRUE;     /* Ctrl-C/Break/Close: 終了要求 */
}

static void term_init(void)
{
    DWORD im, om;
    g_hin  = GetStdHandle(STD_INPUT_HANDLE);
    g_hout = GetStdHandle(STD_OUTPUT_HANDLE);
    GetConsoleMode(g_hin, &g_inmode_old);
    GetConsoleMode(g_hout, &g_outmode_old);
    g_cp_old = GetConsoleCP(); g_cpout_old = GetConsoleOutputCP();
    SetConsoleCP(65001); SetConsoleOutputCP(65001);       /* UTF-8 */

    om = g_outmode_old | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/
                       | 0x0008 /*DISABLE_NEWLINE_AUTO_RETURN*/;
    SetConsoleMode(g_hout, om);
    /* 入力は ReadConsoleInput でイベントを取り、自前で VT バイト列へ翻訳する
     * (VT入力に依存しないので Win7/8 や wine でも動く)。line(0x0002)/echo(0x0004)
     * を切り、QuickEdit(0x0040) も切ってマウスを有効化。PROCESSED_INPUT(0x0001)
     * は残し Ctrl-C を CtrlHandler に渡す。EXTENDED_FLAGS(0x0080) は Mouse/
     * QuickEdit の変更に必須。WINDOW_INPUT(0x0008) でリサイズ通知を得る。 */
    im = (g_inmode_old & ~(DWORD)(0x0002 /*LINE*/ | 0x0004 /*ECHO*/
                                   | 0x0040 /*QUICK_EDIT*/))
         | 0x0080 /*ENABLE_EXTENDED_FLAGS*/ | 0x0010 /*ENABLE_MOUSE_INPUT*/
         | 0x0008 /*ENABLE_WINDOW_INPUT*/ | 0x0001 /*ENABLE_PROCESSED_INPUT*/;
    SetConsoleMode(g_hin, im);
    g_rawon = 1;
    atexit(term_restore);
    SetConsoleCtrlHandler(ctrl_handler, TRUE);

    wrs("\x1b[?1049h\x1b[2J\x1b[?25l\x1b[?1000h\x1b[?1006h\x1b[?2004h");
    term_getsize();
}

/* 入力バイトのリングキュー (翻訳したエスケープ列を溜める) */
static unsigned char g_inq[256];
static int g_inq_h = 0, g_inq_t = 0;
static DWORD g_prevbtn = 0;

static void q_push(int c)
{
    int nt = (g_inq_t + 1) & 255;
    if (nt != g_inq_h) { g_inq[g_inq_t] = (unsigned char)c; g_inq_t = nt; }
}
static void q_pushs(const char *s) { while (*s) q_push((unsigned char)*s++); }
static int q_pop(void)
{
    int c;
    if (g_inq_h == g_inq_t) return -1;
    c = g_inq[g_inq_h]; g_inq_h = (g_inq_h + 1) & 255;
    return c;
}

/* INPUT_RECORD を VT バイト列へ翻訳してキューへ積む */
static void translate_record(const INPUT_RECORD *ir)
{
    if (ir->EventType == WINDOW_BUFFER_SIZE_EVENT) { g_resized = 1; return; }
    if (ir->EventType == KEY_EVENT) {
        const KEY_EVENT_RECORD *k = &ir->Event.KeyEvent;
        WORD vk = k->wVirtualKeyCode, rc = k->wRepeatCount, i;
        int shift = (k->dwControlKeyState & 0x0010) != 0;   /* SHIFT_PRESSED */
        unsigned ch;
        if (!k->bKeyDown) return;
        switch (vk) {
        case 0x26: q_pushs("\x1b[A"); return;   /* Up    */
        case 0x28: q_pushs("\x1b[B"); return;   /* Down  */
        case 0x27: q_pushs("\x1b[C"); return;   /* Right */
        case 0x25: q_pushs("\x1b[D"); return;   /* Left  */
        case 0x24: q_pushs("\x1b[H"); return;   /* Home  */
        case 0x23: q_pushs("\x1b[F"); return;   /* End   */
        case 0x21: q_pushs("\x1b[5~"); return;  /* PgUp  */
        case 0x22: q_pushs("\x1b[6~"); return;  /* PgDn  */
        case 0x2E: q_pushs("\x1b[3~"); return;  /* Del   */
        case 0x09: if (shift) q_pushs("\x1b[Z"); else q_push('\t'); return;
        case 0x0D: q_push('\r'); return;        /* Enter */
        case 0x08: q_push(127);   return;       /* Backspace */
        case 0x1B: q_push(0x1b);  return;       /* Esc   */
        default: break;
        }
        ch = (unsigned)k->uChar.UnicodeChar;    /* 印字文字はそのまま */
        if (ch >= 32 && ch < 127)
            for (i = 0; i < rc; i++) q_push((int)ch);
        return;
    }
    if (ir->EventType == MOUSE_EVENT) {
        const MOUSE_EVENT_RECORD *me = &ir->Event.MouseEvent;
        int x = me->dwMousePosition.X + 1, y = me->dwMousePosition.Y + 1;
        char tmp[32];
        if (me->dwEventFlags & 0x0004) {         /* MOUSE_WHEELED */
            int up = ((long)me->dwButtonState >> 16) > 0;
            sprintf(tmp, "\x1b[<%d;%d;%dM", up ? 64 : 65, x, y);
            q_pushs(tmp); return;
        }
        if (me->dwEventFlags == 0) {             /* ボタン押下/解放 */
            DWORD now = me->dwButtonState;
            if ((now & 1) && !(g_prevbtn & 1)) {
                sprintf(tmp, "\x1b[<0;%d;%dM", x, y); q_pushs(tmp);
            } else if (!(now & 1) && (g_prevbtn & 1)) {
                sprintf(tmp, "\x1b[<0;%d;%dm", x, y); q_pushs(tmp);
            }
            g_prevbtn = now;
        }
        return;
    }
}

/* -1=timeout, -2=resize, -3=quit, >=0 = byte */
static int readbyte(int timeout_ms)
{
    for (;;) {
        int c;
        DWORD r, got, i;
        INPUT_RECORD recs[32];
        if (g_quit)    return -3;
        if (g_resized) return -2;
        c = q_pop(); if (c >= 0) return c;
        r = WaitForSingleObject(g_hin, timeout_ms < 0 ? 50u : (DWORD)timeout_ms);
        if (r == WAIT_TIMEOUT) { if (timeout_ms < 0) continue; return -1; }
        if (r != WAIT_OBJECT_0) return -1;
        got = 0;
        if (!ReadConsoleInputW(g_hin, recs, 32, &got) || got == 0) return -1;
        for (i = 0; i < got; i++) translate_record(&recs[i]);
        if (g_resized) return -2;
    }
}

#else
/* ---------------------------- POSIX 実装 ---------------------------- */
static struct termios g_oldtio;
static int g_rawon = 0;

static void term_getsize(void)
{
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        g_cols = ws.ws_col; g_rows = ws.ws_row;
    }
}

static void term_restore(void)
{
    if (!g_rawon) return;
    g_rawon = 0;
    wrs("\x1b[?1000l\x1b[?1006l\x1b[?2004l\x1b[0m\x1b[?25h\x1b[?1049l");
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_oldtio);
}

static void on_sigint(int s)   { (void)s; g_quit = 1; }
static void on_sigwinch(int s) { (void)s; g_resized = 1; }

static void term_init(void)
{
    struct termios t;
    struct sigaction sa;
    tcgetattr(STDIN_FILENO, &g_oldtio);
    t = g_oldtio;
    t.c_lflag &= (tcflag_t)~(ICANON | ECHO);
    t.c_iflag &= (tcflag_t)~(IXON | ICRNL | INLCR);
    t.c_cc[VMIN] = 1; t.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &t);
    g_rawon = 1;
    atexit(term_restore);

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigint;                     /* SA_RESTART なし */
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);                 /* Ctrl-\ でも復元 */
    sigaction(SIGHUP,  &sa, NULL);
    sa.sa_handler = on_sigwinch;
    sigaction(SIGWINCH, &sa, NULL);

    wrs("\x1b[?1049h\x1b[2J\x1b[?25l\x1b[?1000h\x1b[?1006h\x1b[?2004h");
    term_getsize();
}

static int readbyte(int timeout_ms)
{
    struct pollfd p; unsigned char c; long n; int r;
    p.fd = STDIN_FILENO; p.events = POLLIN; p.revents = 0;
    for (;;) {
        if (g_quit)    return -3;
        if (g_resized) return -2;
        r = poll(&p, 1, timeout_ms);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        n = (long)read(STDIN_FILENO, &c, 1);
        if (n == 1) return (int)c;
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
}
#endif

/* ------------------------------------------------------- セルバッファ */

typedef struct { char g[5]; unsigned char fg, bg, bold; } Cell;

static Cell *g_buf = NULL;
static int   g_bw = 0, g_bh = 0;
static int   g_cursx = -1, g_cursy = -1;

static void buf_resize(void)
{
    if (g_bw == g_cols && g_bh == g_rows && g_buf) return;
    free(g_buf);
    g_bw = g_cols; g_bh = g_rows;
    g_buf = calloc((size_t)g_bw * (size_t)g_bh, sizeof(Cell));
    if (!g_buf) { term_restore(); fprintf(stderr, "out of memory\n"); exit(1); }
}

static void put(int x, int y, const char *glyph, int fg, int bg, int bold)
{
    Cell *c; size_t n;
    if (x < 0 || y < 0 || x >= g_bw || y >= g_bh) return;
    c = &g_buf[(size_t)y * (size_t)g_bw + (size_t)x];
    n = strlen(glyph); if (n > 4) n = 4;
    memcpy(c->g, glyph, n); c->g[n] = 0;
    c->fg = (unsigned char)fg; c->bg = (unsigned char)bg;
    c->bold = (unsigned char)bold;
}

static void putc_at(int x, int y, char ch, int fg, int bg, int bold)
{
    unsigned char uch = (unsigned char)ch;
    char s[2];
    s[0] = (uch < 32 || uch == 127) ? '?' : ch;
    s[1] = 0;
    put(x, y, s, fg, bg, bold);
}

static void puts_at(int x, int y, const char *s, int fg, int bg, int bold)
{
    int i;
    /* putc_at keeps application/config data from becoming control sequences. */
    for (i = 0; s[i]; i++) putc_at(x + i, y, s[i], fg, bg, bold);
}

static void fill(int x, int y, int w, int h, const char *g, int fg, int bg, int bold)
{
    int i, j;
    for (j = 0; j < h; j++) for (i = 0; i < w; i++) put(x + i, y + j, g, fg, bg, bold);
}

static void flush_frame(void)
{
    static char *out = NULL; static size_t cap = 0;
    size_t need = (size_t)g_bw * (size_t)g_bh * 24u + 512u;
    size_t o = 0;
    int x, y, lf = -1, lb = -1, lB = -1;

    if (need > cap) { free(out); out = malloc(need); cap = need;
        if (!out) { term_restore(); exit(1); } }

    o += (size_t)sprintf(out + o, "\x1b[?25l\x1b[H");
    for (y = 0; y < g_bh; y++) {
        o += (size_t)sprintf(out + o, "\x1b[%d;1H", y + 1);
        for (x = 0; x < g_bw; x++) {
            Cell *c = &g_buf[(size_t)y * (size_t)g_bw + (size_t)x];
            if (c->fg != lf || c->bg != lb || c->bold != lB) {
                o += (size_t)sprintf(out + o, "\x1b[0;%d;%d%sm",
                                     30 + c->fg, 40 + c->bg, c->bold ? ";1" : "");
                lf = c->fg; lb = c->bg; lB = c->bold;
            }
            if (c->g[0]) { size_t n = strlen(c->g); memcpy(out + o, c->g, n); o += n; }
            else out[o++] = ' ';
        }
    }
    o += (size_t)sprintf(out + o, "\x1b[0m");
    if (g_cursx >= 0 && g_cursy >= 0)
        o += (size_t)sprintf(out + o, "\x1b[%d;%dH\x1b[?25h", g_cursy + 1, g_cursx + 1);
    wrs_n(out, o);
}

/* ------------------------------------------------------------- 罫線 */

static const char *G_HL(void) { return g_ascii ? "-" : "\xe2\x94\x80"; }
static const char *G_VL(void) { return g_ascii ? "|" : "\xe2\x94\x82"; }
static const char *G_TL(void) { return g_ascii ? "+" : "\xe2\x94\x8c"; }
static const char *G_TR(void) { return g_ascii ? "+" : "\xe2\x94\x90"; }
static const char *G_BL(void) { return g_ascii ? "+" : "\xe2\x94\x94"; }
static const char *G_BR(void) { return g_ascii ? "+" : "\xe2\x94\x98"; }
static const char *G_LT(void) { return g_ascii ? "+" : "\xe2\x94\x9c"; }
static const char *G_RT(void) { return g_ascii ? "+" : "\xe2\x94\xa4"; }

static void draw_box(int x, int y, int w, int h, int bg)
{
    int i;
    if (w < 2 || h < 2) return;
    put(x, y, G_TL(), C_WHITE, bg, 1);
    put(x + w - 1, y, G_TR(), C_BLACK, bg, 0);
    put(x, y + h - 1, G_BL(), C_WHITE, bg, 1);
    put(x + w - 1, y + h - 1, G_BR(), C_BLACK, bg, 0);
    for (i = 1; i < w - 1; i++) {
        put(x + i, y, G_HL(), C_WHITE, bg, 1);
        put(x + i, y + h - 1, G_HL(), C_BLACK, bg, 0);
    }
    for (i = 1; i < h - 1; i++) {
        put(x, y + i, G_VL(), C_WHITE, bg, 1);
        put(x + w - 1, y + i, G_VL(), C_BLACK, bg, 0);
    }
}

static void draw_shadow(int x, int y, int w, int h)
{
    int i;
    for (i = 1; i <= h; i++) {
        put(x + w, y + i, " ", C_BLACK, C_BLACK, 0);
        put(x + w + 1, y + i, " ", C_BLACK, C_BLACK, 0);
    }
    for (i = 2; i < w + 2; i++) put(x + i, y + h, " ", C_BLACK, C_BLACK, 0);
}

/* 語単位の折返し。行数を返す。width<=0 では何もせず 1 を返す(防御) */
static int wrap_text(const char *s, int width, int x, int y, int draw,
                     int fg, int bg, int bold)
{
    int lines = 0, col = 0, i = 0;
    if (width <= 0) return 1;
    while (s[i]) {
        int wlen = 0, j = i;
        if (s[i] == '\n') { lines++; col = 0; i++; continue; }
        while (s[j] && s[j] != ' ' && s[j] != '\n') { wlen++; j++; }
        if (wlen > width) wlen = width;
        if (col + wlen > width) { lines++; col = 0; }
        if (draw && wlen > 0) {
            int k;
            for (k = 0; k < wlen; k++)
                putc_at(x + col + k, y + lines, s[i + k], fg, bg, bold);
        }
        col += wlen; i += wlen;
        while (s[i] == ' ') {
            if (col < width) { if (draw) putc_at(x + col, y + lines, ' ', fg, bg, bold); col++; }
            i++;
        }
    }
    return lines + 1;
}

/* ------------------------------------------------------------ 入力 */

static Key getkey(void)
{
    Key k; memset(&k, 0, sizeof k); k.type = K_NONE;
    for (;;) {
        int c;
        if (g_quit)    { k.type = K_QUIT;   return k; }
        if (g_resized) { g_resized = 0; term_getsize(); buf_resize();
                         k.type = K_RESIZE; return k; }
        c = readbyte(200);
        if (c == -3) { k.type = K_QUIT; return k; }
        if (c == -2) { g_resized = 0; term_getsize(); buf_resize();
                       k.type = K_RESIZE; return k; }
        if (c < 0) continue;

        if (c == 0x1b) {
            int c2 = readbyte(60);
            if (c2 < 0) { k.type = K_ESC; return k; }
            if (c2 == '[' || c2 == 'O') {
                int par[4] = {0,0,0,0}; int ip = 0, priv = 0, fin = -1;
                if (c2 == 'O') fin = readbyte(60);
                else for (;;) {
                    int c3 = readbyte(60);
                    if (c3 < 0) { fin = -1; break; }
                    if (c3 == '<') { priv = 1; continue; }
                    if (c3 >= '0' && c3 <= '9') {
                        if (par[ip] < 1000000) par[ip] = par[ip]*10 + (c3-'0');
                        continue;
                    }
                    if (c3 == ';') { if (ip < 3) ip++; continue; }
                    fin = c3; break;
                }
                switch (fin) {
                case 'A': k.type = K_UP;    return k;
                case 'B': k.type = K_DOWN;  return k;
                case 'C': k.type = K_RIGHT; return k;
                case 'D': k.type = K_LEFT;  return k;
                case 'H': k.type = K_HOME;  return k;
                case 'F': k.type = K_END;   return k;
                case 'Z': k.type = K_BTAB;  return k;
                case '~':
                    switch (par[0]) {
                    case 1: case 7: k.type = K_HOME; return k;
                    case 4: case 8: k.type = K_END;  return k;
                    case 5: k.type = K_PGUP; return k;
                    case 6: k.type = K_PGDN; return k;
                    case 3: k.type = K_DEL;  return k;
                    case 200: {                       /* bracketed paste 開始 */
                        size_t pn = 0;
                        for (;;) {
                            int pc = readbyte(200);
                            if (pc < 0) break;
                            if (pc == 0x1b) {         /* ESC[201~ を検出 */
                                int a = readbyte(60), b = readbyte(60);
                                int d = readbyte(60), e = readbyte(60);
                                int f = readbyte(60);
                                if (a=='[' && b=='2' && d=='0' && e=='1' && f=='~')
                                    break;
                                break;
                            }
                            if (pn < PASTE_MAX - 1 && pc >= 32 && pc < 127)
                                g_paste[pn++] = (char)pc;
                        }
                        g_paste[pn] = 0;
                        k.type = K_PASTE; return k;
                    }
                    default: break;
                    }
                    continue;
                case 'M': case 'm':
                    if (priv) {                       /* SGR-1006 */
                        k.type = K_MOUSE; k.mb = par[0];
                        k.mx = par[1] - 1; k.my = par[2] - 1;
                        k.mpress = (fin == 'M');
                        return k;
                    } else {                          /* X10: 続く3バイト */
                        int b = readbyte(60), xx = readbyte(60), yy = readbyte(60);
                        if (b < 0 || xx < 0 || yy < 0) continue;
                        k.type = K_MOUSE;
                        k.mb = (b - 32) & 0xff;
                        k.mx = xx - 33; k.my = yy - 33;
                        k.mpress = ((k.mb & 3) != 3); /* 3=release */
                        if (k.mb == 3) k.mpress = 0;
                        return k;
                    }
                default: continue;
                }
            }
            k.type = K_ESC; return k;
        }
        if (c == '\r' || c == '\n') { k.type = K_ENTER; return k; }
        if (c == '\t')              { k.type = K_TAB;   return k; }
        if (c == 127 || c == 8)     { k.type = K_BS;    return k; }
        if (c == 3)                 { k.type = K_QUIT;  return k; }
        k.type = c; return k;
    }
}


static void init_tree(UtItem *it)
{
    int i;
    for (i = 0; i < it->nchild; i++) {
        it->children[i].parent = it;
        it->children[i].idx = i;
        init_tree(&it->children[i]);
    }
}

/* ---------------------------------------------------- 項目テキスト */

static int item_enterable(const UtItem *it)
{
    if (!it->nchild) return 0;
    if (it->type == UT_TYPE_BOOL && it->value == 0 && !it->forced) return 0;
    return 1;
}

static int item_text(const UtItem *it, char *buf, size_t cap)
{
    char mark[16] = "    ";
    char tail[8]  = "";
    int off;
    switch (it->type) {
    case UT_TYPE_BOOL:
        if (it->forced)      strcpy(mark, "-*- ");
        else if (it->value)  strcpy(mark, "[*] ");
        else                 strcpy(mark, "[ ] ");
        break;
    case UT_TYPE_TRI:
        if (it->value == 2)      strcpy(mark, "<*> ");
        else if (it->value == 1) strcpy(mark, "<M> ");
        else                     strcpy(mark, "< > ");
        break;
    case UT_TYPE_STR: case UT_TYPE_INT:
        snprintf(mark, sizeof mark, "(%.10s) ", it->strval);
        break;
    case UT_TYPE_RADIO:
        strcpy(mark, (it->parent && it->parent->value == it->idx) ? "(X) " : "( ) ");
        break;
    case UT_TYPE_COMMENT:
        snprintf(buf, cap, "    *** %s ***", it->name);
        return 4;
    default: break;
    }
    if (it->nchild) strcpy(tail, item_enterable(it) ? "  --->" : "  ----");
    off = (int)strlen(mark);
    if (it->type == UT_TYPE_CHOICE)
        snprintf(buf, cap, "%s%s (%s)%s", mark, it->name,
                 it->children[it->value].name, tail);
    else
        snprintf(buf, cap, "%s%s%s", mark, it->name, tail);
    return off;
}

static const char *type_name(const UtItem *it)
{
    switch (it->type) {
    case UT_TYPE_BOOL: return "bool";       case UT_TYPE_TRI: return "tristate";
    case UT_TYPE_STR:  return "string";     case UT_TYPE_INT: return "integer";
    case UT_TYPE_CHOICE: return "choice";   case UT_TYPE_RADIO: return "bool (choice)";
    case UT_TYPE_MENU: return "menu";       default: return "comment";
    }
}

static void value_str(const UtItem *it, char *out, size_t cap)
{
    switch (it->type) {
    case UT_TYPE_BOOL: snprintf(out, cap, "%s", it->forced || it->value ? "y" : "n"); break;
    case UT_TYPE_TRI:  snprintf(out, cap, "%s", it->value == 2 ? "y" : it->value == 1 ? "m" : "n"); break;
    case UT_TYPE_STR: case UT_TYPE_INT: snprintf(out, cap, "%s", it->strval); break;
    case UT_TYPE_CHOICE: snprintf(out, cap, "%s", it->children[it->value].name); break;
    case UT_TYPE_RADIO: snprintf(out, cap, "%s",
                   it->parent && it->parent->value == it->idx ? "y" : "n"); break;
    default: out[0] = 0; break;
    }
}

/* ------------------------------------------------------ ナビ状態 */

typedef struct { UtItem *menu; int sel, top, btn; } NavFrame;

static NavFrame g_stack[MAX_DEPTH];
static int g_depth = 0;

static int g_list_x, g_list_y, g_list_w, g_list_h, g_list_top;
static int g_btn_y, g_btn_x[8], g_btn_w[8], g_btn_n;

static int sel_ok(const UtItem *m, int i)
{
    return i >= 0 && i < m->nchild && m->children[i].type != UT_TYPE_COMMENT;
}
static int next_sel(const UtItem *m, int from, int dir)
{
    int i = from;
    for (;;) {
        i += dir;
        if (i < 0 || i >= m->nchild) return from;
        if (m->children[i].type != UT_TYPE_COMMENT) return i;
    }
}
static int first_sel(const UtItem *m)
{
    int i;
    for (i = 0; i < m->nchild; i++)
        if (m->children[i].type != UT_TYPE_COMMENT) return i;
    return 0;
}
static int last_sel(const UtItem *m)
{
    int i;
    for (i = m->nchild - 1; i >= 0; i--)
        if (m->children[i].type != UT_TYPE_COMMENT) return i;
    return 0;
}

/* -------------------------------------------------------- 描画 */

static const char *INSTR =
"Arrow keys navigate the menu.  <Enter> selects submenus ---> (or empty "
"submenus ----).  Highlighted letters are hotkeys.  Pressing <Y> includes, "
"<N> excludes, <M> modularizes features.  Press <Esc><Esc> to exit, <?> for "
"Help, </> for Search.  Legend: [*] built-in  [ ] excluded  <M> module  "
"< > module capable";

static void draw_backdrop(void)
{
    int i;
    buf_resize();
    fill(0, 0, g_cols, g_rows, " ", C_WHITE, C_BLUE, 0);
    puts_at(0, 0, g_app->backtitle, C_WHITE, C_BLUE, 1);
    for (i = 0; i < g_cols; i++) put(i, 1, G_HL(), C_WHITE, C_BLUE, 0);
}

static void draw_title(int x, int y, int w, const char *title)
{
    int len = (int)strlen(title);
    int tx = x + (w - len - 2) / 2;
    if (tx < x + 1) tx = x + 1;
    putc_at(tx, y, ' ', C_BLUE, C_WHITE, 1);
    puts_at(tx + 1, y, title, C_BLUE, C_WHITE, 1);
    putc_at(tx + 1 + len, y, ' ', C_BLUE, C_WHITE, 1);
}

static void draw_buttons(int y, int cx, const char *const *labels, int n, int focus)
{
    int total = 0, i, x;
    for (i = 0; i < n; i++) total += (int)strlen(labels[i]) + 2;
    total -= 2;
    x = cx - total / 2;
    g_btn_y = y; g_btn_n = n;
    for (i = 0; i < n; i++) {
        const char *lb = labels[i];
        int len = (int)strlen(lb), j, hot = -1;
        int ac = (i == focus);
        int fg = ac ? C_WHITE : C_BLACK, bg = ac ? C_BLUE : C_WHITE;
        g_btn_x[i] = x; g_btn_w[i] = len;
        for (j = 0; lb[j]; j++)
            if (isupper((unsigned char)lb[j])) { hot = j; break; }
        for (j = 0; j < len; j++) {
            int f = fg, b = ac;
            if (j == hot) { f = ac ? C_YELLOW : C_RED; b = 1; }
            putc_at(x + j, y, lb[j], f, bg, b);
        }
        x += len + 2;
    }
}

static void draw_menu(void)
{
    NavFrame *fr = &g_stack[g_depth];
    UtItem *m = fr->menu;
    static const char *BTNS[5] = { "<Select>", "< Exit >", "< Help >",
                                   "< Save >", "< Load >" };
    int dw, dh, dx, dy, ilines, mby, mbh, lh, i;
    char buf[MAX_LABEL];

    draw_backdrop();

    if (g_cols < MIN_COLS || g_rows < MIN_ROWS) {
        const char *msg = "Your display is too small to run Menuconfig!";
        const char *msg2 = "It must be at least 19 lines by 80 columns.";
        puts_at((g_cols - (int)strlen(msg)) / 2, g_rows / 2 - 1, msg, C_WHITE, C_BLUE, 1);
        puts_at((g_cols - (int)strlen(msg2)) / 2, g_rows / 2, msg2, C_WHITE, C_BLUE, 0);
        g_list_h = 0; g_btn_n = 0;
        return;
    }

    dw = g_cols - 8;  if (dw > 130) dw = 130;
    dh = g_rows - 4;
    dx = (g_cols - dw) / 2;
    dy = 2 + (g_rows - 2 - dh) / 2;

    draw_shadow(dx, dy, dw, dh);
    fill(dx, dy, dw, dh, " ", C_BLACK, C_WHITE, 0);
    draw_box(dx, dy, dw, dh, C_WHITE);
    draw_title(dx, dy, dw, g_depth ? m->name : g_app->title);

    ilines = wrap_text(INSTR, dw - 4, dx + 2, dy + 1, 1, C_BLACK, C_WHITE, 0);

    mby = dy + 1 + ilines;
    mbh = (dy + dh - 4) - mby + 1;
    if (mbh < 3) mbh = 3;
    lh = mbh - 2;
    draw_box(dx + 2, mby, dw - 4, mbh, C_WHITE);

    if (fr->sel >= m->nchild) fr->sel = m->nchild ? m->nchild - 1 : 0;
    if (m->nchild && m->children[fr->sel].type == UT_TYPE_COMMENT) fr->sel = first_sel(m);
    if (fr->sel < fr->top) fr->top = fr->sel;
    if (fr->sel >= fr->top + lh) fr->top = fr->sel - lh + 1;
    if (fr->top < 0) fr->top = 0;
    if (fr->top > m->nchild - lh) fr->top = m->nchild - lh;
    if (fr->top < 0) fr->top = 0;

    g_list_x = dx + 3; g_list_y = mby + 1;
    g_list_w = dw - 6; g_list_h = lh; g_list_top = fr->top;

    for (i = 0; i < lh && fr->top + i < m->nchild; i++) {
        UtItem *it = &m->children[fr->top + i];
        int off = item_text(it, buf, sizeof buf);
        int selr = (fr->top + i == fr->sel);
        int len = (int)strlen(buf), j;
        if (len > g_list_w - 1) { len = g_list_w - 1; buf[len] = 0; }
        for (j = 0; j < len; j++) {
            int fg = C_BLACK, bg = C_WHITE, bold = 0;
            if (j >= off && selr) { fg = C_WHITE; bg = C_BLUE; bold = 1; }
            if (j == off && it->type != UT_TYPE_COMMENT) { fg = selr ? C_YELLOW : C_BLUE; bold = 1; }
            putc_at(g_list_x + 1 + j, g_list_y + i, buf[j], fg, bg, bold);
        }
    }
    if (fr->top > 0) puts_at(dx + 4, mby, "^(-)", C_BLACK, C_WHITE, 0);
    if (fr->top + lh < m->nchild) puts_at(dx + 4, mby + mbh - 1, "v(+)", C_BLACK, C_WHITE, 0);

    put(dx, dy + dh - 3, G_LT(), C_WHITE, C_WHITE, 1);
    for (i = 1; i < dw - 1; i++) put(dx + i, dy + dh - 3, G_HL(), C_BLACK, C_WHITE, 0);
    put(dx + dw - 1, dy + dh - 3, G_RT(), C_BLACK, C_WHITE, 0);
    draw_buttons(dy + dh - 2, dx + dw / 2, BTNS, 5, fr->btn);
}

/* ------------------------------------------------- 汎用モーダル */

static void modal_frame(int *ox, int *oy, int w, int h, const char *title)
{
    int x = (g_cols - w) / 2, y = (g_rows - h) / 2 + 1;
    if (y < 2) y = 2;
    if (x < 0) x = 0;
    draw_shadow(x, y, w, h);
    fill(x, y, w, h, " ", C_BLACK, C_WHITE, 0);
    draw_box(x, y, w, h, C_WHITE);
    if (title) draw_title(x, y, w, title);
    *ox = x; *oy = y;
}

static int clampw(int w) { if (w > g_cols - 4) w = g_cols - 4; if (w < 24) w = 24; return w; }

static int hit_button(int mx, int my)
{
    int i;
    if (my != g_btn_y) return -1;
    for (i = 0; i < g_btn_n; i++)
        if (mx >= g_btn_x[i] && mx < g_btn_x[i] + g_btn_w[i]) return i;
    return -1;
}

static void msgbox(const char *title, const char *text)
{
    static const char *B[1] = { "< Ok >" };
    for (;;) {
        int w, h, x, y, tl;
        Key k;
        draw_menu();
        tl = (int)strlen(text);
        w = clampw(tl + 8);
        h = wrap_text(text, w - 4, 0, 0, 0, 0, 0, 0) + 5;
        modal_frame(&x, &y, w, h, title);
        wrap_text(text, w - 4, x + 2, y + 2, 1, C_BLACK, C_WHITE, 0);
        draw_buttons(y + h - 2, x + w / 2, B, 1, 0);
        flush_frame();
        k = getkey();
        if (k.type == K_ENTER || k.type == K_ESC || k.type == ' ' || k.type == K_QUIT)
            return;
        if (k.type == K_MOUSE && k.mpress && hit_button(k.mx, k.my) == 0) return;
    }
}

static int yesno(const char *title, const char *text)
{
    static const char *B[2] = { "< Yes >", "<  No  >" };
    int focus = 0;
    for (;;) {
        int w, h, x, y;
        Key k;
        draw_menu();
        w = clampw(60);
        h = wrap_text(text, w - 4, 0, 0, 0, 0, 0, 0) + 5;
        modal_frame(&x, &y, w, h, title);
        wrap_text(text, w - 4, x + 2, y + 2, 1, C_BLACK, C_WHITE, 0);
        draw_buttons(y + h - 2, x + w / 2, B, 2, focus);
        flush_frame();
        k = getkey();
        switch (k.type) {
        case K_LEFT: case K_RIGHT: case K_TAB: case K_BTAB: focus = !focus; break;
        case K_ENTER: return focus == 0;
        case 'y': case 'Y': return 1;
        case 'n': case 'N': return 0;
        case K_ESC: case K_QUIT: return -1;
        case K_MOUSE:
            if (k.mpress) { int b = hit_button(k.mx, k.my); if (b >= 0) return b == 0; }
            break;
        default: break;
        }
    }
}

static int inputbox(const char *title, const char *prompt, char *val,
                    size_t cap, int digits_only)
{
    static const char *B[2] = { "<  Ok  >", "< Help >" };
    int focus = 0, cur = (int)strlen(val), off = 0;
    for (;;) {
        int w, h, x, y, fw, i, len;
        Key k;
        draw_menu();
        w = clampw(66);
        h = 11;
        modal_frame(&x, &y, w, h, title);
        wrap_text(prompt, w - 4, x + 2, y + 2, 1, C_BLACK, C_WHITE, 0);
        fw = w - 8; if (fw < 1) fw = 1;
        len = (int)strlen(val);
        if (cur < off) off = cur;
        if (cur - off >= fw) off = cur - fw + 1;
        draw_box(x + 3, y + h - 6, w - 6, 3, C_WHITE);
        for (i = 0; i < fw; i++) {
            char ch = (off + i < len) ? val[off + i] : ' ';
            putc_at(x + 4 + i, y + h - 5, ch, C_WHITE, C_BLUE, 1);
        }
        draw_buttons(y + h - 2, x + w / 2, B, 2, focus);
        g_cursx = x + 4 + (cur - off); g_cursy = y + h - 5;
        flush_frame();
        g_cursx = g_cursy = -1;
        k = getkey();
        switch (k.type) {
        case K_ENTER:
            if (focus == 1) { msgbox("Help",
                "Please enter a value.  Use <Left>/<Right> to move the cursor, "
                "<Backspace> to delete.  Press <Enter> on <Ok> to accept, "
                "<Esc> to cancel."); break; }
            return 0;
        case K_ESC: case K_QUIT: return -1;
        case K_TAB: case K_BTAB: focus = !focus; break;
        case K_LEFT:  if (cur > 0) cur--; break;
        case K_RIGHT: if (cur < len) cur++; break;
        case K_HOME:  cur = 0; break;
        case K_END:   cur = len; break;
        case K_BS:
            if (cur > 0) { memmove(val + cur - 1, val + cur, (size_t)(len - cur) + 1); cur--; }
            break;
        case K_DEL:
            if (cur < len) memmove(val + cur, val + cur + 1, (size_t)(len - cur));
            break;
        case K_PASTE: {
            const char *pp;
            for (pp = g_paste; *pp; pp++) {
                if (digits_only && !isdigit((unsigned char)*pp)) continue;
                if ((size_t)len + 1 >= cap) break;
                memmove(val + cur + 1, val + cur, (size_t)(len - cur) + 1);
                val[cur++] = *pp; len++;
            }
            break;
        }
        case K_MOUSE:
            if (k.mpress) {
                int b = hit_button(k.mx, k.my);
                if (b == 0) return 0;
                if (b == 1) focus = 1;
            }
            break;
        default:
            if (k.type >= 32 && k.type < 127 && (size_t)len + 1 < cap) {
                if (digits_only && !isdigit(k.type)) break;
                memmove(val + cur + 1, val + cur, (size_t)(len - cur) + 1);
                val[cur] = (char)k.type; cur++;
            }
            break;
        }
    }
}

static int textview(const char *title, const char *text, int njump)
{
    static const char *B[1] = { "< Exit >" };
    int top = 0;
    for (;;) {
        int w, h, x, y, total, vh, i;
        Key k;
        char pb[16]; int pct;
        draw_menu();
        w = g_cols - 10; if (w > 110) w = 110; if (w < 40) w = 40;
        h = g_rows - 6;  if (h < 10) h = 10;
        total = wrap_text(text, w - 4, 0, 0, 0, 0, 0, 0);
        vh = h - 4;
        if (top > total - vh) top = total - vh;
        if (top < 0) top = 0;
        modal_frame(&x, &y, w, h, title);
        {
            static char *lines = NULL; static size_t lcap = 0;
            size_t need = (size_t)(total + 1) * (size_t)w;
            if (need > lcap) { free(lines); lines = malloc(need); lcap = need; }
            if (lines) {
                int li = 0, col = 0; size_t ii = 0;
                memset(lines, ' ', need);
                while (text[ii]) {
                    int wl = 0; size_t jj = ii;
                    if (text[ii] == '\n') { li++; col = 0; ii++; continue; }
                    while (text[jj] && text[jj] != ' ' && text[jj] != '\n') { wl++; jj++; }
                    if (wl > w - 4) wl = w - 4;
                    if (col + wl > w - 4) { li++; col = 0; }
                    if (wl > 0 && li <= total)
                        memcpy(lines + (size_t)li * (size_t)w + (size_t)col, text + ii, (size_t)wl);
                    col += wl; ii += (size_t)wl;
                    while (text[ii] == ' ') { if (col < w - 4) col++; ii++; }
                }
                for (i = 0; i < vh && top + i < total; i++) {
                    int cx2;
                    for (cx2 = 0; cx2 < w - 4; cx2++)
                        putc_at(x + 2 + cx2, y + 1 + i,
                                lines[(size_t)(top + i) * (size_t)w + (size_t)cx2],
                                C_BLACK, C_WHITE, 0);
                }
            }
        }
        pct = total <= vh ? 100 : (top + vh) * 100 / total;
        snprintf(pb, sizeof pb, " (%d%%) ", pct);
        put(x, y + h - 3, G_LT(), C_WHITE, C_WHITE, 1);
        for (i = 1; i < w - 1; i++) put(x + i, y + h - 3, G_HL(), C_BLACK, C_WHITE, 0);
        put(x + w - 1, y + h - 3, G_RT(), C_BLACK, C_WHITE, 0);
        puts_at(x + w - (int)strlen(pb) - 2, y + h - 3, pb, C_BLACK, C_WHITE, 0);
        draw_buttons(y + h - 2, x + w / 2, B, 1, 0);
        flush_frame();
        k = getkey();
        switch (k.type) {
        case K_UP:   top--; break;
        case K_DOWN: top++; break;
        case K_PGUP: top -= vh; break;
        case K_PGDN: case ' ': top += vh; break;
        case K_HOME: top = 0; break;
        case K_END:  top = total; break;
        case K_ENTER: case K_ESC: case K_QUIT: return -1;
        case K_MOUSE:
            if (k.mb == 64) top -= 3;
            else if (k.mb == 65) top += 3;
            else if (k.mpress && hit_button(k.mx, k.my) == 0) return -1;
            break;
        default:
            if (k.type >= '1' && k.type <= '9' && k.type - '1' < njump)
                return k.type - '1';
            break;
        }
    }
}

/* ------------------------------------------------------ 保存/読込 */

/* オンディスクのシンボル名 "PREFIX_SYM"、prefix 空なら "SYM" */
static void sym_name(char *buf, size_t n, const char *sym)
{
    const char *p = g_app ? g_app->sym_prefix : NULL;
    if (p && *p) snprintf(buf, n, "%s_%s", p, sym);
    else         snprintf(buf, n, "%s", sym);
}

static int valid_symbol_part(const char *s, int allow_empty)
{
    const unsigned char *p = (const unsigned char *)s;
    if (!s) return allow_empty;
    if (!*s && !allow_empty) return 0;
    for (; *p; p++) if (!isalnum(*p) && *p != '_') return 0;
    return 1;
}

static int validate_tree(const UtItem *it, int depth)
{
    int i;
    if (!it || depth >= MAX_DEPTH || it->nchild < 0 ||
        (it->nchild > 0 && !it->children) ||
        (it->type < UT_TYPE_MENU || it->type > UT_TYPE_COMMENT)) return 0;
    if ((it->type == UT_TYPE_STR || it->type == UT_TYPE_INT) &&
        !memchr(it->strval, 0, sizeof it->strval)) return 0;
    if (it->type == UT_TYPE_CHOICE &&
        (it->nchild <= 0 || it->value < 0 || it->value >= it->nchild)) return 0;
    if (it->sym && !valid_symbol_part(it->sym, 0)) return 0;
    for (i = 0; i < it->nchild; i++)
        if (!validate_tree(&it->children[i], depth + 1)) return 0;
    return 1;
}

static int valid_request(const UtItem *root, const UtApp *app, const char *path)
{
    return root && root->type == UT_TYPE_MENU && app && app->title && path && *path &&
           valid_symbol_part(app->sym_prefix, 1) && validate_tree(root, 0);
}

static void save_quoted(FILE *f, const char *s)
{
    const unsigned char *p;
    fputc('"', f);
    for (p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') fputc('\\', f);
        /* strval normally comes from the ASCII-only editor, but public callers
         * may fill it directly.  Encode controls rather than injecting lines. */
        if (*p == '\n') { fputs("\\n", f); continue; }
        if (*p == '\r') { fputs("\\r", f); continue; }
        if (*p == '\t') { fputs("\\t", f); continue; }
        if (*p < 32 || *p == 127) { fprintf(f, "\\x%02X", *p); continue; }
        fputc(*p, f);
    }
    fputc('"', f);
}

static void save_walk(FILE *f, UtItem *m)
{
    int i;
    for (i = 0; i < m->nchild; i++) {
        UtItem *it = &m->children[i];
        char v[80], nm[160];
        switch (it->type) {
        case UT_TYPE_BOOL:
            if (it->sym) {
                sym_name(nm, sizeof nm, it->sym);
                if (it->forced || it->value) fprintf(f, "CONFIG_%s=y\n", nm);
                else fprintf(f, "# CONFIG_%s is not set\n", nm);
            }
            break;
        case UT_TYPE_TRI:
            if (it->sym) {
                sym_name(nm, sizeof nm, it->sym);
                value_str(it, v, sizeof v);
                if (it->value) fprintf(f, "CONFIG_%s=%s\n", nm, v);
                else fprintf(f, "# CONFIG_%s is not set\n", nm);
            }
            break;
        case UT_TYPE_STR:
            if (it->sym) { sym_name(nm, sizeof nm, it->sym);
                fprintf(f, "CONFIG_%s=", nm); save_quoted(f, it->strval);
                fputc('\n', f); }
            break;
        case UT_TYPE_INT:
            if (it->sym) { sym_name(nm, sizeof nm, it->sym);
                fprintf(f, "CONFIG_%s=%s\n", nm, it->strval); }
            break;
        case UT_TYPE_CHOICE: {
            int j;
            for (j = 0; j < it->nchild; j++) {
                const UtItem *r = &it->children[j];
                if (!r->sym) continue;
                sym_name(nm, sizeof nm, r->sym);
                if (j == it->value) fprintf(f, "CONFIG_%s=y\n", nm);
                else fprintf(f, "# CONFIG_%s is not set\n", nm);
            }
            break;
        }
        default: break;
        }
        if (it->nchild && it->type != UT_TYPE_CHOICE) {
            fprintf(f, "\n#\n# %s\n#\n", it->name);
            save_walk(f, it);
        }
    }
}

static int save_config(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "#\n# Automatically generated file; DO NOT EDIT.\n# %s\n#\n", g_app->title);
    save_walk(f, g_root_ptr);
    if (fclose(f) != 0) return -1;
    return 0;
}

static UtItem *find_sym(UtItem *m, const char *sym)
{
    int i;
    for (i = 0; i < m->nchild; i++) {
        UtItem *it = &m->children[i], *r;
        if (it->sym && strcmp(it->sym, sym) == 0) return it;
        if (it->nchild && (r = find_sym(it, sym)) != NULL) return r;
    }
    return NULL;
}

static void reset_walk(UtItem *m)
{
    int i;
    for (i = 0; i < m->nchild; i++) {
        UtItem *it = &m->children[i];
        if ((it->type == UT_TYPE_BOOL || it->type == UT_TYPE_TRI) && !it->forced) it->value = 0;
        if (it->nchild) reset_walk(it);
    }
}

/* sscanf は "CONFIG_" を消費済み。prefix ありなら残る "PREFIX_" を外す。
   prefix 空ならシンボルはそのまま。不一致なら NULL(このアプリの記号でない)。 */
static const char *strip_prefix(const char *sym)
{
    const char *p = g_app ? g_app->sym_prefix : NULL;
    if (p && *p) {
        char pf[64];
        size_t n = (size_t)snprintf(pf, sizeof pf, "%s_", p);
        if (strncmp(sym, pf, n) == 0) return sym + n;
        return NULL;
    }
    return sym;
}

static int load_quoted(char *dst, size_t cap, const char *src)
{
    size_t o = 0, i = 1, n = strlen(src);
    if (n < 2 || src[0] != '"' || src[n - 1] != '"') return -1;
    while (i < n - 1) {
        unsigned char ch = (unsigned char)src[i++];
        if (ch == '\\') {
            if (i >= n - 1) return -1;
            ch = (unsigned char)src[i++];
            if (ch == 'n') ch = '\n';
            else if (ch == 'r') ch = '\r';
            else if (ch == 't') ch = '\t';
            else if (ch == 'x') {
                int hi, lo;
                if (i + 1 >= n - 1 || !isxdigit((unsigned char)src[i]) ||
                    !isxdigit((unsigned char)src[i + 1])) return -1;
                hi = isdigit((unsigned char)src[i]) ? src[i] - '0' :
                     tolower((unsigned char)src[i]) - 'a' + 10;
                lo = isdigit((unsigned char)src[i + 1]) ? src[i + 1] - '0' :
                     tolower((unsigned char)src[i + 1]) - 'a' + 10;
                ch = (unsigned char)(hi * 16 + lo); i += 2;
                if (ch == 0) return -1;
            }
            else if (ch != '\\' && ch != '"') {
                /* 未知のエスケープはリテラルの '\\' として扱い、続く文字も保持
                   する (save_quoted は既知エスケープしか出さないので新しい保存
                   データには無影響。旧データの素の '\\' を失わないための寛容化)。 */
                if (o + 1 >= cap) return -1;
                dst[o++] = '\\';
            }
        }
        if (o + 1 >= cap) return -1;
        dst[o++] = (char)ch;
    }
    dst[o] = 0;
    return 0;
}

static int decimal_value(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    if (*p == '-') p++;                  /* 先頭の符号を許可 (負の整数値) */
    if (!*p) return 0;                   /* 数字が無い ("" や "-" 単独) は不正 */
    for (; *p; p++) if (!isdigit(*p)) return 0;
    return 1;
}

static int load_config(const char *path)
{
    char line[512];
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    reset_walk(g_root_ptr);
    while (fgets(line, sizeof line, f)) {
        char sym[160], val[256];
        const char *bare;
        UtItem *it;
        int n = -1;
        if (sscanf(line, "# CONFIG_%159[A-Za-z0-9_] is not set%n", sym, &n) == 1
            && n > 0 && (line[n] == '\n' || line[n] == '\r' || line[n] == 0)) {
            bare = strip_prefix(sym);
            it = bare ? find_sym(g_root_ptr, bare) : NULL;
            if (it && !it->forced && (it->type == UT_TYPE_BOOL || it->type == UT_TYPE_TRI))
                it->value = 0;
            continue;
        }
        if (sscanf(line, "CONFIG_%159[A-Za-z0-9_]=%255[^\r\n]", sym, val) == 2) {
            bare = strip_prefix(sym);
            it = bare ? find_sym(g_root_ptr, bare) : NULL;
            if (!it) continue;
            if (it->type == UT_TYPE_RADIO) {
                if (strcmp(val, "y") == 0 && it->parent) it->parent->value = it->idx;
            } else if (it->type == UT_TYPE_BOOL) {
                if (!it->forced && (strcmp(val, "y") == 0 || strcmp(val, "n") == 0))
                    it->value = strcmp(val, "y") == 0 ? 2 : 0;
            } else if (it->type == UT_TYPE_TRI) {
                if (strcmp(val, "y") == 0) it->value = 2;
                else if (strcmp(val, "m") == 0) it->value = 1;
                else if (strcmp(val, "n") == 0) it->value = 0;
            } else if (it->type == UT_TYPE_STR) {
                char decoded[sizeof it->strval];
                if (load_quoted(decoded, sizeof decoded, val) == 0)
                    memcpy(it->strval, decoded, strlen(decoded) + 1);
            } else if (it->type == UT_TYPE_INT) {
                size_t len = strlen(val);
                if (len < sizeof it->strval && decimal_value(val))
                    memcpy(it->strval, val, len + 1);
            }
        }
    }
    fclose(f);
    return 0;
}

/* --------------------------------------------------------- ヘルプ */

static void show_help(const UtItem *it)
{
    char text[4096];
    char v[80];
    size_t o = 0;
    if (it->help)
        o += (size_t)snprintf(text + o, sizeof text - o, "%s\n\n", it->help);
    else
        o += (size_t)snprintf(text + o, sizeof text - o,
                              "There is no help available for this option.\n\n");
    if (it->sym) {
        char nm[160];
        sym_name(nm, sizeof nm, it->sym);
        value_str(it, v, sizeof v);
        o += (size_t)snprintf(text + o, sizeof text - o,
                              "Symbol: %s [=%s]\nType  : %s\n",
                              nm, v, type_name(it));
    }
    (void)o;
    textview(it->name, text, 0);
}

/* --------------------------------------------------------- 検索 */

static int  g_njump = 0;
static UtItem *g_jump[MAX_RESULTS];

static int ci_contains(const char *hay, const char *needle)
{
    size_t i, j, hl = strlen(hay), nl = strlen(needle);
    if (nl == 0) return 1;
    if (nl > hl) return 0;
    for (i = 0; i + nl <= hl; i++) {
        for (j = 0; j < nl; j++)
            if (tolower((unsigned char)hay[i+j]) != tolower((unsigned char)needle[j])) break;
        if (j == nl) return 1;
    }
    return 0;
}

static int ci_startswith(const char *s, const char *p)
{
    size_t i;
    for (i = 0; p[i]; i++)
        if (!s[i] || tolower((unsigned char)s[i]) != tolower((unsigned char)p[i]))
            return 0;
    return 1;
}

static void search_walk(UtItem *m, const char *q, char *out, size_t cap, size_t *o)
{
    int i;
    for (i = 0; i < m->nchild; i++) {
        UtItem *it = &m->children[i];
        int hit = 0;
        if (it->type != UT_TYPE_COMMENT) {
            if (it->name && ci_contains(it->name, q)) hit = 1;
            if (it->sym && ci_contains(it->sym, q)) hit = 1;
        }
        if (hit && g_njump < MAX_RESULTS && *o + 512 < cap) {
            char v[80], nm[160]; UtItem *path[MAX_DEPTH]; int np = 0, j;
            UtItem *p;
            value_str(it, v, sizeof v);
            if (g_njump < 9) *o += (size_t)snprintf(out + *o, cap - *o, "(%d) ", g_njump + 1);
            if (it->sym) { sym_name(nm, sizeof nm, it->sym);
                *o += (size_t)snprintf(out + *o, cap - *o, "Symbol: %s [=%s]\n", nm, v); }
            else *o += (size_t)snprintf(out + *o, cap - *o, "Symbol: <none>\n");
            *o += (size_t)snprintf(out + *o, cap - *o, "Type  : %s\n", type_name(it));
            *o += (size_t)snprintf(out + *o, cap - *o, "Prompt: %s\n  Location:\n", it->name);
            for (p = it->parent; p; p = p->parent) if (np < MAX_DEPTH) path[np++] = p;
            for (j = np - 1; j >= 0; j--)
                *o += (size_t)snprintf(out + *o, cap - *o, "    -> %s\n", path[j]->name);
            *o += (size_t)snprintf(out + *o, cap - *o, "\n");
            g_jump[g_njump++] = it;
        }
        if (it->nchild) search_walk(it, q, out, cap, o);
    }
}

static void jump_to(UtItem *target)
{
    UtItem *path[MAX_DEPTH]; int np = 0, i;
    UtItem *p;
    if (!target) return;
    for (p = target; p; p = p->parent) if (np < MAX_DEPTH) path[np++] = p;
    g_depth = 0;
    g_stack[0].menu = g_root_ptr; g_stack[0].top = 0; g_stack[0].btn = 0;
    g_stack[0].sel = first_sel(g_root_ptr);
    for (i = np - 2; i >= 1; i--) {
        g_stack[g_depth].sel = path[i]->idx;
        if (g_depth + 1 < MAX_DEPTH && path[i]->nchild) {
            g_depth++;
            g_stack[g_depth].menu = path[i];
            g_stack[g_depth].sel = 0; g_stack[g_depth].top = 0; g_stack[g_depth].btn = 0;
        }
    }
    g_stack[g_depth].sel = target->idx;
}

static void do_search(void)
{
    static char q[64] = "";
    static char out[32768];
    size_t o = 0;
    int r;
    const char *qq;
    char pfx[32];
    if (inputbox("Search Configuration Parameter",
                 "Enter (sub)string to search for "
                 "(with or without the CONFIG_ prefix)", q, sizeof q, 0) != 0)
        return;
    qq = q;
    if (g_app && g_app->sym_prefix && *g_app->sym_prefix)
        snprintf(pfx, sizeof pfx, "CONFIG_%s_", g_app->sym_prefix);
    else
        snprintf(pfx, sizeof pfx, "CONFIG_");
    if (ci_startswith(q, pfx)) qq = q + strlen(pfx);
    else if (ci_startswith(q, "CONFIG_")) qq = q + 7;
    g_njump = 0;
    search_walk(g_root_ptr, qq, out, sizeof out, &o);
    if (o == 0) snprintf(out, sizeof out, "No matches found for \"%s\".", q);
    r = textview("Search Results", out, g_njump);
    if (r >= 0 && r < g_njump) jump_to(g_jump[r]);
}

/* ------------------------------------------------------ 値の操作 */

static void toggle_item(UtItem *it)
{
    if (it->forced) return;
    if (it->type == UT_TYPE_BOOL) it->value = it->value ? 0 : 2;
    else if (it->type == UT_TYPE_TRI) it->value = (it->value == 0) ? 1 : (it->value == 1) ? 2 : 0;
}
static void set_item(UtItem *it, int v)
{
    if (it->forced) return;
    if (it->type == UT_TYPE_BOOL) { if (v != 1) it->value = v; }
    else if (it->type == UT_TYPE_TRI) it->value = v;
}

/* -------------------------------------------------------- 終了 */

static int g_saved_on_exit = 0;

static int exit_flow(void)
{
    int r = yesno(" ",
        "Do you wish to save your new configuration?\n"
        "(Press <ESC><ESC> to continue configuration.)");
    if (r < 0) return 0;
    if (r == 1) {
        if (save_config(g_app->config_file) != 0) {
            char mb[192];
            snprintf(mb, sizeof mb, "Can't create file %s!", g_app->config_file);
            msgbox("Error", mb);
            return 0;
        }
        g_saved_on_exit = 1;
    }
    return 1;
}

/* -------------------------------------------------- Select 動作 */

static void save_as(void)
{
    static char fn[128];
    if (!fn[0]) snprintf(fn, sizeof fn, "%s", g_app->config_file);
    if (inputbox("Save Configuration",
        "Enter a filename to which this configuration should be saved.  "
        "Leave blank to abort.", fn, sizeof fn, 0) == 0 && fn[0]) {
        if (save_config(fn) == 0) {
            char mb[192];
            snprintf(mb, sizeof mb, "Configuration written to %s", fn);
            msgbox(" ", mb);
        } else msgbox("Error", "Can't create file!");
    }
}
static void load_as(void)
{
    static char fn[128];
    if (!fn[0]) snprintf(fn, sizeof fn, "%s", g_app->config_file);
    if (inputbox("Load Configuration",
        "Enter the name of the configuration file to load.  Accept the name "
        "shown to restore the configuration you last retrieved.",
        fn, sizeof fn, 0) == 0 && fn[0]) {
        if (load_config(fn) == 0) msgbox(" ", "Configuration loaded");
        else msgbox("Error", "File does not exist!");
    }
}

static void activate_select(void)
{
    NavFrame *fr = &g_stack[g_depth];
    UtItem *m = fr->menu;
    UtItem *it;
    if (!m->nchild) return;
    it = &m->children[fr->sel];
    switch (it->type) {
    case UT_TYPE_RADIO:
        if (it->parent) it->parent->value = it->idx;
        if (g_depth > 0) g_depth--;
        break;
    case UT_TYPE_STR:
        inputbox(it->name, "Please enter a string value.  Use the <TAB> key to "
                 "move from the input field to the buttons below it.",
                 it->strval, sizeof it->strval, 0);
        break;
    case UT_TYPE_INT:
        inputbox(it->name, "Please enter a decimal value.  Fractions will not "
                 "be accepted.  Use the <TAB> key to move from the input field "
                 "to the buttons below it.", it->strval, sizeof it->strval, 1);
        break;
    default:
        if (it->nchild && item_enterable(it)) {
            if (g_depth + 1 < MAX_DEPTH) {
                g_depth++;
                g_stack[g_depth].menu = it;
                g_stack[g_depth].sel = first_sel(it);
                g_stack[g_depth].top = 0; g_stack[g_depth].btn = 0;
            }
        } else if (it->type == UT_TYPE_BOOL || it->type == UT_TYPE_TRI) {
            toggle_item(it);
        }
        break;
    }
}

/* ---------------------------------------------------- メインループ */

static void hotkey_jump(NavFrame *fr, int ch)
{
    UtItem *m = fr->menu;
    int n = m->nchild, i, start = fr->sel;
    if (n == 0) return;
    ch = tolower(ch);
    for (i = 1; i <= n; i++) {
        int j = (start + i) % n;
        const UtItem *it = &m->children[j];
        if (it->type == UT_TYPE_COMMENT || !it->name) continue;
        if (tolower((unsigned char)it->name[0]) == ch) { fr->sel = j; return; }
    }
}

static int do_button(int b)   /* 戻り値 1=終了 */
{
    NavFrame *fr = &g_stack[g_depth];
    switch (b) {
    case 0: activate_select(); break;
    case 1: if (g_depth) g_depth--; else if (exit_flow()) return 1; break;
    case 2: if (fr->menu->nchild) show_help(&fr->menu->children[fr->sel]); break;
    case 3: save_as(); break;
    case 4: load_as(); break;
    default: break;
    }
    return 0;
}

static void handle_mouse(Key *k)
{
    NavFrame *fr = &g_stack[g_depth];
    if (k->mb == 64) { fr->sel = next_sel(fr->menu, fr->sel, -1); return; }
    if (k->mb == 65) { fr->sel = next_sel(fr->menu, fr->sel, +1); return; }
    if (!k->mpress) return;
    if ((k->mb & 3) == 0) {
        int b = hit_button(k->mx, k->my);
        if (b >= 0) { fr->btn = b; do_button(b); return; }
        if (k->my >= g_list_y && k->my < g_list_y + g_list_h &&
            k->mx >= g_list_x && k->mx < g_list_x + g_list_w) {
            int idx = g_list_top + (k->my - g_list_y);
            if (sel_ok(fr->menu, idx)) {
                if (fr->sel == idx) activate_select();
                else fr->sel = idx;
            }
        }
    }
}

static void main_loop(void)
{
    g_stack[0].menu = g_root_ptr;
    g_stack[0].sel = first_sel(g_root_ptr);
    g_stack[0].top = 0; g_stack[0].btn = 0;
    g_depth = 0;

    for (;;) {
        NavFrame *fr;
        UtItem *m;
        Key k;
        draw_menu();
        flush_frame();
        k = getkey();
        fr = &g_stack[g_depth];
        m = fr->menu;
        switch (k.type) {
        case K_QUIT: return;
        case K_RESIZE: break;                    /* getkey が既に反映済 */
        case K_PASTE: break;                     /* メニューではペースト無視 */
        case K_UP:   fr->sel = next_sel(m, fr->sel, -1); break;
        case K_DOWN: fr->sel = next_sel(m, fr->sel, +1); break;
        case K_PGUP: { int i; for (i = 0; i < g_list_h - 1; i++) fr->sel = next_sel(m, fr->sel, -1); } break;
        case K_PGDN: { int i; for (i = 0; i < g_list_h - 1; i++) fr->sel = next_sel(m, fr->sel, +1); } break;
        case K_HOME: fr->sel = first_sel(m); break;
        case K_END:  fr->sel = last_sel(m);  break;
        case K_LEFT:  fr->btn = (fr->btn + 4) % 5; break;
        case K_RIGHT: case K_TAB: fr->btn = (fr->btn + 1) % 5; break;
        case K_BTAB:  fr->btn = (fr->btn + 4) % 5; break;
        case K_ENTER: if (do_button(fr->btn)) return; break;
        case K_ESC:   if (g_depth) g_depth--; else if (exit_flow()) return; break;
        case ' ':
            if (m->nchild) {
                UtItem *it = &m->children[fr->sel];
                if (it->type == UT_TYPE_RADIO) { if (it->parent) it->parent->value = it->idx; }
                else toggle_item(it);
            }
            break;
        case 'y': case 'Y':
            if (m->nchild) set_item(&m->children[fr->sel], 2);
            break;
        case 'n': case 'N':
            if (m->nchild) set_item(&m->children[fr->sel], 0);
            break;
        case 'm': case 'M':
            if (m->nchild) {
                UtItem *it = &m->children[fr->sel];
                if (it->type == UT_TYPE_TRI) set_item(it, 1);
            }
            break;
        case '?': case 'h': case 'H':
            if (m->nchild) show_help(&m->children[fr->sel]);
            break;
        case '/': do_search(); break;
        case K_MOUSE: handle_mouse(&k); break;
        default:
            if (k.type >= 32 && k.type < 127) hotkey_jump(fr, k.type);
            break;
        }
    }
}

/* ---------------------------------------------------- 公開 API */

#if !defined(_WIN32)
static int stdio_is_tty(void) { return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO); }
#else
static int stdio_is_tty(void)
{
    return _isatty(_fileno(stdin)) && _isatty(_fileno(stdout));
}
#endif

/* ASCII 罫線を使うか自動判定 (Windows は UTF-8 CP を設定するので Unicode) */
static int auto_ascii(void)
{
#if defined(_WIN32)
    return 0;
#else
    const char *l = getenv("LC_ALL");
    if (!l || !*l) l = getenv("LC_CTYPE");
    if (!l || !*l) l = getenv("LANG");
    if (l && (ci_contains(l, "utf-8") || ci_contains(l, "utf8"))) return 0;
    return 1;
#endif
}

int ut_load(UtItem *root, const UtApp *app, const char *path)
{
    if (!valid_request(root, app, path)) return -1;
    g_app = app; g_root_ptr = root;
    init_tree(root);
    return load_config(path);
}

int ut_save(UtItem *root, const UtApp *app, const char *path)
{
    if (!valid_request(root, app, path)) return -1;
    g_app = app; g_root_ptr = root;
    init_tree(root);
    return save_config(path);
}

int ut_run(UtItem *root, const UtApp *app)
{
    if (!root || !app || !app->config_file ||
        !valid_request(root, app, app->config_file)) return -1;
    if (!stdio_is_tty()) return -1;
    g_app = app; g_root_ptr = root;
    g_ascii = (app->ascii == 0) ? 0 : (app->ascii > 0) ? 1 : auto_ascii();
    init_tree(root);
    if (app->config_file) load_config(app->config_file);   /* 無ければ黙って無視 */
    term_init();
    buf_resize();
    g_saved_on_exit = 0;
    main_loop();
    term_restore();
    return g_saved_on_exit;
}

int ut_main(UtItem *root, UtApp *app, int argc, char **argv)
{
    int i, saved;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--ascii") == 0) app->ascii = 1;
        else if (strcmp(argv[i], "--unicode") == 0) app->ascii = 0;
        else if (strcmp(argv[i], "--config") == 0 && i + 1 < argc)
            app->config_file = argv[++i];
        else if (strcmp(argv[i], "--version") == 0) {
            printf("%s (utui %s)\n", app->app_name ? app->app_name : "utui",
                   UTUI_VERSION);
            return 0;
        } else {
            printf("usage: %s [--ascii|--unicode] [--config FILE]\n"
                   "  %s\n", argv[0],
                   app->app_name ? app->app_name : "Universal TUI configurator");
            return strcmp(argv[i], "--help") == 0 ? 0 : 1;
        }
    }
    saved = ut_run(root, app);
    if (saved < 0) {
        fprintf(stderr, "%s: stdin/stdout must be a terminal\n", argv[0]);
        return 1;
    }
    if (saved) {
        if (app->saved_epilogue) fputs(app->saved_epilogue, stdout);
    } else {
        printf("\n\nYour configuration changes were NOT saved.\n\n");
    }
    return 0;
}
