/* Ette (Encrypted Terminal Text Editor)
 *
 *   The MIT License (MIT)
 *
 *   Copyright (c) 2023 Ryan McDermott
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included in all
 *   copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *   SOFTWARE
 *
 * Based on Kilo by antirez
 * -----------------------------------------------------------------------
 * A very simple editor in less than 1-kilo lines of code (as counted
 * by "cloc"). Does not depend on libcurses, directly emits VT100
 * escapes on the terminal.
 *
 * -----------------------------------------------------------------------
 *
 * Copyright (C) 2016 Salvatore Sanfilippo <antirez at gmail dot com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *  *  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *  *  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef __linux__
#define _POSIX_C_SOURCE 200809L
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>

#include "crypto.h"
#include "editor.h"
#include "status.h"

using ::ette::CryptoAlgorithm;
using ::ette::CryptoState;
using ::ette::Decrypt;
using ::ette::Encrypt;
using ::ette::GenerateRandomAsciiByteVector;
using ::ette::IsKeyCorrect;

// Syntax highlight types
constexpr int32_t HL_NORMAL = 0;
constexpr int32_t HL_NONPRINT = 1;
constexpr int32_t HL_COMMENT = 2;    // Single line comment.
constexpr int32_t HL_MLCOMMENT = 3;  // Multi-line comment.
constexpr int32_t HL_KEYWORD1 = 4;
constexpr int32_t HL_KEYWORD2 = 5;
constexpr int32_t HL_STRING = 6;
constexpr int32_t HL_NUMBER = 7;
constexpr int32_t HL_MATCH = 8; /* Search match. */

constexpr int32_t HL_HIGHLIGHT_STRINGS = 1 << 0;
constexpr int32_t HL_HIGHLIGHT_NUMBERS = 1 << 1;

constexpr int32_t QUERY_LEN = 256;

#define ABUF_INIT \
    { NULL, 0 }

static struct State* E;
static struct termios orig_termios;  // In order to restore at exit.

// PURE
/* Set an editor status message for the second line of the status, at the
 * end of the screen. */
void SetStatusMessage(State* state, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(state->statusmsg, sizeof(state->statusmsg), fmt, ap);
    va_end(ap);
    state->statusmsg_time = time(NULL);
}

/* =========================== Syntax highlights DB =========================
 *
 * In order to add a new syntax, define two arrays with a list of file name
 * matches and keywords. The file name matches are used in order to match
 * a given syntax with a given file name: if a match pattern starts with a
 * dot, it is matched as the last past of the filename, for example ".c".
 * Otherwise the pattern is just searched inside the filenme, like "Makefile").
 *
 * The list of keywords to highlight is just a list of words, however if they
 * a trailing '|' character is added at the end, they are highlighted in
 * a different color, so that you can have two different sets of keywords.
 *
 * Finally add a stanza in the HLDB global variable with two two arrays
 * of strings, and a set of flags in order to enable highlighting of
 * comments and numbers.
 *
 * The characters for single and multi line comments must be exactly two
 * and must be provided as well (see the C language example).
 *
 * There is no support to highlight patterns currently. */

/* C / C++ */
const char* C_HL_extensions[] = {".c", ".h", ".cpp", ".hpp", ".cc", NULL};
const char* C_HL_keywords[] = {
    /* C Keywords */
    "auto", "break", "case", "continue", "default", "do", "else", "enum",
    "extern", "for", "goto", "if", "register", "return", "sizeof", "static",
    "struct", "switch", "typedef", "union", "volatile", "while", "NULL",

    /* C++ Keywords */
    "alignas", "alignof", "and", "and_eq", "asm", "bitand", "bitor", "class",
    "compl", "constexpr", "const_cast", "deltype", "delete", "dynamic_cast",
    "explicit", "export", "false", "friend", "inline", "mutable", "namespace",
    "new", "noexcept", "not", "not_eq", "nullptr", "operator", "or", "or_eq",
    "private", "protected", "public", "reinterpret_cast", "static_assert",
    "static_cast", "template", "this", "thread_local", "throw", "true", "try",
    "typeid", "typename", "virtual", "xor", "xor_eq",

    /* C types */
    "int|", "long|", "double|", "float|", "char|", "unsigned|", "signed|",
    "void|", "short|", "auto|", "const|", "bool|", NULL};

/* Here we define an array of syntax highlights by extensions, keywords,
 * comments delimiters and flags. */
struct Syntax HLDB[] = {{/* C / C++ */
                         (char**)C_HL_extensions, (char**)C_HL_keywords, "//",
                         "/*", "*/",
                         HL_HIGHLIGHT_STRINGS | HL_HIGHLIGHT_NUMBERS}};

#define HLDB_ENTRIES (sizeof(HLDB) / sizeof(HLDB[0]))

/* ======================= Low level terminal handling ====================== */

// SIDE EFFECTS
void DisableRawMode(int fd) {
    /* Don't even check the return value as it's too late. */
    if (E->rawmode) {
        tcsetattr(fd, TCSAFLUSH, &orig_termios);
        E->rawmode = 0;
    }
}

// SIDE EFFECTS
/* Called at exit to avoid remaining in raw mode. */
void OnExit() {
    DisableRawMode(STDIN_FILENO);
}

// SIDE EFFECTS
/* Raw mode: 1960s style. */
int EnableRawMode(int fd) {
    struct termios raw;

    if (E->rawmode)
        return 0; /* Already enabled. */
    if (!isatty(STDIN_FILENO))
        goto fatal;
    atexit(OnExit);
    if (tcgetattr(fd, &orig_termios) == -1)
        goto fatal;

    raw = orig_termios; /* modify the original mode */
    /* input modes: no break, no CR to NL, no parity check, no strip char,
     * no start/stop output control. */
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    /* output modes - disable post processing */
    raw.c_oflag &= ~(OPOST);
    /* control modes - set 8 bit chars */
    raw.c_cflag |= (CS8);
    /* local modes - choing off, canonical off, no extended functions,
     * no signal chars (^Z,^C) */
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    /* control chars - set return condition: min number of bytes and timer. */
    raw.c_cc[VMIN] = 0;  /* Return each byte, or zero for timeout. */
    raw.c_cc[VTIME] = 1; /* 100 ms timeout (unit is tens of second). */

    /* put terminal in raw mode after flushing */
    if (tcsetattr(fd, TCSAFLUSH, &raw) < 0)
        goto fatal;
    E->rawmode = 1;
    return 0;

fatal:
    errno = ENOTTY;
    return -1;
}

// SIDE EFFECTS
/* Read a key from the terminal put in raw mode, trying to handle
 * escape sequences. */
int ReadKey(int fd) {
    int nread;
    char c, seq[3];
    while ((nread = read(fd, &c, 1)) == 0)
        ;
    if (nread == -1)
        exit(1);

    while (1) {
        switch (c) {
            case ESC: /* escape sequence */
                /* If this is just an ESC, we'll timeout here. */
                if (read(fd, seq, 1) == 0)
                    return ESC;
                if (read(fd, seq + 1, 1) == 0)
                    return ESC;

                /* ESC [ sequences. */
                if (seq[0] == '[') {
                    if (seq[1] >= '0' && seq[1] <= '9') {
                        /* Extended escape, read additional byte. */
                        if (read(fd, seq + 2, 1) == 0)
                            return ESC;
                        if (seq[2] == '~') {
                            switch (seq[1]) {
                                case '3':
                                    return DEL_KEY;
                                case '5':
                                    return PAGE_UP;
                                case '6':
                                    return PAGE_DOWN;
                            }
                        }
                    } else {
                        switch (seq[1]) {
                            case 'A':
                                return ARROW_UP;
                            case 'B':
                                return ARROW_DOWN;
                            case 'C':
                                return ARROW_RIGHT;
                            case 'D':
                                return ARROW_LEFT;
                            case 'H':
                                return HOME_KEY;
                            case 'F':
                                return END_KEY;
                        }
                    }
                }

                /* ESC O sequences. */
                else if (seq[0] == 'O') {
                    switch (seq[1]) {
                        case 'H':
                            return HOME_KEY;
                        case 'F':
                            return END_KEY;
                    }
                }
                break;
            default:
                return c;
        }
    }
}

// SIDE EFFECTS
/* Use the ESC [6n escape sequence to query the horizontal cursor position
 * and return it. On error -1 is returned, on success the position of the
 * cursor is stored at *rows and *cols and 0 is returned. */
int GetCursorPos(int ifd, int ofd, int* rows, int* cols) {
    char buf[32];
    unsigned int i = 0;

    /* Report cursor location */
    if (write(ofd, "\x1b[6n", 4) != 4)
        return -1;

    /* Read the response: ESC [ rows ; cols R */
    while (i < sizeof(buf) - 1) {
        if (read(ifd, buf + i, 1) != 1)
            break;
        if (buf[i] == 'R')
            break;
        i++;
    }
    buf[i] = '\0';

    /* Parse it. */
    if (buf[0] != ESC || buf[1] != '[')
        return -1;
    if (sscanf(buf + 2, "%d;%d", rows, cols) != 2)
        return -1;
    return 0;
}

// SIDE EFFECTS
/* Try to get the number of columns in the current terminal. If the ioctl()
 * call fails the function will try to query the terminal itself.
 * Returns 0 on success, -1 on error. */
int GetWindowSize(int ifd, int ofd, int* rows, int* cols) {
    struct winsize ws;

    if (ioctl(1, TIOCGWINSZ, &ws) == -1 || ws.ws_col == 0) {
        /* ioctl() failed. Try to query the terminal itself. */
        int orig_row, orig_col, retval;

        /* Get the initial position so we can restore it later. */
        retval = GetCursorPos(ifd, ofd, &orig_row, &orig_col);
        if (retval == -1)
            goto failed;

        /* Go to right/bottom margin and get position. */
        if (write(ofd, "\x1b[999C\x1b[999B", 12) != 12)
            goto failed;
        retval = GetCursorPos(ifd, ofd, rows, cols);
        if (retval == -1)
            goto failed;

        /* Restore position. */
        char seq[32];
        snprintf(seq, 32, "\x1b[%d;%dH", orig_row, orig_col);
        if (write(ofd, seq, strlen(seq)) == -1) {
            /* Can't recover... */
        }
        return 0;
    } else {
        *cols = ws.ws_col;
        *rows = ws.ws_row;
        return 0;
    }

failed:
    return -1;
}

/* ====================== Syntax highlight color scheme  ==================== */

// PURE
int IsSeparator(int c) {
    return c == '\0' || isspace(c) || strchr(",.()+-/*=~%[];", c) != NULL;
}

// PURE
/* Return true if the specified row last char is part of a multi line comment
 * that starts at this row or at one before, and does not end at the end
 * of the row but spawns to the next row. */
int RowHasOpenComment(Row* row) {
    if (row->hl && row->rsize && row->hl[row->rsize - 1] == HL_MLCOMMENT &&
        (row->rsize < 2 || (row->render[row->rsize - 2] != '*' ||
                            row->render[row->rsize - 1] != '/')))
        return 1;
    return 0;
}

// PURE
/* Set every byte of row->hl (that corresponds to every character in the line)
 * to the right syntax highlight type (HL_* defines). */
void UpdateSyntax(State* state, Row* row) {
    row->hl = (unsigned char*)realloc(row->hl, row->rsize);
    memset(row->hl, HL_NORMAL, row->rsize);

    if (state->syntax == NULL)
        return; /* No syntax, everything is HL_NORMAL. */

    int i, prev_sep, in_string, in_comment;
    char* p;
    char** keywords = state->syntax->keywords;
    char* scs = state->syntax->singleline_comment_start;
    char* mcs = state->syntax->multiline_comment_start;
    char* mce = state->syntax->multiline_comment_end;

    /* Point to the first non-space char. */
    p = row->render;
    i = 0; /* Current char offset */
    while (*p && isspace(*p)) {
        p++;
        i++;
    }
    prev_sep = 1;   /* Tell the parser if 'i' points to start of word. */
    in_string = 0;  /* Are we inside "" or '' ? */
    in_comment = 0; /* Are we inside multi-line comment? */

    /* If the previous line has an open comment, this line starts
     * with an open comment state. */
    if (row->idx > 0 && RowHasOpenComment(&state->row[row->idx - 1]))
        in_comment = 1;

    while (*p) {
        /* Handle // comments. */
        if (prev_sep && *p == scs[0] && *(p + 1) == scs[1]) {
            /* From here to end is a comment */
            memset(row->hl + i, HL_COMMENT, row->size - i);
            return;
        }

        /* Handle multi line comments. */
        if (in_comment) {
            row->hl[i] = HL_MLCOMMENT;
            if (*p == mce[0] && *(p + 1) == mce[1]) {
                row->hl[i + 1] = HL_MLCOMMENT;
                p += 2;
                i += 2;
                in_comment = 0;
                prev_sep = 1;
                continue;
            } else {
                prev_sep = 0;
                p++;
                i++;
                continue;
            }
        } else if (*p == mcs[0] && *(p + 1) == mcs[1]) {
            row->hl[i] = HL_MLCOMMENT;
            row->hl[i + 1] = HL_MLCOMMENT;
            p += 2;
            i += 2;
            in_comment = 1;
            prev_sep = 0;
            continue;
        }

        /* Handle "" and '' */
        if (in_string) {
            row->hl[i] = HL_STRING;
            if (*p == '\\') {
                row->hl[i + 1] = HL_STRING;
                p += 2;
                i += 2;
                prev_sep = 0;
                continue;
            }
            if (*p == in_string)
                in_string = 0;
            p++;
            i++;
            continue;
        } else {
            if (*p == '"' || *p == '\'') {
                in_string = *p;
                row->hl[i] = HL_STRING;
                p++;
                i++;
                prev_sep = 0;
                continue;
            }
        }

        /* Handle non printable chars. */
        if (!isprint(*p)) {
            row->hl[i] = HL_NONPRINT;
            p++;
            i++;
            prev_sep = 0;
            continue;
        }

        /* Handle numbers */
        if ((isdigit(*p) && (prev_sep || row->hl[i - 1] == HL_NUMBER)) ||
            (*p == '.' && i > 0 && row->hl[i - 1] == HL_NUMBER)) {
            row->hl[i] = HL_NUMBER;
            p++;
            i++;
            prev_sep = 0;
            continue;
        }

        /* Handle keywords and lib calls */
        if (prev_sep) {
            int j;
            for (j = 0; keywords[j]; j++) {
                int klen = strlen(keywords[j]);
                int kw2 = keywords[j][klen - 1] == '|';
                if (kw2)
                    klen--;

                if (!memcmp(p, keywords[j], klen) && IsSeparator(*(p + klen))) {
                    /* Keyword */
                    memset(row->hl + i, kw2 ? HL_KEYWORD2 : HL_KEYWORD1, klen);
                    p += klen;
                    i += klen;
                    break;
                }
            }
            if (keywords[j] != NULL) {
                prev_sep = 0;
                continue; /* We had a keyword match */
            }
        }

        /* Not special chars */
        prev_sep = IsSeparator(*p);
        p++;
        i++;
    }

    /* Propagate syntax change to the next row if the open commen
     * state changed. This may recursively affect all the following rows
     * in the file. */
    int oc = RowHasOpenComment(row);
    if (row->hl_oc != oc && row->idx + 1 < state->numrows)
        UpdateSyntax(state, &state->row[row->idx + 1]);
    row->hl_oc = oc;
}

// PURE
/* Maps syntax highlight token types to terminal colors. */
int SyntaxToColor(int hl) {
    switch (hl) {
        case HL_COMMENT:
        case HL_MLCOMMENT:
            return 36; /* cyan */
        case HL_KEYWORD1:
            return 33; /* yellow */
        case HL_KEYWORD2:
            return 32; /* green */
        case HL_STRING:
            return 35; /* magenta */
        case HL_NUMBER:
            return 31; /* red */
        case HL_MATCH:
            return 34; /* blu */
        default:
            return 37; /* white */
    }
}

// PURE
/* Select the syntax highlight scheme depending on the filename,
 * setting it in the global state state->syntax. */
void SelectSyntaxHighlight(State* state, char* filename) {
    for (unsigned int j = 0; j < HLDB_ENTRIES; j++) {
        struct Syntax* s = HLDB + j;
        unsigned int i = 0;
        while (s->filematch[i]) {
            char* p;
            int patlen = strlen(s->filematch[i]);
            if ((p = strstr(filename, s->filematch[i])) != NULL) {
                if (s->filematch[i][0] != '.' || p[patlen] == '\0') {
                    state->syntax = s;
                    return;
                }
            }
            i++;
        }
    }
}

/* ======================= Editor rows implementation ======================= */

// Somewhat PURE but also SIDE EFFECTS -- Can remove the printf though and just return the error code.
/* Update the rendered version and the syntax highlight of a row. */
void UpdateRow(State* state, Row* row) {
    unsigned int tabs = 0, nonprint = 0;
    int j, idx;

    /* Create a version of the row we can directly print on the screen,
     * respecting tabs, substituting non printable characters with '?'. */
    free(row->render);
    for (j = 0; j < row->size; j++)
        if (row->chars[j] == TAB)
            tabs++;

    unsigned long long allocsize =
        (unsigned long long)row->size + tabs * 8 + nonprint * 9 + 1;
    if (allocsize > UINT32_MAX) {
        printf("Some line of the edited file is too long for ette\n");
        exit(1);
    }

    row->render = (char*)malloc(row->size + tabs * 8 + nonprint * 9 + 1);
    idx = 0;
    for (j = 0; j < row->size; j++) {
        if (row->chars[j] == TAB) {
            row->render[idx++] = ' ';
            while ((idx + 1) % 8 != 0)
                row->render[idx++] = ' ';
        } else {
            row->render[idx++] = row->chars[j];
        }
    }
    row->rsize = idx;
    row->render[idx] = '\0';

    /* Update the syntax highlighting attributes of the row. */
    UpdateSyntax(state, row);
}

// PURE -- minor exception that it prints and exits
/* Insert a row at the specified position, shifting the other rows on the bottom
 * if required. */
void InsertRow(State* state, int at, const char* s, size_t len) {
    if (at > state->numrows)
        return;
    state->row = (Row*)realloc(state->row, sizeof(Row) * (state->numrows + 1));
    if (at != state->numrows) {
        memmove(state->row + at + 1, state->row + at,
                sizeof(state->row[0]) * (state->numrows - at));
        for (int j = at + 1; j <= state->numrows; j++)
            state->row[j].idx++;
    }
    state->row[at].size = len;
    state->row[at].chars = (char*)malloc(len + 1);
    memcpy(state->row[at].chars, s, len + 1);
    state->row[at].hl = NULL;
    state->row[at].hl_oc = 0;
    state->row[at].render = NULL;
    state->row[at].rsize = 0;
    state->row[at].idx = at;
    UpdateRow(state, state->row + at);
    state->numrows++;
    state->dirty++;
}

// PURE
/* Free row's heap allocated stuff. */
void FreeRow(Row* row) {
    free(row->render);
    free(row->chars);
    free(row->hl);
}

// PURE
/* Remove the row at the specified position, shifting the remaining on the
 * top. */
void DeleteRow(State* state, int at) {
    Row* row;

    if (at >= state->numrows)
        return;
    row = state->row + at;
    FreeRow(row);
    memmove(state->row + at, state->row + at + 1,
            sizeof(state->row[0]) * (state->numrows - at - 1));
    for (int j = at; j < state->numrows - 1; j++)
        state->row[j].idx++;
    state->numrows--;
    state->dirty++;
}

// PURE
/* Turn the editor rows into a single heap-allocated string.
 * Returns the pointer to the heap-allocated string and populate the
 * integer pointed by 'buflen' with the size of the string, escluding
 * the final nulterm. */
char* RowsToString(State* state, int* buflen) {
    char *buf = NULL, *p;
    int totlen = 0;
    int j;

    /* Compute count of bytes */
    for (j = 0; j < state->numrows; j++)
        totlen +=
            state->row[j].size + 1; /* +1 is for "\n" at end of every row */
    *buflen = totlen;
    totlen++; /* Also make space for nulterm */

    p = buf = (char*)malloc(totlen);
    for (j = 0; j < state->numrows; j++) {
        memcpy(p, state->row[j].chars, state->row[j].size);
        p += state->row[j].size;
        *p = '\n';
        p++;
    }
    *p = '\0';
    return buf;
}

// PURE -- minor exception that it can print and exit
/* Insert a character at the specified position in a row, moving the remaining
 * chars on the right if needed. */
void RowInsertChar(State* state, Row* row, int at, int c) {
    if (at > row->size) {
        /* Pad the string with spaces if the insert location is outside the
         * current length by more than a single character. */
        int padlen = at - row->size;
        /* In the next line +2 means: new char and null term. */
        row->chars = (char*)realloc(row->chars, row->size + padlen + 2);
        memset(row->chars + row->size, ' ', padlen);
        row->chars[row->size + padlen + 1] = '\0';
        row->size += padlen + 1;
    } else {
        /* If we are in the middle of the string just make space for 1 new
         * char plus the (already existing) null term. */
        row->chars = (char*)realloc(row->chars, row->size + 2);
        memmove(row->chars + at + 1, row->chars + at, row->size - at + 1);
        row->size++;
    }
    row->chars[at] = c;
    UpdateRow(state, row);
    state->dirty++;
}

// PURE -- minor exception that it can print and exit
/* Append the string 's' at the end of a row */
void RowAppendString(State* state, Row* row, char* s, size_t len) {
    row->chars = (char*)realloc(row->chars, row->size + len + 1);
    memcpy(row->chars + row->size, s, len);
    row->size += len;
    row->chars[row->size] = '\0';
    UpdateRow(state, row);
    state->dirty++;
}

// PURE -- minor exception that it can print and exit
/* Delete the character at offset 'at' from the specified row. */
void RowDeleteChar(State* state, Row* row, int at) {
    if (row->size <= at)
        return;
    memmove(row->chars + at, row->chars + at + 1, row->size - at);
    UpdateRow(state, row);
    row->size--;
    state->dirty++;
}

// PURE -- minor exception that it can print and exit
/* Insert the specified char at the current prompt position. */
void InsertChar(State* state, int c) {
    int filerow = state->rowoff + state->cy;
    int filecol = state->coloff + state->cx;
    Row* row = (filerow >= state->numrows) ? NULL : &state->row[filerow];

    /* If the row where the cursor is currently located does not exist in our
     * logical representaion of the file, add enough empty rows as needed. */
    if (!row) {
        while (state->numrows <= filerow)
            InsertRow(state, state->numrows, "", 0);
    }
    row = &state->row[filerow];

    if (state->existing_file_password_state ==
            ExistingFilePasswordState::kTyping ||
        state->new_file_password_state ==
            NewFilePasswordState::kTypingEnterPassword ||
        state->new_file_password_state ==
            NewFilePasswordState::kTypingConfirmPassword) {

        state->entry_password += (char)c;
        RowInsertChar(state, row, filecol, '*');
    } else {

        RowInsertChar(state, row, filecol, c);
    }

    if (state->cx == state->screencols - 1)
        state->coloff++;
    else
        state->cx++;

    state->dirty++;
}

// PURE -- minor exception that it can print and exit
/* Inserting a newline is slightly complex as we have to handle inserting a
 * newline in the middle of a line, splitting the line as needed. */
void InsertNewLine(State* state) {
    int filerow = state->rowoff + state->cy;
    int filecol = state->coloff + state->cx;
    Row* row = (filerow >= state->numrows) ? NULL : &state->row[filerow];

    if (!row) {
        if (filerow == state->numrows) {
            InsertRow(state, filerow, "", 0);
            goto fixcursor;
        }
        return;
    }
    /* If the cursor is over the current line size, we want to conceptually
     * think it's just over the last character. */
    if (filecol >= row->size)
        filecol = row->size;
    if (filecol == 0) {
        InsertRow(state, filerow, "", 0);
    } else {
        /* We are in the middle of a line. Split it between two rows. */
        InsertRow(state, filerow + 1, row->chars + filecol,
                  row->size - filecol);
        row = &state->row[filerow];
        row->chars[filecol] = '\0';
        row->size = filecol;
        UpdateRow(state, row);
    }
fixcursor:
    if (state->cy == state->screenrows - 1) {
        state->rowoff++;
    } else {
        state->cy++;
    }
    state->cx = 0;
    state->coloff = 0;
}

// PURE -- minor exception that it can print and exit
/* Delete the char at the current prompt position. */
void DeleteChar(State* state) {
    int filerow = state->rowoff + state->cy;
    int filecol = state->coloff + state->cx;
    Row* row = (filerow >= state->numrows) ? NULL : &state->row[filerow];

    if (!row || (filecol == 0 && filerow == 0))
        return;
    if (filecol == 0) {
        /* Handle the case of column 0, we need to move the current line
         * on the right of the previous one. */
        filecol = state->row[filerow - 1].size;
        RowAppendString(state, &state->row[filerow - 1], row->chars, row->size);
        DeleteRow(state, filerow);
        row = NULL;
        if (state->cy == 0)
            state->rowoff--;
        else
            state->cy--;
        state->cx = filecol;
        if (state->cx >= state->screencols) {
            int shift = (state->screencols - state->cx) + 1;
            state->cx -= shift;
            state->coloff += shift;
        }
    } else {
        if (state->existing_file_password_state ==
                ExistingFilePasswordState::kTyping ||
            state->new_file_password_state ==
                NewFilePasswordState::kTypingEnterPassword ||
            state->new_file_password_state ==
                NewFilePasswordState::kTypingConfirmPassword) {
            state->entry_password.pop_back();
        }

        RowDeleteChar(state, row, filecol - 1);
        if (state->cx == 0 && state->coloff)
            state->coloff--;
        else
            state->cx--;
    }
    if (row)
        UpdateRow(state, row);
    state->dirty++;
}

std::optional<std::string> ReadFileToString(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return content;
}

int OpenEncryptedFile(State* state, char* filename) {
    std::optional<std::string> content = ReadFileToString(filename);
    if (!content) {
        return 1;
    }

    const CryptoState crypto_state =
        Decrypt(*content, state->password, state->crypto_algorithm);

    if (!crypto_state.status.ok()) {
        return 1;
    }

    const std::string plaintext = crypto_state.plaintext;

    std::string line;
    std::istringstream iss(plaintext);
    while (std::getline(iss, line)) {
        InsertRow(state, state->numrows, line.c_str(), line.length());
    }

    state->dirty = 0;

    return 0;
}

// SIDE EFFECTS
/* Load the specified program in the editor memory and returns 0 on success
 * or 1 on error. */
int Open(State* state, char* filename) {
    FILE* fp;
    state->dirty = 0;
    free(state->filename);
    size_t fnlen = strlen(filename) + 1;
    state->filename = (char*)malloc(fnlen);
    memcpy(state->filename, filename, fnlen);

    if (!state->password.empty()) {
        return OpenEncryptedFile(state, filename);
    }

    fp = fopen(filename, "r");
    if (!fp) {
        if (errno != ENOENT) {
            perror("Opening file");
            exit(1);
        }
        return 1;
    }

    char* line = NULL;
    size_t linecap = 0;
    ssize_t linelen;
    while ((linelen = getline(&line, &linecap, fp)) != -1) {
        if (linelen && (line[linelen - 1] == '\n' || line[linelen - 1] == '\r'))
            line[--linelen] = '\0';
        InsertRow(state, state->numrows, line, linelen);
    }

    free(line);
    fclose(fp);
    state->dirty = 0;
    return 0;
}

// SIDE EFFECTS
/* Save the current file on disk. Return 0 on success, 1 on error. */
int Save(State* state) {
    int len;
    char* buf = RowsToString(state, &len);
    const std::string plaintext = std::string(buf, len);
    std::string buffer_str = plaintext;
    free(buf);

    int fd = open(state->filename, O_RDWR | O_CREAT, 0644);
    if (fd == -1) {
        if (fd != -1)
            close(fd);
        SetStatusMessage(state, "Can't save! I/O error: %s", strerror(errno));
        return 1;
    }

    if (state->password.length() > 0) {
        const CryptoState encrypted_state =
            Encrypt(plaintext, state->password, GenerateRandomAsciiByteVector(),
                    state->crypto_algorithm);

        if (encrypted_state.status.ok()) {
            buffer_str = encrypted_state.ciphertext;
            len = buffer_str.length();
        } else {
            SetStatusMessage(state, "ERROR! Failed to encrypt");
            return 1;
        }
    }

    /* Use truncate + a single write(2) call in order to make saving
     * a bit safer, under the limits of what we can do in a small editor. */
    if (ftruncate(fd, len) == -1) {
        if (fd != -1)
            close(fd);
        SetStatusMessage(state, "Can't save! I/O error: %s", strerror(errno));
        return 1;
    }

    if (write(fd, buffer_str.c_str(), len) != len) {
        if (fd != -1)
            close(fd);
        SetStatusMessage(state, "Can't save! I/O error: %s", strerror(errno));
        return 1;
    }

    close(fd);
    state->dirty = 0;
    SetStatusMessage(state, "%d bytes written on disk", len);
    return 0;
}

/* ============================= Terminal update ============================ */

// PURE
void Append(Buffer* ab, const char* s, int len) {
    char* new_buffer = (char*)realloc(ab->b, ab->len + len);

    if (new_buffer == NULL)
        return;
    memcpy(new_buffer + ab->len, s, len);
    ab->b = new_buffer;
    ab->len += len;
}

// PURE
void FreeBuf(Buffer* ab) {
    free(ab->b);
}

// SIDE EFFECTS
/* This function writes the whole screen using VT100 escape characters
 * starting from the logical state of the editor in the global state 'E'. */
void RefreshScreen() {
    int y;
    Row* r;
    char buf[32];
    struct Buffer ab = ABUF_INIT;

    Append(&ab, "\x1b[?25l", 6); /* Hide cursor. */
    Append(&ab, "\x1b[H", 3);    /* Go home. */
    for (y = 0; y < E->screenrows; y++) {
        int filerow = E->rowoff + y;

        if (filerow >= E->numrows) {
            if (E->numrows == 0 && y == E->screenrows / 3) {
                char welcome[80];
                int welcomelen =
                    snprintf(welcome, sizeof(welcome),
                             "ette (Encrypted Terminal Text Editor) "
                             "-- version %s\x1b[0K\r\n",
                             ::ette::kVersionStr);
                int padding = (E->screencols - welcomelen) / 2;
                if (padding) {
                    Append(&ab, "~", 1);
                    padding--;
                }
                while (padding--)
                    Append(&ab, " ", 1);
                Append(&ab, welcome, welcomelen);
            } else {
                Append(&ab, "~\x1b[0K\r\n", 7);
            }
            continue;
        }

        r = &E->row[filerow];

        int len = r->rsize - E->coloff;
        int current_color = -1;
        if (len > 0) {
            if (len > E->screencols)
                len = E->screencols;
            char* c = r->render + E->coloff;
            unsigned char* hl = r->hl + E->coloff;
            int j;
            for (j = 0; j < len; j++) {
                if (hl[j] == HL_NONPRINT) {
                    char sym;
                    Append(&ab, "\x1b[7m", 4);
                    if (c[j] <= 26)
                        sym = '@' + c[j];
                    else
                        sym = '?';
                    Append(&ab, &sym, 1);
                    Append(&ab, "\x1b[0m", 4);
                } else if (hl[j] == HL_NORMAL) {
                    if (current_color != -1) {
                        Append(&ab, "\x1b[39m", 5);
                        current_color = -1;
                    }
                    Append(&ab, c + j, 1);
                } else {
                    int color = SyntaxToColor(hl[j]);
                    if (color != current_color) {
                        char syntax_color_buf[16];
                        int clen =
                            snprintf(syntax_color_buf, sizeof(syntax_color_buf),
                                     "\x1b[%dm", color);
                        current_color = color;
                        Append(&ab, syntax_color_buf, clen);
                    }
                    Append(&ab, c + j, 1);
                }
            }
        }
        Append(&ab, "\x1b[39m", 5);
        Append(&ab, "\x1b[0K", 4);
        Append(&ab, "\r\n", 2);
    }

    /* Create a two rows status. First row: */
    Append(&ab, "\x1b[0K", 4);
    Append(&ab, "\x1b[7m", 4);
    char status[80], rstatus[80];
    int len = snprintf(status, sizeof(status), "%.20s - %d lines %s",
                       E->filename, E->numrows, E->dirty ? "(modified)" : "");
    int rlen = snprintf(rstatus, sizeof(rstatus), "%d/%d",
                        E->rowoff + E->cy + 1, E->numrows);
    if (len > E->screencols)
        len = E->screencols;
    Append(&ab, status, len);
    while (len < E->screencols) {
        if (E->screencols - len == rlen) {
            Append(&ab, rstatus, rlen);
            break;
        } else {
            Append(&ab, " ", 1);
            len++;
        }
    }
    Append(&ab, "\x1b[0m\r\n", 6);

    /* Second row depends on state->statusmsg and the status message update time. */
    Append(&ab, "\x1b[0K", 4);
    int msglen = strlen(E->statusmsg);
    if (msglen && time(NULL) - E->statusmsg_time < 5)
        Append(&ab, E->statusmsg,
               msglen <= E->screencols ? msglen : E->screencols);

    /* Put cursor at its current position. Note that the horizontal position
     * at which the cursor is displayed may be different compared to 'state->cx'
     * because of TABs. */
    int j;
    int cx = 1;
    int filerow = E->rowoff + E->cy;
    Row* row = (filerow >= E->numrows) ? NULL : &E->row[filerow];
    if (row) {
        for (j = E->coloff; j < (E->cx + E->coloff); j++) {
            if (j < row->size && row->chars[j] == TAB)
                cx += 7 - ((cx) % 8);
            cx++;
        }
    }
    snprintf(buf, sizeof(buf), "\x1b[%d;%dH", E->cy + 1, cx);
    Append(&ab, buf, strlen(buf));
    Append(&ab, "\x1b[?25h", 6); /* Show cursor. */
    write(STDOUT_FILENO, ab.b, ab.len);
    FreeBuf(&ab);
}

/* =============================== Find mode ================================ */
// SIDE EFFECTS
void Find(int fd, State* state) {
    char query[QUERY_LEN + 1] = {0};
    int qlen = 0;
    int last_match = -1; /* Last line where a match was found. -1 for none. */
    int find_next = 0;   /* if 1 search next, if -1 search prev. */
    int saved_hl_line = -1; /* No saved HL */
    char* saved_hl = NULL;

#define FIND_RESTORE_HL                                    \
    do {                                                   \
        if (saved_hl) {                                    \
            memcpy(state->row[saved_hl_line].hl, saved_hl, \
                   state->row[saved_hl_line].rsize);       \
            free(saved_hl);                                \
            saved_hl = NULL;                               \
        }                                                  \
    } while (0)

    /* Save the cursor position in order to restore it later. */
    int saved_cx = state->cx, saved_cy = state->cy;
    int saved_coloff = state->coloff, saved_rowoff = state->rowoff;

    while (1) {
        SetStatusMessage(state, "Search: %s (Use ESC/Arrows/Enter)", query);
        RefreshScreen();

        int c = ReadKey(fd);
        if (c == DEL_KEY || c == CTRL_H || c == BACKSPACE) {
            if (qlen != 0)
                query[--qlen] = '\0';
            last_match = -1;
        } else if (c == ESC || c == ENTER) {
            if (c == ESC) {
                state->cx = saved_cx;
                state->cy = saved_cy;
                state->coloff = saved_coloff;
                state->rowoff = saved_rowoff;
            }
            FIND_RESTORE_HL;
            SetStatusMessage(state, "");
            return;
        } else if (c == ARROW_RIGHT || c == ARROW_DOWN) {
            find_next = 1;
        } else if (c == ARROW_LEFT || c == ARROW_UP) {
            find_next = -1;
        } else if (isprint(c)) {
            if (qlen < QUERY_LEN) {
                query[qlen++] = c;
                query[qlen] = '\0';
                last_match = -1;
            }
        }

        /* Search occurrence. */
        if (last_match == -1)
            find_next = 1;
        if (find_next) {
            char* match = NULL;
            int match_offset = 0;
            int i, current = last_match;

            for (i = 0; i < state->numrows; i++) {
                current += find_next;
                if (current == -1)
                    current = state->numrows - 1;
                else if (current == state->numrows)
                    current = 0;
                match = strstr(state->row[current].render, query);
                if (match) {
                    match_offset = match - state->row[current].render;
                    break;
                }
            }
            find_next = 0;

            /* Highlight */
            FIND_RESTORE_HL;

            if (match) {
                Row* row = &state->row[current];
                last_match = current;
                if (row->hl) {
                    saved_hl_line = current;
                    saved_hl = (char*)malloc(row->rsize);
                    memcpy(saved_hl, row->hl, row->rsize);
                    memset(row->hl + match_offset, HL_MATCH, qlen);
                }
                state->cy = 0;
                state->cx = match_offset;
                state->rowoff = current;
                state->coloff = 0;
                /* Scroll horizontally as needed. */
                if (state->cx > state->screencols) {
                    int diff = state->cx - state->screencols;
                    state->cx -= diff;
                    state->coloff += diff;
                }
            }
        }
    }
}

/* ========================= Editor events handling  ======================== */
// PURE
/* Handle cursor position change because arrow keys were pressed. */
void MoveCursor(State* state, int key) {
    int filerow = state->rowoff + state->cy;
    int filecol = state->coloff + state->cx;
    int rowlen;
    Row* row = (filerow >= state->numrows) ? NULL : &state->row[filerow];

    switch (key) {
        case ARROW_LEFT:
            if (state->cx == 0) {
                if (state->coloff) {
                    state->coloff--;
                } else {
                    if (filerow > 0) {
                        state->cy--;
                        state->cx = state->row[filerow - 1].size;
                        if (state->cx > state->screencols - 1) {
                            state->coloff = state->cx - state->screencols + 1;
                            state->cx = state->screencols - 1;
                        }
                    }
                }
            } else {
                state->cx -= 1;
            }
            break;
        case ARROW_RIGHT:
            if (row && filecol < row->size) {
                if (state->cx == state->screencols - 1) {
                    state->coloff++;
                } else {
                    state->cx += 1;
                }
            } else if (row && filecol == row->size) {
                state->cx = 0;
                state->coloff = 0;
                if (state->cy == state->screenrows - 1) {
                    state->rowoff++;
                } else {
                    state->cy += 1;
                }
            }
            break;
        case ARROW_UP:
            if (state->cy == 0) {
                if (state->rowoff)
                    state->rowoff--;
            } else {
                state->cy -= 1;
            }
            break;
        case ARROW_DOWN:
            if (filerow < state->numrows) {
                if (state->cy == state->screenrows - 1) {
                    state->rowoff++;
                } else {
                    state->cy += 1;
                }
            }
            break;
    }
    /* Fix cx if the current line has not enough chars. */
    filerow = state->rowoff + state->cy;
    filecol = state->coloff + state->cx;
    row = (filerow >= state->numrows) ? NULL : &state->row[filerow];
    rowlen = row ? row->size : 0;
    if (filecol > rowlen) {
        state->cx -= filecol - rowlen;
        if (state->cx < 0) {
            state->coloff += state->cx;
            state->cx = 0;
        }
    }
}

void ProcessKeyPressUnlocked(int fd, State* state, int c) {
    switch (c) {
        case ENTER: /* Enter */
            InsertNewLine(state);
            break;
        case CTRL_C: /* Ctrl-c */
            /* We ignore ctrl-c, it can't be so simple to lose the changes
         * to the edited file. */
            break;
        case CTRL_Q: /* Ctrl-q */
            /* Quit if the file was already saved. */
            if (state->dirty && state->quit_times > 0) {
                SetStatusMessage(state,
                                 "WARNING!!! File has unsaved changes. "
                                 "Press Ctrl-Q %d more times to quit.",
                                 state->quit_times);
                state->quit_times = state->quit_times - 1;
                return;
            }
            write(fd, "\033c", 3);
            exit(0);
            break;
        case CTRL_S: /* Ctrl-s */
            Save(state);
            break;
        case CTRL_F:
            Find(fd, state);
            break;
        case BACKSPACE: /* Backspace */
        case CTRL_H:    /* Ctrl-h */
        case DEL_KEY:
            DeleteChar(state);
            break;
        case PAGE_UP:
        case PAGE_DOWN:
            if (c == PAGE_UP && state->cy != 0)
                state->cy = 0;
            else if (c == PAGE_DOWN && state->cy != state->screenrows - 1)
                state->cy = state->screenrows - 1;
            {
                int times = state->screenrows;
                while (times--)
                    MoveCursor(state, c == PAGE_UP ? ARROW_UP : ARROW_DOWN);
            }
            break;

        case ARROW_UP:
        case ARROW_DOWN:
        case ARROW_LEFT:
        case ARROW_RIGHT:
            MoveCursor(state, c);
            break;
        case CTRL_L: /* ctrl+l, clear screen */
            /* Just refresh the line as side effect. */
            break;
        case ESC:
            /* Nothing to do for ESC in this mode. */
            break;
        default:
            InsertChar(state, c);
            break;
    }
}

bool ProcessKeyPressPasswordMode(int fd, State* state, int provided_key) {
    int c = provided_key ? provided_key : ReadKey(fd);

    switch (c) {
        case ENTER: /* Enter */
            return true;
        case CTRL_Q: /* Ctrl-q */
            write(fd, "\033c", 3);
            exit(0);
            break;
        case BACKSPACE:
        case CTRL_H:
        case DEL_KEY:
            if (state->cx <= static_cast<int>(state->indelible_msg.length())) {
                return false;
            }
            DeleteChar(state);
            break;
        case CTRL_S:
        case CTRL_C:
        case CTRL_F:
        case PAGE_UP:
        case PAGE_DOWN:
        case ARROW_UP:
        case ARROW_DOWN:
        case ARROW_LEFT:
        case ARROW_RIGHT:
        case CTRL_L:
        case ESC:
            break;
        default:
            // Insert the actual character
            // Show the user an asterisk
            InsertChar(state, c);
            break;
    }

    return false;
}

// SIDE EFFECTS
void ProcessKeyPress(int fd, State* state, int provided_key) {
    /* When the file is modified, requires Ctrl-q to be pressed N times
     * before actually quitting. */
    int c = provided_key ? provided_key : ReadKey(fd);
    ProcessKeyPressUnlocked(fd, state, c);
}

// SIDE EFFECTS
void UpdateWindowSize() {
    if (GetWindowSize(STDIN_FILENO, STDOUT_FILENO, &E->screenrows,
                      &E->screencols) == -1) {
        exit(1);
    }
    E->screenrows -= 2; /* Get room for status bar. */
}

// SIDE EFFECTS
void HandleWindowChangeSignal(int unused __attribute__((unused))) {
    UpdateWindowSize();
    if (E->cy > E->screenrows)
        if (E->cy > E->screenrows)
            E->cy = E->screenrows - 1;
    if (E->cx > E->screencols)
        E->cx = E->screencols - 1;
    RefreshScreen();
}

// SIDE EFFECTS
void Init(State* state) {
    E = state;
    state->cx = 0;
    state->cy = 0;
    state->rowoff = 0;
    state->coloff = 0;
    state->numrows = 0;
    state->row = NULL;
    state->dirty = 0;
    state->filename = NULL;
    state->syntax = NULL;
    UpdateWindowSize();
    signal(SIGWINCH, HandleWindowChangeSignal);
}

void InsertString(State* state, std::string& s) {
    for (size_t i = 0; i < s.size(); i++) {
        InsertChar(state, s[i]);
    }
}

CryptoAlgorithm GetCryptoAlgorithmFromFilename(std::string& filename) {
    std::string aes256cbc = ".aes256cbc";
    if (filename.find(aes256cbc) != std::string::npos) {
        return CryptoAlgorithm::kAES256CBC;
    }

    return CryptoAlgorithm::kDefaultNone;
}

bool FileExists(const std::string& filename) {
    return std::filesystem::exists(filename);
}

void ClearScreen(State* state) {
    state->cx = 0;
    state->cy = 0;
    state->rowoff = 0;
    state->coloff = 0;
    state->numrows = 0;
    state->row = NULL;
    state->dirty = 0;
    state->entry_password = "";
}

std::string GetPasswordFromState(State* state) {
    return state->entry_password;
}

void HandleNewFileEncryption(State* state,
                             const std::vector<int>& provided_keys) {
    state->unlock_state = UnlockState::kNewFile;
    state->new_file_password_state = NewFilePasswordState::kShowEnterPassword;

    std::string password;
    std::string confirm_password;
    int current_provided_key_idx = 0;
    const bool has_provided_keys = provided_keys.size() > 0;

    while (true) {
        switch (state->new_file_password_state) {
            case NewFilePasswordState::kShowEnterPassword: {
                std::string enter_password = "Enter password: ";
                InsertString(state, enter_password);

                state->indelible_msg = enter_password;
                state->new_file_password_state =
                    NewFilePasswordState::kTypingEnterPassword;
                break;
            }
            case NewFilePasswordState::kTypingEnterPassword: {
                const int provided_key =
                    has_provided_keys ? provided_keys[current_provided_key_idx]
                                      : 0;
                const bool enter_pressed = ProcessKeyPressPasswordMode(
                    STDIN_FILENO, state, provided_key);

                current_provided_key_idx++;

                if (enter_pressed) {
                    password = GetPasswordFromState(state);
                    state->new_file_password_state =
                        NewFilePasswordState::kEnterPasswordCompleted;
                }
                break;
            }

            case NewFilePasswordState::kEnterPasswordCompleted: {
                ClearScreen(state);

                std::string confirm_password_preamble = "Confirm password: ";
                InsertString(state, confirm_password_preamble);

                state->indelible_msg = confirm_password_preamble;
                state->new_file_password_state =
                    NewFilePasswordState::kTypingConfirmPassword;
                break;
            }

            case NewFilePasswordState::kTypingConfirmPassword: {
                const int provided_key =
                    has_provided_keys ? provided_keys[current_provided_key_idx]
                                      : 0;
                const bool enter_pressed = ProcessKeyPressPasswordMode(
                    STDIN_FILENO, state, provided_key);

                current_provided_key_idx++;

                if (enter_pressed) {
                    confirm_password = GetPasswordFromState(state);
                    state->new_file_password_state =
                        NewFilePasswordState::kConfirmPasswordNeedsCheck;
                }
                break;
            }

            case NewFilePasswordState::kConfirmPasswordNeedsCheck: {
                if (password == confirm_password) {
                    state->password = password;
                    ClearScreen(state);
                    state->indelible_msg = "";
                    return;
                } else {
                    state->new_file_password_state =
                        NewFilePasswordState::kShowRetryConfirmPassword;
                }
                break;
            }

            case NewFilePasswordState::kShowRetryConfirmPassword: {
                ClearScreen(state);
                std::string retry_confirm_password =
                    "Password mismatch. Confirm password: ";
                InsertString(state, retry_confirm_password);

                state->indelible_msg = retry_confirm_password;
                state->new_file_password_state =
                    NewFilePasswordState::kTypingConfirmPassword;
                break;
            }

            default:
                break;
        }

        // TODO(ryanmcdermott) This is ugly and should be fixed.
        // This only refreshes the screen when NOT in a test mode with provided keys.
        if (!has_provided_keys) {
            RefreshScreen();
        }
    }
}

void HandleExistingFileEncryption(State* state, std::string& filename,
                                  const std::vector<int>& provided_keys) {
    state->existing_file_password_state =
        ExistingFilePasswordState::kShowEnterPassword;

    std::string password;
    int current_provided_key_idx = 0;
    const bool has_provided_keys = provided_keys.size() > 0;

    while (true) {
        switch (state->existing_file_password_state) {
            case ExistingFilePasswordState::kShowEnterPassword: {
                std::string enter_password = "Enter password: ";
                InsertString(state, enter_password);

                state->indelible_msg = enter_password;
                state->existing_file_password_state =
                    ExistingFilePasswordState::kTyping;
                break;
            }

            case ExistingFilePasswordState::kTyping: {
                const int provided_key =
                    has_provided_keys ? provided_keys[current_provided_key_idx]
                                      : 0;
                const bool enter_pressed = ProcessKeyPressPasswordMode(
                    STDIN_FILENO, state, provided_key);

                current_provided_key_idx++;

                if (enter_pressed) {
                    password = GetPasswordFromState(state);
                    state->existing_file_password_state =
                        ExistingFilePasswordState::kEnterPasswordNeedsCheck;
                }
                break;
            }

            case ExistingFilePasswordState::kEnterPasswordNeedsCheck: {
                if (IsKeyCorrect(password, filename, state->crypto_algorithm)) {
                    state->password = password;
                    ClearScreen(state);
                    state->indelible_msg = "";
                    SetStatusMessage(state, "Password correct.");
                    return;
                }

                state->existing_file_password_state =
                    ExistingFilePasswordState::kShowRetryPassword;

                break;
            }

            case ExistingFilePasswordState::kShowRetryPassword: {
                ClearScreen(state);
                std::string retry_password = "Incorrect password. Try again: ";
                InsertString(state, retry_password);

                state->indelible_msg = retry_password;
                state->existing_file_password_state =
                    ExistingFilePasswordState::kTyping;
                break;
            }
        }

        // TODO(ryanmcdermott) This is ugly and should be fixed.
        // This only refreshes the screen when NOT in a test mode with provided keys.
        if (!has_provided_keys) {
            RefreshScreen();
        }
    }
}

void HandleEncryption(State* state, char* filename,
                      const std::vector<int>& provided_keys) {
    std::string filename_str = std::string(filename);
    const CryptoAlgorithm crypto_algorithm =
        GetCryptoAlgorithmFromFilename(filename_str);
    if (crypto_algorithm == CryptoAlgorithm::kDefaultNone) {
        return;
    }

    state->crypto_algorithm = crypto_algorithm;

    if (FileExists(filename_str)) {
        HandleExistingFileEncryption(state, filename_str, provided_keys);
    } else {
        HandleNewFileEncryption(state, provided_keys);
    }
}