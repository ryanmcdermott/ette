#ifndef __EDITOR_H__
#define __EDITOR_H__

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
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "constants.h"
#include "crypto.h"

/* We define a very simple "append buffer" structure, that is an heap
 * allocated string where we can append to. This is useful in order to
 * write all the escape sequences in a buffer and flush them to the standard
 * output in a single call, to avoid flickering effects. */
struct Buffer {
    char* b;
    int len;
};

struct Syntax {
    char** filematch;
    char** keywords;
    char singleline_comment_start[3];
    char multiline_comment_start[3];
    char multiline_comment_end[3];
    int flags;
};

/* This structure represents a single line of the file we are editing. */
typedef struct Row {
    int idx;           /* Row index in the file, zero-based. */
    int size;          /* Size of the row, excluding the null term. */
    int rsize;         /* Size of the rendered row. */
    char* chars;       /* Row content. */
    char* render;      /* Row content "rendered" for screen (for TABs). */
    unsigned char* hl; /* Syntax highlight type for each character in render.*/
    int hl_oc;         /* Row had open comment at end in last syntax highlight
                          check. */
} Row;

typedef struct HLColor {
    int r, g, b;
} HLColor;

enum class ExistingFilePasswordState {
    kShowEnterPassword,
    kTyping,
    kEnterPasswordNeedsCheck,
    kShowRetryPassword,
};

enum class NewFilePasswordState {
    kShowEnterPassword,
    kTypingEnterPassword,
    kEnterPasswordCompleted,
    kShowConfirmPassword,
    kTypingConfirmPassword,
    kConfirmPasswordNeedsCheck,
    kShowRetryConfirmPassword,
};

enum class UnlockState { kUnlocked, kNewFile, kExistingFile };

enum class PasswordStatus {
    kDefaultPasswordStatusNone,
    kPasswordVerified,
    kIncorrectPassword,
    kConfirmPasswordMismatch
};

struct State {
    int cx, cy;     /* Cursor x and y position in characters */
    int rowoff;     /* Offset of row displayed. */
    int coloff;     /* Offset of column displayed. */
    int screenrows; /* Number of rows that we can show */
    int screencols; /* Number of cols that we can show */
    int numrows;    /* Number of rows */
    int rawmode;    /* Is terminal raw mode enabled? */
    Row* row;       /* Rows */
    int dirty;      /* File modified but not saved. */
    char* filename; /* Currently open filename */
    int quit_times{3};
    std::string indelible_msg;
    std::string password;
    std::string entry_password;
    ette::CryptoAlgorithm crypto_algorithm;
    UnlockState unlock_state;
    ExistingFilePasswordState existing_file_password_state;
    NewFilePasswordState new_file_password_state;
    PasswordStatus password_status;
    char statusmsg[80];
    time_t statusmsg_time;
    struct Syntax* syntax; /* Current syntax highlight, or NULL. */
};

enum KEY_ACTION {
    KEY_NULL = 0,    /* NULL */
    CTRL_C = 3,      /* Ctrl-c */
    CTRL_D = 4,      /* Ctrl-d */
    CTRL_F = 6,      /* Ctrl-f */
    CTRL_H = 8,      /* Ctrl-h */
    TAB = 9,         /* Tab */
    CTRL_L = 12,     /* Ctrl+l */
    ENTER = 13,      /* Enter */
    CTRL_Q = 17,     /* Ctrl-q */
    CTRL_S = 19,     /* Ctrl-s */
    CTRL_U = 21,     /* Ctrl-u */
    ESC = 27,        /* Escape */
    BACKSPACE = 127, /* Backspace */
    /* The following are just soft codes, not really reported by the
     * terminal directly. */
    ARROW_LEFT = 1000,
    ARROW_RIGHT,
    ARROW_UP,
    ARROW_DOWN,
    DEL_KEY,
    HOME_KEY,
    END_KEY,
    PAGE_UP,
    PAGE_DOWN
};

void SetStatusMessage(State* state, const char* fmt, ...);

void DisableRawMode(int fd);

int EnableRawMode(int fd);

int ReadKey(int fd);

int GetCursorPos(int ifd, int ofd, int* rows, int* cols);

int GetWindowSize(int ifd, int ofd, int* rows, int* cols);

int IsSeparator(int c);

int RowHasOpenComment(Row* row);

void UpdateSyntax(State* state, Row* row);

int SyntaxToColor(int hl);

void SelectSyntaxHighlight(State* state, char* filename);

void UpdateRow(State* state, Row* row);

void InsertRow(State* state, int at, const char* s, size_t len);

void FreeRow(Row* row);

void DeleteRow(State* state, int at);

char* RowsToString(State* state, int* buflen);

void RowInsertChar(State* state, Row* row, int at, int c);

void RowAppendString(State* state, Row* row, char* s, size_t len);

void RowDeleteChar(State* state, Row* row, int at);

void InsertChar(State* state, int c);

void InsertString(State* state, std::string& s);

void InsertNewLine(State* state);

void DeleteChar(State* state);

int Open(State* state, char* filename);

int Save(State* state);

void Append(Buffer* ab, const char* s, int len);

void FreeBuf(Buffer* ab);

void RefreshScreen();

void Find(int fd, State* state);

void MoveCursor(State* state, int key);

void ProcessKeyPress(int fd, State* state, int provided_key);

void UpdateWindowSize();

void HandleWindowChangeSignal(int unused __attribute__((unused)));

void Init(State* state);

void HandleEncryption(State* state, char* filename,
                      const std::vector<int>& provided_keys);

#endif