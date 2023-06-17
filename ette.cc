#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "constants.h"
#include "editor.h"

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: ette <filename>\n");
        exit(1);
    }

    if (std::string(argv[1]) == std::string("--version")) {
        printf("ette version %d.%d.%d\n", ::ette::kVersionMajor,
               ::ette::kVersionMinor, ::ette::kVersionPatch);
        exit(0);
    }

    State* state = new State();

    Init(state);
    SelectSyntaxHighlight(state, argv[1]);
    EnableRawMode(STDIN_FILENO);
    HandleEncryption(state, argv[1], {});
    Open(state, argv[1]);
    SetStatusMessage(state,
                     "HELP: Ctrl-S = save | Ctrl-Q = quit | Ctrl-F = find");
    while (1) {
        RefreshScreen();
        ProcessKeyPress(STDIN_FILENO, state, 0);
    }

    delete state;
    return 0;
}