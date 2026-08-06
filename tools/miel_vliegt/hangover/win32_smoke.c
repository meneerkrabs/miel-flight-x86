#include <stdio.h>
#include <string.h>
#include <windows.h>

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--debug-break"))
        DebugBreak();
    puts("MIEL_HANGOVER_WIN32_SMOKE_OK");
    return 0;
}
