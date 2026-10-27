# Command processor

`cmd.c` is Raven code, built by CMake with MinGW into `cmd.exe` (and `x86/cmd.exe`) on the public Windows headers, without a C
runtime. Raven copies it into every prefix as `C:\Windows\System32\cmd.exe` and `C:\Windows\SysWOW64\cmd.exe`, where `ComSpec` points,
and `CreateProcess` runs batch files through it as `cmd /c "..."`.

It is written from Microsoft's public description of the command processor and its commands, and from how they behave; no Windows
code is used or consulted, nor the command processors of other projects.

What it does so far:

- the options `/C`, `/K`, `/Q` and `/S`, with the quote rule `cmd /?` describes for the command after `/C` or `/K`;
- a prompt from `PROMPT` (`$P$G` by default) reading commands from the console or from redirected input;
- `%NAME%` expansion, with `%ERRORLEVEL%` and `%CD%`, and in batch files `%0` to `%9`, `%*` and `%%`;
- batch files, run line by line with `ECHO` showing each command, labels and `GOTO` (with `:EOF`);
- `ECHO`, `REM`, `CD`/`CHDIR` (with `/D`), drive changes, `SET`, `CLS`, `VER`, `TITLE`, `TYPE`, `PAUSE`, `PATH`, `EXIT` (with `/B`);
- programs found by their path, or in the current folder and then `PATH`, with the extensions of `PATHEXT`; a program's exit code
  becomes `ERRORLEVEL`, and a command nothing runs sets it to 9009.

Not yet: the operators `&`, `&&`, `||` and `|`, redirection, parenthesised blocks, `IF`, `FOR`, `CALL`, `SETLOCAL`, delayed expansion,
`%~` modifiers, `SET /A` and `SET /P`, and the other built-ins (`DIR`, `COPY`, `DEL`, `MD`, `RD`, `MOVE`, `REN`, `PUSHD`, `POPD`,
`START`, ...).
