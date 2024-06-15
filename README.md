# Tiny JSON Parser in C

## Running the tests

```bash
clear && \
gcc tests.c json.c -Wall -Wextra -Werror -Wpedantic -Wfatal-errors -g && \
./a.out
```

## Limitations

* Only arrays, objects and strings are parsable, since those are the only types that my [grug](https://mynameistrez.github.io/2024/02/29/creating-the-perfect-modding-language.html) programming language requires.

* Having the `\` character in a string does not allow escaping the `"` character.

* Every time `json_parse()` is called its arenas get reset, meaning that calling the function a second time overwrites the previous call's JSON result.
