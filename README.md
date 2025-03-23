# Tiny allocationless JSON parser in C

This library parses a subset of [JSON](https://en.wikipedia.org/wiki/JSON) in 473 lines of C, where only arrays, objects and strings are handled.

I wrote this JSON parser for my tiny programming language called [grug](https://mynameistrez.github.io/2024/02/29/creating-the-perfect-modding-language.html).

I was inspired by null program's [Minimalist C Libraries](https://nullprogram.com/blog/2018/06/10/) blog post, describing how C libraries never really need to allocate any memory themselves. The trick is to expect the user to pass `void *buffer` and `size_t buffer_capacity`:

```c
int main() {
    char buffer[420];

    // If json_init() fails, just increase the starting size
    assert(!json_init(buffer, sizeof(buffer)));

    struct json_node node;

    enum json_status status = json("foo.json", &node, buffer, sizeof(buffer));
    if (status) {
        // Handle error here
        exit(EXIT_FAILURE);
    }

    // You can now recursively walk the JSON data in the node variable here
}
```

Instead of using a fixed size buffer, you can use `realloc()` to keep retrying the call with a bigger buffer:

```c
int main() {
    size_t size = 420;
    void *buffer = malloc(size);

    // If json_init() fails, just increase the starting size
    assert(!json_init(buffer, size));

    struct json_node node;

    enum json_status status;
    do {
        status = json("foo.json", &node, buffer, size);
        if (status == JSON_OUT_OF_MEMORY) {
            size *= 2;
            buffer = realloc(buffer, size);
        }
    } while (status == JSON_OUT_OF_MEMORY);

    if (status) {
        // Handle error here
        exit(EXIT_FAILURE);
    }

    // You can now recursively walk the JSON data in the node variable here
}
```

## How it works

The `json_init()` function puts an internal struct at the start of the buffer [here](https://github.com/MyNameIsTrez/tiny-allocationless-json-parser-in-c/blob/7d5bb76d11aa32da22c39a186ed2f721959abf64/json.c#L539-L543). `json()` uses the remaining buffer bytes to allocate the arrays it needs for parsing [here](https://github.com/MyNameIsTrez/tiny-allocationless-json-parser-in-c/blob/7d5bb76d11aa32da22c39a186ed2f721959abf64/json.c#L465).

If one of the arrays turns out to be too small, it'll automatically restart the parsing, with the array's capacity doubled [here](https://github.com/MyNameIsTrez/tiny-allocationless-json-parser-in-c/blob/1e5dd1ae77e3f247f28026cc10abedd876aa43f0/json.c#L375-L376). So the first parsed JSON file will take a few iterations to be parsed successfully, while the JSON files after that will usually just take a single iteration.

The parser uses an [array-based hash table](https://mynameistrez.github.io/2024/06/19/array-based-hash-table-in-c.html) to detect duplicate object keys, and `longjmp()` to [keep the clutter of error handling at bay](https://mynameistrez.github.io/2024/03/21/setjmp-plus-longjmp-equals-goto-but-awesome.html).

The [JSON spec](https://www.json.org/json-en.html) specifies that the other value types are `number`, `true`, `false` and `null`, but they can all be stored as strings. You could easily support these however by adding just a few dozen lines to `json.c`, so feel free to. The `\` character also does not allow escaping the `"` character in strings.

## Simpler version

If you don't need to have several JSON files open at the same, you can use the [structless branch](https://github.com/MyNameIsTrez/tiny-allocationless-json-parser-in-c/tree/structless). Its `json_init()` can't fail, and it's 400 lines of code, rather than 437:

```c
int main() {
    char buffer[420];

    json_init();

    struct json_node node;

    enum json_status status = json("foo.json", &node, buffer, sizeof(buffer));
    if (status) {
        // Handle error here
        exit(EXIT_FAILURE);
    }

    // You can now recursively walk the JSON data in the node variable here
}
```

## Even simpler version

Originally `json.c` was 397 lines of code, which you can still view in the branch called [static-arrays](https://github.com/MyNameIsTrez/tiny-allocationless-json-parser-in-c/tree/static-arrays):

```c
int main() {
    struct json_node node;
    if (json("foo.json", &node)) {
        // Handle error here
        exit(EXIT_FAILURE);
    }

    // You can now recursively walk the JSON data in the node variable here
}
```

It used static arrays with hardcoded sizes, which I described the advantages of in my blog post titled [Static arrays are the best vectors](https://mynameistrez.github.io/2024/04/09/static-arrays-are-the-best-vectors.html).

There were two problems with it:
1. It didn't give the user control over how the memory was allocated. So you'd have to manually edit `#define` statements in `json.c`, if you wanted to increase say the maximum number of tokens that a JSON file is allowed to contain.
2. Whenever `json_parse()` was called, its static arrays would be reset. This meant that calling the function a second time would overwrite the previous call's JSON result. This was fine if you didn't need to open more than one JSON file at a time, though. But even if you did, you could just manually copy around the arrays containing the JSON data.

## Running the tests

```bash
gcc json.c tests.c && \
./a.out
```

Run this if you want to let the compiler and runtime perform more checks:

```bash
gcc json.c tests.c -Wall -Wextra -Werror -Wpedantic -Wfatal-errors -g -fsanitize=address,undefined && \
./a.out
```

## Generating coverage

Make sure to install [gcovr](https://gcovr.com/en/stable/installation.html) first.

```bash
gcc json.c tests.c -Wall -Wextra -Werror -Wpedantic -Wfatal-errors -g -fsanitize=address,undefined --coverage && \
./a.out && \
gcovr --html-details coverage.html
```

You can then view the generated `coverage.html` in your browser. You should see that the program has nearly 100% line and branch coverage.

## Fuzzing

This uses [libFuzzer](https://llvm.org/docs/LibFuzzer.html), which requires [Clang](https://en.wikipedia.org/wiki/Clang) to be installed.

```bash
clang json.c fuzz.c -Wall -Wextra -Werror -Wpedantic -Wfatal-errors -Ofast -march=native -g -fsanitize=address,undefined,fuzzer && \
mkdir -p test_corpus && \
cp tests_err/* tests_ok/* test_corpus && \
mkdir -p corpus && \
./a.out -timeout=1 corpus test_corpus && \
./a.out corpus
```
