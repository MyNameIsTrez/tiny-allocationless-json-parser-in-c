#include "json.h"

#include <assert.h>
#include <ctype.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define MAX_CHILD_NODES 420
#define MAX_RECURSION_DEPTH 42

#define json_error(error) {\
	error_line_number = __LINE__;\
	longjmp(error_jmp_buffer, error);\
}

#define json_assert(condition, error) {\
	if (!(condition)) {\
		json_error(error);\
	}\
}

static jmp_buf error_jmp_buffer;

static int error_line_number;

enum token_type {
	TOKEN_TYPE_STRING,
	TOKEN_TYPE_ARRAY_OPEN,
	TOKEN_TYPE_ARRAY_CLOSE,
	TOKEN_TYPE_OBJECT_OPEN,
	TOKEN_TYPE_OBJECT_CLOSE,
	TOKEN_TYPE_COMMA,
	TOKEN_TYPE_COLON,
};

struct token {
	enum token_type type;
	char *str;
};

static struct {
	char *text;
	size_t text_capacity;
	size_t text_size;

	struct token *tokens;
	size_t tokens_capacity;
	size_t tokens_size;

	struct json_node *nodes;
	size_t nodes_capacity;
	size_t nodes_size;

	char *strings;
	size_t strings_capacity;
	size_t strings_size;

	struct json_field *fields;
	size_t fields_capacity;
	size_t fields_size;
	uint32_t *fields_buckets;
	uint32_t *fields_chains;
} *g;

static void *buffer;
static size_t buffer_capacity;
static size_t buffer_size;

static size_t recursion_depth;

static struct json_node parse_string(size_t *i);
static struct json_node parse_array(size_t *i);

static void check_if_out_of_memory() {
	if (buffer_size > buffer_capacity) {
		json_error(JSON_OUT_OF_MEMORY);
	}
}

// Used to align to 16 bytes
static size_t get_padding(size_t n) {
	return (16 - (n % 16)) % 16;
}

static void *get_next_aligned_area() {
	// buffer_size+=get_padding(0x1+0x12)
	// buffer_size+=get_padding(0x13)
	// buffer_size+=0xd
	// buffer_size=0x1f
	buffer_size += get_padding((size_t)buffer + buffer_size);

	return (char *)buffer + buffer_size; // 0x1+0x1f is 0x20
}

void grow(void *data_, size_t *capacity, size_t size, size_t element_size) {
	void **data = data_;

	if (size + 1 <= *capacity) {
		return;
	}

	if (*capacity == 0) {
		*capacity = 1;
	}

	// Grow by 2x
	*capacity *= 2;

	void *new_data = get_next_aligned_area();
	buffer_size += (*capacity) * element_size;
	check_if_out_of_memory();

	if (*data) {
		memcpy(new_data, *data, size * element_size);
	}

	*data = new_data;
}

size_t ceil_div(size_t x, size_t y) {
	return (x + y - 1) / y;
}

void grow_n(void *data_, size_t *capacity, size_t size, size_t element_size, size_t n) {
	void **data = data_;

	if (size + n <= *capacity) {
		return;
	}

	if (*capacity == 0) {
		*capacity = 1;
	}

	// size=0, n=1, capacity=1 => growth_factor is 1
	// size=1, n=1, capacity=1 => growth_factor is 2
	// size=1, n=2, capacity=2 => growth_factor is 2
	//   This is the case that requires ceil_div(), rather than regular division
	size_t growth_factor = ceil_div(size + n, *capacity);

	*capacity *= growth_factor;

	void *new_data = get_next_aligned_area();
	buffer_size += (*capacity) * element_size;
	check_if_out_of_memory();

	if (*data) {
		memcpy(new_data, *data, size * element_size);
	}

	*data = new_data;
}

void grow_table(void *data_, size_t *capacity, size_t size, size_t element_size, uint32_t **buckets, uint32_t **chains) {
	void **data = data_;

	if (size + 1 <= *capacity) {
		return;
	}

	if (*capacity == 0) {
		*capacity = 1;
	}

	// Grow by 2x
	*capacity *= 2;

	void *new_data = get_next_aligned_area();
	buffer_size += (*capacity) * element_size;

	void *new_buckets = get_next_aligned_area();
	buffer_size += (*capacity) * sizeof(uint32_t);

	void *new_chains = get_next_aligned_area();
	buffer_size += (*capacity) * sizeof(uint32_t);

	check_if_out_of_memory();

	if (*data) {
		memcpy(new_data, *data, size * element_size);

		assert(*buckets);
		memcpy(new_buckets, *buckets, size * sizeof(uint32_t));

		assert(*chains);
		memcpy(new_chains, *chains, size * sizeof(uint32_t));
	}

	*data = new_data;
	*buckets = new_buckets;
	*chains = new_chains;
}

static void push_node(struct json_node node) {
	grow(&g->nodes, &g->nodes_capacity, g->nodes_size, sizeof(struct json_node));
	g->nodes[g->nodes_size++] = node;
}

static void push_field(struct json_field field) {
	grow_table(&g->fields, &g->fields_capacity, g->fields_size, sizeof(struct json_field), &g->fields_buckets, &g->fields_chains);
	g->fields[g->fields_size++] = field;
}

static char *push_string(char *slice_start, size_t length) {
	grow_n(&g->strings, &g->strings_capacity, g->strings_size, sizeof(char), length + 1);

	char *new_str = g->strings + g->strings_size;

	for (size_t i = 0; i < length; i++) {
		g->strings[g->strings_size++] = slice_start[i];
	}
	g->strings[g->strings_size++] = '\0';

	return new_str;
}

// From https://sourceware.org/git/?p=binutils-gdb.git;a=blob;f=bfd/elf.c#l193
static uint32_t elf_hash(const char *namearg) {
	uint32_t h = 0;

	for (const unsigned char *name = (const unsigned char *) namearg; *name; name++) {
		h = (h << 4) + *name;
		h ^= (h >> 24) & 0xf0;
	}

	return h & 0x0fffffff;
}

static bool is_duplicate_key(struct json_field *child_fields, size_t field_count, char *key) {
	uint32_t i = g->fields_buckets[elf_hash(key) % field_count];

	while (1) {
		if (i == UINT32_MAX) {
			return false;
		}

		if (strcmp(key, child_fields[i].key) == 0) {
			break;
		}

		i = g->fields_chains[i];
	}

	return true;
}

static void check_duplicate_keys(struct json_field *child_fields, size_t field_count) {
	memset(g->fields_buckets, 0xff, field_count * sizeof(*g->fields_buckets));

	size_t chains_size = 0;

	for (size_t i = 0; i < field_count; i++) {
		char *key = child_fields[i].key;

		json_assert(!is_duplicate_key(child_fields, field_count, key), JSON_DUPLICATE_KEY);

		uint32_t bucket_index = elf_hash(key) % field_count;

		g->fields_chains[chains_size++] = g->fields_buckets[bucket_index];

		g->fields_buckets[bucket_index] = i;
	}
}

static struct json_node parse_object(size_t *i) {
	struct json_node node;

	node.type = JSON_NODE_OBJECT;
	(*i)++;

	recursion_depth++;
	json_assert(recursion_depth <= MAX_RECURSION_DEPTH, JSON_MAX_RECURSION_DEPTH_EXCEEDED);

	node.object.field_count = 0;

	struct json_field child_fields[MAX_CHILD_NODES];

	bool seen_key = false;
	bool seen_colon = false;
	bool seen_value = false;
	bool seen_comma = false;

	struct json_field field;

	struct json_node string;
	struct json_node array;
	struct json_node object;

	while (*i < g->tokens_size) {
		struct token *token = g->tokens + *i;

		switch (token->type) {
		case TOKEN_TYPE_STRING:
			if (!seen_key) {
				seen_key = true;
				field.key = token->str;
				(*i)++;
			} else if (seen_colon && !seen_value) {
				seen_value = true;
				seen_comma = false;
				string = parse_string(i);
				field.value = g->nodes + g->nodes_size;
				push_node(string);
				json_assert(node.object.field_count < MAX_CHILD_NODES, JSON_TOO_MANY_CHILD_NODES);
				child_fields[node.object.field_count++] = field;
			} else {
				json_error(JSON_UNEXPECTED_STRING);
			}
			break;
		case TOKEN_TYPE_ARRAY_OPEN:
			if (seen_colon && !seen_value) {
				seen_value = true;
				seen_comma = false;
				array = parse_array(i);
				field.value = g->nodes + g->nodes_size;
				push_node(array);
				json_assert(node.object.field_count < MAX_CHILD_NODES, JSON_TOO_MANY_CHILD_NODES);
				child_fields[node.object.field_count++] = field;
			} else {
				json_error(JSON_UNEXPECTED_ARRAY_OPEN);
			}
			break;
		case TOKEN_TYPE_ARRAY_CLOSE:
			json_error(JSON_UNEXPECTED_ARRAY_CLOSE);
		case TOKEN_TYPE_OBJECT_OPEN:
			if (seen_colon && !seen_value) {
				seen_value = true;
				seen_comma = false;
				object = parse_object(i);
				field.value = g->nodes + g->nodes_size;
				push_node(object);
				json_assert(node.object.field_count < MAX_CHILD_NODES, JSON_TOO_MANY_CHILD_NODES);
				child_fields[node.object.field_count++] = field;
			} else {
				json_error(JSON_UNEXPECTED_OBJECT_OPEN);
			}
			break;
		case TOKEN_TYPE_OBJECT_CLOSE:
			if (seen_key && !seen_colon) {
				json_error(JSON_EXPECTED_COLON);
			} else if (seen_colon && !seen_value) {
				json_error(JSON_EXPECTED_VALUE);
			} else if (seen_comma) {
				json_error(JSON_TRAILING_COMMA);
			}
			node.object.fields = g->fields + g->fields_size;
			for (size_t field_index = 0; field_index < node.object.field_count; field_index++) {
				push_field(child_fields[field_index]);
			}
			check_duplicate_keys(child_fields, node.object.field_count);
			(*i)++;
			recursion_depth--;
			return node;
		case TOKEN_TYPE_COMMA:
			json_assert(seen_value, JSON_UNEXPECTED_COMMA);
			seen_key = false;
			seen_colon = false;
			seen_value = false;
			seen_comma = true;
			(*i)++;
			break;
		case TOKEN_TYPE_COLON:
			json_assert(seen_key, JSON_UNEXPECTED_COLON);
			seen_colon = true;
			(*i)++;
			break;
		}
	}

	json_error(JSON_EXPECTED_OBJECT_CLOSE);
}

static struct json_node parse_array(size_t *i) {
	struct json_node node;

	node.type = JSON_NODE_ARRAY;
	(*i)++;

	recursion_depth++;
	json_assert(recursion_depth <= MAX_RECURSION_DEPTH, JSON_MAX_RECURSION_DEPTH_EXCEEDED);

	node.array.value_count = 0;

	struct json_node child_nodes[MAX_CHILD_NODES];

	bool seen_value = false;
	bool seen_comma = false;

	while (*i < g->tokens_size) {
		struct token *token = g->tokens + *i;

		switch (token->type) {
		case TOKEN_TYPE_STRING:
			json_assert(!seen_value, JSON_UNEXPECTED_STRING);
			seen_value = true;
			seen_comma = false;
			json_assert(node.array.value_count < MAX_CHILD_NODES, JSON_TOO_MANY_CHILD_NODES);
			child_nodes[node.array.value_count++] = parse_string(i);
			break;
		case TOKEN_TYPE_ARRAY_OPEN:
			json_assert(!seen_value, JSON_UNEXPECTED_ARRAY_OPEN);
			seen_value = true;
			seen_comma = false;
			json_assert(node.array.value_count < MAX_CHILD_NODES, JSON_TOO_MANY_CHILD_NODES);
			child_nodes[node.array.value_count++] = parse_array(i);
			break;
		case TOKEN_TYPE_ARRAY_CLOSE:
			json_assert(!seen_comma, JSON_TRAILING_COMMA);
			node.array.values = g->nodes + g->nodes_size;
			for (size_t value_index = 0; value_index < node.array.value_count; value_index++) {
				push_node(child_nodes[value_index]);
			}
			(*i)++;
			recursion_depth--;
			return node;
		case TOKEN_TYPE_OBJECT_OPEN:
			json_assert(!seen_value, JSON_UNEXPECTED_OBJECT_OPEN);
			seen_value = true;
			seen_comma = false;
			json_assert(node.array.value_count < MAX_CHILD_NODES, JSON_TOO_MANY_CHILD_NODES);
			child_nodes[node.array.value_count++] = parse_object(i);
			break;
		case TOKEN_TYPE_OBJECT_CLOSE:
			json_error(JSON_UNEXPECTED_OBJECT_CLOSE);
		case TOKEN_TYPE_COMMA:
			json_assert(seen_value, JSON_UNEXPECTED_COMMA);
			seen_value = false;
			seen_comma = true;
			(*i)++;
			break;
		case TOKEN_TYPE_COLON:
			json_error(JSON_UNEXPECTED_COLON);
		}
	}

	json_error(JSON_EXPECTED_ARRAY_CLOSE);
}

static struct json_node parse_string(size_t *i) {
	struct json_node node;

	node.type = JSON_NODE_STRING;

	struct token *token = g->tokens + *i;
	node.string = token->str;

	(*i)++;

	return node;
}

static struct json_node parse(size_t *i) {
	struct token *t = g->tokens + *i;
	struct json_node node;

	switch (t->type) {
	case TOKEN_TYPE_STRING:
		node = parse_string(i);
		break;
	case TOKEN_TYPE_ARRAY_OPEN:
		node = parse_array(i);
		break;
	case TOKEN_TYPE_ARRAY_CLOSE:
		json_error(JSON_UNEXPECTED_ARRAY_CLOSE);
	case TOKEN_TYPE_OBJECT_OPEN:
		node = parse_object(i);
		break;
	case TOKEN_TYPE_OBJECT_CLOSE:
		json_error(JSON_UNEXPECTED_OBJECT_CLOSE);
	case TOKEN_TYPE_COMMA:
		json_error(JSON_UNEXPECTED_COMMA);
	case TOKEN_TYPE_COLON:
		json_error(JSON_UNEXPECTED_COLON);
	}

	json_assert(*i >= g->tokens_size, JSON_UNEXPECTED_EXTRA_CHARACTER);

	return node;
}

static void push_token(enum token_type type, size_t offset, size_t length) {
	grow(&g->tokens, &g->tokens_capacity, g->tokens_size, sizeof(struct token));

	g->tokens[g->tokens_size++] = (struct token){
		.type = type,
		.str = push_string(g->text + offset, length),
	};
}

static void tokenize(void) {
	size_t i = 0;

	while (i < g->text_size) {
		if (g->text[i] == '"') {
			size_t string_start_index = i;

			while (++i < g->text_size && g->text[i] != '"') {}

			json_assert(g->text[i] == '"', JSON_UNCLOSED_STRING);

			push_token(
				TOKEN_TYPE_STRING,
				string_start_index + 1,
				i - string_start_index - 1
			);
		} else if (g->text[i] == '[') {
			push_token(TOKEN_TYPE_ARRAY_OPEN, i, 1);
		} else if (g->text[i] == ']') {
			push_token(TOKEN_TYPE_ARRAY_CLOSE, i, 1);
		} else if (g->text[i] == '{') {
			push_token(TOKEN_TYPE_OBJECT_OPEN, i, 1);
		} else if (g->text[i] == '}') {
			push_token(TOKEN_TYPE_OBJECT_CLOSE, i, 1);
		} else if (g->text[i] == ',') {
			push_token(TOKEN_TYPE_COMMA, i, 1);
		} else if (g->text[i] == ':') {
			push_token(TOKEN_TYPE_COLON, i, 1);
		} else if (!isspace(g->text[i])) {
			json_error(JSON_UNRECOGNIZED_CHARACTER);
		}
		i++;
	}
}

static void read_text(char *json_file_path) {
	FILE *f = fopen(json_file_path, "r");
	json_assert(f, JSON_FAILED_TO_OPEN_FILE);

	grow(&g->text, &g->text_capacity, g->text_size, sizeof(char));

	while (true) {
		g->text_size = fread(
			g->text,
			sizeof(char),
			g->text_capacity,
			f
		);

		int is_eof = feof(f);
		int err = ferror(f);

		json_assert(g->text_size != 0, JSON_FILE_EMPTY);
		json_assert(err == 0, JSON_FILE_READING_ERROR);
		
		if (is_eof) {
			break;
		}

		// Double the array's capacity, and retry reading the file
		assert(g->text_size == g->text_capacity);
		grow_n(&g->text, &g->text_capacity, g->text_size, sizeof(char), g->text_capacity);
		fseek(f, 0, SEEK_SET);
	}

	json_assert(fclose(f) == 0, JSON_FAILED_TO_CLOSE_FILE);

}

static void allocate_arrays() {
	// Reserve space for the g struct itself in the buffer
	// Assuming buffer=0x1, sizeof(*g)=0x3, and buffer_capacity=0x20
	size_t padding = get_padding((size_t)buffer); // padding=0xf

	buffer_size = padding + sizeof(*g); // buffer_size=0xf+0x3 is buffer_size=0x12

	check_if_out_of_memory(buffer_size, buffer_capacity); // 0x12 <= 0x20, so not OOM

	g = (void *)(padding + (char *)buffer); // g=0x10

	g->text_size = 0;
	g->tokens_size = 0;
	g->nodes_size = 0;
	g->strings_size = 0;
	g->fields_size = 0;
}

enum json_status json(char *json_file_path, struct json_node *returned, void *buffer_, size_t buffer_capacity_) {
	enum json_status status = setjmp(error_jmp_buffer);
	if (status) {
		return status;
	}

	buffer = buffer_;
	buffer_capacity = buffer_capacity_;

	allocate_arrays();

	read_text(json_file_path);

	tokenize();

	recursion_depth = 0;

	size_t token_index = 0;
	*returned = parse(&token_index);

	return JSON_OK;
}

// The sole reason this function exists, is so that the user
// does not have to zero-initialize the *entire* buffer:
// Zero-initializing say a 1 GB buffer is slow and wastes COW RAM,
// so this function only initializes the g->x_capacity fields.
bool json_init(void *buffer_, size_t buffer_capacity_) {
	size_t padding = get_padding((size_t)buffer_);

	if (buffer_capacity_ < padding + sizeof(*g)) {
		return true;
	}

	g = (void *)(padding + (char *)buffer_);

	g->text_capacity = 0;
	g->tokens_capacity = 0;
	g->nodes_capacity = 0;
	g->strings_capacity = 0;
	g->fields_capacity = 0;

	return false;
}

char *json_get_error_message(enum json_status status) {
	static char *messages[] = {
		[JSON_OK] = "No error",
		[JSON_OUT_OF_MEMORY] = "Out of memory",
		[JSON_FAILED_TO_OPEN_FILE] = "Failed to open file",
		[JSON_FAILED_TO_CLOSE_FILE] = "Failed to close file",
		[JSON_FILE_EMPTY] = "File is empty",
		[JSON_FILE_TOO_BIG] = "File is too big",
		[JSON_FILE_READING_ERROR] = "File reading error",
		[JSON_UNRECOGNIZED_CHARACTER] = "Unrecognized character",
		[JSON_UNCLOSED_STRING] = "Unclosed string",
		[JSON_DUPLICATE_KEY] = "Duplicate key",
		[JSON_TOO_MANY_CHILD_NODES] = "Too many child nodes",
		[JSON_MAX_RECURSION_DEPTH_EXCEEDED] = "Max recursion depth exceeded",
		[JSON_TRAILING_COMMA] = "Trailing comma",
		[JSON_EXPECTED_ARRAY_CLOSE] = "Expected ']'",
		[JSON_EXPECTED_OBJECT_CLOSE] = "Expected '}'",
		[JSON_EXPECTED_COLON] = "Expected colon",
		[JSON_EXPECTED_VALUE] = "Expected value",
		[JSON_UNEXPECTED_STRING] = "Unexpected string",
		[JSON_UNEXPECTED_ARRAY_OPEN] = "Unexpected '['",
		[JSON_UNEXPECTED_ARRAY_CLOSE] = "Unexpected ']'",
		[JSON_UNEXPECTED_OBJECT_OPEN] = "Unexpected '{'",
		[JSON_UNEXPECTED_OBJECT_CLOSE] = "Unexpected '}'",
		[JSON_UNEXPECTED_COMMA] = "Unexpected ','",
		[JSON_UNEXPECTED_COLON] = "Unexpected ':'",
		[JSON_UNEXPECTED_EXTRA_CHARACTER] = "Unexpected extra character",
	};
	return messages[status];
}

int json_get_error_line_number(void) {
	return error_line_number;
}
