#pragma once

#include <stdbool.h>
#include <stddef.h>

struct json_array {
	struct json_node *values;
	size_t value_count;
};

struct json_object {
	struct json_field *fields;
	size_t field_count;
};

struct json_field {
	char *key;
	struct json_node *value;
};

struct json_node {
	enum {
		JSON_NODE_STRING,
		JSON_NODE_ARRAY,
		JSON_NODE_OBJECT,
	} type;
	union {
		char *string;
		struct json_array array;
		struct json_object object;
	};
};

enum json_status {
	JSON_OK,
	JSON_OUT_OF_MEMORY,
	JSON_FAILED_TO_OPEN_FILE,
	JSON_FAILED_TO_CLOSE_FILE,
	JSON_FILE_EMPTY,
	JSON_FILE_TOO_BIG,
	JSON_FILE_READING_ERROR,
	JSON_UNRECOGNIZED_CHARACTER,
	JSON_UNCLOSED_STRING,
	JSON_DUPLICATE_KEY,
	JSON_TOO_MANY_CHILD_NODES,
	JSON_MAX_RECURSION_DEPTH_EXCEEDED,
	JSON_TRAILING_COMMA,
	JSON_EXPECTED_ARRAY_CLOSE,
	JSON_EXPECTED_OBJECT_CLOSE,
	JSON_EXPECTED_COLON,
	JSON_EXPECTED_VALUE,
	JSON_UNEXPECTED_STRING,
	JSON_UNEXPECTED_ARRAY_OPEN,
	JSON_UNEXPECTED_ARRAY_CLOSE,
	JSON_UNEXPECTED_OBJECT_OPEN,
	JSON_UNEXPECTED_OBJECT_CLOSE,
	JSON_UNEXPECTED_COMMA,
	JSON_UNEXPECTED_COLON,
	JSON_UNEXPECTED_EXTRA_CHARACTER,
};

bool json_init(void *buffer, size_t buffer_capacity) __attribute__((warn_unused_result));
enum json_status json(char *json_file_path, struct json_node *returned, void *buffer, size_t buffer_capacity) __attribute__((warn_unused_result));
char *json_get_error_message(enum json_status status);
int json_get_error_line_number(void);
