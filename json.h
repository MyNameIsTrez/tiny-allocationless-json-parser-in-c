#pragma once

#include <stdbool.h>
#include <stddef.h>

struct json_string {
	char *str;
};

struct json_array {
	size_t nodes_offset;
	size_t node_count;
};

struct json_object {
	size_t fields_offset;
	size_t field_count;
};

struct json_field {
	char *key;
	size_t node_index;
};

struct json_node {
	enum {
		JSON_NODE_STRING,
		JSON_NODE_ARRAY,
		JSON_NODE_OBJECT,
	} type;
	union {
		struct json_string string;
		struct json_array array;
		struct json_object object;
	} data;
};

enum json_error {
	JSON_NO_ERROR,
	JSON_ERROR_FAILED_TO_OPEN_JSON_FILE,
	JSON_ERROR_FAILED_TO_CLOSE_JSON_FILE,
	JSON_ERROR_JSON_FILE_IS_EMPTY,
	JSON_ERROR_JSON_FILE_TOO_BIG,
	JSON_ERROR_JSON_FILE_READING_ERROR,
	JSON_ERROR_TOO_MANY_TOKENS,
	JSON_ERROR_UNRECOGNIZED_CHARACTER,
	JSON_ERROR_TOO_MANY_JSON_NODES,
	JSON_ERROR_TOO_MANY_STRINGS_CHARACTERS,
	JSON_ERROR_UNMATCHED_ARRAY_CLOSE,
	JSON_ERROR_UNMATCHED_OBJECT_CLOSE,
};

// Use to figure out what type of error occurred
extern enum json_error json_error;

// Returns whether there was an error
bool json_parse(char *json_file_path, struct json_node *returned);
