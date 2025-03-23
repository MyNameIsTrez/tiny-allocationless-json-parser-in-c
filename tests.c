#include "json.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char buffer[420420];

#define OK_PARSE(path, node) {\
	json_init();\
	enum json_status status;\
    do {\
		status = json(path, node, buffer, sizeof(buffer));\
    } while (status == JSON_OUT_OF_MEMORY);\
	if (status) {\
		fprintf(\
			stderr,\
			"json.c:%d: %s in %s\n",\
			json_get_error_line_number(),\
			json_get_error_message(status),\
			path\
		);\
		abort();\
	}\
}

#define ERROR_PARSE(path, error) {\
	json_init();\
	struct json_node node;\
    enum json_status status;\
    do {\
        status = json(path, &node, buffer, sizeof(buffer));\
    } while (status == JSON_OUT_OF_MEMORY);\
	if (status != error) {\
		fprintf(\
			stderr,\
			"json.c:%d: %s in %s\n",\
			json_get_error_line_number(),\
			json_get_error_message(status),\
			path\
		);\
		abort();\
	}\
}

static void ok_array_in_array(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/array_in_array.json", &node);
	assert(node.type == JSON_NODE_ARRAY);
	assert(node.array.value_count == 1);
	assert(node.array.values[0].type == JSON_NODE_ARRAY);
	assert(node.array.values[0].array.value_count == 0);
}

static void ok_array_within_max_recursion_depth(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/array_within_max_recursion_depth.json", &node);
	for (size_t i = 0; i < 41; i++) {
		assert(node.type == JSON_NODE_ARRAY);
		assert(node.array.value_count == 1);
		node = node.array.values[0];
	}
	assert(node.type == JSON_NODE_ARRAY);
	assert(node.array.value_count == 0);
}

static void ok_array(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/array.json", &node);
	assert(node.type == JSON_NODE_ARRAY);
	assert(node.array.value_count == 0);
}

static void ok_comma_in_string(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/comma_in_string.json", &node);
	assert(node.type == JSON_NODE_STRING);
	assert(strcmp(node.string, ",") == 0);
}

static void ok_grug(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/grug.json", &node);

	struct json_object foo_fn;
	struct json_object bar_fn;
	struct json_array fn_array;
	struct json_field *field;
	struct json_node *value;

	assert(node.type == JSON_NODE_ARRAY);
	fn_array = node.array;
	assert(fn_array.value_count == 2);

	// foo fn

	assert(fn_array.values[0].type == JSON_NODE_OBJECT);
	foo_fn = fn_array.values[0].object;
	assert(foo_fn.field_count == 4);

	field = foo_fn.fields;

	assert(strcmp(field->key, "name") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "foo") == 0);
	field++;

	assert(strcmp(field->key, "description") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "deez") == 0);
	field++;

	assert(strcmp(field->key, "return_type") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "i32") == 0);
	field++;

	assert(strcmp(field->key, "arguments") == 0);
	assert(field->value->type == JSON_NODE_ARRAY);
	value = field->value->array.values;
	assert(field->value->array.value_count == 2);

	assert(value->type == JSON_NODE_OBJECT);
	assert(value->object.field_count == 2);
	field = value->object.fields;

	assert(strcmp(field->key, "name") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "a") == 0);
	field++;

	assert(strcmp(field->key, "type") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "i64") == 0);
	field++;
	value++;

	assert(value->type == JSON_NODE_OBJECT);
	assert(value->object.field_count == 2);
	field = value->object.fields;

	assert(strcmp(field->key, "name") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "b") == 0);
	field++;

	assert(strcmp(field->key, "type") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "i64") == 0);
	field++;

	// bar fn

	assert(fn_array.values[1].type == JSON_NODE_OBJECT);
	bar_fn = fn_array.values[1].object;
	assert(bar_fn.field_count == 4);

	field = bar_fn.fields;

	assert(strcmp(field->key, "name") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "bar") == 0);
	field++;

	assert(strcmp(field->key, "description") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "nuts") == 0);
	field++;

	assert(strcmp(field->key, "return_type") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "f32") == 0);
	field++;

	assert(strcmp(field->key, "arguments") == 0);
	assert(field->value->type == JSON_NODE_ARRAY);
	value = field->value->array.values;
	assert(field->value->array.value_count == 1);

	assert(value->type == JSON_NODE_OBJECT);
	assert(value->object.field_count == 2);
	field = value->object.fields;

	assert(strcmp(field->key, "name") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "x") == 0);
	field++;

	assert(strcmp(field->key, "type") == 0);
	assert(field->value->type == JSON_NODE_STRING);
	assert(strcmp(field->value->string, "i32") == 0);
	field++;
}

static void ok_misaligned_buffer(void) {
	struct json_node node;

	static struct {
		char c;
		char buffer[291]; // Experimentally determined to be the minimum number of required bytes
	} misaligned;

	json_init();
	enum json_status status;
	char *path = "./tests_ok/misaligned_buffer.json";
    do {
		status = json(path, &node, misaligned.buffer, sizeof(misaligned.buffer));
    } while (status == JSON_OUT_OF_MEMORY);
	if (status) {
		fprintf(
			stderr,
			"json.c:%d: %s in %s\n",
			json_get_error_line_number(),
			json_get_error_message(status),
			path
		);
		abort();
	}

	assert(node.type == JSON_NODE_ARRAY);
	assert(node.array.value_count == 0);
}

static void ok_object_foo(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/object_foo.json", &node);
	assert(node.type == JSON_NODE_OBJECT);
	assert(node.object.field_count == 1);
}

static void ok_object_wide_doesnt_trigger_max_recursion_depth(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/object_wide_doesnt_trigger_max_recursion_depth.json", &node);
	assert(node.type == JSON_NODE_ARRAY);
	struct json_array array = node.array;
	assert(array.value_count == 50);

	for (size_t i = 0; i < array.value_count; i++) {
		assert(array.values[i].type == JSON_NODE_ARRAY);
		assert(array.values[i].array.value_count == 0);
	}
}

static void ok_object_within_max_recursion_depth(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/object_within_max_recursion_depth.json", &node);
	for (size_t i = 0; i < 41; i++) {
		assert(node.type == JSON_NODE_OBJECT);
		assert(node.object.field_count == 1);
		node = *node.object.fields[0].value;
	}
	assert(node.type == JSON_NODE_OBJECT);
	assert(node.object.field_count == 0);
}

static void ok_object(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/object.json", &node);
	assert(node.type == JSON_NODE_OBJECT);
	assert(node.object.field_count == 0);
}

static void ok_string_foo(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/string_foo.json", &node);
	assert(node.type == JSON_NODE_STRING);
	assert(strcmp(node.string, "foo") == 0);
}

static void ok_string(void) {
	struct json_node node;
	OK_PARSE("./tests_ok/string.json", &node);
	assert(node.type == JSON_NODE_STRING);
	assert(strcmp(node.string, "") == 0);
}

static void error_duplicate_key(void) {
	ERROR_PARSE("./tests_err/duplicate_key.json", JSON_DUPLICATE_KEY);
}

static void error_expected_array_close(void) {
	ERROR_PARSE("./tests_err/expected_array_close.json", JSON_EXPECTED_ARRAY_CLOSE);
}

static void error_expected_colon(void) {
	ERROR_PARSE("./tests_err/expected_colon.json", JSON_EXPECTED_COLON);
}

static void error_expected_object_close(void) {
	ERROR_PARSE("./tests_err/expected_object_close.json", JSON_EXPECTED_OBJECT_CLOSE);
}

static void error_expected_value(void) {
	ERROR_PARSE("./tests_err/expected_value.json", JSON_EXPECTED_VALUE);
}

static void error_failed_to_open_file(void) {
	ERROR_PARSE("", JSON_FAILED_TO_OPEN_FILE);
}

static void error_file_empty(void) {
	ERROR_PARSE("./tests_err/file_empty.json", JSON_FILE_EMPTY);
}

static void error_max_recursion_depth_array(void) {
	ERROR_PARSE("./tests_err/max_recursion_depth_array.json", JSON_MAX_RECURSION_DEPTH_EXCEEDED);
}

static void error_max_recursion_depth_object(void) {
	ERROR_PARSE("./tests_err/max_recursion_depth_object.json", JSON_MAX_RECURSION_DEPTH_EXCEEDED);
}

static void error_trailing_array_comma(void) {
	ERROR_PARSE("./tests_err/trailing_array_comma.json", JSON_TRAILING_COMMA);
}

static void error_trailing_object_comma(void) {
	ERROR_PARSE("./tests_err/trailing_object_comma.json", JSON_TRAILING_COMMA);
}

static void error_unclosed_string(void) {
	ERROR_PARSE("./tests_err/unclosed_string.json", JSON_UNCLOSED_STRING);
}

static void error_unexpected_array_close(void) {
	ERROR_PARSE("./tests_err/unexpected_array_close.json", JSON_UNEXPECTED_ARRAY_CLOSE);
}

static void error_unexpected_array_object_close(void) {
	ERROR_PARSE("./tests_err/unexpected_array_object_close.json", JSON_UNEXPECTED_OBJECT_CLOSE);
}

static void error_unexpected_array_open_1(void) {
	ERROR_PARSE("./tests_err/unexpected_array_open_1.json", JSON_UNEXPECTED_ARRAY_OPEN);
}

static void error_unexpected_array_open_2(void) {
	ERROR_PARSE("./tests_err/unexpected_array_open_2.json", JSON_UNEXPECTED_ARRAY_OPEN);
}

static void error_unexpected_array_open_3(void) {
	ERROR_PARSE("./tests_err/unexpected_array_open_3.json", JSON_UNEXPECTED_ARRAY_OPEN);
}

static void error_unexpected_colon_1(void) {
	ERROR_PARSE("./tests_err/unexpected_colon_1.json", JSON_UNEXPECTED_COLON);
}

static void error_unexpected_colon_2(void) {
	ERROR_PARSE("./tests_err/unexpected_colon_2.json", JSON_UNEXPECTED_COLON);
}

static void error_unexpected_colon_3(void) {
	ERROR_PARSE("./tests_err/unexpected_colon_3.json", JSON_UNEXPECTED_COLON);
}

static void error_unexpected_comma_array_1(void) {
	ERROR_PARSE("./tests_err/unexpected_comma_array_1.json", JSON_UNEXPECTED_COMMA);
}

static void error_unexpected_comma_array_2(void) {
	ERROR_PARSE("./tests_err/unexpected_comma_array_2.json", JSON_UNEXPECTED_COMMA);
}

static void error_unexpected_comma_object_1(void) {
	ERROR_PARSE("./tests_err/unexpected_comma_object_1.json", JSON_UNEXPECTED_COMMA);
}

static void error_unexpected_comma_object_2(void) {
	ERROR_PARSE("./tests_err/unexpected_comma_object_2.json", JSON_UNEXPECTED_COMMA);
}

static void error_unexpected_comma(void) {
	ERROR_PARSE("./tests_err/unexpected_comma.json", JSON_UNEXPECTED_COMMA);
}

static void error_unexpected_extra_character_array(void) {
	ERROR_PARSE("./tests_err/unexpected_extra_character_array.json", JSON_UNEXPECTED_EXTRA_CHARACTER);
}

static void error_unexpected_extra_character_object(void) {
	ERROR_PARSE("./tests_err/unexpected_extra_character_object.json", JSON_UNEXPECTED_EXTRA_CHARACTER);
}

static void error_unexpected_extra_character_string(void) {
	ERROR_PARSE("./tests_err/unexpected_extra_character_string.json", JSON_UNEXPECTED_EXTRA_CHARACTER);
}

static void error_unexpected_object_array_close(void) {
	ERROR_PARSE("./tests_err/unexpected_object_array_close.json", JSON_UNEXPECTED_ARRAY_CLOSE);
}

static void error_unexpected_object_close(void) {
	ERROR_PARSE("./tests_err/unexpected_object_close.json", JSON_UNEXPECTED_OBJECT_CLOSE);
}

static void error_unexpected_object_open_1(void) {
	ERROR_PARSE("./tests_err/unexpected_object_open_1.json", JSON_UNEXPECTED_OBJECT_OPEN);
}

static void error_unexpected_object_open_2(void) {
	ERROR_PARSE("./tests_err/unexpected_object_open_2.json", JSON_UNEXPECTED_OBJECT_OPEN);
}

static void error_unexpected_object_open_3(void) {
	ERROR_PARSE("./tests_err/unexpected_object_open_3.json", JSON_UNEXPECTED_OBJECT_OPEN);
}

static void error_unexpected_string_1(void) {
	ERROR_PARSE("./tests_err/unexpected_string_1.json", JSON_UNEXPECTED_STRING);
}

static void error_unexpected_string_2(void) {
	ERROR_PARSE("./tests_err/unexpected_string_2.json", JSON_UNEXPECTED_STRING);
}

static void error_unexpected_string_3(void) {
	ERROR_PARSE("./tests_err/unexpected_string_3.json", JSON_UNEXPECTED_STRING);
}

static void error_unrecognized_character(void) {
	ERROR_PARSE("./tests_err/unrecognized_character.json", JSON_UNRECOGNIZED_CHARACTER);
}

static void ok_tests(void) {
	ok_array_in_array();
	ok_array_within_max_recursion_depth();
	ok_array();
	ok_comma_in_string();
	ok_grug();
	ok_misaligned_buffer();
	ok_object_foo();
	ok_object_wide_doesnt_trigger_max_recursion_depth();
	ok_object_within_max_recursion_depth();
	ok_object();
	ok_string_foo();
	ok_string();
}

static void error_tests(void) {
	error_failed_to_open_file();

	error_duplicate_key();
	error_expected_array_close();
	error_expected_colon();
	error_expected_object_close();
	error_expected_value();
	error_file_empty();
	error_max_recursion_depth_array();
	error_max_recursion_depth_object();
	error_trailing_array_comma();
	error_trailing_object_comma();
	error_unclosed_string();
	error_unexpected_array_close();
	error_unexpected_array_object_close();
	error_unexpected_array_open_1();
	error_unexpected_array_open_2();
	error_unexpected_array_open_3();
	error_unexpected_colon_1();
	error_unexpected_colon_2();
	error_unexpected_colon_3();
	error_unexpected_comma_array_1();
	error_unexpected_comma_array_2();
	error_unexpected_comma_object_1();
	error_unexpected_comma_object_2();
	error_unexpected_comma();
	error_unexpected_extra_character_array();
	error_unexpected_extra_character_object();
	error_unexpected_extra_character_string();
	error_unexpected_object_array_close();
	error_unexpected_object_close();
	error_unexpected_object_open_1();
	error_unexpected_object_open_2();
	error_unexpected_object_open_3();
	error_unexpected_string_1();
	error_unexpected_string_2();
	error_unexpected_string_3();
	error_unrecognized_character();
}

int main(void) {
	error_tests();
	ok_tests();
	printf("All tests passed!\n");
}
