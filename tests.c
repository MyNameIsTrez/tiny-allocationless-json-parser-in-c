#include "json.h"

#include <assert.h>
#include <string.h>

static void ok_string() {
	struct json_node node;
	assert(!json_parse("./tests_ok/string.json", &node));
	assert(node.type == JSON_NODE_STRING);
	assert(strcmp(node.data.string.str, "\"\"") == 0);
}

static void ok_array() {
	struct json_node node;
	assert(!json_parse("./tests_ok/array.json", &node));
	assert(node.type == JSON_NODE_ARRAY);
	assert(node.data.array.node_count == 0);
}

static void ok_object() {
	struct json_node node;
	assert(!json_parse("./tests_ok/object.json", &node));
	assert(node.type == JSON_NODE_OBJECT);
	assert(node.data.object.field_count == 0);
}

static void error_json_file_is_empty() {
	assert(json_parse("./tests_err/empty.json", NULL) && json_error == JSON_ERROR_JSON_FILE_IS_EMPTY);
}

static void error_failed_to_open_json_file() {
	assert(json_parse("", NULL) && json_error == JSON_ERROR_FAILED_TO_OPEN_JSON_FILE);
}

static void ok_tests() {
	ok_string();
	ok_array();
	ok_object();
}

static void error_tests() {
	error_failed_to_open_json_file();
	error_json_file_is_empty();
}

int main() {
	error_tests();
	ok_tests();
}
