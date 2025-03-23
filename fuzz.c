#include "json.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Source: https://github.com/google/security-research-pocs/blob/d10780c3ddb8070dff6c5e5862c93c01392d1727/autofuzz/fuzz_utils.cc#L10
int ignore_stdout(void) {
	int fd = open("/dev/null", O_WRONLY);
	if (fd == -1) {
		warn("open(\"/dev/null\") failed");
		return -1;
	}

	int ret = 0;
	if (dup2(fd, STDOUT_FILENO) == -1) {
		warn("failed to redirect stdout to /dev/null\n");
		ret = -1;
	}

	if (close(fd) == -1) {
		warn("close");
		ret = -1;
	}

	return ret;
}

// Source: https://github.com/google/security-research-pocs/blob/d10780c3ddb8070dff6c5e5862c93c01392d1727/autofuzz/fuzz_utils.cc#L31
int delete_file(const char *pathname) {
	int ret = unlink(pathname);
	if (ret == -1) {
		warn("failed to delete \"%s\"", pathname);
	}

	free((void *)pathname);

	return ret;
}

// Source: https://github.com/google/security-research-pocs/blob/d10780c3ddb8070dff6c5e5862c93c01392d1727/autofuzz/fuzz_utils.cc#L42
char *buf_to_file(const uint8_t *buf, size_t size) {
	char *pathname = strdup("/dev/shm/fuzz-XXXXXX");
	if (pathname == NULL) {
		return NULL;
	}

	int fd = mkstemp(pathname);
	if (fd == -1) {
		warn("mkstemp(\"%s\")", pathname);
		free(pathname);
		return NULL;
	}

	size_t pos = 0;
	while (pos < size) {
		int nbytes = write(fd, &buf[pos], size - pos);
		if (nbytes <= 0) {
		if (nbytes == -1 && errno == EINTR) {
			continue;
		}
		warn("write");
		goto err;
		}
		pos += nbytes;
	}

	if (close(fd) == -1) {
		warn("close");
		goto err;
	}

	return pathname;

err:
	delete_file(pathname);
	return NULL;
}

// Source: https://github.com/google/security-research-pocs/blob/649b6ed74c842f533d15410f13d94aada96375ef/autofuzz/alembic_fuzzer.cc#L293
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	static bool initialized = false;
	if (!initialized) {
		ignore_stdout();
		initialized = true;
	}

	char* file = buf_to_file(data, size);
	if (file == NULL) {
		exit(EXIT_FAILURE);
	}

	static char buffer[420420];

	json_init();

	struct json_node node;

	(void)json(file, &node, buffer, sizeof(buffer));

	if (delete_file(file) != 0) {
		exit(EXIT_FAILURE);
	}

	return EXIT_SUCCESS;
}
