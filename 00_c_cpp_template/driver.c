/*
 * Testing harness driver. Suitable for use with Mayhem, AFL, and libfuzzer.
 * Compiles with C and C++.
 *
 * Write your harness in a separate file. Your harness entry routine should be
 * called `LLVMFuzzerTestOneInput` by default.
 * Compile it and link against this file.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fenv.h>

int debug = 0;

#ifdef __cplusplus // Make compatible with C++
extern "C" {
#endif

  int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size);
  __attribute__((weak)) int LLVMFuzzerInitialize(int* argc, char*** argv);

#ifdef __cplusplus // Make compatible with C++
}
#endif

#define MAXSIZE (1 << 20)
static const size_t kMaxInputSize = MAXSIZE;
static uint8_t InputBuf[MAXSIZE];

// Execute a single file
static int execute_file(const char* appname, const char* filename) {
  FILE* file;
  uint8_t* data;
  size_t size;

  file = fopen(filename, "rb");
  if (file == NULL) {
    perror("Error opening file");
    return -1;
  }

  fseek(file, 0, SEEK_END);
  size = ftell(file);
  rewind(file);

  data = (uint8_t*)malloc(size);
  if (data == NULL) {
    perror("Error allocating memory");
    fclose(file);
    return -1;
  }

  if (fread(data, 1, size, file) != size) {
    perror("Error reading file");
    free(data);
    fclose(file);
    return -1;
  }

  fclose(file);
  LLVMFuzzerTestOneInput(data, size);
  free(data);

  if (debug)
    printf("%s: successfully executed on %zu bytes from %s\n", appname, size, filename);

  return 0;
}

void floating_init() {
  // Clear all floating point exceptions
  feclearexcept(FE_ALL_EXCEPT);

  // Enable floating point exceptions for Linux
#ifdef __linux__
  feenableexcept(FE_DIVBYZERO | FE_INVALID | FE_OVERFLOW);
#endif
}

int main(int argc, char** argv) {
  char* appname = argv[0];

  // Enable debug mode if "-d" argument is provided
  if (argc > 1 && (strcmp(argv[1], "-d") == 0)) {
    debug = 1;
    argc--;
    argv++;
  }

  // Comment out if you don't want to check floating point code OR you are
  // using a separate sanitizer that covers this case. 
  floating_init();


  // Initialize fuzzer if the function is defined
  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);

  // Testing input comes from files
  if (argc > 1) {
    for (int i = 1; i < argc; i++) {
      if (execute_file(appname, argv[i]) < 0) {
        return -1;
      }
    }
    return 0;
  }

  // Testing input comes from stdin
  ssize_t n_read = read(0, InputBuf, kMaxInputSize);
  if (n_read > 0) {
    // Copy InputBuf into a separate buffer to let asan find buffer overflows.
    uint8_t* copy = (uint8_t*)malloc(n_read);
    if (copy == NULL) {
      perror("Error allocating memory for input buffer");
      return -1;
    }
    memcpy(copy, InputBuf, n_read);
    LLVMFuzzerTestOneInput(copy, n_read);
    free(copy);

    if (debug)
      printf("%s: successfully executed on %zu bytes from stdin\n", argv[0], n_read);
  }
  else {
    if (debug)
      printf("%s: no input read from stdin\n", argv[0]);
  }

  return 0;
}
