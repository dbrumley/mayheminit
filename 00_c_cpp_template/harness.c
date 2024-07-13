#include "FuzzDataProvider.h"

#ifdef __cplusplus
extern "C" {
#endif

  // LLVMFuzzerInitialize is called exactly once.
  int LLVMFuzzerInitialize(int* argc, char*** argv) {
    // Initialization code if any
    return 0;
  }

  int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /* Example usage. Replace with your own code */

    if (size < 3)
      return 0;

    if (size > 0 && data[0] == 'b')
      if (size > 1 && data[1] == 'a')
        if (size > 2 && data[2] == 'd')
          __builtin_trap();
    return 0;

  }

#ifdef __cplusplus
}
#endif
