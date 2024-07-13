/*
   Copyright (c) 2024 ForAllSecure

  License: MIT

## Summary.
  A C and C++ compatible data provider for structure-aware testing.
  Use this if you want a structure-aware test harness that provides
  error detection.

  Inspired by LLVM's FuzzDataProvider (see https://tinyurl.com/mtz6xb4d)

## Use case
  Suppose your harness wants a structure like:
  ```
  typedef struct {
    int int_value;
    float float_value;
    char string_value[256];
  } MyStruct;
  ```

  You need a way to parse the bytes from Mayhem into this structure. A
  quick-and-dirty solution is just to use memcpy, e.g.,:
  ```
  int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(MyStruct)) {
        return 0; // Not enough data to fill the structure
    }

    MyStruct myStruct;
    memcpy(&myStruct, Data, sizeof(MyStruct));

    // Now use myStruct safely
    return 0;
  }
  ```

  This is fine, but can be improved to add incremental error checking. This is
  especially useful if don't have just one structure. That's the purpose
  of this library. You would write the above code using this library as:

  ```
    FuzzDataProvider provider;
    FuzzDataProviderInit(&provider, Data, Size);

    MyStruct myStruct;

    if (FuzzDataProviderGetInt(&provider, &myStruct.int_value, sizeof(int)) != 0) {
        return 0; // Not enough data
    }

    if (FuzzDataProviderGetInt(&provider, &myStruct.float_value, sizeof(float)) != 0) {
        return 0; // Not enough data
    }

    if (FuzzDataProviderGetString(&provider, myStruct.string_value, sizeof(myStruct.string_value)) != 0) {
        return 0; // Not enough data
    }

    // Now use myStruct safely
    return 0;

  ```

*/

#ifndef FUZZDATAPROVIDER_H
#define FUZZDATAPROVIDER_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Struct to keep track of the data buffer and its size
typedef struct {
  const uint8_t* data;
  size_t size;
  size_t offset;
} FuzzDataProvider;

// Initialize the FuzzDataProvider
static void FuzzDataProviderInit(FuzzDataProvider* provider, const uint8_t* data, size_t size) {
  provider->data = data;
  provider->size = size;
  provider->offset = 0;
}

// Extract a specified number of bytes from the data buffer
static int FuzzDataProviderGetBytes(FuzzDataProvider* provider, void* output, size_t size) {
  if (provider->offset + size > provider->size) {
    return -1; // Not enough data left
  }
  memcpy(output, provider->data + provider->offset, size);
  provider->offset += size;
  return 0;
}

// Extract a string (up to a specified length) from the data buffer
static int FuzzDataProviderGetString(FuzzDataProvider* provider, char* output, size_t max_len) {
  if (provider->offset >= provider->size) {
    return -1; // Not enough data left
  }
  size_t str_len = strnlen((char*)(provider->data + provider->offset), provider->size - provider->offset);
  if (str_len >= max_len) {
    return -1; // String is too long
  }
  memcpy(output, provider->data + provider->offset, str_len);
  output[str_len] = '\0'; // Null-terminate the string
  provider->offset += str_len + 1; // Move past the string and null terminator
  return 0;
}

// Extract a float from the data buffer
static int FuzzDataProviderGetFloat(FuzzDataProvider* provider, float* output) {
  return FuzzDataProviderGetBytes(provider, output, sizeof(float));
}

// Extract a double from the data buffer
static int FuzzDataProviderGetDouble(FuzzDataProvider* provider, double* output) {
  return FuzzDataProviderGetBytes(provider, output, sizeof(double));
}

#endif // FUZZDATAPROVIDER_H
