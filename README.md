# Mayhem Testing

This directory includes the harnesses for Mayhem analysis. Mayhem performs
security and property-based testing, which makes sure your code works even
under stress conditions. 

A TLDR of the value is:
  * Normal unit test: `assert(add(2,2) == 4)`
  * Mayhem test: `assert(add(a,b) == add(b,a))` (oh, and that there isn't any
    undefined behavior or safety problems)

Under-the-hood, Mayhem:
  * Supports a full CICD workflow, such as regression testing, triage,
    diagnoses, and managing test suites.
  * Runs patented symbolic execution to provide more comprehensive testing.
  * Supports binary-only analysis, as well as OSS fuzzers like AFL, libfuzzer,
    and hongfuzz.



## Quick Start

We've set this up to give you a good starting point. You can rearrange files as
suites your files, though see the next section for some battle-tested
recommendations.

```bash
cp -r 00_c_cpp_template harness1 # Copy the template to your own harness
cd harness1 # switch to your harness; edit as you like

################################################ 
## Now, edit harness.c to call your own code. ##
################################################

make # build you harness. Works great with Mayhem.

# Build with instrumentation. Even faster analysis! Requires afl-clang
# (Mayhem supports raw binaries, as well as afl, hongfuzz, and libfuzzer harnesses)
# make clean && CC=afl-clang make 

# Run harness using stdin. Provided sample code will crash (intended). 
echo "bad" | ./harness

# Add a new file to your testsuite
echo "ok" > testsuite/ok;

# Driver accepts multiple file arguments ./harness file1 [file2] [file3] ...
# Example: run harness on all inputs in ./testsuite
./harness ./testsuite/*

# Run locally with AFL to make sure it all works
mkdir OUT && afl-fuzz -i testsuite -o OUT ./harness

# Switch up to the master directory and build a docker image
# TODO: any args for pushing to Mayhem docker registry pls add.
make clean && cd .. && docker build -t harness .

# Build and push the docker image to the Mayhem server (TODO: Push to right registry)
docker push 

# Run Mayhem
mayhem run -f harness1/Mayhemfile

# Pull the test suite
cd harness1 && mayhem sync . 

# Run the test suite inside the docker image
# TODO: How to run the docker image and then execute a test from
# the sync'ed results. 
docker run -ti -v `pwd`:/mayhem harnesses /bin/bash

```

## Recommendations
 * Each harness has its own directory because the output test suite for each
   harness may be unique.
 * Each harness directory have associated files for building your harness, a
   `testsuite` directory, and the associated `Mayhemfile`
 * One docker image for all harnesses by default. Once your final image is
   greater than 10GB, then start considering multiple images.
  * This template, by default, assumes your harness entrypoint function is
    `LLVMFuzzerTestOneInput`. This was chosen for maximal compatability with
    Mayhem and raw AFL and libfuzzer. 


## Further reading

TODO
