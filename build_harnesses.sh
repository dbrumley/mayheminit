#!/bin/sh

for dir in `ls -d harness*`; do
  cd $dir
  make
  cd ..
done