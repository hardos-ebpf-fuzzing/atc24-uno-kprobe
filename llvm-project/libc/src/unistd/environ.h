//===-- Declaration of POSIX environ ----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIBC_SRC_UNISTD_ENVIRON_H
#define LLVM_LIBC_SRC_UNISTD_ENVIRON_H

namespace __llvm_libc {

extern "C" char **environ;

} // namespace __llvm_libc

#endif // LLVM_LIBC_SRC_UNISTD_ENVIRON_H