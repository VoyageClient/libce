# libce - Fast & Secure libolm fork
lib**c**reek-**e**ncrypt is an implementation of the Double Ratchet cryptographic ratchet
described by https://whispersystems.org/docs/specifications/doubleratchet/, written in C and
C++11 and exposed as a C API.

The specification of the Olm ratchet can be found in [docs/olm.md](docs/olm.md).

This library also includes an implementation of the Megolm cryptographic
ratchet, as specified in [docs/megolm.md](docs/megolm.md).

## Installing

### Linux and other Unix-like systems

Your distribution may have pre-compiled packages available.  If not, or if you
need a newer version, you will need to compile from source.  See the "Building"
section below for more details.

### Windows

You will need to build from source.  See the "Building" section below for more
details.

## Building

To build libce as a shared library run:

```bash
cmake . -Bbuild
cmake --build build
```

To run the tests, run:

```bash
cd build/tests
ctest .
```

To build libce as a static library (which still needs libstdc++ dynamically) run:

```bash
cmake . -Bbuild -DBUILD_SHARED_LIBS=NO
cmake --build build
```

The library can also be used as a dependency with CMake using:

```cmake
find_package(LibCE:LibCE REQUIRED)
target_link_libraries(my_exe LibCE::LibCE)
```

### Using make instead of cmake

**WARNING:** Using cmake is the preferred method for building the libce library;
the Makefile may be removed in the future or have functionality removed.  In
addition, the Makefile may make certain assumptions about your system and is
not as well tested.

To build libce as a dynamic library, run:

```bash
make
```

To run the tests, run:

```bash
make test
```

To build libce as a static library, run:

```bash
make static
```

## Release process

First: bump version numbers in ``common.mk`` and ``CMakeLists.txt``.

Also, ensure that everything is committed to git.

It's probably sensible to do the above on a release branch (``release-vx.y.z``
by convention), and merge back to master once the release is complete.

```bash
make clean

# build and test C library
make test

VERSION=x.y.z
git tag $VERSION -s
git push --tags
```

## Design

libce was originally implemented in C++, with a plain-C layer providing the public
API. As development has progressed, it has become clear that C++ gives little
advantage, and new functionality is being added in C, with C++ parts being
rewritten as the need ariases.

### Error Handling

All C functions in the API for libce return ``olm_error()`` on error.

### Random Numbers

libce doesn't generate random numbers itself. Instead the caller must
provide the random data. This makes it easier to port the library to different
platforms since the caller can use whatever cryptographic random number
generator their platform provides.

### Memory

libce avoids calling malloc or allocating memory on the heap itself.
Instead the library calculates how much memory will be needed to hold the
output and the caller supplies a buffer of the appropriate size.

### Output Encoding

Binary output is encoded as base64 so that languages that prefer unicode
strings will find it easier to handle the output.

### Dependencies

libce uses pure C implementations of the cryptographic primitives used by
the ratchet. While this decreases the performance it makes it much easier
to compile the library for different architectures.
