# libolm

An implementation of the Double Ratchet cryptographic ratchet described by
https://whispersystems.org/docs/specifications/doubleratchet/, written in C and
C++11 and exposed as a C API.

The specification of the Olm ratchet can be found in [docs/olm.md](docs/olm.md).

This library also includes an implementation of the Megolm cryptographic
ratchet, as specified in [docs/megolm.md](docs/megolm.md).

## Installing

### Linux and other Unix-like systems

Your distribution may have pre-compiled packages available.  If not, or if you
need a newer version, you will need to compile from source.  See the "Building"
section below for more details.

### macOS

The easiest way to install on macOS is via Homebrew.  If you do not have
Homebrew installed, follow the instructions at https://brew.sh/ to install it.

You can then install libolm by running

```bash
brew install libolm
```

### Windows

You will need to build from source.  See the "Building" section below for more
details.

## Building

To build olm as a shared library run:

```bash
cmake . -Bbuild
cmake --build build
```

To run the tests, run:

```bash
cd build/tests
ctest .
```

To build olm as a static library (which still needs libstdc++ dynamically) run:

```bash
cmake . -Bbuild -DBUILD_SHARED_LIBS=NO
cmake --build build
```

The library can also be used as a dependency with CMake using:

```cmake
find_package(Olm::Olm REQUIRED)
target_link_libraries(my_exe Olm::Olm)
```

### Using make instead of cmake

**WARNING:** Using cmake is the preferred method for building the olm library;
the Makefile may be removed in the future or have functionality removed.  In
addition, the Makefile may make certain assumptions about your system and is
not as well tested.

To build olm as a dynamic library, run:

```bash
make
```

To run the tests, run:

```bash
make test
```

To build olm as a static library, run:

```bash
make static
```

## Release process

First: bump version numbers in ``common.mk``, ``CMakeLists.txt``, and ``Package.swift``.

Also, ensure the changelog is up to date, and that everything is committed to
git.

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

Olm was originally implemented in C++, with a plain-C layer providing the public
API. As development has progressed, it has become clear that C++ gives little
advantage, and new functionality is being added in C, with C++ parts being
rewritten as the need ariases.

### Error Handling

All C functions in the API for olm return ``olm_error()`` on error.

### Random Numbers

Olm doesn't generate random numbers itself. Instead the caller must
provide the random data. This makes it easier to port the library to different
platforms since the caller can use whatever cryptographic random number
generator their platform provides.

### Memory

Olm avoids calling malloc or allocating memory on the heap itself.
Instead the library calculates how much memory will be needed to hold the
output and the caller supplies a buffer of the appropriate size.

### Output Encoding

Binary output is encoded as base64 so that languages that prefer unicode
strings will find it easier to handle the output.

### Dependencies

Olm uses pure C implementations of the cryptographic primitives used by
the ratchet. While this decreases the performance it makes it much easier
to compile the library for different architectures.

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) when making contributions to the library.

## Security assessment

Olm 1.3.0 was independently assessed by NCC Group's Cryptography Services
Practive in September 2016 to check for security issues: you can read all
about it at
https://www.nccgroup.com/globalassets/our-research/us/public-reports/2016/november/ncc_group_olm_cryptogrpahic_review_2016_11_01.pdf
and https://matrix.org/blog/2016/11/21/matrixs-olm-end-to-end-encryption-security-assessment-released-and-implemented-cross-platform-on-riot-at-last/

## Security issues

If you think you found a security issue in libolm or the Olm/Megolm protocols, please follow our [Security Disclosure Policy](https://matrix.org/security-disclosure-policy/) to report.

## Bug reports

For non-sensitive bugs, please file bug reports at https://github.com/matrix-org/olm/issues.

## What's an olm?

It's a really cool species of European troglodytic salamander.
http://www.postojnska-jama.eu/en/come-and-visit-us/vivarium-proteus/

## Legal Notice

The software may be subject to the U.S. export control laws and regulations
and by downloading the software the user certifies that he/she/it is
authorized to do so in accordance with those export control laws and
regulations.
