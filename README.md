## Overview

asynctls is a C library for Linux-like operating systems that offers a
TLS protocol abstraction compatible with the [async][] library.

## Building

asynctls uses [SCons][] and `pkg-config` for building.

Before building asynctls for the first time, run
```
git submodule update --init
```

To build asynctls, run
```
scons [ prefix=<prefix> ]
```
from the top-level asynctls directory. The optional prefix argument is a
directory, `/usr/local` by default, where the build system installs
asynctls.

To install asynctls, run
```
sudo scons [ prefix=<prefix> ] install
```

## Documentation

The header files under `include` contain detailed documentation.

[SCons]: https://scons.org/
[async]: https://github.com/F-Secure/async
