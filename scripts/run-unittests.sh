#!/usr/bin/env bash

set -ex

test-hostname-verification() {
    local arch=$1
    test/tlscommunicationtest.py "$arch" test test 0 0
    test/tlscommunicationtest.py "$arch" test '*' 1 1
    test/tlscommunicationtest.py "$arch" test 'te*' 1 1
    test/tlscommunicationtest.py "$arch" test '*st' 1 1
    test/tlscommunicationtest.py "$arch" test 'test*' 1 1
    test/tlscommunicationtest.py "$arch" test '*test' 1 1
    test/tlscommunicationtest.py "$arch" test 't*st' 1 1
    test/tlscommunicationtest.py "$arch" test 'te*st' 1 1
    test/tlscommunicationtest.py "$arch" test 't*s*' 1 1
    test/tlscommunicationtest.py "$arch" test.sub test.sub 0 0
    test/tlscommunicationtest.py "$arch" test.sub '*.sub' 0 0
    test/tlscommunicationtest.py "$arch" test.sub '*' 1 1
    test/tlscommunicationtest.py "$arch" test.sub '*.*' 1 1
    test/tlscommunicationtest.py "$arch" test.sub 'te*.sub' 0 0
    test/tlscommunicationtest.py "$arch" test.sub '*st.sub' 0 0
    test/tlscommunicationtest.py "$arch" test.sub 'test*.sub' 0 0
    test/tlscommunicationtest.py "$arch" test.sub '*test.sub' 0 0
    test/tlscommunicationtest.py "$arch" test.sub 't*st.sub' 1 1
    test/tlscommunicationtest.py "$arch" test.sub 'te*st.sub' 1 1
    test/tlscommunicationtest.py "$arch" test.sub 't*s*.sub' 1 1
    test/tlscommunicationtest.py "$arch" test.sub invalid.sub 1 1
    test/tlscommunicationtest.py "$arch" test.sub 'invalid.*' 1 1
    test/tlscommunicationtest.py "$arch" TEST.SUB test.sub 0 0
    test/tlscommunicationtest.py "$arch" test tes 1 1
    test/tlscommunicationtest.py "$arch" test testa 1 1
}

test-server() {
    local arch=$1
    test/tlscommunicationtest.py --client openssl "$arch" test.foo '*.foo' 0 0
    test/tlscommunicationtest.py --client tcp "$arch" test.foo '*.foo' 0 1
}

test-fstrace() {
    local arch=$1
    stage/$arch/build/test/fstracecheck
}

realpath () {
    if [ -x "/bin/realpath" ]; then
        /bin/realpath "$@"
    else
        python -c "import os.path, sys; print(os.path.realpath(sys.argv[1]))" \
               "$1"
    fi
}

main() {
    cd "$(dirname "$(realpath "$0")")/.."
    local os=$(uname -m -s)
    case $os in
        "Darwin arm64")
            test-fstrace darwin
            test-server darwin
            ;;
        "Darwin x86_64")
            test-fstrace darwin
            test-server darwin
            ;;
        "FreeBSD amd64")
            test-fstrace freebsd_amd64
            test-hostname-verification freebsd_amd64
            test-server freebsd_amd64
            ;;
        "Linux x86_64")
            test-fstrace linux64
            test-hostname-verification linux64
            test-server linux64
            ;;
        "OpenBSD amd64")
            test-fstrace openbsd_amd64
            test-hostname-verification openbsd_amd64
            test-server openbsd_amd64
            ;;
        *)
            echo "$0: Unknown OS architecture: $os" >&2
            exit 1
    esac
}

main "$@"
