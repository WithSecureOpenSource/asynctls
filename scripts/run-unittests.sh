#!/bin/bash

set -ex

test-hostname-verification() {
    local arch=$1
    test/tlscommunicationtest.py "$arch" test test pass
    test/tlscommunicationtest.py "$arch" test '*' fail
    test/tlscommunicationtest.py "$arch" test 'te*' fail
    test/tlscommunicationtest.py "$arch" test '*st' fail
    test/tlscommunicationtest.py "$arch" test 'test*' fail
    test/tlscommunicationtest.py "$arch" test '*test' fail
    test/tlscommunicationtest.py "$arch" test 't*st' fail
    test/tlscommunicationtest.py "$arch" test 'te*st' fail
    test/tlscommunicationtest.py "$arch" test 't*s*' fail
    test/tlscommunicationtest.py "$arch" test.sub test.sub pass
    test/tlscommunicationtest.py "$arch" test.sub '*.sub' pass
    test/tlscommunicationtest.py "$arch" test.sub '*' fail
    test/tlscommunicationtest.py "$arch" test.sub '*.*' fail
    test/tlscommunicationtest.py "$arch" test.sub 'te*.sub' pass
    test/tlscommunicationtest.py "$arch" test.sub '*st.sub' pass
    test/tlscommunicationtest.py "$arch" test.sub 'test*.sub' pass
    test/tlscommunicationtest.py "$arch" test.sub '*test.sub' pass
    test/tlscommunicationtest.py "$arch" test.sub 't*st.sub' fail
    test/tlscommunicationtest.py "$arch" test.sub 'te*st.sub' fail
    test/tlscommunicationtest.py "$arch" test.sub 't*s*.sub' fail
    test/tlscommunicationtest.py "$arch" test.sub invalid.sub fail
    test/tlscommunicationtest.py "$arch" test.sub 'invalid.*' fail
    test/tlscommunicationtest.py "$arch" TEST.SUB test.sub pass
    test/tlscommunicationtest.py "$arch" test tes fail
    test/tlscommunicationtest.py "$arch" test testa fail
}

test-server() {
    local arch=$1
    test/tlscommunicationtest.py --use-openssl-client "$arch" test.foo '*.foo' pass
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
    case "$(uname)" in
        Linux)
            test-fstrace linux64
            test-hostname-verification linux64
            test-server linux64
            ;;
        Darwin)
            test-fstrace darwin
            test-server darwin
            ;;
        *)
            echo "$0: Unknown OS architecture: $os" >&2
            exit 1
    esac
}

main "$@"
