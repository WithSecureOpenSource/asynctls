#!/bin/bash

set -ex

test-hostname-verification() {
    test/tlscommunicationtest.py test test pass
    test/tlscommunicationtest.py test '*' fail
    test/tlscommunicationtest.py test 'te*' fail
    test/tlscommunicationtest.py test '*st' fail
    test/tlscommunicationtest.py test 'test*' fail
    test/tlscommunicationtest.py test '*test' fail
    test/tlscommunicationtest.py test 't*st' fail
    test/tlscommunicationtest.py test 'te*st' fail
    test/tlscommunicationtest.py test 't*s*' fail
    test/tlscommunicationtest.py test.sub test.sub pass
    test/tlscommunicationtest.py test.sub '*.sub' pass
    test/tlscommunicationtest.py test.sub '*' fail
    test/tlscommunicationtest.py test.sub '*.*' fail
    test/tlscommunicationtest.py test.sub 'te*.sub' pass
    test/tlscommunicationtest.py test.sub '*st.sub' pass
    test/tlscommunicationtest.py test.sub 'test*.sub' pass
    test/tlscommunicationtest.py test.sub '*test.sub' pass
    test/tlscommunicationtest.py test.sub 't*st.sub' fail
    test/tlscommunicationtest.py test.sub 'te*st.sub' fail
    test/tlscommunicationtest.py test.sub 't*s*.sub' fail
    test/tlscommunicationtest.py test.sub invalid.sub fail
    test/tlscommunicationtest.py test.sub 'invalid.*' fail
    test/tlscommunicationtest.py TEST.SUB test.sub pass
    test/tlscommunicationtest.py test tes fail
    test/tlscommunicationtest.py test testa fail
}

test-server() {
    test/tlscommunicationtest.py --use-openssl-client test.foo '*.foo' pass
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
            test-hostname-verification
            test-server
            ;;
        Darwin)
            test-fstrace darwin
            test-server
            ;;
        *)
            echo "$0: Unknown OS architecture: $os" >&2
            exit 1
    esac
}

main "$@"
