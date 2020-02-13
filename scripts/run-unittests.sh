#!/bin/bash

set -ex

run-test () {
    local arch=$1
    shift
    case $arch in
        darwin)
            "$@"
            ;;
        *)
            valgrind -q --leak-check=full --error-exitcode=123 "$@"
            ;;
    esac
}

test-hostname-verification() {
    test/tlscommunicationtest.py test test pass
    test/tlscommunicationtest.py test '*' pass
    test/tlscommunicationtest.py test 'te*' pass
    test/tlscommunicationtest.py testsite 'te*site' pass
    test/tlscommunicationtest.py testsite 't*s*e' fail
    test/tlscommunicationtest.py test.sub test.sub pass
    test/tlscommunicationtest.py test.sub '*.sub' pass
    test/tlscommunicationtest.py test.sub '*' fail
    test/tlscommunicationtest.py test.sub '*.*' pass
    test/tlscommunicationtest.py test.sub invalid.sub fail
    test/tlscommunicationtest.py test.sub 'invalid.*' fail
    test/tlscommunicationtest.py TEST.SUB test.sub pass
    test/tlscommunicationtest.py test '*ss' fail
    test/tlscommunicationtest.py test 'tt*' fail
    test/tlscommunicationtest.py test 'test*' pass
    test/tlscommunicationtest.py test '*test' pass
    test/tlscommunicationtest.py test '*te' fail
    test/tlscommunicationtest.py test 'te*st' pass
    test/tlscommunicationtest.py test tes fail
    test/tlscommunicationtest.py test testa fail
    test/tlscommunicationtest.py teest 'tee*est' fail
}

test-client-system-bundle() {
    local arch=$1 openssl_dir
    openssl_dir=$(openssl version -d | awk '{ print $2 }' | tr -d '"')
    SSL_CERT_DIR=$openssl_dir/certs \
    SSL_CERT_FILE=$openssl_dir/cert.pem \
    run-test $arch stage/$arch/build/test/tlstest \
        github.com 443 github.com
}

test-client-file-bundle() {
    local arch=$1
    run-test $arch stage/$arch/build/test/tlstest \
        --file test/certs/DigiCert_High_Assurance_EV_Root_CA.pem \
        github.com 443 github.com
}

test-server() {
    test/tlscommunicationtest.py --use-openssl-client test.foo '*.foo' pass
}

test-fstrace() {
    local arch=$1
    stage/$arch/build/test/fstracecheck
}

realpath () {
    # reimplementation of "readlink -fw" for OSX
    python -c "import os.path, sys; print os.path.realpath(sys.argv[1])" "$1"
}

main() {
    cd "$(dirname "$(realpath "$0")")/.."
    case "$(uname)" in
        Linux)
            test-fstrace linux64
            test-client-system-bundle linux64
            test-client-file-bundle linux64
            test-hostname-verification
            test-server
            ;;
        Darwin)
            test-fstrace darwin
            test-client-system-bundle darwin
            test-server
            ;;
        *)
            echo "$0: Unknown OS architecture: $os" >&2
            exit 1
    esac
}

main "$@"
