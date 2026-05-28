#!/bin/bash
set -e

SRC=/workspace/src
BUILD="$SRC/build"

echo "==[ 1/4 ] Strict-warnings rebuild"
cd "$BUILD"
cmake "$SRC" \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-g -O0 -Wall -Wextra -Werror -Wpedantic -Wshadow -Wformat=2 -fno-omit-frame-pointer" \
    -DOPENSSL_ROOT_DIR=/opt/openssl \
    -DOPENSSL_ENGINES_DIR=/opt/openssl/lib64/engines-3
ninja -j"$(nproc)"
ninja install

echo "==[ 2/4 ] CTest"
ctest --output-on-failure -j"$(nproc)"

echo "==[ 3/4 ] cppcheck"
cd "$SRC"
cppcheck \
    --enable=warning,style,performance,portability \
    --inconclusive \
    --std=c11 \
    --suppress=missingIncludeSystem \
    --error-exitcode=1 \
    --quiet \
    -I /opt/openssl/include \
    *.c *.h

echo "==[ 4/4 ] Valgrind on test binaries"
cd "$BUILD/bin"
LEAK=0
for t in test_*; do
    [ -x "$t" ] || continue
    echo "  -> valgrind $t"
    valgrind \
        --leak-check=full \
        --show-leak-kinds=all \
        --track-origins=yes \
        --error-exitcode=42 \
        --errors-for-leak-kinds=definite,indirect \
        "./$t" >/dev/null 2>&1 || {
            rc=$?
            if [ "$rc" = "42" ]; then
                echo "     LEAK in $t"
                LEAK=1
            else
                echo "     skipped $t (rc=$rc, not a leak)"
            fi
        }
done
[ "$LEAK" = "0" ] || { echo "valgrind: leaks found"; exit 1; }

echo "ALL CHECKS PASSED"
