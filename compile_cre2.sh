

if [ $# -lt 1 ]; then
    echo "usage: $0 <source_file> [executable_name]"
    echo "example: $0 test_cre2.c test_cre2"
    exit 1
fi

SOURCE_FILE="$1"
EXECUTABLE="${2:-${1%.*}}" 


CRE2_INCLUDE="/opt/re2/2024-07-02/shared/include"
CRE2_LIB="/opt/re2/2024-07-02/shared/lib64"
RE2_LIB="/usr/local/lib"

echo "compile $SOURCE_FILE -> $EXECUTABLE"
echo "use cre2 library: $CRE2_LIB"
echo "use re2 library: $RE2_LIB"

# compile
g++ "$SOURCE_FILE" -o "$EXECUTABLE" \
    -I"$CRE2_INCLUDE" \
    -L"$CRE2_LIB" \
    -lcre2

if [ $? -eq 0 ]; then
    echo "compile success!"
    echo "run before set library path:"
    echo "export LD_LIBRARY_PATH=$CRE2_LIB:$RE2_LIB:\$LD_LIBRARY_PATH"
    echo ""
    echo "run program:"
    echo "./$EXECUTABLE"
else
    echo "compile failed!"
    exit 1
fi 