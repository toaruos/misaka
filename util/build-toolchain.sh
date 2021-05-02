DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TARGET=x86_64-pc-toaru
PREFIX="$DIR/local"
SYSROOT="$DIR/../base"

mkdir -p $DIR/build/binutils
cd $DIR/build/binutils
../../binutils-gdb/configure --target=$TARGET --prefix="$PREFIX" --with-sysroot="$SYSROOT" --disable-werror --enable-shared
make -j8
make install

mkdir -p $DIR/build/gcc
cd $DIR/build/gcc
../../gcc/configure --target=$TARGET --prefix="$PREFIX" --with-sysroot="$SYSROOT" --enable-languages=c,c++ --enable-shared
make -j8 all-gcc all-target-libgcc
make install-gcc install-target-libgcc
