# Maintainer: Roman Kivalin <roman@shl.dev>
pkgname=dnsforge
pkgver=0.3.0
pkgrel=1
pkgdesc='Declarative DNS zone manager with Rhai scripting'
arch=('x86_64' 'aarch64')
license=('MIT')
depends=()
makedepends=('rustup')
options=(!lto !debug)

prepare() {
  cd "$startdir"
  export RUSTUP_TOOLCHAIN=stable
  cargo fetch --locked --target "$( rustc -vV | sed -n 's/host: //p' )"
}

build() {
  cd "$startdir"
  export RUSTUP_TOOLCHAIN=stable
  export CARGO_TARGET_DIR=target
  cargo build --frozen --release
}

check() {
  cd "$startdir"
  export RUSTUP_TOOLCHAIN=stable
  export CARGO_TARGET_DIR=target
  cargo test --frozen
}

package() {
  cd "$startdir"

  install -Dm755 "target/release/$pkgname" "$pkgdir/usr/bin/$pkgname"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
