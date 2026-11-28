pkgname=sensible
pkgver=0
pkgrel=1
pkgdesc='Configures Linux hosts from a directory of YAML over SSH'
arch=('x86_64')
url='https://git.yak-wall.ts.net/public/sensible'
license=('CC0-1.0')
optdepends=('sudo: bootstrapping the local machine')
makedepends=('git' 'go' 'make')

pkgver() {
  cd "$startdir"
  if tag=$(git describe --long --tags --abbrev=7 2>/dev/null); then
    sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g' <<< "$tag"
  else
    printf '0.r%s.g%s' "$(git rev-list --count HEAD)" "$(git rev-parse --short=7 HEAD)"
  fi
}

prepare() {
  # makepkg's pkg/ and src/ sit inside the checkout, where go's ./... patterns
  # would walk into them, so build from a copy of the source instead.
  rm -rf "$srcdir/$pkgname"
  mkdir "$srcdir/$pkgname"
  git -C "$startdir" archive HEAD | tar -x -C "$srcdir/$pkgname"
}

build() {
  cd "$srcdir/$pkgname"
  export CGO_ENABLED=0 GOFLAGS='-mod=readonly -modcacherw'
  make sensible
}

package() {
  cd "$srcdir/$pkgname"
  install -Dm755 sensible "$pkgdir/usr/bin/sensible"
  install -Dm644 completions/sensible.bash "$pkgdir/usr/share/bash-completion/completions/sensible"
  install -Dm644 completions/_sensible "$pkgdir/usr/share/zsh/site-functions/_sensible"
  install -Dm644 LICENCE "$pkgdir/usr/share/licenses/$pkgname/LICENCE"
}
