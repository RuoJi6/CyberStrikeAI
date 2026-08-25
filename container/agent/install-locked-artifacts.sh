#!/usr/bin/env bash
# Install non-APT artifacts declared in toolchain.lock with SHA-256 verification.
# Usage: install-locked-artifacts.sh <TARGETARCH>
# TARGETARCH is docker TARGETARCH: amd64 | arm64
#
# CYBERSTRIKE_STAGE:
#   builder      - GitHub releases + Go sources + libc-database
#   runtime-npm - npm only (builder stage)
#   runtime-gem  - gem only (final image)
#   runtime-lang - npm + gem (compatibility alias)
#   all          - everything (default when unset)
set -euo pipefail

TARGETARCH=${1:-}
if [[ "$TARGETARCH" != "amd64" && "$TARGETARCH" != "arm64" ]]; then
  printf 'usage: %s <amd64|arm64>\n' "$0" >&2
  exit 2
fi

STAGE=${CYBERSTRIKE_STAGE:-all}
LOCK_FILE=${LOCK_FILE:-/tmp/toolchain.lock}
if [[ ! -f "$LOCK_FILE" ]]; then
  LOCK_FILE="$(cd "$(dirname "$0")" && pwd)/toolchain.lock"
fi
command -v jq >/dev/null

DEST_BIN=${DEST_BIN:-/usr/local/bin}
mkdir -p "$DEST_BIN" /opt /tmp/cyberstrike-dl
TMP=/tmp/cyberstrike-dl
sha_field="sha256_${TARGETARCH}"

download_verify() {
  local url=$1 expected=$2 out=$3
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || {
    printf 'refusing download without a real sha256: %s\n' "$url" >&2
    return 1
  }
  command -v curl >/dev/null
  command -v sha256sum >/dev/null
  curl -fsSL --retry 3 --retry-delay 2 -o "$out" "$url"
  local got
  got=$(sha256sum "$out" | awk '{print $1}')
  if [[ "$got" != "$expected" ]]; then
    printf 'sha256 mismatch for %s\n expected=%s\n got=%s\n' "$url" "$expected" "$got" >&2
    rm -f "$out"
    return 1
  fi
}

install_tarball_bin() {
  local archive=$1 bin_name=$2
  local extract=$TMP/extract-$$
  mkdir -p "$extract"
  case "$archive" in
    *.zip) unzip -qo "$archive" -d "$extract" ;;
    *.tar.gz|*.tgz) tar -xzf "$archive" -C "$extract" ;;
    *.tar.xz) tar -xJf "$archive" -C "$extract" ;;
    *.deb) dpkg-deb -x "$archive" "$extract" ;;
    *) printf 'unsupported archive: %s\n' "$archive" >&2; return 1 ;;
  esac
  local found
  found=$(find "$extract" -type f -name "$bin_name" | head -n1 || true)
  if [[ -z "$found" ]]; then
    found=$(find "$extract" -type f -perm -111 -name "$bin_name" | head -n1 || true)
  fi
  if [[ -z "$found" ]]; then
    printf 'binary %s not found in %s\n' "$bin_name" "$archive" >&2
    rm -rf "$extract"
    return 1
  fi
  install -m 0755 "$found" "$DEST_BIN/$bin_name"
  rm -rf "$extract"
}

install_rustscan() {
  local archive=$1
  local extract=$TMP/rustscan-extract
  local found nested
  rm -rf "$extract"
  mkdir -p "$extract"
  unzip -qo "$archive" -d "$extract"
  found=$(find "$extract" -type f -name rustscan | head -n1 || true)
  if [[ -z "$found" ]]; then
    nested=$(find "$extract" -type f -name '*.tar.gz' | head -n1 || true)
    [[ -n "$nested" ]] || {
      printf 'rustscan binary or nested archive not found in %s\n' "$archive" >&2
      return 1
    }
    tar -xzf "$nested" -C "$extract"
    found=$(find "$extract" -type f -name rustscan | head -n1 || true)
  fi
  [[ -n "$found" ]] || {
    printf 'rustscan binary not found in %s\n' "$archive" >&2
    return 1
  }
  install -m 0755 "$found" "$DEST_BIN/rustscan"
  rm -rf "$extract"
}

install_github() {
  mapfile -t RELEASE_IDS < <(jq -r '.github_releases[].id' "$LOCK_FILE")
  for id in "${RELEASE_IDS[@]}"; do
    local repo tag expected asset_arm asset_amd asset_name download_url download_url_arch
    local asset url out ver Arch arch supported packaging
    repo=$(jq -r --arg id "$id" '.github_releases[] | select(.id==$id) | .repo' "$LOCK_FILE")
    tag=$(jq -r --arg id "$id" '.github_releases[] | select(.id==$id) | .tag' "$LOCK_FILE")
    supported=$(jq -r --arg id "$id" --arg arch "$TARGETARCH" \
      '.github_releases[] | select(.id==$id) | ((.supported_architectures // ["amd64", "arm64"]) | index($arch) != null)' \
      "$LOCK_FILE")
    if [[ "$supported" != true ]]; then
      printf 'skip github %s: explicitly unsupported on linux/%s\n' "$id" "$TARGETARCH"
      continue
    fi

    expected=$(jq -r --arg id "$id" --arg f "$sha_field" '.github_releases[] | select(.id==$id) | .[$f] // empty' "$LOCK_FILE")
    asset_arm=$(jq -r --arg id "$id" '.github_releases[] | select(.id==$id) | .asset_arm64 // empty' "$LOCK_FILE")
    asset_amd=$(jq -r --arg id "$id" '.github_releases[] | select(.id==$id) | .asset_amd64 // empty' "$LOCK_FILE")
    asset_name=$(jq -r --arg id "$id" '.github_releases[] | select(.id==$id) | .asset_name // empty' "$LOCK_FILE")
    download_url=$(jq -r --arg id "$id" '.github_releases[] | select(.id==$id) | .download_url_template // empty' "$LOCK_FILE")
    download_url_arch=$(jq -r --arg id "$id" --arg a "$TARGETARCH" '.github_releases[] | select(.id==$id) | .["download_url_"+$a] // empty' "$LOCK_FILE")
    packaging=$(jq -r --arg id "$id" '.github_releases[] | select(.id==$id) | .packaging // "archive"' "$LOCK_FILE")

    case "$TARGETARCH" in
      arm64) asset=${asset_arm:-$asset_name} ;;
      amd64) asset=${asset_amd:-$asset_name} ;;
    esac

    if [[ -n "$download_url_arch" ]]; then
      url=$download_url_arch
      asset=$(basename "$url")
    elif [[ -n "$download_url" ]]; then
      url=$download_url
      asset=$(basename "$url")
    elif [[ -n "${asset:-}" ]]; then
      url="https://github.com/${repo}/releases/download/${tag}/${asset}"
    else
      ver=${tag#v}
      arch=$TARGETARCH
      case "$id" in
        trivy)
          if [[ "$TARGETARCH" == amd64 ]]; then Arch=64bit; else Arch=ARM64; fi
          asset="trivy_${ver}_Linux-${Arch}.tar.gz"
          ;;
        kube-bench)
          asset="kube-bench_${ver}_linux_${arch}.tar.gz"
          ;;
        terrascan)
          if [[ "$TARGETARCH" == amd64 ]]; then Arch=x86_64; else Arch=arm64; fi
          asset="terrascan_${ver}_Linux_${Arch}.tar.gz"
          ;;
        falco)
          if [[ "$TARGETARCH" == amd64 ]]; then arch=x86_64; else arch=aarch64; fi
          asset="falco-${ver}-${arch}.tar.gz"
          url="https://download.falco.org/packages/bin/${arch}/${asset}"
          ;;
        *)
          printf 'github %s has no asset for linux/%s\n' "$id" "$TARGETARCH" >&2
          exit 1
          ;;
      esac
      url=${url:-"https://github.com/${repo}/releases/download/${tag}/${asset}"}
    fi

    out="$TMP/${id}-${asset}"
    printf 'install github %s <- %s\n' "$id" "$url"
    download_verify "$url" "$expected" "$out"

    case "$id" in
      linpeas) install -m 0755 "$out" "$DEST_BIN/linpeas.sh" ;;
      cloudmapper)
        [[ "$packaging" == source_tree ]]
        local extract cloudmapper_root source_dir compat wrapper
        extract="$TMP/cloudmapper-extract"
        cloudmapper_root=/opt
        [[ -d /out/opt ]] && cloudmapper_root=/out/opt
        rm -rf "$extract" "$cloudmapper_root/cloudmapper"
        mkdir -p "$extract"
        tar -xzf "$out" -C "$extract"
        source_dir=$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
        test -n "$source_dir"
        mv "$source_dir" "$cloudmapper_root/cloudmapper"
        compat=/build/cloudmapper-pyjq-compat.py
        wrapper=/build/cloudmapper-wrapper.sh
        [[ -f "$compat" ]] || compat="$(cd "$(dirname "$0")" && pwd)/cloudmapper-pyjq-compat.py"
        [[ -f "$wrapper" ]] || wrapper="$(cd "$(dirname "$0")" && pwd)/cloudmapper-wrapper.sh"
        install -m 0644 "$compat" "$cloudmapper_root/cloudmapper/pyjq.py"
        install -m 0755 "$wrapper" "$DEST_BIN/cloudmapper"
        ;;
      graphqlmap)
        [[ "$packaging" == source_tree ]]
        local extract graphqlmap_root source_dir wrapper
        extract="$TMP/graphqlmap-extract"
        graphqlmap_root=/opt
        [[ -d /out/opt ]] && graphqlmap_root=/out/opt
        rm -rf "$extract" "$graphqlmap_root/graphqlmap"
        mkdir -p "$extract"
        tar -xzf "$out" -C "$extract"
        source_dir=$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
        test -n "$source_dir"
        mv "$source_dir" "$graphqlmap_root/graphqlmap"
        test -f "$graphqlmap_root/graphqlmap/graphqlmap/attacks.py"
        test -f "$graphqlmap_root/graphqlmap/bin/graphqlmap"
        wrapper=/build/graphqlmap-wrapper.sh
        [[ -f "$wrapper" ]] || wrapper="$(cd "$(dirname "$0")" && pwd)/graphqlmap-wrapper.sh"
        install -m 0755 "$wrapper" "$DEST_BIN/graphqlmap"
        ;;
      jwt-tool)
        [[ "$packaging" == source_tree ]]
        local extract jwt_tool_root source_dir wrapper
        extract="$TMP/jwt-tool-extract"
        jwt_tool_root=/opt
        [[ -d /out/opt ]] && jwt_tool_root=/out/opt
        rm -rf "$extract" "$jwt_tool_root/jwt_tool"
        mkdir -p "$extract"
        tar -xzf "$out" -C "$extract"
        source_dir=$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
        test -n "$source_dir"
        mv "$source_dir" "$jwt_tool_root/jwt_tool"
        test -f "$jwt_tool_root/jwt_tool/jwt_tool.py"
        test -f "$jwt_tool_root/jwt_tool/jwt-common.txt"
        test -f "$jwt_tool_root/jwt_tool/jwks-common.txt"
        wrapper=/build/jwt-tool-wrapper.sh
        [[ -f "$wrapper" ]] || wrapper="$(cd "$(dirname "$0")" && pwd)/jwt-tool-wrapper.sh"
        install -m 0755 "$wrapper" "$DEST_BIN/jwt_tool"
        ;;
      paramspider)
        [[ "$packaging" == source_tree ]]
        local extract paramspider_root source_dir wrapper
        extract="$TMP/paramspider-extract"
        paramspider_root=/opt
        [[ -d /out/opt ]] && paramspider_root=/out/opt
        rm -rf "$extract" "$paramspider_root/paramspider"
        mkdir -p "$extract"
        tar -xzf "$out" -C "$extract"
        source_dir=$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
        test -n "$source_dir"
        mv "$source_dir" "$paramspider_root/paramspider"
        test -f "$paramspider_root/paramspider/paramspider/main.py"
        test -f "$paramspider_root/paramspider/paramspider/client.py"
        wrapper=/build/paramspider-wrapper.sh
        [[ -f "$wrapper" ]] || wrapper="$(cd "$(dirname "$0")" && pwd)/paramspider-wrapper.sh"
        install -m 0755 "$wrapper" "$DEST_BIN/paramspider"
        ;;
      hashpump)
        [[ "$packaging" == source_build ]]
        local extract source_dir
        extract="$TMP/hashpump-extract"
        rm -rf "$extract"
        mkdir -p "$extract"
        tar -xzf "$out" -C "$extract"
        source_dir=$(find "$extract" -mindepth 1 -maxdepth 1 -type d | head -n1)
        test -n "$source_dir"
        make -C "$source_dir" -j"$(nproc)" hashpump
        install -m 0755 "$source_dir/hashpump" "$DEST_BIN/hashpump"
        ;;
      pwninit)
        [[ "$packaging" == raw_binary ]]
        install -m 0755 "$out" "$DEST_BIN/pwninit"
        ;;
      x8)
        [[ "$packaging" == gzip_binary ]]
        gzip -dc "$out" >"$DEST_BIN/x8"
        chmod 0755 "$DEST_BIN/x8"
        ;;
      rustscan)
        [[ "$packaging" == nested_archive ]]
        install_rustscan "$out"
        ;;
      falco|trivy|kube-bench|terrascan|katana|dalfox|gau)
        install_tarball_bin "$out" "$id"
        ;;
      *)
        printf 'unknown github id packaging: %s\n' "$id" >&2
        exit 1
        ;;
    esac
  done
}

install_go_modules() {
  command -v go >/dev/null
  export GOPATH=${GOPATH:-/usr/local/go-tools}
  export GOBIN=$DEST_BIN
  export PATH="$DEST_BIN:$PATH"
  mapfile -t GO_PATHS < <(jq -r '.go_modules[] | "\(.path)@\(.version)"' "$LOCK_FILE")
  for mod in "${GO_PATHS[@]}"; do
    local bin
    bin=$(basename "${mod%%@*}")
    if command -v "$bin" >/dev/null 2>&1 || [[ -x "$DEST_BIN/$bin" ]]; then
      printf 'go skip %s (already present)\n' "$bin"
      continue
    fi
    printf 'go install %s\n' "$mod"
    go install -ldflags='-s -w' "$mod"
  done
}

install_npm() {
  command -v npm >/dev/null
  mapfile -t NPM_PKGS < <(jq -r '.npm_packages[] | "\(.name)@\(.version)"' "$LOCK_FILE")
  ((${#NPM_PKGS[@]})) || return 0
  npm install -g --omit=dev "${NPM_PKGS[@]}"
}

install_gems() {
  command -v gem >/dev/null
  mapfile -t GEM_PKGS < <(jq -r '.gem_packages[] | "\(.name):\(.version)"' "$LOCK_FILE")
  for spec in "${GEM_PKGS[@]}"; do
    local name=${spec%%:*}
    local ver=${spec#*:}
    gem install --no-document "$name" -v "$ver"
  done
}

install_libc_database() {
  local dest=/opt/libc-database
  [[ -d /out/opt ]] && dest=/out/opt/libc-database
  if [[ -d "$dest" ]]; then
    return 0
  fi
  command -v git >/dev/null
  local repository revision
  repository=$(jq -r '.git_sources[] | select(.name=="libc-database") | .repository' "$LOCK_FILE")
  revision=$(jq -r '.git_sources[] | select(.name=="libc-database") | .revision' "$LOCK_FILE")
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { printf 'invalid libc-database revision\n' >&2; exit 1; }
  git init "$dest"
  git -C "$dest" remote add origin "$repository"
  git -C "$dest" fetch --depth 1 origin "$revision"
  git -C "$dest" checkout --detach FETCH_HEAD
  test -x "$dest/find"
  rm -rf "$dest/.git"
  ln -sfn "$dest/find" "$DEST_BIN/libc-database"
}

case "$STAGE" in
  builder)
    install_github
    install_go_modules
    install_libc_database
    ;;
  runtime-npm)
    install_npm
    ;;
  runtime-gem)
    install_gems
    ;;
  runtime-lang)
    install_npm
    install_gems
    ;;
  all|*)
    install_github
    install_go_modules
    install_npm
    install_gems
    install_libc_database
    ;;
esac

if command -v bloodhound.py >/dev/null 2>&1 && ! command -v bloodhound-python >/dev/null 2>&1; then
  ln -sfn "$(command -v bloodhound.py)" "$DEST_BIN/bloodhound-python"
fi

printf 'install-locked-artifacts: stage=%s arch=%s done\n' "$STAGE" "$TARGETARCH"
