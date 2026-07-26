#!/usr/bin/env bash
set -euo pipefail

root="${GITHUB_WORKSPACE:-$(pwd)}"
cd "${root}"

rm -f go.work go.work.sum

modules=(
  ./jwt
  ./jws
  ./jwe
  ./jwk
  ./jwks
)

if [[ -f ./doctests/go.mod ]]; then
  modules+=(./doctests)
fi

if [[ "${1:-}" == "--with-examples" ]]; then
  while IFS= read -r -d '' mod; do
    modules+=("$(dirname "${mod}")")
  done < <(find ./examples -name go.mod -print0 | sort -z)
fi

# Create an ephemeral workspace in the checkout. It is never committed.
GOWORK=off go work init "${modules[@]}"

# Make unpublished internal requirements explicit. The use directives are
# sufficient for ordinary builds, while these version-specific replacements
# also prevent tools from resolving current xjose module versions remotely.
while read -r module version; do
  case "${module}" in
    github.com/mkbeh/xjose/*)
      local_dir="${root}/${module#github.com/mkbeh/xjose/}"
      if [[ -f "${local_dir}/go.mod" ]]; then
        GOWORK="${root}/go.work" go work edit \
          -replace="${module}@${version}=${local_dir}"
      fi
      ;;
  esac
done < <(
  find ./jwt ./jws ./jwe ./jwk ./jwks ./doctests ./examples \
    -name go.mod -type f -print0 2>/dev/null |
  xargs -0 awk '
    $1 ~ /^github\.com\/mkbeh\/xjose\// && $2 ~ /^v[0-9]/ {
      print $1, $2
    }
  ' |
  sort -u
)

echo "Created temporary Go workspace at ${root}/go.work"
GOWORK="${root}/go.work" go work edit -json
