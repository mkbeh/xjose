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

# The workspace is ephemeral and exists only for the current CI job.
GOWORK=off go work init "${modules[@]}"

# Internal modules already reference their release versions in go.mod, while
# those tags may not exist yet. Keep those requirements local to this checkout.
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
  find ./jwt ./jws ./jwe ./jwk ./jwks ./doctests \
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
