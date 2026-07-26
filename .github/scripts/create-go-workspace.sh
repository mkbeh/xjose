#!/usr/bin/env bash
set -euo pipefail

root="${GITHUB_WORKSPACE:-$(pwd)}"
include_examples=false

case "${1:-}" in
  "")
    ;;
  --with-examples)
    include_examples=true
    ;;
  *)
    echo "unknown argument: ${1}" >&2
    exit 2
    ;;
esac

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

if [[ "${include_examples}" == "true" ]]; then
  while IFS= read -r -d '' mod; do
    modules+=("$(dirname "${mod}")")
  done < <(find ./examples -name go.mod -type f -print0 | sort -z)
fi

# The workspace is ephemeral and exists only for the current CI job.
GOWORK=off go work init "${modules[@]}"

# Internal modules already reference release versions in go.mod, while the
# corresponding tags may not exist during the initial repository bootstrap.
# Keep those requirements bound to the current checkout inside this temporary
# workspace only.
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

if [[ "${WORKSPACE_DEBUG:-false}" == "true" ]]; then
  GOWORK="${root}/go.work" go work edit -json
fi
