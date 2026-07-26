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

# Create the workspace in the repository root, exactly where Go commands run.
# All internal modules become workspace main modules, so unpublished module
# versions are resolved from the current checkout rather than from the proxy.
GOWORK=off go work init "${modules[@]}"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "GOWORK=${root}/go.work" >> "${GITHUB_ENV}"
fi

echo "Created temporary Go workspace:"
GOWORK="${root}/go.work" go work edit -json
