#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${GITHUB_WORKSPACE:-}" ]]; then
  root="${GITHUB_WORKSPACE}"
else
  root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
fi

include_examples=false

for arg in "$@"; do
  case "${arg}" in
    --with-examples)
      include_examples=true
      ;;
    *)
      echo "unknown argument: ${arg}" >&2
      exit 2
      ;;
  esac
done

cd "${root}"

rm -f go.work go.work.sum

modules=(
  ./jwt
  ./jws
  ./jwe
  ./jwk
)

if [[ -f ./doctests/go.mod ]]; then
  modules+=(./doctests)
fi

if [[ "${include_examples}" == "true" ]]; then
  while IFS= read -r -d '' mod; do
    modules+=("$(dirname "${mod}")")
  done < <(find ./examples -name go.mod -type f -print0 2>/dev/null | sort -z)
fi

# The workspace is ephemeral in CI and local-only for development.
GOWORK=off go work init "${modules[@]}"

# Internal modules may already require published versions while the current
# checkout contains newer, not-yet-released changes. Bind those exact
# requirements to local modules inside this temporary workspace only.
while read -r module version; do
  [[ -n "${module}" && -n "${version}" ]] || continue

  case "${module}" in
    github.com/mkbeh/xjose/*)
      local_dir="./${module#github.com/mkbeh/xjose/}"
      ;;
    *)
      continue
      ;;
  esac

  if [[ -f "${root}/${local_dir#./}/go.mod" ]]; then
    GOWORK="${root}/go.work" go work edit \
      -replace="${module}@${version}=${local_dir}"
  fi
done < <(
  for dir in "${modules[@]}"; do
    if [[ -f "${dir}/go.mod" ]]; then
      printf '%s\0' "${dir}/go.mod"
    fi
  done |
    while IFS= read -r -d '' mod; do
      awk '
        $1 == "require" &&
        $2 ~ /^github\.com\/mkbeh\/xjose\/[^[:space:]]+$/ &&
        $3 ~ /^v[0-9]/ {
          print $2, $3
          next
        }

        $1 ~ /^github\.com\/mkbeh\/xjose\/[^[:space:]]+$/ &&
        $2 ~ /^v[0-9]/ {
          print $1, $2
        }
      ' "${mod}"
    done |
    sort -u
)

echo "Created temporary Go workspace at ${root}/go.work"

if [[ "${WORKSPACE_DEBUG:-false}" == "true" ]]; then
  GOWORK="${root}/go.work" go work edit -json
fi
