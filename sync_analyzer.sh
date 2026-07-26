#!/usr/bin/env bash
# Vendor the code analyzer into the action image.
#
# The action ships as a self-contained Docker container and cannot import from
# the backend, which is why detection.py already lives here as a synced copy.
# The analyzer follows the same rule — but it is copied by this script rather
# than by hand, so the two never quietly drift apart.
#
# Both CI integrations get the same copy. Run after changing anything under
# Backend/services/code_analysis, and commit the result.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="${here}/../Backend/services/code_analysis"
targets=("${here}/code_analysis" "${here}/../Gitlab-Components/code_analysis")

if [[ ! -d "$source_dir" ]]; then
  echo "error: ${source_dir} not found" >&2
  exit 1
fi

for target_dir in "${targets[@]}"; do
  rm -rf "$target_dir"
  mkdir -p "$target_dir"

  # Everything except caches and the __main__ bridge, which assumes the
  # backend package layout.
  (cd "$source_dir" && find . -name "*.py" -not -path "*/__pycache__/*" -not -name "__main__.py" -print0) \
    | while IFS= read -r -d '' rel; do
        mkdir -p "${target_dir}/$(dirname "$rel")"
        cp "${source_dir}/${rel}" "${target_dir}/${rel}"
      done

  # The vendored copy must not import from the backend. If it does, the image
  # will build and then fail at runtime inside a customer's CI.
  if grep -rn "^from models\|^import models" "$target_dir" >/dev/null 2>&1; then
    echo "error: vendored analyzer still imports the backend's models package" >&2
    exit 1
  fi

  count=$(find "$target_dir" -name "*.py" | wc -l | tr -d ' ')
  echo "synced ${count} modules into ${target_dir}"
done
