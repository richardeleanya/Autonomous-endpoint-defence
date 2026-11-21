#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "Usage: $0 fixture | {integration|release} COMPOSE_FILE [DEPENDENCY_SERVICE ...]" >&2
  exit 2
}

mode=${1:-}
[[ $# -gt 0 ]] || usage
shift
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$repo"

case "$mode" in
  fixture)
    [[ $# -eq 0 ]] || usage
    compose_file=test/workflow/compose.yaml
    ;;
  integration|release)
    [[ $# -gt 0 ]] || usage
    compose_file=$1
    shift
    ;;
  *) usage ;;
esac
compose_file=$(realpath -e -- "$compose_file")
[[ -f "$compose_file" ]] || usage
for service in "$@"; do
  [[ "$service" =~ ^[[:alnum:]_][[:alnum:]_.-]*$ && "$service" != integration-tests ]] || usage
done

umask 077
evidence=$(mktemp -d "${TMPDIR:-/tmp}/ada-docker-check.XXXXXXXX")
project="ada-check-${evidence##*.}"
project=${project,,}
compose=(docker compose --env-file /dev/null --project-name "$project" --file "$compose_file")
docker_started=false
stage=preflight
test_exit=not-run
printf 'Evidence directory: %s\n' "$evidence"

finish() {
  local status=$? evidence_status=0 image_id container
  trap - EXIT
  set +e
  if [[ "$docker_started" == true ]]; then
    "${compose[@]}" logs --no-color --timestamps > "$evidence/services.log" 2>&1 || evidence_status=1
    docker ps -aq --filter "label=com.docker.compose.project=$project" > "$evidence/containers.txt" || evidence_status=1
    if [[ "$test_exit" == 0 && ! -s "$evidence/containers.txt" ]]; then evidence_status=1; fi
    while IFS= read -r container; do
      docker container inspect --format '{{index .Config.Labels "com.docker.compose.service"}} {{.Image}} {{.State.Status}} {{.State.ExitCode}}' "$container" >> "$evidence/container-images.txt" || evidence_status=1
      image_id=$(docker container inspect --format '{{.Image}}' "$container") || evidence_status=1
      docker image inspect --format '{{.Id}} {{json .RepoDigests}}' "$image_id" >> "$evidence/image-digests.txt" || evidence_status=1
    done < "$evidence/containers.txt"
    "${compose[@]}" down --volumes --remove-orphans > "$evidence/cleanup.log" 2>&1 || evidence_status=1
  fi
  git status --porcelain=v1 --untracked-files=all > "$evidence/git-status-after.txt" || evidence_status=1
  if [[ "$mode" == release ]]; then
    git rev-parse --verify HEAD > "$evidence/git-sha-after.txt" || evidence_status=1
    cmp -s "$evidence/git-sha.txt" "$evidence/git-sha-after.txt" || evidence_status=1
    [[ ! -s "$evidence/git-status-after.txt" ]] || evidence_status=1
  fi
  if (( status == 0 && evidence_status != 0 )); then status=1; fi
  printf 'mode=%s\nstage=%s\ntest_exit=%s\nevidence_or_cleanup_exit=%s\nexit=%s\n' \
    "$mode" "$stage" "$test_exit" "$evidence_status" "$status" > "$evidence/result.txt"
  if ! (cd "$evidence" && shopt -s nullglob && sha256sum -- *.txt *.log > SHA256SUMS); then
    echo 'Could not write evidence checksums.' >&2
    if (( status == 0 )); then status=1; fi
  fi
  printf 'Docker check exit %s (%s). Evidence: %s\n' "$status" "$stage" "$evidence"
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

git rev-parse --verify HEAD > "$evidence/git-sha.txt"
git status --porcelain=v1 --untracked-files=all > "$evidence/git-status.txt"
sha256sum -- "$compose_file" > "$evidence/compose-input.txt"
if [[ "$mode" == release ]]; then
  if [[ -s "$evidence/git-status.txt" ]]; then
    echo 'Release checks require a clean checkout.' >&2
    exit 2
  fi
  [[ "$compose_file" == "$repo/"* ]] || usage
  git ls-files --error-unmatch -- "${compose_file#"$repo"/}" > /dev/null
fi

docker version > "$evidence/docker.log" 2>&1
docker compose version >> "$evidence/docker.log" 2>&1
stage=configuration
"${compose[@]}" config --services > "$evidence/services.txt" 2> "$evidence/config.log"
if ! grep -Fxq integration-tests "$evidence/services.txt"; then
  echo 'Compose must define an integration-tests service.' >&2
  exit 2
fi
docker_started=true
stage=build
"${compose[@]}" build > "$evidence/build.log" 2>&1
if (( $# > 0 )); then
  stage=dependencies
  "${compose[@]}" up --detach --wait --wait-timeout 120 --no-build "$@" > "$evidence/startup.log" 2>&1
fi
stage=tests
if "${compose[@]}" run --no-deps -T integration-tests > "$evidence/tests.log" 2>&1; then
  test_exit=0
else
  test_exit=$?
  exit "$test_exit"
fi
stage=complete
