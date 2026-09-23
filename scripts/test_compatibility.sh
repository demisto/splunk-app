#!/usr/bin/env bash
#
# test_compatibility.sh
# ---------------------------------------------------------------------------
# Local, reproducible compatibility test for the Demisto Add-on for Splunk
# (TA-Demisto) against the latest Splunk image.
#
# It mirrors what CI (.github/workflows/build.yml) does, but runs entirely on
# your machine, adds real pass/fail verification, and requires NO Splunk.com
# credentials for the AppInspect stage (it uses the splunk/appinspect Docker
# CLI image instead of the cloud API).
#
# Stages:
#   1. Preflight   - verify docker + tooling are available
#   2. Lint/tests  - flake8 + pytest (same commands as CI)
#   3. Package     - build the .tgz SPL (identical to CI tar command)
#   4. AppInspect  - static compatibility checks via the splunk-appinspect
#                    Python CLI (offline, no Splunk.com credentials needed)
#   5. Runtime     - boot a clean splunk/splunk:latest container
#   6. Health      - poll container health, then INSTALL the packaged .tgz via
#                    the apps REST endpoint (the real install flow) and restart
#   7. Verify      - REST call (mgmt port) confirms the add-on is loaded/enabled
#   8. Logs        - scan splunkd.log + add-on log for TA-Demisto errors
#   9. Summary     - aggregate results; non-zero exit on any failure
#
# Usage:
#   scripts/test_compatibility.sh [options]
#
# Options:
#   --skip-tests        Skip flake8 + pytest
#   --skip-appinspect   Skip the AppInspect static stage
#   --skip-runtime      Skip the latest-image runtime stage
#   --keep-container    Do not remove the Splunk container on exit (for debugging)
#   --image <ref>       Splunk image to test against (default: splunk/splunk:latest)
#   --splunk-version <v>
#                       Test a specific Splunk version, e.g. 10.2.6 (shorthand
#                       for --image splunk/splunk:<v>).
#   --platform <p>      Docker platform for the Splunk image (default:
#                       linux/amd64). Splunk images are amd64-only for many tags;
#                       on arm64 hosts this runs them via emulation.
#   --xsoar             Run the live end-to-end XSOAR incident-creation stage.
#                       Auto-detects which flavor(s) are configured in .env and
#                       runs against EACH present flavor (v6, NG, or both):
#                         v6:  DEMISTO6_BASE_URL / DEMISTO6_API_KEY
#                         NG:  DEMISTO8_BASE_URL / DEMISTO8_API_KEY / DEMISTO8_AUTH_ID
#                       Confirms each incident is created via the XSOAR REST API.
#   --xsoar-ng          Like --xsoar but restricts the run to XSOAR NG (v8+)
#                       only, using the DEMISTO8_* set (advanced API-key format
#                       <API_KEY>$<KEY_ID> plus the NG REST endpoints).
#   --instance <name>   (Optional) XSOAR instance name configured in the add-on.
#   -h, --help          Show this help and exit
#
# Environment (.env):
#   SPLUNK_USERNAME / SPLUNK_PASSWORD  Splunk container admin creds (REQUIRED for
#                                      the runtime/verify/xsoar stages). The
#                                      Splunk image provisions an 'admin' account;
#                                      the password must meet Splunk's policy. See
#                                      https://splunk.github.io/docker-splunk/ADVANCED.html
#   DEMISTO6_BASE_URL / DEMISTO6_API_KEY               XSOAR v6 connection
#   DEMISTO8_BASE_URL / DEMISTO8_API_KEY / DEMISTO8_AUTH_ID  XSOAR NG connection
#
# Exit code: 0 if all executed stages pass, non-zero otherwise.
# ---------------------------------------------------------------------------

set -o errexit
set -o nounset
set -o pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ADD_ON_ROOT="${REPO_ROOT}/add-on"
ADD_ON_NAME="TA-Demisto"
ADD_ON_DIR="${ADD_ON_ROOT}/${ADD_ON_NAME}"
ARTIFACTS_DIR="${REPO_ROOT}/artifacts"
SPL_PATH="${ARTIFACTS_DIR}/demisto-add-on-for-splunk.tgz"

SPLUNK_IMAGE="splunk/splunk:latest"
# Splunk publishes its images for linux/amd64. On Apple Silicon / arm64 hosts,
# many tags (e.g. 10.2.6) have NO arm64 manifest, so Docker refuses to pull them
# unless we explicitly request the amd64 platform (runs via emulation). Default
# to linux/amd64; override with --platform if needed.
SPLUNK_PLATFORM="linux/amd64"
APPINSPECT_VENV="${TMPDIR:-/tmp}/ta-demisto-appinspect-venv"
CONTAINER_NAME="ta-demisto-compat-$$"
# The add-on is installed into the container FROM THE PACKAGED .tgz (see
# stage_runtime_install), never bind-mounted from the repo source tree. Splunk's
# runtime writes (local/ credentials, etc.) stay inside the disposable container
# and are discarded when it is removed on cleanup.
# Splunk admin credentials for the container. These are NOT hardcoded here;
# they are read from .env (SPLUNK_USERNAME / SPLUNK_PASSWORD) by the loader
# below. The Splunk Docker image always provisions an 'admin' account, and the
# password must satisfy Splunk's password policy. See:
#   https://splunk.github.io/docker-splunk/ADVANCED.html
SPLUNK_USERNAME=""
SPLUNK_PASSWORD=""

HEALTH_MAX_TRIES=15
HEALTH_SLEEP_SECONDS=20

SKIP_TESTS=false
SKIP_APPINSPECT=false
SKIP_RUNTIME=false
KEEP_CONTAINER=false
RUN_XSOAR=false          # opt-in: live end-to-end incident creation in XSOAR
XSOAR_NG=false           # target XSOAR NG (v8+): auth_id + NG REST endpoints

ENV_FILE="${REPO_ROOT}/.env"

# Load Splunk admin credentials from .env (SPLUNK_USERNAME / SPLUNK_PASSWORD).
# There are no hardcoded defaults; the values come solely from .env. Kept inline
# (and early) so it runs before any stage; the general read_env_var helper is
# defined later.
if [ -f "${ENV_FILE}" ]; then
  _env_splunk_user="$(grep -E '^SPLUNK_USERNAME=' "${ENV_FILE}" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'" | sed 's/[[:space:]]*$//')"
  _env_splunk_pass="$(grep -E '^SPLUNK_PASSWORD=' "${ENV_FILE}" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '"' | tr -d "'" | sed 's/[[:space:]]*$//')"
  [ -n "${_env_splunk_user}" ] && SPLUNK_USERNAME="${_env_splunk_user}"
  [ -n "${_env_splunk_pass}" ] && SPLUNK_PASSWORD="${_env_splunk_pass}"
  unset _env_splunk_user _env_splunk_pass
fi

XSOAR_INSTANCE_NAME=""   # name of the XSOAR server instance configured in the add-on
XSOAR_POLL_MAX_TRIES=12
XSOAR_POLL_SLEEP_SECONDS=10

# Effective (resolved) XSOAR connection values. These are populated by
# load_xsoar_env from either the v6 (DEMISTO6_*) or the NG (DEMISTO8_*) set of
# variables in .env, depending on --xsoar-ng / auto-detection.
DEMISTO_BASE_URL=""
DEMISTO_API_KEY=""
DEMISTO_AUTH_ID=""       # XSOAR NG (v8+) API key ID; sent as x-xdr-auth-id

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RED="$(printf '\033[31m')"; C_GRN="$(printf '\033[32m')"
  C_YEL="$(printf '\033[33m')"; C_BLU="$(printf '\033[34m')"
  C_BOLD="$(printf '\033[1m')"; C_RST="$(printf '\033[0m')"
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BOLD=""; C_RST=""
fi

# Ordered list of "STAGE|RESULT" records for the final summary.
declare -a RESULTS=()

log()  { printf '%s[compat]%s %s\n' "${C_BLU}" "${C_RST}" "$*"; }
warn() { printf '%s[compat]%s %s\n' "${C_YEL}" "${C_RST}" "$*" >&2; }
err()  { printf '%s[compat]%s %s\n' "${C_RED}" "${C_RST}" "$*" >&2; }

record_pass() { RESULTS+=("$1|PASS"); log "${C_GRN}PASS${C_RST}: $1"; }
record_fail() { RESULTS+=("$1|FAIL"); err "${C_RED}FAIL${C_RST}: $1"; }
record_skip() { RESULTS+=("$1|SKIP"); warn "SKIP: $1"; }

section() {
  printf '\n%s========================================================%s\n' "${C_BOLD}" "${C_RST}"
  printf '%s %s %s\n' "${C_BOLD}" "$*" "${C_RST}"
  printf '%s========================================================%s\n' "${C_BOLD}" "${C_RST}"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
usage() {
  sed -n '2,61p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-tests)      SKIP_TESTS=true ;;
    --skip-appinspect) SKIP_APPINSPECT=true ;;
    --skip-runtime)    SKIP_RUNTIME=true ;;
    --keep-container)  KEEP_CONTAINER=true ;;
    --image)           shift; SPLUNK_IMAGE="${1:?--image requires a value}" ;;
    --platform)        shift; SPLUNK_PLATFORM="${1:?--platform requires a value}" ;;
    --splunk-version)
      # Optional value: if the next token is missing or looks like another
      # flag, fall back to the default 'latest' image.
      if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then
        shift; SPLUNK_IMAGE="splunk/splunk:$1"
      else
        SPLUNK_IMAGE="splunk/splunk:latest"
      fi
      ;;
    --xsoar)           RUN_XSOAR=true ;;
    --xsoar-ng)        RUN_XSOAR=true; XSOAR_NG=true ;;
    --instance)        shift; XSOAR_INSTANCE_NAME="${1:?--instance requires a value}" ;;
    -h|--help)         usage; exit 0 ;;
    *) err "Unknown option: $1"; usage; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
  if [ "${KEEP_CONTAINER}" = true ]; then
    warn "Leaving container '${CONTAINER_NAME}' running (--keep-container)."
    warn "Remove it later with: docker rm -f ${CONTAINER_NAME}"
    warn "NOTE: the running container holds the installed add-on and any stored"
    warn "XSOAR credentials; remove it when done to discard that runtime state."
    return
  fi
  # Removing the container discards all runtime state (installed app + any stored
  # encrypted XSOAR credentials); nothing is written back to the repo source tree.
  if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "${CONTAINER_NAME}"; then
    log "Removing container '${CONTAINER_NAME}'..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Stage 1: Preflight
# ---------------------------------------------------------------------------
stage_preflight() {
  section "Stage 1/9: Preflight"
  local ok=true

  if ! command -v docker >/dev/null 2>&1; then
    record_fail "preflight: docker not found on PATH"; ok=false
  elif ! docker info >/dev/null 2>&1; then
    record_fail "preflight: docker daemon not reachable (is Docker running?)"; ok=false
  fi

  if [ ! -d "${ADD_ON_DIR}" ]; then
    record_fail "preflight: add-on dir not found at ${ADD_ON_DIR}"; ok=false
  fi

  if [ "${SKIP_TESTS}" = false ] && ! command -v pipenv >/dev/null 2>&1; then
    warn "pipenv not found - test stage will be skipped."
    SKIP_TESTS=true
  fi

  if [ "${ok}" = true ]; then
    record_pass "preflight"
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Stage 2: Lint + unit tests (same commands as CI)
# ---------------------------------------------------------------------------
stage_tests() {
  section "Stage 2/9: Lint + Unit Tests"
  if [ "${SKIP_TESTS}" = true ]; then
    record_skip "tests"
    return 0
  fi

  local ok=true
  ( cd "${REPO_ROOT}" && pipenv run flake8 ./add-on/TA-Demisto ) || ok=false
  ( cd "${REPO_ROOT}" && pipenv run pytest -v ) || ok=false

  if [ "${ok}" = true ]; then record_pass "tests"; else record_fail "tests"; fi
}

# ---------------------------------------------------------------------------
# Stage 3: Package the add-on (identical to CI tar command)
# ---------------------------------------------------------------------------
stage_package() {
  section "Stage 3/9: Package Add-on"
  mkdir -p "${ARTIFACTS_DIR}"
  rm -f "${SPL_PATH}"

  # Remove runtime-generated / non-packable files from the SOURCE add-on tree
  # before building the SPL. Splunk (and prior runs of this script) can leave
  # behind state that must never ship in the package:
  #   - metadata/local.meta : fails AppInspect (check_for_local_meta) and may
  #                           contain encrypted credential references
  #   - local/              : runtime config incl. encrypted credentials
  #   - *.pyc / __pycache__ : compiled Python
  #   - .DS_Store / ._*     : macOS cruft (prohibited-file checks)
  # These are also .gitignored, so deleting them keeps the working tree clean.
  log "Cleaning runtime-generated files from the source add-on tree..."
  rm -f  "${ADD_ON_DIR}/metadata/local.meta" 2>/dev/null || true
  rm -rf "${ADD_ON_DIR}/local" 2>/dev/null || true
  find "${ADD_ON_DIR}" \
      \( -name '*.pyc' -o -name '.DS_Store' -o -name '._*' \) \
      -type f -delete 2>/dev/null || true
  find "${ADD_ON_DIR}" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

  # Exclude macOS cruft (.DS_Store, ._* AppleDouble), compiled Python, and any
  # runtime-generated local state. These trip AppInspect checks:
  #   - .DS_Store / ._*  -> "prohibited files" / "files outside of app"
  #   - metadata/local.meta -> check_for_local_meta (all settings must be in
  #     default.meta); Splunk writes this file at runtime and it can also carry
  #     encrypted credential references, so it must never ship in the package.
  # COPYFILE_DISABLE=1 stops BSD tar from emitting ._* resource-fork entries.
  if ( cd "${ADD_ON_ROOT}" && COPYFILE_DISABLE=1 tar -czf "${SPL_PATH}" \
        --exclude='*.pyc' \
        --exclude='.DS_Store' \
        --exclude='._*' \
        --exclude="${ADD_ON_NAME}/metadata/local.meta" \
        --exclude="${ADD_ON_NAME}/local" \
        --exclude="${ADD_ON_NAME}/local.meta" \
        "${ADD_ON_NAME}" ) \
     && [ -s "${SPL_PATH}" ]; then
    record_pass "package (${SPL_PATH})"
    return 0
  fi
  record_fail "package"
  return 1
}

# ---------------------------------------------------------------------------
# Stage 4: AppInspect static checks (offline, no cloud credentials)
#
# Uses the official splunk-appinspect Python CLI installed into a throwaway
# virtualenv. This runs Splunk's own compatibility rule sets locally. The
# 'cloud' tag covers Splunk Cloud vetting rules (a superset of the Enterprise
# checks most relevant to compatibility).
# ---------------------------------------------------------------------------
stage_appinspect() {
  section "Stage 4/9: AppInspect (static compatibility)"
  if [ "${SKIP_APPINSPECT}" = true ]; then
    record_skip "appinspect"
    return 0
  fi
  if [ ! -s "${SPL_PATH}" ]; then
    record_fail "appinspect: package not found (${SPL_PATH})"
    return 1
  fi

  local py
  py="$(command -v python3 || command -v python || true)"
  if [ -z "${py}" ]; then
    warn "python3 not found; skipping AppInspect."
    record_skip "appinspect (no python)"
    return 0
  fi

  if [ ! -x "${APPINSPECT_VENV}/bin/splunk-appinspect" ]; then
    log "Installing splunk-appinspect into ${APPINSPECT_VENV} (first run only)..."
    if ! "${py}" -m venv "${APPINSPECT_VENV}" >/dev/null 2>&1 \
       || ! "${APPINSPECT_VENV}/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 \
       || ! "${APPINSPECT_VENV}/bin/pip" install --quiet splunk-appinspect >/dev/null 2>&1; then
      warn "Could not install splunk-appinspect (offline?). Skipping AppInspect."
      record_skip "appinspect (install failed)"
      return 0
    fi
  fi

  # splunk-appinspect depends on python-magic, which needs the native libmagic
  # library. On macOS this is provided by Homebrew (`brew install libmagic`).
  # If it's missing, degrade to SKIP with a clear hint instead of failing.
  local import_err
  import_err="$("${APPINSPECT_VENV}/bin/python" -c "import splunk_appinspect" 2>&1 || true)"
  if echo "${import_err}" | grep -qi 'libmagic'; then
    warn "splunk-appinspect requires libmagic, which is not installed."
    warn "Install it (macOS: 'brew install libmagic') and re-run to enable this stage."
    record_skip "appinspect (libmagic missing)"
    return 0
  fi

  local report="${ARTIFACTS_DIR}/appinspect-report.json"
  log "Running splunk-appinspect (mode=precert, tags=cloud)..."
  # splunk-appinspect exits non-zero when there are failures; it writes a
  # JSON report we keep for inspection.
  if "${APPINSPECT_VENV}/bin/splunk-appinspect" inspect "${SPL_PATH}" \
        --mode precert \
        --included-tags cloud \
        --output-file "${report}" \
        --data-format json; then
    record_pass "appinspect (report: ${report})"
    return 0
  fi
  err "AppInspect reported failures. Full report: ${report}"
  record_fail "appinspect"
  return 1
}

# ---------------------------------------------------------------------------
# Stage 5: Runtime on the latest Splunk image
# ---------------------------------------------------------------------------
stage_runtime_start() {
  section "Stage 5/9: Runtime on ${SPLUNK_IMAGE}"
  if [ "${SKIP_RUNTIME}" = true ]; then
    record_skip "runtime"
    return 1   # signal: downstream runtime stages should be skipped too
  fi

  # The runtime (and every downstream) stage needs Splunk admin creds. They are
  # sourced only from .env (SPLUNK_USERNAME / SPLUNK_PASSWORD); there are no
  # hardcoded defaults, so fail fast with a clear message if they are missing.
  if [ -z "${SPLUNK_USERNAME}" ] || [ -z "${SPLUNK_PASSWORD}" ]; then
    err "SPLUNK_USERNAME / SPLUNK_PASSWORD are not set. Add them to ${ENV_FILE}."
    err "The Splunk image uses an 'admin' account and a policy-compliant password;"
    err "see https://splunk.github.io/docker-splunk/ADVANCED.html"
    record_fail "runtime"
    return 1
  fi

  # Splunk images are amd64-only for many tags; on arm64 hosts we must request
  # the platform explicitly or the pull/run fails with "no matching manifest".
  local platform_args=()
  if [ -n "${SPLUNK_PLATFORM}" ]; then
    platform_args=(--platform "${SPLUNK_PLATFORM}")
    log "Using platform ${SPLUNK_PLATFORM} (emulated on non-matching hosts)."
  fi

  log "Pulling ${SPLUNK_IMAGE}..."
  docker pull "${platform_args[@]}" "${SPLUNK_IMAGE}" >/dev/null 2>&1 \
      || warn "Pull failed; using local image if present."

  # We do NOT bind-mount the repo source tree. Instead we boot a clean Splunk,
  # then INSTALL the packaged .tgz (the same artifact AppInspect validated) via
  # the apps REST endpoint. This exercises the real install path (packaging,
  # permissions, app.conf [install]/setup handling) and does not depend on any
  # local source files being present at runtime. The install itself happens in
  # stage_runtime_install, after the container is healthy.
  if [ ! -s "${SPL_PATH}" ]; then
    err "Packaged add-on '${SPL_PATH}' not found. The package stage must run first."
    record_fail "runtime: missing package artifact"
    return 1
  fi

  log "Starting a CLEAN container '${CONTAINER_NAME}' (add-on installed from the .tgz later)..."
  if docker run -d \
        "${platform_args[@]}" \
        --name "${CONTAINER_NAME}" \
        -p 8000:8000 -p 8088:8088 -p 8089:8089 \
        -e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" \
        -e "SPLUNK_START_ARGS=--accept-license" \
        -e "SPLUNK_PASSWORD=${SPLUNK_PASSWORD}" \
        "${SPLUNK_IMAGE}" >/dev/null; then
    record_pass "runtime: container started"
    return 0
  fi
  record_fail "runtime: container failed to start"
  return 1
}

# ---------------------------------------------------------------------------
# Stage 6b: Install the packaged add-on from the .tgz (real install flow)
#
# Copies the built .tgz into the running container and installs it through the
# Splunk apps REST endpoint (POST /services/apps/local with name=<path> &
# filename=true), exactly as an "install app from file" / Splunkbase install
# would. Then restarts splunkd and waits for the app to load. No source-tree
# bind mount, no reliance on local files at runtime.
# ---------------------------------------------------------------------------
stage_runtime_install() {
  section "Stage 6b/9: Install Packaged Add-on (.tgz via apps REST)"

  local in_container="/tmp/${ADD_ON_NAME}.tgz"
  log "Copying packaged add-on into the container (${SPL_PATH} -> ${in_container})..."
  if ! docker cp "${SPL_PATH}" "${CONTAINER_NAME}:${in_container}"; then
    record_fail "install: docker cp failed"
    return 1
  fi

  log "Installing via apps REST endpoint (POST /services/apps/local, filename=true)..."
  local install_code
  install_code="$(docker exec "${CONTAINER_NAME}" curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" \
      -o /dev/null -w '%{http_code}' \
      "https://localhost:8089/services/apps/local" \
      -d "name=${in_container}" \
      -d "filename=true" \
      -d "update=true" \
      -d "output_mode=json" 2>/dev/null || echo "000")"
  log "App install returned HTTP ${install_code}."

  case "${install_code}" in
    2??) : ;;  # created/updated OK
    *)
      err "App install via REST failed (HTTP ${install_code}). Recent logs:"
      docker logs --tail 30 "${CONTAINER_NAME}" 2>&1 || true
      record_fail "install: REST install failed (HTTP ${install_code})"
      return 1
      ;;
  esac

  # Installing an app requires a restart to fully load its Python/REST handlers.
  log "Restarting splunkd so the freshly installed add-on loads..."
  docker exec "${CONTAINER_NAME}" curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" \
      -X POST "https://localhost:8089/services/server/control/restart" \
      -d "output_mode=json" >/dev/null 2>&1 || true

  # Wait for splunkd to come back and serve the app over REST.
  local tries=1 max=30
  while [ "${tries}" -le "${max}" ]; do
    sleep "${HEALTH_SLEEP_SECONDS}"
    if docker exec "${CONTAINER_NAME}" curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" \
         "https://localhost:8089/services/apps/local/${ADD_ON_NAME}?output_mode=json" 2>/dev/null \
         | grep -q "\"name\":\"${ADD_ON_NAME}\""; then
      log "Add-on is served over REST after restart (attempt ${tries})."
      record_pass "install: packaged add-on installed"
      return 0
    fi
    log "attempt ${tries}/${max}: splunkd/app not ready yet after restart..."
    tries=$((tries + 1))
  done

  err "Add-on did not become available via REST after install+restart."
  docker logs --tail 40 "${CONTAINER_NAME}" 2>&1 || true
  record_fail "install: add-on not available after restart"
  return 1
}

# ---------------------------------------------------------------------------
# Stage 6: Health poll
# ---------------------------------------------------------------------------
stage_health() {
  section "Stage 6/9: Container Health"
  local tries=1 status="starting"
  while [ "${tries}" -le "${HEALTH_MAX_TRIES}" ]; do
    status="$(docker inspect --format='{{.State.Health.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "unknown")"
    log "attempt ${tries}/${HEALTH_MAX_TRIES}: health=${status}"
    if [ "${status}" = "healthy" ]; then
      record_pass "health"
      return 0
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
      err "Container exited unexpectedly. Recent logs:"
      docker logs --tail 40 "${CONTAINER_NAME}" 2>&1 || true
      record_fail "health: container exited"
      return 1
    fi
    sleep "${HEALTH_SLEEP_SECONDS}"
    tries=$((tries + 1))
  done
  err "Container did not become healthy. Recent logs:"
  docker logs --tail 40 "${CONTAINER_NAME}" 2>&1 || true
  record_fail "health: timeout after $((HEALTH_MAX_TRIES * HEALTH_SLEEP_SECONDS))s"
  return 1
}

# ---------------------------------------------------------------------------
# Stage 7: Verify the add-on actually loaded
# ---------------------------------------------------------------------------
stage_verify() {
  section "Stage 7/9: Verify Add-on Loaded"
  local ok=true

  # Query the running splunkd over the management port (8089) from inside the
  # container using curl. This talks to the live process, avoiding the
  # filesystem-permission issues that plague the CLI/btool when the container's
  # exec user is not the 'splunk' user.
  log "Querying REST (mgmt port 8089) for add-on state..."
  local rest_out
  rest_out="$(docker exec "${CONTAINER_NAME}" \
      curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" \
      "https://localhost:8089/services/apps/local/${ADD_ON_NAME}?output_mode=json" 2>/dev/null || true)"

  if [ -z "${rest_out}" ] || ! echo "${rest_out}" | grep -q "\"name\":\"${ADD_ON_NAME}\""; then
    err "Add-on '${ADD_ON_NAME}' not found via REST."
    err "Response head: $(echo "${rest_out}" | head -c 200)"
    ok=false
  else
    # Parse the 'disabled' flag from the JSON content block.
    local state
    state="$(docker exec "${CONTAINER_NAME}" bash -c \
        "curl -sk -u '${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}' 'https://localhost:8089/services/apps/local/${ADD_ON_NAME}?output_mode=json' \
         | python3 -c \"import sys,json; c=json.load(sys.stdin)['entry'][0]['content']; print('disabled=%s version=%s' % (c.get('disabled'), c.get('version')))\"" 2>/dev/null || true)"
    log "Add-on state: ${state:-unknown}"
    if echo "${state}" | grep -qi 'disabled=True'; then
      err "Add-on is present but DISABLED."
      ok=false
    fi
  fi

  if [ "${ok}" = true ]; then record_pass "verify"; else record_fail "verify"; fi
}

# ---------------------------------------------------------------------------
# Stage 8: Scan logs for add-on errors
# ---------------------------------------------------------------------------
stage_logs() {
  section "Stage 8/9: Log Scan"
  local ok=true

  log "Scanning splunkd.log for ${ADD_ON_NAME} errors..."
  local splunkd_hits
  splunkd_hits="$(docker exec "${CONTAINER_NAME}" bash -c \
      "grep -iE 'ERROR|FATAL' /opt/splunk/var/log/splunk/splunkd.log 2>/dev/null | grep -i '${ADD_ON_NAME}' || true")"
  if [ -n "${splunkd_hits}" ]; then
    err "Add-on-related errors in splunkd.log:"
    echo "${splunkd_hits}" | head -n 30
    ok=false
  fi

  log "Scanning add-on modalert log (if present)..."
  local modalert_hits
  modalert_hits="$(docker exec "${CONTAINER_NAME}" bash -c \
      "grep -iE 'ERROR|Traceback' /opt/splunk/var/log/splunk/create_xsoar_incident_modalert.log 2>/dev/null || true")"
  if [ -n "${modalert_hits}" ]; then
    err "Errors in create_xsoar_incident_modalert.log:"
    echo "${modalert_hits}" | head -n 30
    ok=false
  fi

  if [ "${ok}" = true ]; then record_pass "logs"; else record_fail "logs"; fi
}

# ---------------------------------------------------------------------------
# Stage 9: Summary
# ---------------------------------------------------------------------------
stage_summary() {
  section "Stage 9/9: Summary"
  local failures=0
  local rec stage result
  for rec in "${RESULTS[@]}"; do
    stage="${rec%%|*}"
    result="${rec##*|}"
    case "${result}" in
      PASS) printf '  %sPASS%s  %s\n' "${C_GRN}" "${C_RST}" "${stage}" ;;
      SKIP) printf '  %sSKIP%s  %s\n' "${C_YEL}" "${C_RST}" "${stage}" ;;
      FAIL) printf '  %sFAIL%s  %s\n' "${C_RED}" "${C_RST}" "${stage}"; failures=$((failures + 1)) ;;
    esac
  done

  printf '\n'
  if [ "${failures}" -eq 0 ]; then
    log "${C_GRN}Compatibility check PASSED on ${SPLUNK_IMAGE}.${C_RST}"
    return 0
  fi
  err "${C_RED}Compatibility check FAILED: ${failures} stage(s) failed.${C_RST}"
  return 1
}

# ---------------------------------------------------------------------------
# Optional Stage: Live end-to-end incident creation in XSOAR
#
# Enabled with --xsoar. Reads DEMISTO_BASE_URL / DEMISTO_API_KEY from .env,
# creates a scheduled saved search whose alert action (create_xsoar_incident)
# fires against the already-configured XSOAR instance with a unique marker in
# the incident name, dispatches it, then polls XSOAR's /incidents/search API
# (XSOAR v6) to confirm the incident was actually created.
# ---------------------------------------------------------------------------
# Configure (idempotently) one XSOAR server instance inside the running add-on
# via the ta_demisto_account REST endpoint. username = server URL, password =
# API key (stored encrypted by Splunk). Safe to call repeatedly.
#   $1 flavor ("v6"|"ng")  $2 stanza  $3 url  $4 api_key  $5 auth_id (ng only)
configure_xsoar_instance() {
  local flavor="$1" stanza="$2" url="$3" api_key="$4" auth_id="${5:-}"
  local acct_base="https://localhost:8089/servicesNS/nobody/${ADD_ON_NAME}/TA_Demisto_account"

  # For XSOAR NG (v8+) the add-on expects an *Advanced* API key stored in the
  # password field as "<API_KEY>$<KEY_ID>" (per README). Compose it here so the
  # add-on can split it back out. For v6 the raw API key is used as-is.
  local api_secret="${api_key}"
  if [ "${flavor}" = "ng" ]; then
    api_secret="${api_key}\$${auth_id}"
    log "Configuring XSOAR NG instance (stanza='${stanza}', url='${url}', auth_id set)..."
  else
    log "Configuring XSOAR v6 instance (stanza='${stanza}', url='${url}')..."
  fi

  # Create-or-edit, best effort. NOTE: the add-on's UCC REST handler can throw a
  # 500 on read-back (_encrypt_raw_credentials) even when the credential is
  # stored fine, so we DO NOT trust a list/GET here. The real proof that config
  # worked is whether an incident is actually created in XSOAR downstream.
  local create_code
  create_code="$(docker exec "${CONTAINER_NAME}" curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" \
      -o /dev/null -w '%{http_code}' \
      "${acct_base}" \
      --data-urlencode "name=${stanza}" \
      --data-urlencode "username=${url}" \
      --data-urlencode "password=${api_secret}" \
      -d "output_mode=json" 2>/dev/null || echo "000")"

  log "Account create returned HTTP ${create_code}."
  # 201 = created, 409 = already exists -> edit its credentials instead.
  if [ "${create_code}" = "409" ]; then
    local edit_code
    edit_code="$(docker exec "${CONTAINER_NAME}" curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" \
        -o /dev/null -w '%{http_code}' \
        "${acct_base}/${stanza}" \
        --data-urlencode "username=${url}" \
        --data-urlencode "password=${api_secret}" \
        -d "output_mode=json" 2>/dev/null || echo "000")"
    log "Account edit returned HTTP ${edit_code}."
  fi

  # Treat 2xx/409 as "configured"; the incident poll is the authoritative check.
  case "${create_code}" in
    2??|409) log "XSOAR instance '${stanza}' configured (server: ${url})."; return 0 ;;
    *) err "Account create returned HTTP ${create_code}; continuing (incident poll decides)."; return 0 ;;
  esac
}

# Read a single KEY=value from .env, stripping quotes/whitespace. Empty if absent.
read_env_var() {
  grep -E "^$1=" "${ENV_FILE}" 2>/dev/null | tail -n1 | cut -d= -f2- \
    | tr -d '"' | tr -d "'" | sed 's/[[:space:]]*$//'
}

# Run the full incident-creation + verification flow against ONE XSOAR flavor.
#   $1 flavor ("v6"|"ng")  $2 stanza  $3 url  $4 api_key  $5 auth_id (ng only)
# Records its own pass/fail and returns 0/1 accordingly.
run_xsoar_flavor() {
  local flavor="$1" stanza="$2" url="$3" api_key="$4" auth_id="${5:-}"
  local label; [ "${flavor}" = "ng" ] && label="NG" || label="v6"

  section "XSOAR ${label} - Live Incident Creation (${url})"

  if ! configure_xsoar_instance "${flavor}" "${stanza}" "${url}" "${api_key}" "${auth_id}"; then
    record_fail "xsoar ${label}: instance auto-configuration failed"
    return 1
  fi

  # Derive the tested Splunk version from the image tag (part after ':'),
  # defaulting to 'latest'. Sanitize to keep the marker filename/search-safe.
  local splunk_ver="${SPLUNK_IMAGE##*:}"
  [ "${splunk_ver}" = "${SPLUNK_IMAGE}" ] && splunk_ver="latest"
  splunk_ver="$(printf '%s' "${splunk_ver}" | tr -c 'A-Za-z0-9._' '-')"

  local marker="SPLUNK-COMPAT-${splunk_ver}-${flavor}-$(date +%Y%m%d%H%M%S)-$$"
  local search_name="ta_demisto_compat_${marker}"
  # SPL that always returns exactly one row carrying the marker as a field.
  local spl="| makeresults | eval host=\"compat-host\", marker=\"${marker}\""

  log "Creating scheduled alert '${search_name}' (marker: ${marker})..."
  # The incident name embeds the marker so we can find it unambiguously. The
  # alert targets THIS flavor's server via server_url (send_all_servers=false)
  # so v6 and NG runs don't cross-fire into each other.
  local create_out
  create_out="$(docker exec "${CONTAINER_NAME}" curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" \
      "https://localhost:8089/servicesNS/admin/${ADD_ON_NAME}/saved/searches" \
      -d "name=${search_name}" \
      --data-urlencode "search=${spl}" \
      -d "is_scheduled=1" \
      -d "cron_schedule=*/1 * * * *" \
      -d "dispatch.earliest_time=-5m" \
      -d "dispatch.latest_time=now" \
      -d "alert_type=always" \
      -d "alert.track=1" \
      -d "actions=create_xsoar_incident" \
      --data-urlencode "action.create_xsoar_incident.param.incident_name=${marker} from Splunk" \
      -d "action.create_xsoar_incident.param.type=Unclassified" \
      -d "action.create_xsoar_incident.param.severity=1" \
      -d "action.create_xsoar_incident.param.send_all_servers=false" \
      --data-urlencode "action.create_xsoar_incident.param.server_url=${url}" \
      --data-urlencode "action.create_xsoar_incident.param.details=Compatibility test incident (${marker})" \
      -d "output_mode=json" 2>/dev/null || true)"

  if ! echo "${create_out}" | grep -q "\"name\":\"${search_name}\""; then
    err "Failed to create saved search. Response head:"
    echo "${create_out}" | head -c 400
    record_fail "xsoar ${label}: saved search creation failed"
    return 1
  fi

  log "Dispatching the alert to trigger incident creation now..."
  docker exec "${CONTAINER_NAME}" curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" \
      "https://localhost:8089/servicesNS/admin/${ADD_ON_NAME}/saved/searches/${search_name}/dispatch" \
      -d "trigger_actions=1" \
      -d "dispatch.now=true" \
      -d "output_mode=json" >/dev/null 2>&1 || true

  # Resolve the search endpoint for this flavor.
  #   v6:  POST <base>/incidents/search
  #   NG:  POST <base>/xsoar/public/v1/incidents/search
  local search_url="${url}/incidents/search"
  [ "${flavor}" = "ng" ] && search_url="${url}/xsoar/public/v1/incidents/search"

  log "Polling XSOAR ${label} (${url}) for incident with marker '${marker}'..."
  local found=false tries=1 body="" incident_id=""
  local qbody="{\"filter\":{\"query\":\"name:\\\"${marker} from Splunk\\\"\",\"size\":10}}"
  while [ "${tries}" -le "${XSOAR_POLL_MAX_TRIES}" ]; do
    if [ "${flavor}" = "ng" ]; then
      # XSOAR NG requires an advanced-key auth computed fresh per request,
      # matching the add-on's scheme (see modalert helper process_event):
      #   nonce     = 64 random alphanumerics
      #   timestamp = epoch milliseconds (string)
      #   Authorization = sha256(api_key + nonce + timestamp).hexdigest()
      #   headers: x-xdr-auth-id / x-xdr-nonce / x-xdr-timestamp
      local ng_hdrs
      ng_hdrs="$(NG_API_KEY="${api_key}" NG_AUTH_ID="${auth_id}" python3 -c '
import os, secrets, string, hashlib, time
key = os.environ["NG_API_KEY"]
auth_id = os.environ["NG_AUTH_ID"]
nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
timestamp = str(int(time.time()) * 1000)
auth_hash = hashlib.sha256((key + nonce + timestamp).encode("utf-8")).hexdigest()
# Emit three lines: Authorization, nonce, timestamp.
print(auth_hash)
print(nonce)
print(timestamp)
' 2>/dev/null || true)"
      local ng_auth ng_nonce ng_ts
      ng_auth="$(printf '%s\n' "${ng_hdrs}" | sed -n '1p')"
      ng_nonce="$(printf '%s\n' "${ng_hdrs}" | sed -n '2p')"
      ng_ts="$(printf '%s\n' "${ng_hdrs}" | sed -n '3p')"
      body="$(curl -sk -X POST "${search_url}" \
          -H "Authorization: ${ng_auth}" \
          -H "x-xdr-auth-id: ${auth_id}" \
          -H "x-xdr-nonce: ${ng_nonce}" \
          -H "x-xdr-timestamp: ${ng_ts}" \
          -H "Content-Type: application/json" \
          -d "${qbody}" 2>/dev/null || true)"
    else
      body="$(curl -sk -X POST "${search_url}" \
          -H "Authorization: ${api_key}" \
          -H "Content-Type: application/json" \
          -d "${qbody}" 2>/dev/null || true)"
    fi
    if echo "${body}" | grep -q "${marker}"; then
      found=true
      break
    fi
    log "attempt ${tries}/${XSOAR_POLL_MAX_TRIES}: incident not visible yet..."
    sleep "${XSOAR_POLL_SLEEP_SECONDS}"
    tries=$((tries + 1))
  done

  # Best-effort cleanup of the temporary saved search.
  docker exec "${CONTAINER_NAME}" curl -sk -u "${SPLUNK_USERNAME}:${SPLUNK_PASSWORD}" -X DELETE \
      "https://localhost:8089/servicesNS/admin/${ADD_ON_NAME}/saved/searches/${search_name}" \
      >/dev/null 2>&1 || true

  if [ "${found}" = true ]; then
    # Extract the created incident's id so we can print a direct link.
    if command -v python3 >/dev/null 2>&1; then
      incident_id="$(printf '%s' "${body}" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
items = d.get("data") or d.get("incidents") or []
marker = sys.argv[1]
for it in items:
    if marker in (it.get("name") or ""):
        print(it.get("id") or it.get("investigationId") or "")
        break
' "${marker}" 2>/dev/null || true)"
    fi

    # Build a clickable URL to the incident:
    #   v6:  <base>/#/Details/<id>
    #   NG:  <ui-base>/incident/<id>
    # For NG, the API host is "api-<tenant>..." but the human-facing UI lives at
    # the same host WITHOUT the leading "api-" prefix, so strip it for the link.
    local incident_url=""
    if [ -n "${incident_id}" ]; then
      if [ "${flavor}" = "ng" ]; then
        local ui_base="${url}"
        # Strip a leading 'api-' from the host (handles http:// and https://).
        ui_base="$(printf '%s' "${ui_base}" | sed -E 's#^(https?://)api-#\1#')"
        incident_url="${ui_base}/incident/${incident_id}"
      else
        incident_url="${url}/#/Details/${incident_id}"
      fi
      log "${C_GRN}Incident URL:${C_RST} ${incident_url}"
      record_pass "xsoar ${label}: incident '${marker}' created (id=${incident_id}) -> ${incident_url}"
    else
      warn "Incident found but could not parse its id from the response."
      record_pass "xsoar ${label}: incident '${marker}' created in XSOAR"
    fi
    return 0
  fi
  err "Incident with marker '${marker}' not found in XSOAR ${label} after polling."
  record_fail "xsoar ${label}: incident not confirmed"
  return 1
}

# Orchestrate the XSOAR stage: detect which flavor(s) are configured in .env and
# run the live incident flow against EACH present flavor (v6, NG, or both).
#   XSOAR 6:  DEMISTO6_BASE_URL / DEMISTO6_API_KEY
#   XSOAR NG: DEMISTO8_BASE_URL / DEMISTO8_API_KEY / DEMISTO8_AUTH_ID
# Flag behavior: --xsoar-ng restricts to NG only; --xsoar (default) runs every
# flavor that has complete credentials.
stage_xsoar() {
  section "Optional Stage: Live XSOAR Incident Creation"
  if [ "${RUN_XSOAR}" != true ]; then
    record_skip "xsoar (not requested; use --xsoar)"
    return 0
  fi
  if [ ! -f "${ENV_FILE}" ]; then
    record_fail "xsoar: no .env at ${ENV_FILE}"
    return 1
  fi

  local v6_url v6_key v8_url v8_key v8_auth
  v6_url="$(read_env_var DEMISTO6_BASE_URL)"; v6_url="${v6_url%/}"
  v6_key="$(read_env_var DEMISTO6_API_KEY)"
  v8_url="$(read_env_var DEMISTO8_BASE_URL)"; v8_url="${v8_url%/}"
  v8_key="$(read_env_var DEMISTO8_API_KEY)"
  v8_auth="$(read_env_var DEMISTO8_AUTH_ID)"

  local v6_ready=false ng_ready=false
  [ -n "${v6_url}" ] && [ -n "${v6_key}" ] && v6_ready=true
  [ -n "${v8_url}" ] && [ -n "${v8_key}" ] && [ -n "${v8_auth}" ] && ng_ready=true

  # --xsoar-ng restricts to NG only.
  if [ "${XSOAR_NG}" = true ]; then
    v6_ready=false
    if [ "${ng_ready}" != true ]; then
      record_fail "xsoar: --xsoar-ng set but DEMISTO8_BASE_URL / DEMISTO8_API_KEY / DEMISTO8_AUTH_ID missing in .env"
      return 1
    fi
  fi

  if [ "${v6_ready}" != true ] && [ "${ng_ready}" != true ]; then
    record_fail "xsoar: no complete credential set found in .env (need DEMISTO6_* and/or DEMISTO8_*)"
    return 1
  fi

  # Stanza slugs are per-flavor so both instances can coexist in the add-on.
  local v6_stanza="${XSOAR_INSTANCE_NAME:-xsoar_compat}_v6"
  local ng_stanza="${XSOAR_INSTANCE_NAME:-xsoar_compat}_ng"

  local overall_ok=true
  if [ "${v6_ready}" = true ]; then
    log "XSOAR v6 credentials detected; running v6 flow."
    run_xsoar_flavor "v6" "${v6_stanza}" "${v6_url}" "${v6_key}" "" || overall_ok=false
  fi
  if [ "${ng_ready}" = true ]; then
    log "XSOAR NG credentials detected; running NG flow."
    run_xsoar_flavor "ng" "${ng_stanza}" "${v8_url}" "${v8_key}" "${v8_auth}" || overall_ok=false
  fi

  [ "${overall_ok}" = true ] && return 0 || return 1
}

# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
main() {
  section "Demisto Add-on for Splunk - Local Compatibility Test"
  log "Repo:   ${REPO_ROOT}"
  log "Add-on: ${ADD_ON_DIR}"
  log "Image:  ${SPLUNK_IMAGE}"
  if [ "${RUN_XSOAR}" = true ]; then
    if [ "${XSOAR_NG}" = true ]; then
      log "XSOAR:  end-to-end enabled (target: XSOAR NG / v8+)"
    else
      log "XSOAR:  end-to-end enabled (target: XSOAR v6)"
    fi
  fi

  # Preflight is a hard gate.
  if ! stage_preflight; then
    stage_summary || true
    exit 1
  fi

  # These stages record their own results and never abort the run so the
  # summary can report every stage. errexit is relaxed around them.
  set +o errexit
  stage_tests
  stage_package
  stage_appinspect

  local runtime_ok=true
  stage_runtime_start || runtime_ok=false
  if [ "${runtime_ok}" = true ] && [ "${SKIP_RUNTIME}" = false ]; then
    # Wait for the clean Splunk to be healthy, then install the packaged .tgz
    # (real install flow) before verifying/exercising the add-on.
    if stage_health && stage_runtime_install; then
      stage_verify
      stage_logs
      stage_xsoar
    fi
  fi
  set -o errexit

  stage_summary
}

main "$@"
