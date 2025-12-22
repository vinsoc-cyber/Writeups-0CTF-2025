#!/bin/sh
set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <ID> <FD>" >&2
    exit 1
fi

ID="$1"
FD="$2"

TEMPLATE_ROOT="/usr/jails/template"
CONN_ROOT="/usr/jails/conn_${ID}"
JAIL_NAME="conn_${ID}"
SERVICE_PATH="/env_manager"

# Tunables (override via environment)
# WARNING: it may changed on server
TIMEOUT_SECONDS=${TIMEOUT_SECONDS:-360}          # Wall-clock limit for the jail process
TIMEOUT_KILL_GRACE=${TIMEOUT_KILL_GRACE:-5}      # Extra seconds before force-kill after timeout
MEMORY_LIMIT=${MEMORY_LIMIT:-512M}
CPU_PCT_LIMIT=${CPU_PCT_LIMIT:-100}               # Percent of one CPU
TMPFS_SIZE=${TMPFS_SIZE:-512M}                   # Bounds writable space inside the jail

if [ ! -d "${TEMPLATE_ROOT}" ]; then
    echo "Template root ${TEMPLATE_ROOT} does not exist" >&2
    exit 1
fi
if [ ! -x "${TEMPLATE_ROOT}${SERVICE_PATH}" ]; then
    echo "Service ${TEMPLATE_ROOT}${SERVICE_PATH} not found or not executable" >&2
    exit 1
fi

cleanup() {
    jail -r "${JAIL_NAME}" 2>/dev/null || true
    rctl -r "jail:${JAIL_NAME}" 2>/dev/null || true
    umount "${CONN_ROOT}/tmp"    2>/dev/null || true
    umount "${CONN_ROOT}/dev"    2>/dev/null || true
    umount "${CONN_ROOT}"        2>/dev/null || true
    rm -rf "${CONN_ROOT}" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

mkdir -p "${CONN_ROOT}"
mkdir -p "${CONN_ROOT}/tmp" \
         "${CONN_ROOT}/dev"

# 1) Base system, read‑only, at /
mount -t nullfs -o ro "${TEMPLATE_ROOT}" "${CONN_ROOT}"

# 2) Writable tmpfs on top of places you need write access
mount -t tmpfs -o size="${TMPFS_SIZE}" tmpfs "${CONN_ROOT}/tmp"
chmod 1777 "${CONN_ROOT}/tmp"

# 3) devfs
mount -t devfs devfs "${CONN_ROOT}/dev"

# Resource controls (jail-scoped) — deny hard limits if exceeded
rctl -r "jail:${JAIL_NAME}" 2>/dev/null || true
rctl -a "jail:${JAIL_NAME}:memoryuse:deny=${MEMORY_LIMIT}"
rctl -a "jail:${JAIL_NAME}:pcpu:deny=${CPU_PCT_LIMIT}"

# Jail (timeout enforces overall lifetime)
timeout -k "${TIMEOUT_KILL_GRACE}s" "${TIMEOUT_SECONDS}s" \
  jail -c \
    name="${JAIL_NAME}" \
    host.hostname="${JAIL_NAME}.local" \
    path="${CONN_ROOT}" \
    allow.raw_sockets=0 \
    command="${SERVICE_PATH}" \
    <&${FD} >&${FD} 2>&1
