#!/bin/sh
set -e

# Default UID and GID if not specified
PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

# Use existing group if the GID is already taken, otherwise create one
if ! getent group "${PGID}" >/dev/null 2>&1; then
    addgroup -g "${PGID}" sbv
fi
SBV_GROUP="$(getent group "${PGID}" | cut -d: -f1)"

# Use existing user if the UID is already taken, otherwise create one
if ! getent passwd "${PUID}" >/dev/null 2>&1; then
    adduser -D -u "${PUID}" -G "${SBV_GROUP}" sbv
fi
SBV_USER="$(getent passwd "${PUID}" | cut -d: -f1)"

# Ensure data directory exists and has correct permissions
mkdir -p "${DB_PATH_PREFIX:-/data}"
chown -R "${SBV_USER}:${SBV_GROUP}" "${DB_PATH_PREFIX:-/data}"

# Log the user we're running as
echo "Running as UID=${PUID} GID=${PGID} (${SBV_USER}:${SBV_GROUP})"

# Switch to the sbv user and execute the application
exec su-exec "${SBV_USER}" "$@"
