#!/bin/bash
# Prevent direct commits to main branch
# Part of family workflow protection

BRANCH=$(git rev-parse --abbrev-ref HEAD)

if [ "$BRANCH" = "main" ]; then
    cat <<EOF
ERROR: Direct commits to main are not allowed

This protects:
  - PR workflow (changes should be reviewable)
  - Code review before merge
  - Family coordination (clear feature branches)

Create a feature branch:
  git checkout -b <your-name>/<feature-name>

EOF
    exit 1
fi

exit 0
