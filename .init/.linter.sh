#!/bin/bash
cd /home/kavia/workspace/code-generation/photo-editor-pro-206616-206625/photo_editing_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi

