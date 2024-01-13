#!/bin/bash

pushd $(dirname "$0")

# -------------------------------
# GITHUB runner don't support ARM
# GitHub workflow sends "GITHUB-RUNNER"
# parameter if a macos runner is used
# -------------------------------

# -------------------------------------
# Put icon icns file in the same folder
# -------------------------------------
cp ../shared/imaging/icon.icns icon.icns

# -----------------------------
# Create cxinventory executable
# -----------------------------
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/cxoneflow/macos ---workpath=temp --paths=../shared --icon=icon.icns ../cxoneflow/cxoneflow.py
cp ../cxoneflow/src/cxoneflowapplication.yaml ../.dist/cxoneflow/macos/application.yaml
cp ../LICENSE ../.dist/cxinventory/cxoneflow/LICENSE
rm -f -r --interactive=never cxoneflow.spec
rm -f -r --interactive=never temp
tar -czvf ../.dist/cxoneflow-macos.tar.gz -C ../.dist/cxoneflow/macos .

popd