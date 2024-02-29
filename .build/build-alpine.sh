#!/bin/bash

pushd $(dirname "$0")

# -----------------------------
# Create cxinventory executable
# -----------------------------
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/cxoneflow/alpine --workpath=temp --paths=../shared ../cxoneflow/cxoneflow.py
cp ../cxoneflow/src/cxoneflowapplication.yaml ../.dist/cxoneflow/alpine/application.yaml
cp ../LICENSE ../.dist/cxoneflow/alpine/LICENSE
rm -f -r cxoneflow.spec
rm -f -r temp
tar -czvf ../.dist/cxoneflow-alpine64.tar.gz -C ../.dist/cxoneflow/alpine .

popd