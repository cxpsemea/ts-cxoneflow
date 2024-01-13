#!/bin/bash

pushd $(dirname "$0")

# -----------------------------
# Create cxinventory executable
# -----------------------------
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=../.dist/cxoneflow/ubuntu --workpath=temp --paths=../shared ../cxoneflow/cxoneflow.py
cp ../cxoneflow/src/cxoneflowapplication.yaml ../.dist/cxoneflow/ubuntu/application.yaml
cp ../LICENSE ../.dist/cxoneflow/ubuntu/LICENSE
rm -f -r --interactive=never cxoneflow.spec
rm -f -r --interactive=never temp
tar -czvf ../.dist/cxoneflow-ubuntu64.tar.gz -C ../.dist/cxoneflow/ubuntu .

popd