@echo off
pushd "%~dp0"

:: -----------------------------
:: Create cxinventory executable
:: -----------------------------
create-version-file ..\cxoneflow\src\cxoneflowmanifestwindows.yaml --outfile cxoneflowmanifestwindows.txt
pyinstaller --clean --noconfirm --onefile --nowindow --distpath=..\.dist\cxoneflow\windows --workpath=temp --paths=..\shared --version-file=cxoneflowmanifestwindows.txt --icon=..\shared\imaging\icon.ico ..\cxoneflow\cxoneflow.py
copy ..\cxoneflow\src\cxoneflowapplication.yaml ..\.dist\cxoneflow\windows\application.yaml
copy ..\LICENSE ..\.dist\cxoneflow\windows\LICENSE
del cxoneflowmanifestwindows.txt
del cxoneflow.spec
rmdir /s /q temp
powershell Compress-Archive -Force -CompressionLevel Optimal -Path ..\.dist\cxoneflow\windows\* ..\.dist\cxoneflow-win64.zip

popd
