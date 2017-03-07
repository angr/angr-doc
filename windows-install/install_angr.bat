;@echo off

powershell -Command "wget https://github.com/angr/archinfo/archive/master.zip -OutFile archinfo-master.zip"
powershell -Command "wget https://github.com/angr/pyvex/archive/master.zip -OutFile pyvex-master.zip"
powershell -Command "wget https://github.com/angr/cle/archive/master.zip -OutFile cle-master.zip"
powershell -Command "wget https://github.com/angr/simuvex/archive/master.zip -OutFile simuvex-master.zip"
powershell -Command "wget https://github.com/angr/angr/archive/master.zip -OutFile angr-master.zip"
powershell -Command "wget https://github.com/unicorn-engine/unicorn/releases/download/1.0/unicorn-1.0.0-python-win32.msi -OutFile unicorn-python.msi"
powershell -Command "wget https://github.com/unicorn-engine/unicorn/releases/download/1.0/unicorn-1.0-win32.zip -OutFile unicorn-core.zip"
powershell -Command "wget https://github.com/aquynh/capstone/releases/download/3.0.5-rc2/capstone-3.0.5-rc2-python-win32.msi -OutFile capstone-python.msi"
powershell -Command "Expand-Archive -Force archinfo-master.zip ."
powershell -Command "Expand-Archive -Force pyvex-master.zip ."
powershell -Command "Expand-Archive -Force cle-master.zip ."
powershell -Command "Expand-Archive -Force simuvex-master.zip ."
powershell -Command "Expand-Archive -Force angr-master.zip ."
powershell -Command "Expand-Archive -Force unicorn-core.zip ."

cd archinfo-master
mv requirements.txt requirements.txt.bak
powershell -Command "wget https://raw.githubusercontent.com/Spirotot/angr_windows_install/master/requirements/archinfo_requirements.txt -OutFile requirements.txt"
python setup.py install

cd ..\pyvex-master
mv requirements.txt requirements.txt.bak
powershell -Command "wget https://raw.githubusercontent.com/Spirotot/angr_windows_install/master/requirements/pyvex_requirements.txt -OutFile requirements.txt"
pip install -r requirements.txt
python setup.py install

cd ..
unicorn-python.msi
if errorlevel 1 (
    echo Warning: Unicorn installer failed!
REM    exit /b %errorlevel%
)
python copy_unicorn_files.py unicorn-1.0-win32

capstone-python.msi
if errorlevel 1 (
    echo Warning: Capstone installer failed!
REM    exit /b %errorlevel%
)

pip install .\simuvex-master .\cle-master

cd angr-master
mv requirements.txt requirements.txt.bak
powershell -Command "wget https://raw.githubusercontent.com/Spirotot/angr_windows_install/master/requirements/angr_requirements.txt -OutFile requirements.txt"
pip install -r requirements.txt
cd ..
pip install .\angr-master
