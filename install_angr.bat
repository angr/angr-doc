;@echo off

powershell -Command "wget https://github.com/angr/archinfo/archive/master.zip -OutFile archinfo-master.zip"
powershell -Command "wget https://github.com/angr/pyvex/archive/master.zip -OutFile pyvex-master.zip"
powershell -Command "wget https://github.com/angr/angr/archive/master.zip -OutFile angr-master.zip"
powershell -Command "Expand-Archive archinfo-master.zip ."
powershell -Command "Expand-Archive pyvex-master.zip ."
powershell -Command "Expand-Archive angr-master.zip ."

pip install capstone-windows

cd archinfo-master
mv requirements.txt requirements.txt.bak
powershell -Command "wget https://raw.githubusercontent.com/Spirotot/angr_windows_install/master/requirements/archinfo_requirements.txt -OutFile requirements.txt"
python setup.py install

cd ..\pyvex-master
mv requirements.txt requirements.txt.bak
powershell -Command "wget https://raw.githubusercontent.com/Spirotot/angr_windows_install/master/requirements/pyvex_requirements.txt -OutFile requirements.txt"
python setup.py install
python setup.py install

cd ..\angr-master
mv requirements.txt requirements.txt.bak
powershell -Command "wget https://raw.githubusercontent.com/Spirotot/angr_windows_install/master/requirements/angr_requirements.txt -OutFile requirements.txt"
pip install -r requirements.txt
python setup.py install
