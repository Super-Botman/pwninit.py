mkdir dev_env
cd dev_env
python -m venv venv
rm -fr ./venv/lib/python3.*/site-packages/pwninit
ln -s $(pwd)/src/pwninit ./venv/lib/python3.*/site-packages/
