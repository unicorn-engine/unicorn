# Python Bindings for Unicorn

Originally written by Nguyen Anh Quynh, polished and redesigned by elicn, maintained by all community contributors.

## Install

Install a prebuilt wheel from PyPI:

```bash
pip3 install unicorn
```

In case you would like to develop the bindings:

```bash
# Python3
DEBUG=1 THREADS=4 pip3 install --user -e .
# Workaround for Pylance
DEBUG=1 THREADS=4 pip3 install --user -e . --config-settings editable_mode=strict
# Python2
DEBUG=1 THREADS=4 pip install -e .
```

or install it by building it by yourself:

```bash
# Python3
THREADS=4 pip3 install --user .
# Python2, unfortunately `pip2` doesn't support in-tree build
THREADS=4 python3 setup.py install
```

Explanations for arguments:

- `THREADS=4` will use 4 threads for building.
- `DEBUG=1` will build debug version of unicorn.
- `--user` will install the bindings to your user directory instead of requiring root permission.
- `-e` infers the editable mode, which gives your instant feedback instead of re-compiling every time.

Note that you should setup a valid building environment according to docs/COMPILE.md but not necessarily build it because `setup.py` will do this for you. 

## Python2 compatibility

By default, Unicorn python bindings will be maintained against Python3 as it offers more powerful features which improves developing efficiency. Meanwhile, Unicorn will only keep compatible with all features Unicorn1 offers regarding Python2 because Python2 has reached end-of-life for more than 3 years as the time of writing this README. While offering all features for both Python2 & Python3 is desirable and doable, it inevitably costs too much efforts to maintain and few users really rely on this. Therefore, we assume that if users still stick to Python2, previous Unicorn1 features we offer should be enough. If you really want some new features Unicorn2 offers, please check and pull request to `unicorn/unicorn_py2``. We are happy to review and accept!