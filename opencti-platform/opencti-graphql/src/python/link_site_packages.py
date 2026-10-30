"""Link <venv>/site-packages to the site-packages of the running virtual environment.

app:python_execution_venv points at this stable path, whatever the Python version
(lib/pythonX.Y/site-packages on POSIX, Lib/site-packages on Windows).
Run with the interpreter of the virtual environment: `yarn install:python` and the
platform Dockerfiles do.
"""

import os
import sys
import sysconfig

link = os.path.join(sys.prefix, "site-packages")
target = sysconfig.get_paths()["purelib"]
if not os.path.lexists(link):
    if os.name == "nt":
        # a directory junction needs no symlink privilege
        import _winapi

        _winapi.CreateJunction(target, link)
    else:
        os.symlink(target, link)
