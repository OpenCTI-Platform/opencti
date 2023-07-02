# Prerequisites Windows

Development stack require some base software that need to be installed.

## Docker or podman

Platform dependencies in development are deployed through container management, so you need to install a container stack.

We currently support docker and postman.

Docker Desktop from - [https://docs.docker.com/desktop/install/windows-install/](https://docs.docker.com/desktop/install/windows-install/)

- Install new version of - [https://docs.microsoft.com/windows/wsl/wsl2-kernel](https://docs.microsoft.com/windows/wsl/wsl2-kernel). This will require a reboot.
- Shell out to CMD as Administrator and run the following **powershell** command: 

`wsl --set-default-version 2`

- Reboot computer and continue to next step       
- Load Docker Application
- **NOTE DOCKER LICENSE - You are agreeing to the licence for Non-commercial Open Source Project use. OpenCTI is Open Source and the version you would be possibly contributing to enhancing is the unpaid non-commercial/non-enterprise version. If you intention is different - please consult with your organization's legal/licensing department.**
- Leave Docker Desktop running

## NodeJS and yarn

The platform is developed on nodejs technology, so you need to install node and the yarn package manager.

- Install NodeJS from - [https://nodejs.org/download/release/v16.20.0/node-v16.20.0-x64.msi](https://nodejs.org/download/release/v16.20.0/node-v16.20.0-x64.msi)
   - Select the option for installing Chocolatey on the Tools for Native Modules screen
       - Will do this install for you automatically - [https://chocolatey.org/packages/visualstudio2019-workload-vctools](https://chocolatey.org/packages/visualstudio2019-workload-vctools)
       - Includes Python 3.11.4
   - Shell out to CMD prompt as Administrator and install/run:
       - `pip3 install pywin32`

- Configure Yarn ([https://yarnpkg.com/getting-started/install](https://yarnpkg.com/getting-started/install))
   - Open CMD as Administrator and run the following command:
       - `corepack enable`

## Python runtime

For worker and connectors, a python runtime is needed. Even if you already have a python runtime installed through node installation, 
on windows some nodejs package will be recompiled with python and C++ runtime. 

For this reason **Visual Studio Build Tools** is required.

- Install Visual Studio Build Tools from - [https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools)
  - Check off Desktop Development with C++
  - Run install

## Git and dev tool

- Download GIT for Windows (64-bit Setup)- [https://git-scm.com/download/win](https://git-scm.com/download/win)
  - Just use defaults on each screen

- Install your preferred IDE
  - Intellij community edition - [https://www.jetbrains.com/idea/download/](https://www.jetbrains.com/idea/download/)
  - VSCode - [https://code.visualstudio.com/docs/?dv=win64](https://code.visualstudio.com/docs/?dv=win64)


     


