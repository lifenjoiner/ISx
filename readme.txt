ISx is an InstallShield installer extractor.

Why I made it?
There is a program which is old but needed. It's packaged by InstallShield.
It is no longer maintained. I need to change some actions of the installation,
and make the installation work well.

What doest this program do?
It focuses on why it is created.
It extracts ALL the components of the InstallShield installer.

The capability?
DevStudio 9 (2003) to InstallShield 2016, based on my limited tests.

Usage?
ISx <file>

Compile?
It's coded on Windows, and has been compiled by tcc/gcc/msvc. Read the comments.

Dependency?
miniz's tinfl. Of course you can make your preferred wrapper.

Further information?
1. You can use 'ISCab' from InstallShield (2009) to modify the cab file(s).
2. You can use 'Orca' to modify the msi files.
3. You can use 'isd'/'sid' to the inx/ins file.
4. You can run the extracted '*_sfx.exe' file to launch the installation.
5. For the older version installer, try 'IsXunpack'.
6. More? Read the source file!
