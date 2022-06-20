# task-manager-hider

DLL that can hide arbitrary processes/programs from Windows Task Manager by performing IAT hooking on NtQuerySystemInformation.

### Usage

Inject the DLL using any method (e.g LoadLibrary) into (64 bit) Task Manager. Specify the process to be hidden. 
[Video demo](https://youtu.be/dl-Sqp9_em8). For 32 bit systems, compile the DLL in 32 bit.

Hiding multiple different processes could be easily achieved by modifying the name checks when looping through the SystemProcessInformation linked list.
