========================================================================
    nethk_load.exe: nethk injector
========================================================================

Developed by Artem Martynovich for MOBILE PRO TECH.

nethk_load injects nethk.dll into target process using traditional 
CreateRemoteThread technique. It also opens a named pipe \\.\pipe\Nethk<pid>,
where <pid> is a PID of the target process, reads from it and prints formatted
data.

Call nethk_load as follows:

  nethk_load 
If nethk.dll residing in the same directory as nethk_load is found, nethk_load
will prompt for PID of the target process. Otherwise it fails.

  nethk_load <arg>
will inject nethk.dll residing in the same directory as nethk_load to the
process with PID=<arg>, if the former was found. Otherwise nethk_load treats
<arg> as a path to nethk.dll and will prompt for PID of the process.

  nethk_load <file> <pid>
Will inject a dll file <file> into proces with PID=<pid>.

WHATSNEW in Milestone 2:
The DLL is now ejected after you press 'q' for the first time. If you
eject nethk.dll, it might fail several times. It might take lots of time to
eject it. You have 2 options: 1) be patient 2) press Ctrl+C and kill target
process.

WHATSNEW in Milestone 3:
You can now see debug output in the console window (colored in green).
