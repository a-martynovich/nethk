========================================================================
    libnethk.lib - WSPAPI interception
========================================================================

Developed by Artem Martynovich for MOBILE PRO TECH.

You can use "Debug", "Debug mincrt" and "Release" configurations to build 
the solution for both x86 and x64. The "Debug" configuration has standard 
CRT enabled, the two others have it disabled.

You can define macros to help you debug nethk:
  _TRACE makes nethk print debug info to OutputDebugString;    
  _TRACE_NETHK, _TRACE_HANDLERS and _TRACE_MHOOKS print even more data.

*: requires standard CRT