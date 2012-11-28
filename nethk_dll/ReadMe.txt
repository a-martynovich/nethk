========================================================================
    nethk.dll - WSPAPI interception (now with HTTP support)
========================================================================

Developed by Artem Martynovich for MOBILE PRO TECH.

This DLL uses libnethk API to print out intercepted network traffic. Thus
it has a dependency on libnethk, and it will be built first. The configu-
rations are the same as for libnethk, except for the _TRACE macro. The
latter turns on and off debug output, but the intercepted data is printed
regardless of this macro.

You can turn on and off HTTP message debug output by using _TRACE_HTTP macro.
