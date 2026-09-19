Gotcha

Network security laboratory toolkit for Windows — traffic analysis helpers, protocol attacks, and high-rate flood modules for controlled testing environments.



Author: hedromanie
Repository: https://github.com/hedromanie/Gotcha
Linux port (official fork): https://github.com/TeZFuN/Gotcha-linux
License: MIT



⚠️ Legal notice

Gotcha is intended only for:





authorized penetration testing



education and research



your own lab / networks you own or have explicit written permission to test

Unauthorized use against third-party systems is illegal. You are solely responsible for how you use this software.



Features

Auxiliary







Tool



Description





ICMP Ping



Reachability check





Port Scan



Simple TCP port probe





Traceroute



Path discovery (tracert)





Routing table



IPv4 route dump





Network adapters



Interface / IP / MAC list





Network scan



Local /24 ARP discovery

Attacks







Module



Engine



Notes





Packet intercept



Scapy



Capture / inspect / modify packets





DHCP Starvation



Scapy



Exhaust DHCP pool with fake clients





DoS — TCP SYN



WinDivert (NPtcpT)



High-rate SYN flood, 1–8 threads





DoS — UDP



WinDivert (NPudpT)



UDP flood, configurable size





DoS — ICMP



WinDivert (NPicmpT)



Echo Request flood





DoS — DNS



WinDivert (NPdnsT)



DNS Query flood to UDP/53





DoS — ARP



Npcap (NParpT)



L2 ARP flood, optional random MAC/IP





ARP Spoofing



Scapy



MITM-oriented ARP poisoning





DNS Spoofing



Scapy



Spoof DNS answers (rules / catch-all)





MAC flood



Npcap (NPmac-aT)



Random source MAC frames

Stack split (by design):





WinDivert — L3/L4 floods (TCP, UDP, ICMP, DNS)



Npcap — true L2 (ARP, MAC flood)



Scapy — interactive / stateful lab tools (spoof, DHCP, intercept)



Install from Release (recommended)





Open Releases and download the Windows installer, e.g.
gotcha-win10-x64-v2.3-setup.exe
(exact name changes with the version).



Run the setup (Administrator recommended).



Choose the install directory.



Optionally allow install of Wireshark / Nmap when prompted.



Launch Gotcha from the Start menu or install folder.

The installer ships ready-to-run binaries and required DLLs (WinDivert, Npcap-compatible libraries). No manual Npcap GUI installer is required — the project uses a silent/compat install path (npcap.py + bundled files).

Requirements at runtime





Windows 10/11 x64



Administrator rights (WinDivert / raw send / driver)



Nothing else if you use the official setup



Run from source (development)

1. Python





Tested on Python 3.11.6 (3.10+ should work)



Install dependencies:

pip install -r requirements.txt

Contents of requirements.txt:

scapy>=2.5.0
psutil>=5.9.0

(tkinter is part of the standard Windows Python installer — enable Tcl/Tk if you use embeddable builds.)

2. Native flood modules

Toolchain used upstream: MinGW g++.

Headers / import libs live in the project tree:





Include\ — windivert.h, pcap.h, …



Lib\x64\ — WinDivert.lib, wpcap.lib, …



WinDivert runtime: WinDivert.dll + WinDivert64.sys next to the flood .exe files

VS Code tasks (.vscode\tasks.json):







Task



Use for





build-windivert



NPtcpT, NPudpT, NPicmpT, NPdnsT





build-npcap



NParpT, NPmac-aT

Example (from project root, adjust paths):

:: WinDivert module
g++ -O2 -o main\bin\NPtcpT.exe workspace\NPtcpT.cpp -IInclude -LLib\x64 -lWinDivert -lws2_32 -liphlpapi

:: Npcap module
g++ -O2 -o main\bin\NParpT.exe workspace\NParpT.cpp -IInclude -LLib\x64 -lwpcap -lws2_32 -liphlpapi

Put compiled tools and DLLs where the GUI can find them (typically main\bin\ or bin\ next to Gotcha.py).

3. Npcap (L2 modules)

Official Npcap GUI installer is not required. Use the project helper:

python npcap.py --install

Place wpcap.dll, packet.dll, NPFInstall.exe (and npf.sys if available) next to npcap.py. Run elevated. This installs in WinPcap-compatible mode so ARP/MAC modules resolve wpcap.dll from System32.

4. Start GUI

python Gotcha.py

On Windows the app requests Administrator elevation automatically (UAC).



Project layout (overview)

Gotcha/
├── Gotcha.py              # Main GUI
├── npcap.py               # Silent Npcap-compatible install helper
├── requirements.txt
├── Include/               # Headers (WinDivert, pcap, …)
├── Lib/x64/               # Import libraries
├── main/bin/              # Built flood .exe + runtime DLLs
├── workspace/             # C++ sources (or repo root, depending on branch)
│   ├── NPtcpT.cpp
│   ├── NPudpT.cpp
│   ├── NPicmpT.cpp
│   ├── NPdnsT.cpp
│   ├── NParpT.cpp
│   └── NPmac-aT.cpp
└── .vscode/               # Build / debug tasks

Release packages contain prebuilt .exe and DLLs only — you do not need a compiler to use Gotcha from Releases.



Building a full installer (maintainers)

Typical pipeline used for official Windows builds:





PyInstaller — package Gotcha.py (and npcap.py if shipped as a helper).



Compile all NP*.cpp modules into main\bin\.



Bundle WinDivert + Npcap-compat DLLs/driver helpers.



Inno Setup — produce gotcha-win10-x64-vX.Y-setup.exe with optional Wireshark/Nmap offers.



Linux

Use the official Linux fork maintained for non-Windows environments:

https://github.com/TeZFuN/Gotcha-linux

Windows-specific pieces (WinDivert, Npcap, Inno installer) do not apply there; see that repository’s README for stack and build steps.



Troubleshooting







Symptom



What to check





WinDivertOpen failed / access denied



Run as Administrator; WinDivert.dll + WinDivert64.sys next to the flood exe





wpcap.dll not found



Run npcap.py --install elevated, or place DLLs next to ARP/MAC exe





GUI starts then exits



UAC declined; start again and accept elevation





Flood exe not found



Ensure binaries are under bin\ or main\bin\ relative to Gotcha.py





Low DNS/TCP rate on Scapy-only paths



Use the native DoS tab modules (NPdnsT, NPtcpT, …)



Credits





hedromanie — Gotcha (Windows)



TeZFuN — Gotcha-linux official Linux fork



WinDivert — packet diversion on Windows



Npcap — Windows packet capture / injection API



Scapy — interactive packet crafting



License

MIT — see LICENSE.
