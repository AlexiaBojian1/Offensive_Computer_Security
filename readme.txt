UI of the Scapy Attack Tool - a Guide for Users

Software Overview

Desktop UI for launching DNS spoofing, ARP poisoning and SSL stripping with using Scapy. And PySlide6 is used to create the UI. It includes real time logging of what has happened and there is a built in help pdf that the users can use whne they are lost.

Prerequisites (these can change in the future this is what we thought at the moment)

Operating System: Linux 
Python: 3.7 or newer
Permissions: Run with root/administrator rights

Installation

Install required packages:
pip install scapy PySide6 PyYAML
Place the main script (ui.py) and help.pdf in the same folder.

Launching the Application
Run the UI with sudo (or equivalent):
sudo python ui.py

Main Window Layout

Toolbar (Top)
• Interface: Dropdown to select your network adapter (e.g. eth0, wlan0) (this is not fully integrated at the moment)
• Load DNS Mapping…: Opens file dialog to load a YAML file mapping domains to spoofed IPs
• Help: Opens the bundled help.pdf in your system’s default PDF viewer (help.pdf is not yet ready as we are currently working on it; so, there is only a test pdf)
• Quit: Closes the application

Targets Panel (Left)
A table with columns IP, Mask, Spoof IP
Click + Add row to insert a new target for ARP poisoning

Modes Panel (Center) (these modes are not implemented; hwoever we have some progress on ARP poisoning and DNS spoofing)
Checkboxes to enable one or more attack modes:
• ARP Poisoning
• DNS Spoofing
• SSL Stripping

Logs Panel (Right)
Live, timestamped output showing ARP replies sent and DNS queries spoofed

Control Buttons (Bottom)
• Silent / All-Out (radio buttons): choose between stealth or aggressive timing (not yet implemented)
• Start: Begin selected attacks
• Pause / Resume: Temporarily suspend and resume packet loops (not yet implemented)
• Stop: Halt all activity and threads


Pausing and Resuming

Click Pause to suspend packet loops without killing threads

Button label switches to Resume—click again to continue


Stopping

Click Stop to terminate all attacks and return to an idle state


Help

Click the Help button to open help.pdf

If the PDF is missing, you’ll see an error prompt
