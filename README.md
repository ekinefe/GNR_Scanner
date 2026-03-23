# GNR_Scanner

A Python-based Terminal User Interface (TUI) for Linux system security and hardware telemetry. 

🚧 **Project Status: Active Development** 🚧

We are currently developing the core features of this product. The `main` branch is reserved for final stable releases. 

**To see the latest features, code updates, and ongoing work, please switch to the `dev` branch!**

## About The Project

GNR_Scanner acts as an advanced security orchestrator directly within the Linux terminal. It automates the installation, updating, and execution of industry-standard security tools, wrapping them in a highly responsive and modern Textual UI. 

Currently, the dashboard integrates with **ClamAV** (Anti-Virus) and **RKHunter** (Rootkit Hunter), with plans to expand the toolset in future updates.

## Current Features

* **Automated Dependency Management:** Automatically detects if ClamAV or RKHunter are missing and handles installation and database updates seamlessly in the background.
* **Live Hardware Telemetry:** Monitors real-time CPU usage, RAM consumption, Root Disk capacity, Core Temperatures, and Fan RPM during heavy scan operations.
* **Multiple Scan Modes:**
  * **Quick Scan:** A highly optimized ClamAV scan targeting high-risk directories (`/home`, `/etc`, `/tmp`) with strict file-size and scan-time limitations to prevent system hanging.
  * **Deep Scan:** A comprehensive, full-system ClamAV sweep.
  * **System Check:** Executes RKHunter to verify system binary integrity and detect hidden rootkits.
  * **Combo Scan:** A sequential pipeline that runs both tools back-to-back for maximum security auditing.
* **Automated Logging:** Generates physical, timestamped log files of all terminal output and detected threats for post-scan analysis.

## Technologies Used
* **Python 3**
* **Textual** (TUI Framework)
* **Psutil** (Hardware metrics)
* **Subprocess & OS** (System-level execution)

---
This project is released under the MIT License. If you use this code in your own public or commercial projects, a visible credit in your UI or documentation linking back to this repository is highly appreciated!
