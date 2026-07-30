# WebDefend: Confidence-Weighted Ensemble for Detecting Coordinated Web Attacks in SD-IoT via Stateful Traffic Analysis

This repository contains the source code, configuration files, and documentation for WebDefend, a framework designed to detect and mitigate coordinated web attacks in Software-Defined IoT (SD-IoT) environments. WebDefend integrates multiple layers of detection and mitigation, leveraging P4-enabled switches and intelligent control plane algorithms.

## Project Overview

WebDefend combines several key modules to provide robust protection:

* **P4-EWTP Module:** Implements data plane-based early stage threat prevention using P4, providing real-time traffic monitoring, feature extraction, attack detection, and alerting.
* **CWE Module:** Utilizes a Confidence-Weighted Ensemble algorithm for accurate attack classification in the control plane.
* **CRS Module:** Implements a Coordinated Response System to effectively counter advanced web attacks through coordinated control plane actions.

This repository provides a fully integrated implementation of WebDefend, along with individual modules for flexible exploration and deployment.

## Repository Structure

The repository is organized as follows:

* **`CRS - java (ONOS, ODL, Flood, Beacon)`:** Contains Java source files for the CRS module, compatible with ONOS, ODL, Floodlight, and Beacon controllers.
* **`CRS - Python (Ryu & POX)`:** Contains Python source files for the CRS module, compatible with Ryu and POX controllers.
* **`CWE - java (Beacon)`:** Contains Java source files for the CWE module, tailored for Beacon.
* **`CWE - java (Floodlight)`:** Contains Java source files for the CWE module, tailored for Floodlight.
* **`CWE - java (ONOS)`:** Contains Java source files for the CWE module, tailored for ONOS.
* **`CWE - java (OpenDaylight)`:** Contains Java source files for the CWE module, tailored for OpenDaylight.
* **`CWE - Python (POX)`:** Contains Python source files for the CWE module, tailored for POX.
* **`CWE - Python (Ryu)`:** Contains Python source files for the CWE module, tailored for Ryu.
* **`P4_tutorial/`:** Contains tutorial materials and examples related to P4 programming.
* **`P4 - EWTP Module - (P4) - Ingress Processing and State Updates.pdf`:** Contains P4 source code, explanations, and deployment instructions for Ingress Processing and State Updates.
* **`P4 - EWTP Module - (P4) - Real-time Attack Detection and Alerting.pdf`:** Contains P4 source code, explanations, and deployment instructions for Real-time Attack Detection and Alerting.
* **`P4 - EWTP Module App - (P4) - Ingress Processing and ....pdf`:** Contains P4 source code, explanations, and deployment instructions for the complete P4 EWTP application.
* **`P4-Mininet_App.py`:** Python script for setting up the SD-IoT network using Mininet-WiFi.
* **`P4runtime_switch.py`:** Python script for interacting with the P4 switch using P4Runtime.
* **`P4-SW[1-4]-runtime/`:** Contains JSON configuration files for the P4 switches.
* **`WebDefend - Topology.py`:** Python script defining the network topology for WebDefend.
* **`WebDefend - Top - JSON.json`:** JSON file defining the network topology for WebDefend.

## Getting Started

To run the WebDefend framework, follow these general steps:

1.  **Environment Setup:** Ensure you have the necessary software installed:
    * Mininet-WiFi
    * P4 compiler (`p4c`)
    * P4 runtime environment (e.g., `simple_switch`)
    * ONOS, ODL, Floodlight, Beacon, Ryu, or POX controllers
    * Python 3 with required libraries (see respective module files for dependencies).
    * Java Development Kit (JDK) for Java-based modules.
    * Weka python wrapper for machine learning components.

2.  **Network Setup:** Use `P4-Mininet_App.py`, `WebDefend - Topology.json`, and `WebDefend - Top - JSON.json` to create the SD-IoT network topology in Mininet-WiFi.

3.  **P4 Switch Configuration:** Compile the P4 programs from the EWTP Module (P4 - EWTP Module.P4) and configure the P4 switches using the provided JSON configuration files (`P4-SW[1-4]-runtime/`).

4.  **CWE Module Deployment:** Deploy the CWE module (Java or Python) on your chosen SDN controller (ONOS, ODL, Floodlight, Beacon, Ryu, or POX) using the instructions in the respective PDF files.

5.  **CRS Module Deployment:** Deploy the CRS module (Java or Python) on your chosen platform, ensuring it is configured to communicate with the CWE module and the P4 switches, using the instructions in the respective PDF files.

6.  **Integration:** Configure the communication between the P4 switches and the control plane modules to enable the complete framework functionality.

7.  **Testing:** Generate attack traffic and verify the detection and mitigation capabilities of the WebDefend framework.

## Module-Specific Instructions

For detailed instructions on each module, please refer to the corresponding PDF files:

* `P4 - EWTP Module - (P4) - Ingress Processing and State Updates.pdf`
* `P4 - EWTP Module - (P4) - Real-time Attack Detection and Alerting.pdf`
* `P4 - EWTP Module App - (P4) - Ingress Processing and ....pdf`
* `CWE - java (Beacon).pdf`, etc.
* `CWE - Python (POX).pdf`, etc.
* `CRS - java (ONOS, ODL, Flood, Beacon).pdf`, etc.
* `CRS - Python (Ryu & POX).pdf`

## Dependencies

The project has the following dependencies:

* Mininet-WiFi
* P4 compiler (`p4c`)
* P4 runtime environment (e.g., `simple_switch`)
* ONOS, ODL, Floodlight, Beacon, Ryu, or POX controllers
* Python 3
* Java Development Kit (JDK)
* Python and Java libraries (see respective module files for detailed lists)
* Weka python wrapper
