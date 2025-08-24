<div align="center">
  <h1>📡 Network Traffic Visualizer 📊</h1>
  <p>
    A real-time network traffic monitoring and visualization tool. This project evolved from a low-level C++ DNS server into a dynamic Python-based packet sniffer that visualizes network flows and protocol distribution using Scapy and Matplotlib.
  </p>
</div>

---

## 📖 Project Story

This project is a tale of two phases, starting with low-level C++ networking and evolving into a high-level Python visualization tool.

### ⚙️ Phase 1: The C++ Foundation - A Mock DNS Server
The journey began with a C++ application that simulated an authoritative DNS server. The primary goal was to gain a fundamental understanding of network protocols, packet structures, and socket programming.

*   **Implemented a UDP server** on port 53 to listen for DNS queries.
*   **Parsed raw DNS query packets** to extract requested domain names.
*   **Crafted and sent valid DNS responses** for predefined domains.
*   Gained hands-on experience with the **Winsock API, byte-order conversions (htons, htonl), and the DNS protocol (RFC 1035)**.

This initial phase provided a solid, low-level foundation in networking concepts.

### 🐍 Phase 2: The Python Evolution - Real-Time Sniffer & Visualizer
Building on the C++ experience, the project transitioned to Python for its flexibility and powerful libraries. Using **Scapy**, a packet sniffer was developed to capture, analyze, and visualize live network traffic in real-time.

*   **Live Packet Capture**: Sniffs network traffic on the local machine.
*   **Protocol Analysis**: Identifies and categorizes packets by protocol (TCP, UDP, ICMP).
*   **Data Flow Tracking**: Monitors the volume of data transferred between unique source/destination pairs.
*   **Real-time Visualization**: Uses **Matplotlib** to display the captured data in continuously updating charts.

---

## ✨ Features

*   **Live Traffic Analysis**: Captures and processes network packets on the fly.
*   **Multi-Protocol Support**: Differentiates between TCP, UDP, and ICMP traffic.
*   **Flow-Based Monitoring**: Tracks data volume for each distinct network flow (Source IP/Port -> Destination IP/Port).
*   **Dummy Traffic Generator**: Includes a simple traffic generator for demonstration purposes.
*   **Dual-Chart Visualization**:
    *   📊 **Bar Chart**: Displays the total bytes transferred for each network flow.
    *   🥧 **Pie Chart**: Shows the percentage-based distribution of traffic across different protocols.

---

## 🛠️ Tech Stack

*   **Python Sniffer & Visualizer**:
    *   ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
    *   ![Scapy](https://img.shields.io/badge/Scapy-000000?style=for-the-badge&logo=python&logoColor=white)
    *   ![Matplotlib](https://img.shields.io/badge/Matplotlib-3776AB?style=for-the-badge&logo=matplotlib&logoColor=white)
*   **Mock DNS Server (Legacy)**:
    *   ![C++](https://img.shields.io/badge/C%2B%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
    *   **Winsock2 API**

---

## 🚀 Getting Started

### Prerequisites

Ensure you have Python installed on your system. You will also need to install the required libraries.

### Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/Rudraksha-007/Traffic-Visualizer.git
    cd Traffic-Visualizer
    ```

2.  **Install Python libraries:**
    ```sh
    pip install scapy matplotlib
    ```

### Running the Visualizer

To start capturing and visualizing network traffic, run the `logger.py` script. You may need to run this with administrative/root privileges to allow Scapy to capture network packets.

```sh
# On Windows (run PowerShell/CMD as Administrator)
python logger.py

# On Linux/macOS
sudo python logger.py
```

The script will open a Matplotlib window with two updating charts.

#### Optional Flag

*   `--tcp-only`: Use this flag to filter the visualization and show only TCP traffic.
    ```sh
    python logger.py --tcp-only
    ```

---

## 📈 Example Visualizations

The tool generates two main visualizations that update every second:

1.  **Data Volume by Flow**: A horizontal bar chart showing the amount of data (in bytes) exchanged in each flow.
2.  **Protocol Distribution**: A pie chart illustrating the share of each protocol (TCP, UDP, ICMP) in the total traffic.

*(Example images of the charts would go here)*

---

## ✅ Learnings & Future Work

This project was an excellent exercise in both low-level and high-level networking. The C++ phase solidified my understanding of core protocols, while the Python phase highlighted the power of modern libraries for rapid development and data visualization.

**Future enhancements could include:**
*   Developing a full-fledged web-based dashboard (e.g., using Flask or Django).
*   Adding more detailed packet analysis (e.g., DNS query types, HTTP requests).
*   Implementing alerts for unusual traffic patterns.
*   Saving and loading captured data for offline analysis.
</div>
