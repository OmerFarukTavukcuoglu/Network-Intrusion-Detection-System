<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
</head>
<body>

<h1>🚀 Network Intrusion Detection System (IDS/IPS)</h1>

<h2>📌 Overview</h2>

<p>
    The <b>Network Intrusion Detection System (IDS) and Intrusion Prevention System (IPS)</b> is a powerful security tool designed to monitor network traffic, identify malicious activities, and log or prevent unauthorized access. It captures live network packets using raw sockets, decodes packet headers, and applies signature-based detection to flag potential threats.
</p>

<h3>🔹 Key Capabilities:</h3>
<ul>
    <li>✅ <b>Live Packet Capture:</b> Monitors incoming and outgoing network traffic.</li>
    <li>✅ <b>Signature-Based Detection:</b> Compares packet payloads against predefined attack patterns.</li>
    <li>✅ <b>Real-Time Logging:</b> Alerts are logged in real time with timestamps for further analysis.</li>
    <li>✅ <b>Modular & Extensible:</b> New attack signatures and detection rules can be added easily.</li>
    <li>✅ <b>Intrusion Prevention Mode:</b> Can actively block malicious IPs when enabled.</li>
</ul>

<h2>⚙️ Features</h2>

<h3>🔍 Packet Capture</h3>
<ul>
    <li>Uses raw sockets to capture network packets directly from a specified network interface.</li>
    <li>Supports monitoring of Ethernet, IPv4, and IPv6 traffic.</li>
</ul>

<h3>🔎 Signature-Based Detection</h3>
<ul>
    <li>Predefined attack signatures to detect suspicious payloads in network packets.</li>
    <li>Customizable rules to extend detection capabilities.</li>
</ul>

<h3>📋 Real-Time Logging</h3>
<ul>
    <li>Records detected threats in real-time to an alert log file.</li>
    <li>Stores timestamp, source/destination IP, protocol, and signature match.</li>
</ul>

<h3>🛠 Modular Design</h3>
<ul>
    <li>Easily extendable detection logic.</li>
    <li>Pluggable logging system for database or remote logging integration.</li>
</ul>

<h3>🛑 Intrusion Prevention (IPS Mode)</h3>
<ul>
    <li>Can be configured to actively block malicious IPs using firewall rules.</li>
    <li>Provides an additional layer of security against real-time threats.</li>
</ul>

<h2>📥 Installation</h2>

<h3>📌 Prerequisites</h3>
<ul>
    <li>Python <b>3.8+</b> is required.</li>
    <li>Root privileges are needed for raw socket access.</li>
</ul>

<h3>📌 Clone the Repository</h3>
<pre>
<code>git clone https://github.com/yourusername/Cybersecurity-Portfolio.git
cd Cybersecurity-Portfolio/2_Network_IDS_IPS</code>
</pre>

<h2>⚙️ Configuration</h2>

<table border="1">
    <tr>
        <th>Parameter</th>
        <th>Description</th>
        <th>Example</th>
    </tr>
    <tr>
        <td><b>--interface</b></td>
        <td>Specify the network interface for packet capture.</td>
        <td>eth0</td>
    </tr>
    <tr>
        <td><b>--mode</b></td>
        <td>Set IDS (detect only) or IPS (detect & block).</td>
        <td>IDS / IPS</td>
    </tr>
    <tr>
        <td><b>--log</b></td>
        <td>Specify the log file for recording alerts.</td>
        <td>ids_alerts.log</td>
    </tr>
</table>

<h2>🚀 Usage</h2>

<h3>🔹 Run the IDS</h3>
<p>To start the intrusion detection system:</p>
<pre>
<code>sudo python ids.py --interface eth0 --mode IDS</code>
</pre>

<h3>🔹 Run the IPS (Blocking Mode)</h3>
<p>To enable automatic blocking of malicious activity:</p>
<pre>
<code>sudo python ids.py --interface eth0 --mode IPS</code>
</pre>

<h2>🏗 Architecture Overview</h2>

<p>The <b>Network IDS/IPS</b> consists of multiple modular components:</p>

<ul>
    <li><b>🛠 Packet Capture Module:</b> Uses raw sockets to intercept network packets.</li>
    <li><b>🛠 Protocol Decoding Module:</b> Extracts Ethernet, IP, and TCP/UDP headers.</li>
    <li><b>🛠 Signature Detection Module:</b> Compares packet payloads to known attack patterns.</li>
    <li><b>🛠 Logging Module:</b> Writes intrusion alerts to <code>ids_alerts.log</code>.</li>
    <li><b>🛠 Prevention Module (IPS Mode):</b> Blocks malicious IPs dynamically.</li>
</ul>

<p>📌 <b>Architecture Diagram:</b> See <b>docs/architecture.png</b> for details.</p>

<h2>📊 Sample Output</h2>

<h3>📄 Log File Example:</h3>
<p>Alerts are logged in <b>ids_alerts.log</b>. Example:</p>

<pre>
[2024-02-14 15:23:12] ALERT: Malicious packet detected from 192.168.1.100 (Signature Match: SQL Injection)
[2024-02-14 15:23:45] ALERT: Unauthorized access attempt from 10.0.0.5 (Signature Match: SSH Brute Force)
</pre>

<p>📌 <b>Sample log file:</b> See <b>docs/sample_ids_alerts.log</b></p>

<h2>🎯 Contributing</h2>

<p>🚀 Contributions are welcome! If you'd like to contribute:</p>

<ol>
    <li>Fork the repository.</li>
    <li>Create a feature branch.</li>
    <li>Commit changes following best practices.</li>
    <li>Submit a pull request.</li>
</ol>

<p>🔹 Ensure that your code follows <b>PEP8</b> guidelines and includes <b>unit tests</b> before submitting.</p>

<h2>📜 License</h2>

<p>This project is licensed under the <b>MIT License</b>. See the <b>LICENSE</b> file for details.</p>

<h2>🛠 Future Enhancements</h2>

<ul>
    <li>✔ Real-time Threat Intelligence Feed Integration</li>
    <li>✔ Advanced Machine Learning-based Anomaly Detection</li>
    <li>✔ Web Interface for Alert Visualization</li>
</ul>

<h2>🚀 Developed for security professionals, system administrators, and ethical hackers.</h2>
<h3>Happy Monitoring! 🛡️</h3>

</body>
</html>
