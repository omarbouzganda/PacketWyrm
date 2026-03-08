🐉 PacketWyrm - Network Guardian
A modern, Wireshark-like network packet analyzer with real-time capture, threat detection, and plain English explanations.

PacketWyrmLicensePlatform
🚀 PacketWyrm - Quick Start Guide
Requirements
Linux (Kali, Ubuntu, Debian) with libpcap-dev
Go 1.21+
Node.js 18+ (for frontend)
1️⃣ Clone & Build Backend
bash

# Install dependencies
sudo apt update && sudo apt install -y libpcap-dev

# Clone repository
git clone https://github.com/YOUR_USERNAME/packetwyrm.git
cd packetwyrm/packetwyrm-backend

# Build
go mod tidy
go build -o packetwyrm .
2️⃣ Run Backend (requires root)
bash

sudo ./packetwyrm
You'll see:

text

🐉 PACKETWYRM - Network Packet Analyzer v2.0
🚀 Server: http://localhost:8080
📡 WebSocket: ws://localhost:8080/ws/packets
3️⃣ Run Frontend
Open a new terminal:

bash

cd packetwyrm
npm install
npm run dev
Open browser: http://localhost:3000

4️⃣ Start Capturing
Select a network interface from dropdown
Click ▶ Start button
Watch packets flow in real-time!
📋 One-Line Install (Kali/Linux)
bash

sudo apt install -y libpcap-dev && git clone https://github.com/YOUR_USERNAME/packetwyrm.git && cd packetwyrm/packetwyrm-backend && go mod tidy && go build -o packetwyrm . && sudo ./packetwyrm
🛠️ Features
Feature
How to Use
Filter by Protocol	Click protocol buttons (HTTP, DNS, TCP...)
Search	Type IP, domain, or keyword in search box
View Details	Click any packet row
Hex Dump	Click "Hex" tab in details panel
Stats	Click "📊 Stats" button
Threats	Click "⚠️ Threats" button (shows alerts)
Export	Click "💾 Export" for CSV download
VirusTotal	Click "🛡️ VirusTotal" on suspicious packets

⚡ Quick Test
To test if it's working, open another terminal and generate traffic:

bash

# Generate DNS traffic
nslookup google.com
ping -c 3 8.8.8.8

# Generate HTTP traffic
curl https://www.google.com
You should see packets appearing in the UI!

That's it! 🐉
