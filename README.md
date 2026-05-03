# 🌐 Web Server Fingerprinting Tool

A Python-based network analysis tool that scans websites to identify server type, SSL status, and response time.
Includes a simple UI for easy interaction and demonstration.

---

## 🚀 Features

* 🔍 **Web Server Detection**

  * Identifies servers like Apache, nginx, IIS
* 🔐 **SSL Certificate Analysis**

  * Checks HTTPS support
  * Downloads SSL certificates in `.pem` format
* ⚡ **Latency Measurement**

  * Measures response time of each website
* 🧵 **Multi-threading**

  * Scans multiple websites concurrently
* 💾 **Result Storage**


---

## 🛠️ Technologies Used

* Python 3
* Socket Programming
* SSL Module
* ThreadPoolExecutor (Concurrency)
* Tkinter (UI)

---



---

## ▶️ How to Run

### 1. Clone / Download the project

### 2. Open in VS Code or Terminal

### 3. Run the UI

```bash
python3 cert.py
```

---

## 🧪 Example Input

```
nginx.org, example.com, microsoft.com
```

---

## 📊 Sample Output

```
🔍 Scanning: nginx.org
HTTP Info: Server: nginx
Analysis: High-performance server (nginx)
SSL Info: SSL Enabled | Issuer: Let's Encrypt
Latency: 0.21 sec
```

---

## ⚠️ Limitations

* Server detection is based only on HTTP headers
* Some websites hide server info → shown as "Unknown"
* SSL details are basic (issuer only)
* Accuracy depends on server response

---

## 🔮 Future Improvements

* Better server detection (Cloudflare, LiteSpeed, etc.)
* Clean SSL certificate parsing
* Advanced UI (dashboard + charts)
* Export results to CSV/JSON
* Real-time progress tracking

---

## 👨‍💻 Author

**Heemadhawala R**

---

## 📌 Note

This project is developed for **educational and learning purposes only**.
Do not use it for unauthorized scanning of systems.
