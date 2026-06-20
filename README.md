<div align="center">
  <img src="https://img.icons8.com/color/96/000000/cyber-security.png" alt="WatchTower Logo"/>
  <h1>🔭 WatchTower</h1>
  <p><b>Next-Gen AI-Powered Cybersecurity Threat Detection Platform</b></p>
  
  [![Java 21](https://img.shields.io/badge/Java-21-ED8B00?style=for-the-badge&logo=java&logoColor=white)]()
  [![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3-6DB33F?style=for-the-badge&logo=spring-boot&logoColor=white)]()
  [![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)]()
  [![Apache Kafka](https://img.shields.io/badge/Kafka-KRaft-231F20?style=for-the-badge&logo=apache-kafka&logoColor=white)]()
  [![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=for-the-badge&logo=docker&logoColor=white)]()
  [![React](https://img.shields.io/badge/React-18-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)]()
</div>

<br/>

## 📖 What is WatchTower?
WatchTower is a highly scalable, production-grade microservices cybersecurity platform designed to monitor network activity, detect threats in real-time, and act as a central nervous system for your security operations. 

Instead of relying solely on static rules, WatchTower combines **Event-Driven Architecture**, **Statistical Baselines**, and **Machine Learning** to intelligently identify brute force attacks, privilege escalations, and zero-day anomalies. It surfaces these threats instantly on a stunning, animated glassmorphism dashboard.

---

## ⚡ Why is WatchTower Powerful?

- **Real-Time Data Pipeline:** Uses Apache Kafka to stream and process thousands of logs per second from various sources (Syslog, Nginx, Auth) without bottlenecking.
- **AI & ML Anomaly Detection:** Employs a Python-based Machine Learning sidecar (Isolation Forest) alongside Java statistical z-score analysis to profile user behavior and flag deviations.
- **Active Vulnerability Scanner:** Proactively probes external web targets for missing security headers, clickjacking vulnerabilities, and exposed sensitive files (like `.env` or `.git`).
- **File Integrity Monitoring (FIM):** Continuously monitors critical directories, computing SHA-256 hashes to instantly detect unauthorized file modifications.
- **Smart Alert Deduplication:** Utilizes Redis sliding-window algorithms to suppress "alert storms," ensuring administrators only see distinct, actionable threats.
- **Zero-Latency Dashboard:** A React-based, highly animated UI powered by WebSockets (STOMP) that pushes critical alerts to the screen the exact millisecond they are detected.

---

## 🛠️ Techniques & Technology Stack

WatchTower leverages modern, industry-standard technologies split across cleanly decoupled microservices:

### **Backend & Machine Learning**
- **Java 21 & Spring Boot 3.3:** Core microservices (API Gateway, Log Ingestion, Threat Detection, Alerting).
- **Python 3.12 & FastAPI:** Machine Learning sidecar for AI-driven anomaly scoring.
- **Spring Cloud Gateway:** Centralized routing, JWT authentication, and Redis-backed rate limiting.

### **Data & Infrastructure**
- **Apache Kafka (KRaft mode):** High-throughput message broker handling `raw-logs`, `security-alerts`, and `fim-events`.
- **PostgreSQL 16:** Relational storage. Designed without a "Shared-DB Anti-Pattern" (each microservice owns its own isolated database).
- **Redis 7:** High-speed caching for Rate Limiting and Alert Deduplication.
- **Elasticsearch 8:** Powerful document store for massive log retention and querying.
- **Docker & Docker Compose:** Containerization for seamless cross-platform deployment.

### **Frontend UI**
- **React 18 & Vite:** Lightning-fast frontend tooling.
- **Recharts & WebSockets:** Live data visualization.
- **Vanilla CSS Glassmorphism:** Custom-built cyberpunk/neon aesthetic with backdrop filters, animated mesh backgrounds, and hardware-accelerated micro-interactions.

---

## 🚀 Setup & Installation (All Operating Systems)

WatchTower runs flawlessly on **Windows, macOS, and Linux** using Docker. 

### **Prerequisites**
Before you begin, ensure you have the following installed on your machine:
1. **Java 21 JDK** (or newer)
2. **Apache Maven** (for building the Java code)
3. **Docker & Docker Desktop** (Make sure the Docker daemon is running)
4. **Node.js** (Only needed if you want to run the frontend outside of Docker)

### **Step 1: Clone the Repository**
```bash
git clone https://github.com/yourusername/WatchTower.git
cd WatchTower
```

### **Step 2: Build the Backend Microservices**
You must compile the Java `.jar` files before Docker can containerize them.
* **Linux / macOS:**
  ```bash
  mvn clean package -DskipTests
  ```
* **Windows (PowerShell or CMD):**
  ```powershell
  mvn clean package -DskipTests
  ```

### **Step 3: Launch the Infrastructure**
Spin up Kafka, PostgreSQL, Redis, Elasticsearch, and all the microservices.
* **Linux / macOS:**
  ```bash
  sudo docker compose up -d --build
  ```
* **Windows:**
  ```powershell
  docker compose up -d --build
  ```
*(Note: The first run may take a few minutes as it downloads the database images and builds the Python/Java containers).*

### **Step 4: Access the Platform**
Once all containers show as "Healthy" or "Running":

1. **Open the Dashboard:** Navigate to `http://localhost:3000` in your browser.
2. **Login Credentials:**
   - **Username:** `admin`
   - **Password:** `admin123`
3. **Generate Test Traffic (Optional):**
   To see the dashboard light up with real-time data, you can run the built-in log simulator:
   ```bash
   SPRING_PROFILES_ACTIVE=simulator mvn -pl services/log-ingestion-service spring-boot:run
   ```

---

## 🏗️ Architecture Overview

The system is highly decoupled. When a log is received by the **Log Ingestion Service**, it is immediately dumped into **Kafka**. 

The **Threat Detection Service** listens to Kafka, processes the log through Rule Engines and ML Detectors, and if a threat is found, publishes a `SecurityAlert` back to Kafka. 

Finally, the **Alert Dashboard Service** picks up the alert and pushes it via WebSockets directly to the **React Frontend**.

For a deep dive into the architecture and internal routing, please see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 📄 License
MIT License. Free to use, modify, and distribute for educational and commercial purposes.
