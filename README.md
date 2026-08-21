# 🛡️ GuardPost: Artifact Firewall

A stateless, zero-trust sanitization gateway for developer collaboration. 

Modern software development relies heavily on sharing debugging artifacts (HAR files, Postman collections, CI/CD logs) across support tickets and Slack channels. These transient files routinely leak highly sensitive secrets like JWTs, AWS keys, and Database URIs. **Artifact Firewall** intercepts and neutralizes these threats in-flight.

## 🚀 Live Demo
- **Frontend:** [https://artifact-firewall.vercel.app](https://artifact-firewall.vercel.app)
- **API Endpoint:** [https://artifact-firewall-1.onrender.com](https://artifact-firewall-1.onrender.com)

## ✨ Key Features

* **Zero-Trust Stateless Architecture:** Buffer streams are sanitized in-memory and immediately discarded. No databases. No write-to-disk logs. 
* **Multi-Format Parsing:** Native support for recursively traversing deeply nested JSON, standard text payloads, and browser HAR files without breaking structural integrity.
* **Context-Aware Redaction:** Uses high-speed regex engines to identify AWS Credentials, JSON Web Tokens (JWT), Database URIs, and generic API tokens, replacing them with safe placeholders (e.g., `[REDACTED_SECRET]`).
* **Frictionless Developer UX:** Dark-mode optimized, keyboard-friendly interface built for speed so developers don't bypass security due to UI friction.

## 🛠️ Technology Stack

* **Frontend:** React, TypeScript, Vite, Tailwind CSS, Framer Motion
* **Backend:** Node.js, Express.js, Multer (Memory Storage)
* **Deployment:** Vercel (Client), Render (API Gateway)

## ⚙️ Local Development Setup

**1. Clone the repository**
```bash
git clone https://github.com/lamesahil/artifact-firewall.git
cd artifact-firewall
```

**2. Start the Backend API**

```
cd backend
npm install
npm run build
npm start
```
The server will run on http://localhost:3000 (or the port defined in your .env).

**3. Start the Frontend Client**
Open a new terminal window:
```
cd frontend
npm install
npm run dev
```
The client will run on http://localhost:5173.

**4. Environment Configuration**
Create a .env file in the frontend directory:
```
VITE_API_URL=http://localhost:3000/api
```
