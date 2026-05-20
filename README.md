# AI-Based Military Communication Encryption System

## Project Overview
A secure military communication platform combining AES encryption, user authentication, intrusion detection, encrypted message transfer, and a visual dashboard for real-time monitoring.

## Features
- User login/signup with password security and suspicious login detection
- AES encryption/decryption for message confidentiality
- AI-based intrusion detection using Isolation Forest
- Real-time analytics dashboard with Chart.js graphs
- Admin panel for monitoring network events and alerts
- Secure sender/receiver encrypted messaging
- Audit logs for threat events and user activity

## Technology Stack
- Backend: Python, Flask
- Frontend: HTML, CSS, JavaScript
- Database: MongoDB
- Encryption: AES (PyCryptodome)
- Machine learning: scikit-learn Isolation Forest
- Visualization: Chart.js

## Folder Structure
- `app.py` - Flask web application entry point
- `config.py` - environment settings and database configuration
- `backend/` - backend modules for authentication, encryption, communication, threat detection, and dashboard
- `frontend/` - templates and static styles/scripts for UI
- `data/` - model training script and dataset loading
- `docs/` - architecture, flowchart, slides, viva questions

## Setup Instructions
1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start MongoDB locally and update `config.py` or `.env` with your `MONGO_URI`.
3. Train the intrusion detection model:
   ```bash
   python data/train_model.py
   ```
4. Run the Flask application:
   ```bash
   python app.py
   ```
5. Open `http://localhost:5000` in your browser.

## Notes
- The system includes encrypted message storage using AES-CBC-256 with a system master key.
- Threat detection accepts network event payloads and flags anomalies in real time.
- Admin panel supports network traffic review and suspicious activity logs.

## Project Deliverables
- Complete source code
- Frontend and backend integration
- AI model training code
- Database integration using MongoDB
- Documentation and PPT content
- Architecture diagram and flowchart
- Viva questions and answers
# MILITARY
