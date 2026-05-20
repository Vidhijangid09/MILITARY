# Viva Questions and Answers

## Q1: What is the core goal of the project?
A1: To build a secure military communication platform that encrypts messages using AES and detects cyber threats using AI-based intrusion detection.

## Q2: Why did you choose AES encryption?
A2: AES is a widely-accepted symmetric encryption standard with strong confidentiality guarantees and efficient performance for secure messaging.

## Q3: How does the system detect intrusions?
A3: The system uses an Isolation Forest model trained on NSL-KDD network traffic features to identify anomalies and suspicious patterns.

## Q4: What database did you use and why?
A4: MongoDB was used for flexible storage of user profiles, encrypted messages, logs, and alerts, making it easy to store JSON-like records.

## Q5: How is user authentication handled?
A5: Users register and log in via Flask. Passwords are hashed with salt using PBKDF2-SHA256 and login activity is logged for suspicious behavior.

## Q6: What are the main modules of the system?
A6: Authentication, Encryption, Communication, Threat Detection, Dashboard, and Admin Monitoring.

## Q7: What is the role of the dashboard?
A7: The dashboard visualizes message volume, alert trends, active users, and suspicious login activities for real-time monitoring.

## Q8: How does the message transfer workflow function?
A8: The sender composes a message, the backend encrypts it with AES, stores the encrypted payload, and the receiver can decrypt it later with the same key.

## Q9: How do you handle suspicious logins?
A9: Failed login attempts increment a counter. After multiple failures, the account can be locked and the event is recorded in audit logs.

## Q10: What are possible future enhancements?
A10: Add face recognition, multi-factor authentication, end-to-end public-key encryption, real-time websocket monitoring, and automatic attack mitigation.
