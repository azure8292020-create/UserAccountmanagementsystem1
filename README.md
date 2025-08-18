# User Account Management System

## Overview
A FastAPI-based web application for user management with Active Directory integration, deployed on Kubernetes with Helm and Istio, and using PostgreSQL for persistent storage.

## Features
- Register user (with special invite link)
- Unlock user account
- Check account status
- Password help page
- Create user account (manual approval)
- Security questions (20+)
- PostgreSQL database
- Active Directory integration (LDAPS)

## Configuration
All configuration is via environment variables or Helm values. PostgreSQL is used as the database and should be deployed as a pod/service in the same namespace.

## Database
- Uses PostgreSQL (connection string in `app/config.py`)
- Tables are created via SQLAlchemy models

## Running Locally
1. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
2. Set environment variables as needed (see `app/config.py`).
3. Run the app:
   ```sh
   uvicorn app.main:app --reload
   ```

## Kubernetes/Helm
- The Helm chart will deploy this app and a PostgreSQL database.
- Istio Gateway and VirtualService are included for HTTPS ingress.

## Next Steps
- Complete the business logic for each endpoint.
- Add Dockerfile and Helm chart.
- Secure secrets and certificates via Kubernetes secrets.
