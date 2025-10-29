# MITRE Matrix Dashboard

A full-stack application for visualizing and analyzing MITRE ATT&CK framework data with pattern detection capabilities.

## 📋 Table of Contents

- [Overview](#overview)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

## 🔍 Overview

This dashboard provides an interactive interface for exploring MITRE ATT&CK techniques, tactics, and procedures with advanced pattern detection and analysis capabilities.

## 🛠 Tech Stack

### Frontend
- **React** with **Vite** - Fast development and optimized builds
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Utility-first styling
- **ESLint** - Code quality

### Backend
- **Flask** - Web framework
- **FastAPI** - Modern API framework
- **Elasticsearch 8.15.0** - Search and analytics
- **Python 3.11** - Recommended Python version

### Infrastructure
- **Nginx** - Web server and reverse proxy
- **Docker** - Containerization (optional)

## 📦 Prerequisites

- **Node.js** 16+ and npm
- **Python 3.11** or 3.10 (3.14 not supported yet)
- **Elasticsearch** (if using search features)
- **Git**

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd Mitre-Matrix-Dashboard
```

### 2. Frontend Setup

```bash
cd frontend
npm install
```

### 3. Backend Setup

```bash
cd backend

# Create virtual environment with Python 3.11
py -3.11 -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 4. Configure VS Code (Optional)

1. Press `Ctrl + Shift + P` (or `Cmd + Shift + P` on Mac)
2. Type: `Python: Select Interpreter`
3. Select: `.\backend\venv\Scripts\python.exe`

## 🎮 Running the Application

### Option 1: Run All Services (Windows)

```bash
# From project root
runAll.bat
```

This will start:
- Backend API server
- Frontend development server

### Option 2: Run Services Individually

**Backend:**
```bash
cd backend
venv\Scripts\activate
python multi_pattern.py
```

**Frontend:**
```bash
cd frontend
npm run dev
```

The application will be available at:
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:5000` (or configured port)

## 📁 Project Structure

```
Mitre-Matrix-Dashboard/
├── backend/                 # Python backend
│   ├── venv/               # Virtual environment (not in git)
│   ├── multi_pattern.py    # Main backend application
│   ├── requirements.txt    # Python dependencies
│   └── .env               # Environment variables (not in git)
├── frontend/               # React frontend
│   ├── src/               # Source code
│   ├── public/            # Static assets
│   │   └── data/          # MITRE ATT&CK data
│   ├── package.json       # Node dependencies
│   └── vite.config.ts     # Vite configuration
├── nginx/                  # Nginx configuration
├── docker/                 # Docker setup
├── server/                 # Additional server files
├── .gitignore             # Git ignore rules
├── runAll.bat             # Windows startup script
└── README.md              # This file
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the `backend/` directory:

```env
# Example configuration
FLASK_ENV=development
ELASTICSEARCH_URL=http://localhost:9200
API_PORT=5000
```

### Frontend Configuration

Update `frontend/vite.config.ts` if you need to change API proxy settings or ports.

## 💻 Development

### Frontend Development

```bash
cd frontend

# Start dev server with hot reload
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Lint code
npm run lint
```

### Backend Development

```bash
cd backend
venv\Scripts\activate

# Run with auto-reload (if supported)
python multi_pattern.py

# Run tests (if available)
pytest
```

## 🐛 Troubleshooting

### Python Version Issues

If you see Rust compilation errors:
- Ensure you're using Python 3.11 or 3.10 (not 3.14)
- Check your Python version: `python --version`
- Recreate venv with correct version: `py -3.11 -m venv venv`

### Module Not Found Errors

```bash
# Ensure venv is activated (you should see (venv) in prompt)
venv\Scripts\activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Frontend Build Issues

```bash
# Clear cache and reinstall
cd frontend
rm -rf node_modules package-lock.json
npm install
```

### Path Issues

If the backend can't find `enterprise-attack.json`:
- Ensure the file exists at `frontend/public/data/enterprise-attack.json`
- Check the path in your Python code uses: `Path(__file__).parent.parent / "frontend/public/data/enterprise-attack.json"`

### Git Pull Issues with venv

If git complains about venv files:
```bash
git rm -r --cached backend/venv/
git checkout -- backend/venv/
git pull
```

## 📝 Common Commands

```bash
# Check Python versions available
py --list

# Activate venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# Deactivate venv
deactivate

# Update pip
python -m pip install --upgrade pip

# Check installed packages
pip list

# Freeze current dependencies
pip freeze > requirements.txt
```

## 🤝 Contributing

1. Create a feature branch
2. Make your changes
3. Test thoroughly
4. Submit a pull request

## 📄 License

[Add your license here]

## 🔗 Links

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Elasticsearch Documentation](https://www.elastic.co/guide/)
- [React Documentation](https://react.dev/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

## 👥 Authors

[Add author information]

---

**Note:** Make sure to add `.env` files to `.gitignore` and never commit sensitive information like API keys or passwords.