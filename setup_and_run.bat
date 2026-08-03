@echo off
REM =====================================================================
REM  PhishGuard AI - Automated Setup and Run Script
REM  File: setup_and_run.bat
REM  Description: One-click setup: installs dependencies, generates
REM               dataset, trains model, and launches the web app.
REM =====================================================================

title PhishGuard AI Setup

echo.
echo =====================================================================
echo   PHISHGUARD AI - SETUP AND LAUNCH
echo =====================================================================
echo.

REM ─── Check Python ────────────────────────────────────────────────
echo [1/6] Checking Python installation...

python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Python is not found on your PATH!
    echo.
    echo  Please install Python 3.9 or higher from: https://www.python.org/downloads/
    echo  Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

FOR /F "tokens=*" %%V IN ('python --version') DO echo  Found: %%V
echo.

REM ─── Create Virtual Environment ──────────────────────────────────
echo [2/6] Creating virtual environment...
IF NOT EXIST "venv\" (
    python -m venv venv
    IF %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  Virtual environment created: venv\
) ELSE (
    echo  Virtual environment already exists. Skipping.
)
echo.

REM ─── Activate Environment ────────────────────────────────────────
echo [3/6] Activating virtual environment...
call venv\Scripts\activate.bat
echo  Environment activated.
echo.

REM ─── Install Dependencies ────────────────────────────────────────
echo [4/6] Installing dependencies from requirements.txt...
pip install -r requirements.txt --quiet
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)
echo  All dependencies installed.
echo.

REM ─── Generate Dataset ────────────────────────────────────────────
echo [5/6] Generating dataset and training model...
IF NOT EXIST "dataset\phishing_dataset.csv" (
    echo  Generating phishing dataset...
    python dataset/generate_dataset.py
    IF %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Dataset generation failed.
        pause
        exit /b 1
    )
) ELSE (
    echo  Dataset already exists. Skipping generation.
)

IF NOT EXIST "model\model.pkl" (
    echo  Training Random Forest model (this may take 1-2 minutes)...
    python model/train_model.py
    IF %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Model training failed.
        pause
        exit /b 1
    )
) ELSE (
    echo  Trained model already exists. Skipping training.
)
echo.

REM ─── Launch Flask App ────────────────────────────────────────────
echo [6/6] Launching PhishGuard AI web application...
echo.
echo  ============================================================
echo    Application is running at: http://localhost:5000
echo    Press Ctrl+C to stop the server
echo  ============================================================
echo.

python app.py

REM ─── Cleanup ─────────────────────────────────────────────────────
pause
