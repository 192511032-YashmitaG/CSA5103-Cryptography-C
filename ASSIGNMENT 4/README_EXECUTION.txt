ASSIGNMENT 4 PART II - EXECUTION

Windows PowerShell:
1. Extract this folder.
2. Open PowerShell in the extracted implementation folder.
3. Run:
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   python src\assignment4_co4.py

Ubuntu / WSL:
1. Open Terminal in the extracted implementation folder.
2. Run:
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   python src/assignment4_co4.py

Output is saved in results/ (the program creates this folder if needed).
Take genuine screenshots of the terminal after running the program.

SCOPE:
This is an educational prototype. Task 1 uses AES-GCM, RSA-OAEP and RSA-PSS.
Task 3 implements an ESP-style anti-replay-window simulation.
Tasks 2, 4 and 5 are local policy/validation simulations, not full live S/MIME,
HTTPS/mTLS or DNS-backed SPF/DKIM/DMARC deployments. Task 6 demonstrates
recipient eligibility and operation-count scaling. Do not describe simulated
outputs as live network or certificate experiments.
