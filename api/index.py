import sys
import os

# Add root directory to sys.path so backend module can be imported seamlessly on Vercel
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.main import app
