#!/bin/bash
# Run from the repository root: ./run.sh
cd "$(dirname "$0")/src" || exit 1
streamlit run app.py --server.port 8501 --server.address 0.0.0.0
