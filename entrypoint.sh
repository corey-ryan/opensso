#!/bin/bash
if [[ $1 == "test" ]]; then
  echo "Run Tests!"  
else
  python run.py
fi
