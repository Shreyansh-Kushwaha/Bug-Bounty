.PHONY: install test lint run dashboard clean

VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

install:
	python3 -m venv $(VENV)
	$(PIP) install -q --upgrade pip
	$(PIP) install -q -r requirements.txt

test:
	$(PY) -m pytest

lint:
	$(PY) -m py_compile src/*.py src/*/*.py

# Usage: make run TARGET=pyyaml-old ARGS="--top-n 2 --parallel --yes"
run:
	$(PY) -m src.main run $(TARGET) $(ARGS)

dashboard:
	$(PY) -m src.main dashboard

clean:
	rm -rf data/repos data/cache __pycache__ src/**/__pycache__ .pytest_cache
