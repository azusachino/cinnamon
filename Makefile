.PHONY: help run clean install check test lint sync

help:
	@echo "Available commands:"
	@echo "  make run      - Run the eBPF tracer (requires sudo)"
	@echo "  make sync     - Sync uv environment"
	@echo "  make check    - Check if BCC is installed"
	@echo "  make test     - Run a quick test"
	@echo "  make clean    - Clean Python cache files"
	@echo "  make lint     - Check Python code style"

run:
	@echo "Starting eBPF tracer (requires root privileges)..."
	sudo -E uv run python main.py

sync:
	@echo "Syncing uv environment with system site packages..."
	uv venv --python /usr/bin/python3 --system-site-packages
	@echo "Sync complete!"

check:
	@echo "Checking BCC installation..."
	@uv run python -c "import bcc; print('BCC version:', bcc.__version__)" || \
		(echo "ERROR: BCC not installed. Install with: sudo apt install python3-bcc"; exit 1)
	@echo "Checking kernel headers..."
	@ls /lib/modules/$$(uname -r)/build > /dev/null 2>&1 || \
		(echo "WARNING: Kernel headers not found. Install with: sudo apt install linux-headers-$$(uname -r)"; exit 1)
	@echo "All checks passed!"

test:
	@echo "Testing BPF program compilation..."
	@uv run python -c "from bcc import BPF; BPF(text='int dummy(void *ctx) { return 0; }')" && \
		echo "Test passed!" || \
		echo "Test failed!"

clean:
	@echo "Cleaning Python cache files..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean complete!"

lint:
	@echo "Checking Python code style..."
	@command -v pylint >/dev/null 2>&1 && pylint main.py || \
		(echo "pylint not installed. Install with: pip install pylint")
	@command -v flake8 >/dev/null 2>&1 && flake8 main.py || \
		(echo "flake8 not installed. Install with: pip install flake8")
