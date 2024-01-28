.PHONY: run clean

run:
	@echo "Running the program..."
	python3 ehips.py

install:
	@echo "Installing dependencies..."
	pip install -r requirements.txt

clean:
	@echo "Cleaning up..."
	@echo "Done."