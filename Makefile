.PHONY: install lint format typecheck test clean build-dist publish release

install:
	uv sync

lint:
	uv run ruff check src/ tests/

format:
	uv run ruff format src/ tests/
	uv run ruff check --fix src/ tests/

typecheck:
	uv run mypy src/

test:
	uv run pytest tests/ -v

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info .mypy_cache .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +

build-dist: clean
	uv build

publish: build-dist
	uv publish --username __token__ --password "$$(grep password ~/.pypirc | head -1 | cut -d' ' -f3)"

release: lint typecheck test publish
