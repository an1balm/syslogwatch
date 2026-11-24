.PHONY: test gates coverage demo report clean

export PYTHONPATH := src

test:
	python3 -m pytest -q

coverage:
	python3 -m coverage run --source=src,scripts -m pytest -q
	mkdir -p coverage
	python3 -m coverage lcov -o coverage/lcov.info
	python3 -m coverage report -m

gates: coverage
	/workspace/tools/crapper/crapper --use-existing-coverage --threshold 10
	/workspace/tools/dryer/dryer --threshold 0.82
	/workspace/tools/mutator/mutator --use-existing-coverage

demo:
	python3 -m syslogwatch.cli demo --db demo.db
	python3 -m syslogwatch.cli analyze --db demo.db --format markdown

report:
	python3 -m syslogwatch.cli analyze --since 24h --format html -o informe.html
	@echo "abre informe.html"

clean:
	rm -rf .metrics coverage coverage.lcov demo.db informes
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
