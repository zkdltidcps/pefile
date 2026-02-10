.PHONY: help build check run-github run-choco run-portable start-forever stop-forever logs clean-metadata

help:
	@echo "PE Collection Pipeline - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build            Build the Docker container"
	@echo "  make check            Run server diagnostics inside container"
	@echo "  make run-github       Run GitHub crawler once"
	@echo "  make run-choco        Run Chocolatey crawler once"
	@echo "  make run-portable     Run PortableApps crawler once"
	@echo "  make start-forever    Start the 24/7 background collection loop"
	@echo "  make stop-forever     Stop the background collection loop"
	@echo "  make logs             View background loop logs"
	@echo "  make clean-metadata   Reset all download history"

build:
	docker-compose build

check:
	docker-compose run --rm crawler python scripts/server_check.py

run-github:
	docker-compose run --rm crawler python scripts/crawler_github.py

run-choco:
	docker-compose run --rm crawler python scripts/crawler_choco.py

run-portable:
	docker-compose run --rm crawler python scripts/crawler_portable.py

start-forever:
	chmod +x collect_forever.sh
	nohup ./collect_forever.sh > crawl_service.log 2>&1 &
	@echo "Crawler service started in background. Use 'make logs' to monitor."

stop-forever:
	@pkill -f collect_forever.sh || echo "Process not running."

logs:
	tail -f crawl_service.log

clean-metadata:
	rm -f benign_pe/metadata/*.json
	@echo "History reset."
