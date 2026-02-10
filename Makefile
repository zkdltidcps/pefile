.PHONY: help build check count run-github run-choco run-portable start-loop stop-loop logs clean-metadata

help:
	@echo "PE Collection Pipeline - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build            Build the Docker container"
	@echo "  make check            Run server diagnostics inside container"
	@echo "  make run-github       Run GitHub crawler once"
	@echo "  make run-choco        Run Chocolatey crawler once"
	@echo "  make run-portable     Run PortableApps crawler once"
	@echo "  make start-loop       Start the 24/7 background collection loop"
	@echo "  make stop-loop        Stop the background collection loop"
	@echo "  make logs             View background loop logs"
	@echo "  make count            Show number of collected files"
	@echo "  make clean-metadata   Reset all download history"

build:
	docker-compose build

check:
	docker-compose run --rm crawler python scripts/server_check.py

count:
	chmod +x count_files.sh
	./count_files.sh

run-github:
	docker-compose run --rm crawler python scripts/crawler_github.py

run-choco:
	docker-compose run --rm crawler python scripts/crawler_choco.py

run-portable:
	docker-compose run --rm crawler python scripts/crawler_portable.py

start-loop:
	chmod +x collect_loop.sh
	nohup ./collect_loop.sh > crawl_service.log 2>&1 &
	@echo "Crawler service started in background. Use 'make logs' to monitor."

stop-loop:
	@pkill -f "[c]ollect_loop.sh" || echo "Loop process not running."
	-docker-compose down
	@echo "Stop command sent to all containers."

logs:
	tail -f crawl_service.log

clean-metadata:
	rm -f benign_pe/metadata/*.json
	@echo "History reset."
