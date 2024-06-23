docker:
	docker build -t hack .

weekly:
	docker build --no-cache -t hack .
