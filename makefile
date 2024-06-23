docker:
	docker build -t hack .

weekly:
	echo "remember git commits."
	docker build --no-cache -t hack .
