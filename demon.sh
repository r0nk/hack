#!/bin/bash

handlers_path=/root/handlers/
recon_folders=/root/local/

while true; do
	inotifywait --exclude .swp -r -e modify * 2> /dev/null ; sleep 0.5
	for directory in  $(find $recon_folder -type d -not -path '*/.*') ; do
		cd $directory
		for handler in $(ls $handlers_path); do
			./$handler &
		done
		cd -
	done
done
