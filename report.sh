#!/bin/bash

generate_report(){
	printf "
---
title: \"Offensive Security Certified Professional Exam Report\"
author: [\"r0nk@r0nk\", \"OSID: XXXX\"]
date: \"$(date +%D)\"
subject: \"Markdown\"
keywords: [Markdown, Example]
subtitle: \"OSCP Exam Report\"
lang: \"en\"
titlepage: true
titlepage-color: \"1E90FF\"
titlepage-text-color: \"FFFAFA\"
titlepage-rule-color: \"FFFAFA\"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
"
	printf "# "
	pwd | tr '/' '\n' | tail -n 1

	printf "## "
	cat ip.txt

	printf "\n\n\`\`\`\n"
	cat nmap.txt | grep -E "[0-9].*"
	printf "\`\`\`\n\n"

	echo "### User"

	echo "### Priviledge escalation"
}

if [ ! -f report.md ]; then
	echo "report.md not found, generating..."
	generate_report > report.md
fi

lint(){
	#https://github.com/markdownlint/markdownlint?tab=readme-ov-file
	mdl report.md

	#TODO check sizes of screenshots to be included
	cat report.md | grep -o "screenshots/.*.png" | xargs identify -format "%f %w %h\n" | while read name width height; do
		echo $width $height;
		if [ "$width" -gt "800" ] ; then
			echo "SCREENSHOT OVER SIZE for file $name"
		fi
		if [ "$height" -gt "8000" ] ; then
			echo "SCREENSHOT OVER SIZE for file $name"
		fi
	done
}

lint

pandoc report.md -o report.pdf \
	--table-of-contents\
	--number-sections\
	--template eisvogel \
	--highlight-style breezedark\
	--pdf-engine=xelatex

