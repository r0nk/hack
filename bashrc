export HISTSIZE=
export LANG=en_US.UTF-8
export HISTFILESIZE=
export HISTCONTROL=erasedups
export GCC_COLORS=

function nonzero_return() {
	RETVAL=$?
	[ $RETVAL -ne 0  -a  $RETVAL -ne 130 ] && echo "[$RETVAL] "
}

export PS1='$(nonzero_return)\[\e[34m\]\t\[\e[m\] \[\e[32;40m\]\\$\[\e[m\] '

function omd(){
	echo "$@" | bash
	while true; do inotifywait --exclude .swp -r -e modify * 2> /dev/null ;sleep 0.5;clear;  echo "$@" | bash ;done
}

alias x='chmod 755'
alias u="apt update; apt upgrade"
alias g="grep --color=never"
alias qalc='rlwrap qalc +u8 -t -f - -s "color 0"'
alias ls="ls -F"

export TERM=xterm

countdown(){
	date1=$((`date +%s` + $1));
	while [ "$date1" -ge `date +%s` ]; do
## Is this more than 24h away?
		hours=$(($(($(( $date1 - $(date +%s))) * 1 ))/3600))
			echo -ne "$hours:$(date -u --date @$(($date1 - `date +%s`)) +%M:%S)\r";
	sleep 0.1
		done
}

extr(){
        if [[ -z "$1" ]];then
                echo "Missing argument to extract" >&2
                return 1
        fi
        retval=0
        while [[ -n "$1" ]];do
                if [[ -f "$1" ]];then
                        case "$1" in
                                *.tar.*|*.tbz2|*.tgz|*.txz|*.tar|*.tarZ|*.targz|*.tarxz|*.tzst)
                                                tar xf "$1"
                                                retval=$?;;
                                *.bz2)
                                                bunzip2 "$1"
                                                retval=$?;;
                                *.gz)
                                                gunzip "$1"
                                                retval=$?;;
                                *.zip)
                                                unzip "$1"
                                                retval=$?;;
                                *.Z)
                                                uncompress "$1"
                                                retval=$?;;
                                *.7z)
                                                p7zip x "$1"
                                                retval=$?;;
                                *.rar)
                                                unrar x "$1"
                                                retval=$?;;
                                *.zst)
                                                unzstd "$1"
                                                retval=$?;;
                                *)
                                                echo "Unsupported format, ignoring";;
                        esac
                elif [[ -d "$1" ]];then
                        echo "Cannot extract a directory: $1" >&2
                        retval=2
                else
                        echo "No such file or directory: '$1'" >&2
                        retval=3
                fi
                shift
        done
        return $retval
}

export HISTIGNORE='history:clear*'
export HISTFILE='/root/local/history'
PROMP_COMMAND="$PROMPT_COMMAND; history -a; history -n"

alias sus="sort | uniq -c | sort -n"
alias p="proxychains"
alias gip="grep -Eo \"([0-9]{1,3}[\.]){3}[0-9]{1,3}\""

[ -f ~/.fzf.bash ] && source ~/.fzf.bash
PATH=$PATH:/root/.pdtm/go/bin:/root/go/bin
