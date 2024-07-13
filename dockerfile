
# Kali Linux latest with useful tools by tsumarios
FROM kalilinux/kali-rolling

# Set working directory to /root
WORKDIR /root

# Update
RUN apt -y update && DEBIAN_FRONTEND=noninteractive apt -y dist-upgrade && apt -y autoremove && apt clean

# Install common and useful tools
RUN apt -y install curl wget vim git net-tools whois netcat-traditional pciutils usbutils tmux mitmproxy inotify-tools

# Install useful languages
RUN apt -y install python3-pip golang

# Install Kali Linux "Top 10" metapackage and a few cybersecurity useful tools
RUN DEBIAN_FRONTEND=noninteractive apt -y install kali-tools-top10 exploitdb man-db dirb nikto wpscan uniscan lsof apktool dex2jar ltrace strace binwalk

RUN apt install -y libpcap-dev  inetutils-ping enum4linux nbtscan exploitdb python2 rlwrap php seclists ffuf telnet exiftool moreutils  tmuxinator  pandoc  cargo  dnsutils impacket-scripts proxychains proxychains4 tcpdump mimikatz hashcat windows-binaries jq

#unzip rockyou
WORKDIR /usr/share/seclists/Passwords/Leaked-Databases/
RUN tar -xf rockyou.txt.tar.gz
WORKDIR /root

#link common wordlist paths to reduce typing
RUN ln /usr/share/seclists/Discovery/Web-Content/big.txt /big.txt
RUN ln /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt /rockyou.txt

#FZF
RUN git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf && ~/.fzf/install

#ANEW
RUN go install -v github.com/tomnomnom/anew@latest

#PROJECT DISCOVERY
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
RUN /root/go/bin/pdtm -install-all

#TMUX
COPY .tmuxinator.yml .tmuxinator.yml

COPY bashrc .bashrc
COPY .inputrc .inputrc
COPY .tmux.conf .tmux.conf

COPY timer.sh /usr/bin/timer.sh

#I'm completely at a loss as to why this works.
RUN chown root /usr/bin/nmap

COPY demon demon

RUN date -Im > build_date.txt

ENTRYPOINT ["tmuxinator"]
