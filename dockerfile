
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

#FZF
RUN git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf && ~/.fzf/install

#ANEW
RUN go install -v github.com/tomnomnom/anew@latest

#PROJECT DISCOVERY
RUN go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
RUN apt install -y libpcap-dev # For naabu
RUN /root/go/bin/pdtm -install-all

RUN apt install -y inetutils-ping enum4linux nbtscan exploitdb python2 rlwrap php seclists ffuf telnet

#TMUX
RUN apt install -y tmuxinator
COPY .tmuxinator.yml .tmuxinator.yml

COPY bashrc .bashrc

COPY shake /usr/bin/shake
COPY demon demon

COPY timer.sh /usr/bin/timer.sh

ENTRYPOINT ["tmuxinator"]
