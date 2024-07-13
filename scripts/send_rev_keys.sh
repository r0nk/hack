#!/bin/bash

# Step 1: Find the window ID for "revshell"
window_id=$(tmux list-windows -F '#{window_id} #{window_name}' | grep 'revshell' | awk '{print $1}')

# Step 2: List the panes in the window and choose the desired one (index 0 in this case)
pane_id=$(tmux list-panes -t $window_id -F '#{pane_id} #{pane_index}' | grep ' 0$' | awk '{print $1}')


echo "sending to $window_id $pane_id"
# Step 3: Send keys to the desired pane
tmux send-keys -t $pane_id 'echo hello world!' Enter

