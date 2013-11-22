#!/usr/bin/env ruby
# TODO CTRL-Cで終了させたいけど、できない。

require './my_capture'

Signal.trap(:INT) do
  exit 0 
end

cap = MyCapture.new "eth0"
#t = cap.capture "icmp"
t = cap.capture "icmp or tcp or udp"

t.join
