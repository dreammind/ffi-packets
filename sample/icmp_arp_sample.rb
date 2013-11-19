#!/usr/bin/env ruby1.8

MY_HOME=File.expand_path(File.dirname(__FILE__))

require 'rubygems'
require 'ffi/pcap'
require 'hexdump'
require 'pp'

# TODO Please change your environments.
$LOAD_PATH.push(MY_HOME + "/vendor/ffi-packets-master/lib/")

require 'ffi/packets'

def to_s_charArray carray
  s = ""
  carray.each do |x|
    s += x.to_s(16) + " "
  end
  s
end

pcap =
  FFI::PCap::Live.new(:dev => 'eth0',
                      :timeout => 1,
                      :promisc => true,
                      :handler => FFI::PCap::Handler)

pcap.setfilter("icmp or arp")


pcap.loop() do |this,pkt|
#  pkt.body.each_byte {|x| print "%0.2x " % x }
  Hexdump.dump(pkt.body);
  putc "\n"

  # Get ether header
  eth = FFI::Packets::Eth.new :raw => pkt.body
  #puts "eth.dump:#{eth.dump}"
  puts "eth.src:#{eth.src}"
  puts "eth.dst:#{eth.dst}"
  puts "eth.etype:0x#{eth.etype.to_s(16)}"

  if eth.etype == 0x0800	
    # Get IP header
    ip = FFI::Packets::Ip::Hdr.new :raw => pkt.body[0xe .. -1]
    #puts "ip.dump:#{ip.dump}"
    puts "ip.src:#{ip.src}"
    puts "ip.dst:#{ip.dst}"
    puts "ip.proto:#{ip.proto}"
    putc "\n"

    if ip.proto == 1
      # Get ICMP
      icmp = FFI::Packets::Icmp::Hdr.new :raw => pkt.body[0x26 .. -1]
      puts "icmp.dump:#{icmp.dump}"
      putc "\n"
    end
  elsif eth.etype == 0x0806	
    # Get ARP 
    arp = FFI::Packets::Arp::Hdr.new :raw => pkt.body[0xe .. -1]
    puts "arp.hrd:#{arp.hrd}"
    puts "arp.pro:#{arp.pro}"
    puts "arp.hln:#{arp.hln}"
    puts "arp.pln:#{arp.pln}"
    puts "arp.op:#{arp.op}"

    ethip = FFI::Packets::Arp::Ethip.new :raw => pkt.body[0x16 .. -1]
    puts "ethip.sha:#{to_s_charArray(ethip.sha)}" # sender hardware address
    puts "ethip.spa:#{to_s_charArray(ethip.spa)}" # sender protocol address
    puts "ethip.tha:#{to_s_charArray(ethip.tha)}" # target hardware address
    puts "ethip.tpa:#{to_s_charArray(ethip.tpa)}" # target protocol address
  else
    puts "unknown ether type:#{eth.etype}"
  end
end
