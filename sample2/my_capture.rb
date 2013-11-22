# パケットキャプチャー

require 'rubygems'
require 'ffi/pcap'
require 'hexdump'
require 'pp'

MY_HOME=File.expand_path(File.dirname(__FILE__))
$LOAD_PATH.push(MY_HOME + "/vendor/ffi-packets-master/lib/")
require 'ffi/packets'

class MyCapture
  attr_accessor :dev
  attr_accessor :filter
  attr_accessor :pcap

  def initialize dev
    @dev = dev
  end

  def capture filter
    @filter = filter
    pcap =
      FFI::PCap::Live.new(:dev => @dev,
                      :timeout => 1,
                      :promisc => true,
                      :handler => FFI::PCap::Handler)
    pcap.setfilter(@filter)
    @thread = Thread.new do
      begin
        pcap.loop() do |this,pkt|
          # デバッグ
          #Hexdump.dump(pkt.body)
          #putc "\n"

          # ether. ffi/dry 形式なんだ
          eth = FFI::Packets::Eth.new :raw => pkt.body
          #puts "eth.src:#{eth.src}"
          #puts "eth.dst:#{eth.dst}"
          #puts "eth.etype:0x#{eth.etype.to_s(16)}"

          case eth.etype
          when 0x0800	  # IP
            parse_ip eth, pkt
          when 0x0806	# ARP
            parse_arp eth, pkt
          else
            puts "[ether] unknown ether: #{eth.dump}"
          end

        end

      rescue SignalException => e
        puts e
      end
    end

    @thread
  end

  def parse_ip eth, pkt
      ip = FFI::Packets::Ip::Hdr.new :raw => pkt.body[0xe .. -1]
      #puts "ip.dump:#{ip.dump}"
      #puts "ip.src:#{ip.src}"
      #puts "ip.dst:#{ip.dst}"
      #puts "ip.proto:#{ip.proto}"
      #putc "\n"

      case ip.proto 
      when 1  # ICMP
        parse_icmp eth, ip, pkt
      when 4  # IP in IP
        puts "[ip] ip in ip #{ip.dump}"
      when 6 # TCP
        parse_tcp eth, ip, pkt
      when 17
        parse_udp eth, ip, pkt
      else
        puts "[ip] unknown #{ip.proto}, #{ip.dump}"
      end
  end

  def parse_icmp eth, ip, pkt
    puts "[icmp] eth.src:#{eth.src.string()}, eth.dst:#{eth.dst.string()}"
    puts "[icmp] ip.src:#{ip.src}, ip.dst:#{ip.dst}"
    icmp = FFI::Packets::Icmp::Hdr.new :raw => pkt.body[0x22 .. -1]

    case icmp.icmp_type
    when FFI::Packets::Constants::ICMP_TYPE_ECHO
      echo = FFI::Packets::Icmp::Hdr::Msg::Echo.new :raw => pkt.body[0x26 .. -1]
      puts "[icmp echo request] #{echo.dump}"
    when FFI::Packets::Constants::ICMP_TYPE_ECHOREPLY
      echo = FFI::Packets::Icmp::Hdr::Msg::Echo.new :raw => pkt.body[0x26 .. -1]
      puts "[icmp echo reply] #{echo.dump}"
    when FFI::Packets::Constants::ICMP_TYPE_UNREACH
      needfrag =  FFI::Packets::Icmp::Hdr::Msg::NeedFrag.new :raw => pkt.body[0x26 .. -1]
      puts "[icmp destination unreachable message] #{needfrag.dump}"
    else
      puts "unknown type #{icmp.dump}"
      Hexdump.dump(pkt.body)
      putc "\n"
    end

    puts "-----\n\n"
  end

  def parse_tcp eth, ip, pkt
    puts "[tcp] eth.src:#{eth.src.string()}, eth.dst:#{eth.dst.string()}"
    puts "[tcp] ip.src:#{ip.src}, ip.dst:#{ip.dst}"
    tcp = FFI::Packets::TCP::Hdr.new :raw => pkt.body[0x22 .. -1]
    puts "[tcp] #{tcp.dump}"
  end

  def parse_udp eth, ip, pkt
    puts "[udp] eth.src:#{eth.src.string()}, eth.dst:#{eth.dst.string()}"
    puts "[udp] ip.src:#{ip.src}, ip.dst:#{ip.dst}"
    udp = FFI::Packets::UDP.new :raw => pkt.body[0x22 .. -1]
    puts "[udp] #{udp.dump}"
  end

  def parse_arp eth, pkt
    arp = FFI::Packets::Arp::Hdr.new :raw => pkt.body[0xe .. -1]
    puts "arp.hrd:#{arp.hrd}"
    puts "arp.pro:#{arp.pro}"
    puts "arp.hln:#{arp.hln}"
    puts "arp.pln:#{arp.pln}"
    puts "arp.op:#{arp.op}"

    ethip = FFI::Packets::Arp::Ethip.new :raw => pkt.body[0x16 .. -1]
    #puts "ethip.dump:#{ethip.dump}"
    # 型不明なときは、.classで調べる。
    #p ethip.sha.class
    puts "ethip.sha:#{to_s_charArray(ethip.sha)}" # sender hardware address
    puts "ethip.spa:#{to_s_charArray(ethip.spa)}" # sender protocol address
    puts "ethip.tha:#{to_s_charArray(ethip.tha)}" # target hardware address
    puts "ethip.tpa:#{to_s_charArray(ethip.tpa)}" # target protocol address
  end

  def to_s_charArray ca
    s = ""
    ca.each do |x|
      s += x.to_s(16) + " "
    end
    s
  end
end
