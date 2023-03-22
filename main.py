import socket
import struct
import time
import re
from subprocess import Popen, PIPE

#
# The first few functions in the file are utilitarian.
#

# Function for getting information from ethernet frame binary data.
def parse_ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), proto, data[14:]

# Function for getting information from arp frame binary data.
def parse_arp_data(data):
    trash, s_mac_len, t_mac_len, _ = struct.unpack('! 4s s s H', data[:8])

    last_len = s_mac_len + t_mac_len + 3
    s_mac, s_ip, t_mac, t_ip = struct.unpack(f'! {s_mac_len}c 1s {t_mac_len}c 2s', data[8:last_len])

    return s_mac, s_ip, t_mac, t_ip

# Function for getting string with address from bytes.
def get_mac_address(addr_bytes):
    bytes_str = map('{:02x}'.format, addr_bytes)
    return ':'.join(bytes_str).upper()

# Function for getting a frame.
def get_frame(conn):
  raw_data, addr = conn.recvfrom(65536)
  
  return parse_ethernet_frame(raw_data)

# Function for getting max address between all the connected.
def get_max(table):
  res = None
  for elem in table:
    if res == None:
      res = elem
    elif table[res] < table[elem]:
      res = elem
  
  return res

# Function for getting the most frequently called addresses.
def get_most_freq(mac_table):
  max_addr_0 = None
  max_addr_1 = None
  keys = mac_table.keys()

  for cur in keys:
    cur_next = get_max(mac_table[cur])

    if max_addr_0 == None:
      max_addr_0 = cur
      max_addr_1 = cur_next
    elif mac_table[max_addr_0][max_addr_1] < mac_table[cur][cur_next]:
      max_addr_0 = cur
      max_addr_1 = cur_next

  return max_addr_0, max_addr_1

# Function for displaying the metrics collected.
def display_calc_stats(frames_count, arp_count, broadcast_count, strangers_packets, data_size, mac_table):
  print(f"Mac addresses: {len(mac_table.keys())}")
  print(f"The most frequently interacting: {get_most_freq(mac_table)}")
  print(f"Frames count: {frames_count}")
  print(f"ARP frames count: {arp_count}")
  print(f"Broadcast frames frames count: {broadcast_count}")
  print(f"Strangers packets: {strangers_packets}")
  print(f"Total frame data: {data_size}")

#
# The following functions implement user requests handling logic.
#

# Function for collecting metrics for the time given.
# own_mac is the mac adress of the computer, running this code.
def calc_metrics(own_mac, time_mill):
  time_mill /= 1000

  # This mac table represents graph, in which
  # each edge from h0 to h1 with value v
  # means, that v frames were sent between h0 and h1.
  mac_table = {}

  # This method updates edges in graph.
  def add_record(src_mac, dest_mac):
    if mac_table.get(src_mac) == None:
      mac_table[src_mac] = {
          dest_mac: 1
      }
    elif mac_table[src_mac].get(dest_mac) == None:
      mac_table[src_mac][dest_mac] = 1
    else:
      mac_table[src_mac][dest_mac] += 1

  # Here are metrics, containing answers to some questions.
  frames_count = 0
  arp_count = 0
  broadcast_count = 0
  strangers_packets = 0
  data_size = 0

  conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

  time_start = time.time()
  while time.time() - time_start < time_mill:
    dest_mac, src_mac, frame_prot, data = get_frame(conn)

    # Adding records.
    add_record(src_mac, dest_mac)
    add_record(dest_mac, src_mac)

    # Updating frames count.
    frames_count += 1

    # Updating ARP frames count.
    if frame_prot == 2054:
      arp_count += 1

    # Updating broadcast frames count.
    if dest_mac == "ff:ff:ff:ff:ff:ff":
      broadcast_count += 1

    # Updating strangers packets count.
    if (src_mac != own_mac) and (dest_mac != own_mac):
      strangers_packets += 1

    # Updating data size.
    data_size += len(data)

  conn.close()
  display_calc_stats(frames_count, arp_count, broadcast_count, strangers_packets, data_size, mac_table)

# Function for capturing arp packages for time_mill milliseconds.
def capture_arp(time_mill):
  time_mill /= 1000

  conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))

  time_start = time.time()
  while time.time() - time_start < time_mill:
    dest_mac, src_mac, frame_prot, data = get_frame(conn)
    
    if dest_mac == src_mac:
      print("Duplicate address detection ARP frame:")
    else:
      print("ARP frame:")
      print('Destination: {}, Src: {}'.format(dest_mac, src_mac))

    print(time.time())
  
  conn.close()
  print("Out of time")

# Function for making ARP requests.
def arp_req(s_mac, s_ip, goal_mac, goal_ip):
  # Connection configuration.
  interface = "wlan0"

  connect = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0806))
  connect.bind((interface, socket.ntohs(0x0806)))

  # Request params.
  arp_code = b'\x08\x06'
  hardware_type = b'\x00\x01'
  protocol_type = b'\x08\x00'
  hardware_len = b'\x06'
  protocol_len = b'\x04'
  op_code = b'\x00\x02'

  # This variable is responsible for data field in ethernet frame.
  req_data = hardware_type + protocol_type + hardware_len + protocol_len + op_code

  # Forming the packets.
  eth_packet = goal_mac + s_mac + arp_code
  request = eth_packet + req_data + s_mac + s_ip + goal_mac + goal_ip

  # Sending the request.
  connect.send(request)

  # Getting response.
  dest_mac, src_mac, frame_prot, data = get_frame(connect)
  s_mac, s_ip, t_mac, t_ip = parse_arp_data(data)

  return s_mac, s_ip, t_mac, t_ip

# Function for getting the mac address for the given ip.
def get_mac_of(own_mac, own_ip, ip):
  s_mac = ' '.join(format(ord(x), 'b') for x in own_mac)
  s_ip = socket.inet_aton(own_ip)

  goal_mac = b"\xff\xff\xff\xff\xff\xff"
  goal_ip = socket.inet_aton(ip)
  
  print(f"Mac address for the ip given: {s_mac}")
  s_mac, s_ip, t_mac, t_ip = arp_req(s_mac, s_ip, goal_mac, goal_ip)

  print(f"Mac address for the ip given: {s_mac}")

# Function for checking, if there any device with the same ip address.
def ip_is_unique(own_mac, own_ip):
  s_mac = ' '.join(format(ord(x), 'b') for x in own_mac)
  s_ip = socket.inet_aton(own_ip)

  goal_mac = b"\xff\xff\xff\xff\xff\xff"
  goal_ip = socket.inet_aton(own_ip)
  
  print(f"Mac address for the ip given: {s_mac}")
  s_mac, s_ip, t_mac, t_ip = arp_req(s_mac, s_ip, goal_mac, goal_ip)

  if s_ip == t_ip:
    print("The IP is not unique")
  else:
    print("The ip is unique")

#
# The following functions implement console interaction logic.
#

# Helper function (console interaction).
def show_commands():
   print("Available commands:")
   print("Print 'arp_capt <time_mill>' to start capturing all the arp packages for time_mill milliseconds.")
   print("You will see packages interpretations.")
   print()
   print("Print 'mac_of <ip_address>' to get the address of the device with ip = ip_address.")
   print()
   print("Print 'stats <time_mill>' to collect metrics for the time_mill milliseconds.")
   print()
   print("Print 'is_unique' to check, if there another device with the same ip address.")
   print()
   print("Print 'help' to see the list of available commands.")
   print()
   print("Print 'quit' to quit the application.")

# Function for getting mac and ip addresses from the user (console interaction).
def get_user_data():
   print("Please, enter your mac address")
   own_mac = input()

   print("Please, enter your ip address")
   own_ip = input()

   return own_mac, own_ip

# Function for parsing int arguments (console interaction).
def get_int(str):
  try:
    result = int(str)
    return result
  except:
    print("Incorrect input")
    return None

# Application entry point.
def main():
   own_mac, own_ip = get_user_data()
   show_commands()
   print()

   while True:
      try:
        command = input().split()
        print()

        if command[0] == "arp_capt":
          if (len(command) < 2):
            print("Too few arguments\n")
            continue

          arg = get_int(command[1])
          if arg != None:
            capture_arp(arg)
        elif command[0] == "mac_of":
          if (len(command) < 2):
            print("Too few arguments\n")
            continue
          
          get_mac_of(own_mac, command[1])
        elif command[0] == "stats":
          if (len(command) < 2):
            print("Too few arguments\n")
            continue
          
          arg = get_int(command[1])
          if arg != None:
            calc_metrics(own_mac, arg)
        elif command[0] == "is_unique":
          ip_is_unique(own_mac, own_ip)
        elif command[0] == "help":
          show_commands()
        elif command[0] == "quit":
          break
        else:
          print("Unknown command.")
        print()
      except Exception as error:
        print('There was an error: ' + repr(error))
        print('Please, try again\n')


main()
