#!/usr/bin/python3

# AUTHOR: Sergio Pozuelo Martín-Consuegra / Group A / Lab group C1

import os
import socket
import hashlib
import struct
import sys
import array
import base64
import threading
import queue
import urllib.parse
import urllib.request


# COPIED CODE: Checksum calculation
# AUTHOR: David Villa Alises
# Obtained from: https://bitbucket.org/DavidVilla/inet-checksum/src/master/inet_checksum.py
# Used to calculate the checksum in challenge 5 as specified by the instructions
# Changed: Indentation to keep consistent with rest of program

# Internet checksum algorithm RFC-1071" from scapy:
# https://github.com/secdev/scapy/blob/master/scapy/utils.py

def cksum(pkt):
  # type: (bytes) -> int
  if len(pkt) % 2 == 1:
    pkt += b'\0'
  s = sum(array.array('H', pkt))
  s = (s >> 16) + (s & 0xffff)
  s += s >> 16
  s = ~s

  if sys.byteorder == 'little':
    s = ((s >> 8) & 0xff) | s << 8
    
  return s & 0xffff


# findIdentifier: Given the instructions for a challenge, find the identifier
def findIdentifier(data):
  for line in data.split('\n'):
    if 'identifier:' in line: 
      return line.split(':')[-1]


# CreateServer: Given a protocol, create a server in the first available port
def createServer(protocol):
  if protocol == 'udp':
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
  elif protocol == 'tcp':
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
  sock.bind(('', 0))
  serverPort = sock.getsockname()[1]
  return sock, serverPort


# connectTcp: Connect a socket to a TCP address
def connectTcp(addr, port):
  server = (addr, port)
  sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
  sock.connect(server)
  return sock


# recvall: Recieve data from a socket until the server won't send anymore
def recvall(sock):
  buffer = ''
  while True:
    data = sock.recv(1024).decode()
    if not data:
      break
    buffer += data
  return buffer


# WYPheader: Generate the WYP message with the header and payload
def WYPMessage(checksum, sequence, encodedPayload):
  header = struct.pack('!3sBHHH', b'WYP', 0, 0, checksum, sequence)
  message = header + encodedPayload
  return message
  

# handleRequest: Process a single GET request (used as threads)
def handleRequest(clientSock, clientAddr, getQueue, stop):
    request = clientSock.recv(1024) # Recieve the request
    request = urllib.parse.unquote(request.decode()) # Parse the request

    # Form the url or detect the next challenge's instructions
    for line in request.split('\n'):
      if 'identifier:' in line:
        getQueue.put(request) # Save the request to the queue
        stop.set() # Signal that we found the file
        clientSock.close()
        return
      elif 'GET' in line:
        url = line.split(' ')[1] #/rfc<Nombre>.txt
        
    url = f'http://rick:81/rfc{url}'

    # Send a request for the file
    response = urllib.request.urlopen(url)
    content = response.read()
    header = [b'HTTP/1.1 200 OK', b'']
    
    # Form and send the response
    responseClient = b'\r\n'.join(header) + b'\r\n' + content
    clientSock.send(responseClient)
    clientSock.close()
    return

  
# Challenge 0: Login
def ch0(username: str):
  sock = connectTcp('yinkana', 2000)
  sock.recv(1024)
  sock.send(username.encode())

  # Recieve new instructions and identifier
  data = sock.recv(1024).decode()
  print(data)
  sock.close()
  
  return findIdentifier(data)


# Challenge 1: UDP
def ch1(identifier: str):
  sock, serverPort = createServer('udp')

  # Send the identifier and the port
  sentData = (f'{serverPort} {identifier}')
  sock.sendto(sentData.encode(),('yinkana', 4000))
  dataNsender = sock.recvfrom(1024) # Recieve the upper-code?

  # Send the identifier in uppercase
  sock.sendto(identifier.upper().encode(),dataNsender[1])

  # Recieve new instructions + identifier
  data = sock.recv(1024).decode()
  print(data)
  sock.close()
  return findIdentifier(data)


# Challenge 2: Words len
def ch2(identifier: str): 
  sock = connectTcp('yinkana', 3010)
  
  buffer = b''
  totalChars = 0
  wordLengths = ''
  
  while True:
    if totalChars >= 1000:
      break
    
    wordLengths = ''
    totalChars = 0
    data = sock.recv(1024)

    if not data:
      break

    buffer += data
    words = buffer.split()
    
    for word in words[:-1]: # Take every word except the last one
      wordLengths += str(len(word)) + ' '
      totalChars += len(word)
      if totalChars >= 1000:
        break
 
  output = identifier + ' ' + wordLengths + '--'
  
  # Send the requested data
  sock.send(output.encode())

  buffer = recvall(sock)
  instructions = 'identifier:' + buffer.split('identifier:')[1]
  print(instructions)
  sock.close()
  
  return findIdentifier(buffer)


# Challenge 3: Add numbers before
def ch3(identifier: str):
  sock = connectTcp('yinkana', 5500)
  
  # Prepare the buffer, sum and data to send
  buffer = b''
  totalSum = 0
  lastWord = None
  
  while True:
    if totalSum >= 1200:
      break

    data = sock.recv(1024)
    
    if not data:
      break

    buffer += data
    elements = buffer.split()

    for index, element in enumerate(elements): # Search through every word
      if index == len(elements) - 1: # Check if the last word is incomplete (if the space is not found)
        buffer = element
        break

      element.decode()
      if element.isdigit(): # Add the numbers
        totalSum += int(element)
        if totalSum >= 1200:
          break
      else: # Save the words
        lastWord = element.decode()
              
      buffer = b' '.join(elements[index+1:]) # Remove already used data in the buffer

  # Send the requested data
  output = lastWord + ' ' + identifier
  sock.send(output.encode())

  buffer = recvall(sock) 
  instructions = 'identifier:' + buffer.split('identifier:')[1]
  print(instructions)
  sock.close()
    
  return findIdentifier(buffer)


# Challenge 4: SHA1
def ch4(identifier: str):
  sock = connectTcp('yinkana', 9003)
  sock.send(identifier.encode())

  # Recieve the size
  fileSize = ''
  while True:
    data = sock.recv(1)
    if data == b':':
      break
    fileSize += data.decode('ascii')
  fileSize = int(fileSize)

  # Recieve the data
  data = b''
  while len(data) < fileSize:
    data += sock.recv(fileSize - len(data))

  # Calculate and send the sha
  sha = hashlib.sha1(data).hexdigest() 
  sha = bytes.fromhex(sha)
  sock.send(sha)

  buffer = recvall(sock)
  print(buffer)
  return findIdentifier(buffer)


# Challenge 5: WYP
def ch5(identifier: str):
  udpServer = ('yinkana', 6000)
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

  encodedPayload = base64.b64encode(identifier.encode()) # Encode the payload in base64
  message = WYPMessage(0, 1, encodedPayload)

  # Calculate the checksum
  checksum = cksum(message)
  message = WYPMessage(checksum, 1, encodedPayload)

  sock.sendto(message, udpServer)
  data = sock.recv(8192)

  # Extract the payload and header
  replyHeader = data[:10]
  replyPayload = data[10:]
  
  # Pad the received datat (To decode in base64, the response must be a multiple of 4)
  while len(replyPayload) % 4 != 0: 
    replyPayload += b'='
  
  payload = base64.b64decode(replyPayload).decode() # Decode the payload (base64)
  print(payload)

  return findIdentifier(payload)


# Challenge 6: Web Server Get
def ch6(identifier: str):
  sock, serverPort = createServer('tcp')
  sock.settimeout(1.0)
    
  # Send the identifier and the port
  message = f'{identifier} {serverPort}'
  node1Sock = connectTcp('yinkana', 8003)
  node1Sock.send(message.encode())

  stop = threading.Event() # Signal to end the loop
  getQueue = queue.Queue() # Queue to store the special GET request

  sock.listen()
  
  while True:
    if stop.is_set():
      break
    
    try:
      # Accept a each connection in a new thread
      clientSock, clientAddr = sock.accept()
      thread = threading.Thread(target=handleRequest, args=(clientSock, clientAddr, getQueue, stop))
      thread.start()
    except socket.timeout:
      pass

  # Show the next challenge's instructions 
  request = getQueue.get()
  request1 = request.split('\n\n')[0].split('?')[1]
  request2 = request.split('\n\n')[1]
  request = request1 + '\n\n' + request2 + '\n'
  print(request)

  return findIdentifier(request)


# Challenge 7: Finale
def ch7(identifier: str):
  sock = connectTcp('yinkana', 33333)
  sock.send(identifier.encode())
  data = sock.recv(1024)
  print(data.decode())
        
  
# Main: Execute the 8 challenges (0 - 7)
def main():

  username = 'laughing_snyder'
  identifier = ch0(username) # Challenge 0
  identifier = ch1(identifier) # Challenge 1
  identifier = ch2(identifier) # Challenge 2
  identifier = ch3(identifier) # Challenge 3
  identifier = ch4(identifier) # Challenge 4
  identifier = ch5(identifier) # Challenge 5
  identifier = ch6(identifier) # Challenge 6
  ch7(identifier) # Challenge 7


if __name__ == '__main__':
  main()
