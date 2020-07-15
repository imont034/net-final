import os, json, threading, time, urllib, threading
from socket import *

import imutils
from imutils.video import VideoStream
import cv2

vs = VideoStream(0).start()
time.sleep(2.0)

addr = '0.0.0.0'
port = 2001	

server = socket(AF_INET, SOCK_STREAM)	
server.bind((addr, port))	
server.listen(10)

print('Listening...')

def send_bytes(conn, addr):	
	
	while True:		
		frame = vs.read()
		frame = imutils.resize(frame, width=400, height=400)
		gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
		gray = cv2.GaussianBlur(gray, (7, 7), 0)
		
		output_frame = frame.copy()

		if output_frame is None:				
			continue
		
		# encode the frame in JPEG format
		(flag, encoded_image) = cv2.imencode(".jpg", output_frame)		

		if not flag:				
			continue		
		
		conn.send(encoded_image)

# loop over frames from the output stream
while True:
	try:
		conn, addr = server.accept()
		t = threading.Thread(target=send_bytes, args=(conn, addr,))
		t.daemon = True
		t.start()
	except KeyboardInterrupt:
		print('\nInterruptued by ctrl c')
		break

server.close()
vs.stop()