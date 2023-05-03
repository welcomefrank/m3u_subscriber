import cv2
url = "直播源URL"
cap = cv2.VideoCapture(url)
ret, frame = cap.read()
height, width, _ = frame.shape
pixels = height * width
bitrate = cap.get(cv2.CAP_PROP_BITRATE)
if pixels >= 1280*720 and bitrate >= 2000000:
    print("这是一路高清直播源")
else:
    print("这不是一路高清直播源")