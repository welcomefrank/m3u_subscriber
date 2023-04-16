import pyqrcode

url = "http://192.168.5.1:22771/secret/config.yaml"

# Generate QR code instance
qr = pyqrcode.create(url)

# Save the image as PNG file
with open('/qrcode.png', 'wb') as f:
    qr.png(f, scale=10)
