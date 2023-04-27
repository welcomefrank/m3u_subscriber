import pyqrcode

url = "0x139C31B19b759a71b7BC3Ec2F4042A76285EF28b"

# Generate QR code instance
qr = pyqrcode.create(url)

# Save the image as PNG file
with open('/BNB.png', 'wb') as f:
    qr.png(f, scale=10)
