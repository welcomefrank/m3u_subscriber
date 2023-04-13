import qrcode
import Image

# 定义一个函数，将链接转换为二维码
def generate_qrcode(url):
    # 创建QRCode实例，传入链接
    qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=1)
    qr.add_data(url)
    qr.make(fit=True)

    # 生成二维码图片
    img = qr.make_image(fill_color="black", back_color="white")

    # 显示并保存图片
    img.show()
    img.save("qrcode.png")

# 调用函数
generate_qrcode("https://www.baidu.com")