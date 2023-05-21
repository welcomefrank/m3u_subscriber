import subprocess
user_agent = '-user_agent \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\"'

def download_video(url, filename):
    command = f"ffmpeg {user_agent} -y -i {url} -c copy -threads 256 {filename}"
    subprocess.call(command, shell=True)

url = "http://101.34.171.88:5244/d/aliyun1/%E5%A5%BD%E5%8F%8B%E7%9A%84%E5%88%86%E4%BA%AB/%E9%AC%BC%E6%BB%85%E4%B9%8B%E5%88%83%20%E5%8A%87%E5%A0%B4%E7%89%88%20-%20%E7%84%A1%E9%99%90%E5%88%97%E8%BB%8A%E7%AF%87%20%5BPSNRip%5D%5B864p%5D%5BCHT%5D%5Bv2%5D.mp4?sign=bHEcH1U3fwL96Dw00K8q7a9UyUoqCJSZoa2CDJSZE0A=:0"  # 下载链接
filename = "/video.mp4"  # 文件名

download_video(url, filename)
