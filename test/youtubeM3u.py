import re
import argparse

import youtube_dl
import streamlink

YOUTUBE_REGEX = (
    r'(https?://)?(www\.)?'
    '(youtube|youtu|youtube-nocookie)\.(com|be)/'
    '(watch\?.*v=|embed/|v/|.+\?v=)?([^&=%\?]{11})'
)


def get_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-l', '--links', metavar='LINKS',
        help='A comma separated list of links to process.',
    )
    parser.add_argument(
        '-f', '--filename', metavar='FILENAME',
        help='The filename to save the M3U playlist to.',
    )
    parser.add_argument(
        '-q', '--quality', metavar='QUALITY',
        help='The video quality to use (default is bestvideo+bestaudio).',
    )
    return parser


def get_youtube_links(links):
    for link in links:
        match = re.match(YOUTUBE_REGEX, link)
        if not match:
            continue
        yield f'https://www.youtube.com/watch?v={match.group(6)}'


def generate_m3u(filename, urls):
    with open(filename, 'w') as f:
        f.write('#EXTM3U\n')
        for i, url in enumerate(urls):
            f.write(f'#EXTINF:-1, Live {i + 1}\n{url}\n')


def get_video_url(url, quality=None):
    if not quality:
        quality = 'best'
    ydl_opts = {
        'format': quality,
        'ignoreerrors': True,
        'quiet': True,
        'no_warnings': True,
        'forcejson': True,
        'youtube_include_dash_manifest': False,
    }
    try:
        with youtube_dl.YoutubeDL(ydl_opts) as ydl:
            info_dict = ydl.extract_info(url, download=False)
            formats = info_dict.get('formats', [info_dict])
            for f in formats:
                if f.get('acodec') != 'none':
                    return f['url']
    except youtube_dl.utils.DownloadError:
        pass

    # Fallback to streamlink if youtube-dl fails to extract the video URL
    streams = streamlink.streams(url)
    if streams:
        return streams['best'].url
    return None


def get_live_stream_url(url):
    streams = streamlink.streams(url)
    for key in streams.keys():
        if 'audio' in key and 'video' in key:
            return streams[key].url


def get_urls(links, quality):
    urls = []
    for link in links:
        try:
            video_url = get_video_url(link, quality)
        except youtube_dl.utils.DownloadError:
            video_url = None
        if video_url:
            urls.append(video_url)
        else:
            live_stream_url = get_live_stream_url(link)
            if live_stream_url:
                urls.append(live_stream_url)
    return urls


if __name__ == '__main__':
    # parser = get_parser()
    # args = parser.parse_args()
    # links = args.links.split(',') if args.links else []
    # filename = args.filename if args.filename else 'playlist.m3u'
    # quality = args.quality
    # youtube_links = get_youtube_links(links)
    # urls = get_urls(youtube_links, quality)
    # generate_m3u(filename, urls)

    links = ['https://www.youtube.com/watch?v=u23MOITk4LM']
    filename = '/my_playlist.m3u'
    quality = 'best'
    youtube_links = get_youtube_links(links)
    urls = get_urls(youtube_links, quality)
    generate_m3u(filename, urls)
