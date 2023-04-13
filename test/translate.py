import opencc
import re


def translate_subtitle(subtitle, source_language, target_language):
    # 建立 OpenCC 转换器
    if source_language == 'en':
        if target_language == 'zh':
            converter = opencc.OpenCC('s2t.json')
        else:
            raise ValueError('目标语言不支持该字幕的源语言')
    elif source_language == 'ja':
        if target_language == 'zh':
            converter = opencc.OpenCC('jp2t.json')
        else:
            raise ValueError('目标语言不支持该字幕的源语言')
    elif source_language == 'zh':
        if target_language == 'zh':
            converter = opencc.OpenCC('t2s.json')
        else:
            raise ValueError('目标语言不支持该字幕的源语言')
    else:
        raise ValueError('不支持该字幕的源语言')

    # 逐行翻译
    translated_lines = []
    for line in subtitle.splitlines():
        # 提取文本和时间轴信息
        match = re.match(r'(d+:d+:[d,.]+) --> (d+:d+:[d,.]+)(.*)', line)
        if match:
            time_info = match.group(1) + ' --> ' + match.group(2)
            text = match.group(3)
        else:
            time_info = ''
            text = line

        # 使用 OpenCC 进行翻译
        text = converter.convert(text)

        # 重组文本和时间轴信息
        translated_line = time_info + text
        translated_lines.append(translated_line)

    # 拼接翻译后的字幕
    translated_subtitle = 'n'.join(translated_lines)

    return translated_subtitle
