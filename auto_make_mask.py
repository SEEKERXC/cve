from __future__ import print_function

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import requests
import re
import os
import subprocess
import sys
import json
import clang.cindex
from lxml import etree
from hashlib import blake2b

sSecurityBulletinUri = r'https://nvd.nist.gov/vuln/detail/'

FILE_EXISTS_TEMPLATE = {
    "filename": "",
    "testType": "FILE_EXISTS"
}

MASK_TEMPLATE = {
    "filename": "",
    "signature": "",
    "symbol": "",
    "testType": "MASK_SIGNATURE_SYMBOL"
}

CVE_TEMPLATE = {
    "category": "2018-08",
    "cve": "",
    "minApiLevel": 0,
    "maxApiLevel": 0,
    "severity": "",
    "testFixed": {
        "testType": "FALSE"
    },
    "testNotAffected": {
        "testType": "FALSE"
    },
    "testRequires64bit": True,
    "testVulnerable": {
        "subtests": [
        ],
        "testType": "AND"
    },
    "title": ""
}

VERSION_LEVEL = {
    '5.0': '21',
    '5.1': '22',
    '6.0': '23',
    '7.0': '24',
    '7.1': '25',
    '8.0': '26',
    '8.1': '27',
    '9.0': '28',
    '10.0': '29',
    '11.0': '30'
}


# 解析cve补丁页面以获取被修改的函数名
def process_cve(cveid):
    cvefeature = CVE_TEMPLATE.copy()
    cvefeature['cve'] = cveid

    proxies = {
        'http': 'socks5://127.0.0.1:10808',
        'https': 'socks5://127.0.0.1:10808'
    }
    uri = '{}{}'.format(sSecurityBulletinUri, cveid)
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
                 'Chrome/51.0.2704.103 Safari/537.36 '
    headers = {"User-Agent": user_agent}
    html_r = requests.get(uri, timeout=10, headers=headers, proxies=proxies)
    html_text = etree.HTML(html_r.text)
    wpsc = str(etree.tostring(html_text, pretty_print=True))
    diffuris = []
    gp = re.findall(r'(http://source.android.com/security/bulletin.*?)[\"<]', wpsc)
    if not gp:
        gp = re.findall(r'(https://source.android.com/security/bulletin.*?)[\"<]', wpsc)
    if not gp:
        diffuris = re.findall(r'(https://android.googlesource.com/platform/.*?)\"', wpsc)
    if gp == [] and diffuris == []:
        diffuris = re.findall(r'(http://android.googlesource.com/platform/.*?)\"', wpsc)
    if gp == [] and diffuris == []:
        print('[*][func=searchCVEInfo]Error: Can\'t found {} Diff web page address in {}.'.format(cveid, uri))
        return
    func_names = []
    filenames = []
    updated_versions = []
    serveid = None
    upverid = None
    levels = None
    if gp:
        bulletin_url = gp[0]
        html_r2 = requests.get(bulletin_url, timeout=10, headers=headers, proxies=proxies)
        html_text2 = etree.HTML(html_r2.text)
        tbs = html_text2.xpath('//table')

        tags = re.findall(r'([a-zA-Z \n\-\.\(\)]{0,})</p>\n{0,3}\<table\>(.*?)\</table\>', html_r2.text, re.S)
        summary: str = None
        for t in tags:
            if cveid in t[1]:
                summary = t[0].replace('\n', ' ')
                break
        if summary and '<p>' in summary:
            summary = summary.split('<p>')[-1]
        cvefeature['title'] = summary
        # 解析公告页面，提出diff链接
        hasuri = False
        for tb in tbs:
            trs = tb.xpath('.//tr')
            for tr in trs:
                ths = tr.xpath('.//th')
                for thid in range(len(ths)):
                    if ths[thid].text == "Severity": serveid = thid
                    if ths[thid].text == "Updated AOSP versions":
                        upverid = thid
                    elif ths[thid].text == "Updated versions":
                        upverid = thid
                tds = tr.xpath('.//td')
                for tdid in range(len(tds)):
                    if len(tds) < 3: continue
                    if tds[tdid].text != cveid: continue
                    diffuris = [a.get('href') for a in tds[tdid + 1].xpath('.//a')]
                    print(diffuris)

                    isgoogleuri = False
                    for link in diffuris:
                        if 'android.googlesource.com' not in link: continue
                        isgoogleuri = True
                        link = str(bulletin_url)
                        patch_date = link[(link.rindex('/') + 1):]
                        cvefeature['category'] = patch_date[0:7]
                    if not isgoogleuri: continue
                    hasuri = True
                    levels = tds[serveid].text
                    updated_versions = tds[upverid].text.split(', ')
        if not hasuri: return ''
        oneid = 0
        for vr in updated_versions:
            if vr.startswith("4"): oneid += 1
        cvefeature['minApiLevel'] = int(VERSION_LEVEL[str(float(updated_versions[oneid][:3]))])
        cvefeature['maxApiLevel'] = int(VERSION_LEVEL[str(float(updated_versions[-1][:3]))])
        cvefeature['severity'] = levels

        # diff页面
        for uri in diffuris:
            html_r3 = requests.get(uri, timeout=10, headers=headers, proxies=proxies)
            html_text3 = etree.HTML(html_r3.text)
            aa = html_text3.xpath('//a')
            diff_detail = ''
            for a in aa:
                if a.text != 'diff': continue
                diff_detail = 'https://android.googlesource.com{}'.format(a.get('href'))
                break
            print('==================diff详情链接==================')
            print(diff_detail)

            # 找到代码链接以及对应的行数
            html_r4 = requests.get(diff_detail, timeout=10, headers=headers, proxies=proxies)
            html_text4 = etree.HTML(html_r4.text)
            aa = html_text4.xpath('//a')
            aa_texts = []
            for a in aa:
                aa_texts.append(a.text)
            original_code_links = []
            patched_code_links = []

            print('==================代码文件名与链接==================')
            for a in aa:
                text = a.text
                if isinstance(text, str) and text.startswith("b/") \
                        and (text.endswith('.cc') or text.endswith('.c')
                             or text.endswith('.cpp')):
                    if ('a/' + text[2:]) in aa_texts:  # 仅对修改过的c/c++代码
                        post_url = 'https://android.googlesource.com{}'.format(a.get('href'))
                        patched_code_links.append(post_url)
                        name = text[(text.rindex('/') + 1):]
                        filenames.append(name)
                        print('file name:  ', name)
                        print('post-patch: ', post_url)
                        for link in aa:
                            if link.text == 'a/' + text[2:]:
                                pre_url = 'https://android.googlesource.com{}'.format(link.get('href'))
                                original_code_links.append(pre_url)
                                print('pre-patch:  ', pre_url)
            spans = html_text4.xpath("//span[@class='Diff-hunk']")
            linenos = []  # 找到修改后的代码对应的行数
            for span in spans:
                index_start = str(span.text).index('+') + 1
                index_end = str(span.text).index(',', index_start)
                t = str(span.text)[index_start:index_end]
                lineno = int(t)
                linenos.append(lineno)

            for i in range(len(original_code_links)):
                original_link = original_code_links[i]
                patched_link = patched_code_links[i]
                name = filenames[i]

                html_r_pre = requests.get(original_link, timeout=10, headers=headers, proxies=proxies)
                html_r_post = requests.get(patched_link, timeout=10, headers=headers, proxies=proxies)
                html_text_pre = etree.HTML(html_r_pre.text)
                html_text_post = etree.HTML(html_r_post.text)

                # 从代码页面提取出代码，保存到文件中
                trs_pre = html_text_pre.xpath('//tr')
                trs_post = html_text_post.xpath('//tr')

                f_pre = open('pre_' + name, 'x')
                for tr in trs_pre:
                    code_spans = tr.xpath('td[2]/span')
                    line = ''
                    for s in code_spans:
                        line += s.text
                    f_pre.write("{}\n".format(line))
                f_pre.flush()
                f_pre.close()

                f_post = open('post_' + name, 'x')
                for tr in trs_post:
                    code_spans = tr.xpath('td[2]/span')
                    line = ''
                    for s in code_spans:
                        line += s.text
                    f_post.write("{}\n".format(line))
                f_post.flush()
                f_post.close()

                # 从代码文件找到修改行对应的函数
                for lineno in linenos:
                    func_name = find_func_name_by_lineno('post_' + name, lineno)
                    if func_name and func_name not in func_names:
                        func_names.append(func_name)
    return func_names, filenames, cvefeature


# 获取elf文件中函数偏移地址和函数长度，以及对应的代码文件名
def get_func_offset_length(cveid, filename):
    func_names, code_file_names, cvefeature = process_cve(cveid)
    print('Affected function names: ', func_names)
    symbols_res = []
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for s in section.iter_symbols():
                    for func_name in func_names:
                        if func_name in str(s.name) or func_name == str(s.name):
                            symbols_res.append(s)
    return symbols_res, code_file_names, cvefeature


# 获取elf文件的基地址偏移量
def get_offset(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        segment = elffile.get_segment(0)
        header = segment.header
        p_vaddr = header.p_vaddr
        p_paddr = header.p_paddr
        p_offset = header.p_offset
        return int(p_vaddr) - int(p_offset)


# 执行makeMask.exe获取mask_signature
def make_mask(elffile, func_offset, func_len):
    process = subprocess.Popen('makeMask.exe -f {} -offset {} -l {}'.format(elffile, func_offset, func_len),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = process.communicate()
    return str(out, 'utf-8')[:-2]  # 去掉结尾的\r\n


# 遍历抽象语法树（Abstract Syntax Tree），找到距离指定行号最近的函数
class AST(object):
    candidate = None

    def traverse(self, node, lineno):
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            if node.location.line <= lineno:
                if self.candidate is None:
                    self.candidate = node
                distance = lineno - node.location.line
                if distance < lineno - self.candidate.location.line:
                    self.candidate = node
        for n in node.get_children():
            self.traverse(n, lineno)


# 根据文件名和行号找到函数，如果没找到，则返回None
def find_func_name_by_lineno(filename, lineno):
    index = clang.cindex.Index.create()
    parser = index.parse(filename)
    cursor = parser.cursor
    a = AST()
    a.traverse(cursor, lineno)
    if a.candidate:
        return a.candidate.spelling
    else:
        return None


def gen_digest(feature):
    h = blake2b(digest_size=8)
    h.update(str(feature).encode('utf-8'))
    return str(h.hexdigest()).upper()


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: python3 auto_make_mask.py [cveid] [filename]')
    else:
        cve = sys.argv[1]
        file = sys.argv[2]
        offset = get_offset(file)
        symbols, code_names, cvefeature = get_func_offset_length(cve, file)
        print('==================生成结果==================')
        masks = []
        mask_features = []
        base = {}
        for symbol in symbols:
            addr = int(symbol['st_value']) - offset
            if addr % 4 != 0: addr -= 1
            addr = hex(addr)
            length = hex(int(symbol['st_size']))
            mask = make_mask(file, addr, length)
            if mask in masks: continue
            masks.append({
                'signature': mask,
                'symbol': symbol.name
            })
            print('MASK_SIGNATURE_SYMBOL: {}'.format(mask))
            print('SYMBOL: {}'.format(symbol.name))
        for name in code_names:
            os.remove('pre_' + name)
            os.remove('post_' + name)

        for mask in masks:
            mask_feature = MASK_TEMPLATE.copy()
            mask_feature['filename'] = file
            mask_feature['signature'] = mask['signature']
            mask_feature['symbol'] = mask['symbol']
            mask_features.append(mask_feature)
        file_exists = FILE_EXISTS_TEMPLATE.copy()
        file_exists['filename'] = file

        file_exists_digest = gen_digest(file_exists)
        mask_digests = []

        base.update({file_exists_digest: file_exists})
        for mask_feature in mask_features:
            d = gen_digest(mask_feature)
            if d not in mask_digests:
                mask_digests.append(d)
            base.update({d: mask_feature})

        if len(mask_features) == 1:
            cvefeature['testVulnerable']['subtests'] = [file_exists_digest, mask_digests[0]]
        else:
            mask_list = {
                'subtests': [],
                'testType': 'OR'
            }
            for d in mask_digests:
                mask_list['subtests'].append(d)
            cvefeature['testVulnerable']['subtests'].append(file_exists_digest)
            cvefeature['testVulnerable']['subtests'].append(mask_list)
        basic_file = '{}-BASIC.json'.format(cve)
        feature_file = '{}.json'.format(cve)
        with open(basic_file, 'w') as f:
            f.write(json.dumps(base, indent=4))
        with open(feature_file, 'w') as f:
            f.write(json.dumps(cvefeature, indent=4))
