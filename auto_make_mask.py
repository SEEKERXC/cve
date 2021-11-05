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
    "category": "",
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
# returns: 受补丁影响的函数名、代码文件名、cve特征、修改后的代码的所有函数名
def process_cve(cveid):
    cvefeature = CVE_TEMPLATE.copy()
    cvefeature['cve'] = cveid

    proxies = {
        'http': 'socks5://127.0.0.1:10010',
        'https': 'socks5://127.0.0.1:10010'
    }
    uri = '{}{}'.format(sSecurityBulletinUri, cveid)
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
                 'Chrome/51.0.2704.103 Safari/537.36 '
    headers = {"User-Agent": user_agent}
    html_r = requests.get(uri, timeout=60, headers=headers, proxies=proxies)
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
        search_url = 'https://cse.google.com/cse/element/v1'
        params = {
            'rsz': 'filtered_cse',
            'num': 10,
            'hl': 'en',
            'source': 'gcsc',
            'gss': '.com',
            'cselibv': 'cc267ab8871224bd',
            'cx': '016258643462168859875:qqpm8fiwgc0',
            'q': cveid,
            'safe': 'off',
            'cse_tok': 'AJvRUv0cZaTCYrG86F2lGagUcZLg:1636093256173',
            'exp': 'csqr,cc,4618907',
            'callback': 'google.search.cse.api19986'
        }
        search_request = requests.get(search_url, params=params,
                                      timeout=60, headers=headers, proxies=proxies)
        json_search = search_request.text
        index_p = json_search.index('(')
        gp.append(json.loads(json_search[(index_p + 1):-2])['results'][0]['url'])
    func_names = []  # 被修改的函数名
    func_list = []  # 所有函数名
    filenames = []  # 代码文件名
    updated_versions = []
    serveid = None
    upverid = None
    levels = None
    if gp:
        bulletin_url = gp[0]
        if str(bulletin_url).endswith(','): bulletin_url = bulletin_url[:-1]
        html_r2 = requests.get(bulletin_url, timeout=60, headers=headers, proxies=proxies)
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
            if 'https' not in uri or 'http' not in uri:
                uri = 'https:' + uri
            html_r3 = requests.get(uri, timeout=60, headers=headers, proxies=proxies)
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
            html_r4 = requests.get(diff_detail, timeout=60, headers=headers, proxies=proxies)
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

                html_r_pre = requests.get(original_link, timeout=60, headers=headers, proxies=proxies)
                html_r_post = requests.get(patched_link, timeout=60, headers=headers, proxies=proxies)
                html_text_pre = etree.HTML(html_r_pre.text)
                html_text_post = etree.HTML(html_r_post.text)

                # 从代码页面提取出代码，保存到文件中
                trs_pre = html_text_pre.xpath('//tr')
                trs_post = html_text_post.xpath('//tr')

                f_pre = open('pre_' + name, 'w')
                for tr in trs_pre:
                    code_spans = tr.xpath('td[2]/span')
                    line = ''
                    for s in code_spans:
                        line += s.text
                    f_pre.write("{}\n".format(line))
                f_pre.flush()
                f_pre.close()

                f_post = open('post_' + name, 'w')
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
                    func_name, func_list = find_func_name_by_lineno('post_' + name, lineno)
                    if func_name and func_name not in func_names:
                        func_names.append(func_name)

    return func_names, filenames, cvefeature, func_list


# 获取elf文件中函数符号信息
def get_symbol_of_target(target_file, affected_functions):
    symbols_res = []
    with open(target_file, 'rb') as f:
        elffile = ELFFile(f)
        for section in elffile.iter_sections():
            if isinstance(section, SymbolTableSection):
                for s in section.iter_symbols():
                    for func_name in affected_functions:
                        if func_name in str(s.name) or func_name == str(s.name):
                            symbols_res.append(s)
    return symbols_res


# 获取elf文件的基地址偏移量
def get_offset(filename):
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
    func_list = []

    def traverse(self, node, lineno):
        if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
            self.func_list.append(node.spelling)
            if node.location.line <= lineno:
                if self.candidate is None:
                    self.candidate = node
                distance = lineno - node.location.line
                if distance < lineno - self.candidate.location.line:
                    self.candidate = node
        for n in node.get_children():
            self.traverse(n, lineno)


# 根据文件名和行号找到函数，如果没找到，则返回None
# 顺便返回所有函数的名称
def find_func_name_by_lineno(filename, lineno):
    index = clang.cindex.Index.create()
    parser = index.parse(filename)
    cursor = parser.cursor
    a = AST()
    a.traverse(cursor, lineno)
    if a.candidate:
        return a.candidate.spelling, a.func_list
    else:
        return None, a.func_list


# grep所有函数名，找到目标文件
# grep_location: grep.exe文件绝对路径
# all_function: 所有函数列表
# base_location: 要搜索的基础目录
def grep_for_target(grep_location, all_functions, patch_affected_functions, base_location):
    print('==================正在查找目标文件==================')
    # 将补丁影响函数放到前面，复杂度O(N)
    for func in all_functions:
        if func not in patch_affected_functions:
            patch_affected_functions.append(func)

    candidates = []
    for func in patch_affected_functions:
        print("搜索函数：{}".format(func))
        process = subprocess.Popen(
            "{} -r {} {}".format(grep_location, func, base_location),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        results = str(out, 'utf-8').split("\n")
        results.remove('')
        if results and len(results) > 0:
            lindex = 12
            to_remove = []
            for i in range(len(results)):
                if 'matches' not in results[i]:
                    to_remove.append(results[i])
                    continue
                rindex = results[i].index(' matches')
                results[i] = results[i][lindex:rindex]
            for t in to_remove:
                results.remove(t)
            if len(candidates) == 0:
                candidates = results
            for binary in candidates:
                if binary not in results:
                    candidates.remove(binary)
        if len(candidates) == 1: break

        if len(candidates) > 0:
            # 如果候选文件名都一样，那么都作为返回结果
            file_list = []
            for candidate in candidates:
                index = candidate.rindex('/')
                file_list.append(candidate[index:])
            all_the_same = True
            if len(file_list) > 0:
                file0 = file_list[0]
                for binary in file_list:
                    if binary != file0:
                        all_the_same = False
            if all_the_same: break
        to_remove = []
        for i in range(len(candidates)):
            if candidates[i].endswith('.odex') or candidates[i].endswith('.apk') or candidates[i].endswith('.oat') or \
                    candidates[i].endswith('.dex'):
                to_remove.append(candidates[i])
        for s in to_remove:
            candidates.remove(s)
        print('候选文件：{}'.format(candidates))
    return candidates


# 生成摘要
def gen_digest(feature):
    h = blake2b(digest_size=8)
    h.update(str(feature).encode('utf-8'))
    return str(h.hexdigest()).upper()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python3 auto_make_mask.py [cveid]')
    else:
        cve = sys.argv[1]

        file_exists_digests = []
        mask_digests_list = []
        affected_funcs, code_file_names, cvefeature, func_list = process_cve(cve)
        print('Affected function names: ', affected_funcs)
        print('Function total: ', len(func_list))
        base_location = "D:/work_2021/system"
        target_files = grep_for_target("C:/Program Files (x86)/GnuWin32/bin/grep.exe", func_list, affected_funcs,
                                       base_location=base_location)
        print("Target files: ", target_files)

        canGen = False
        base = {}
        for target in target_files:
            symbols = get_symbol_of_target(target, affected_funcs)  # 受影响的函数符号
            offset = get_offset(target)  # 基础偏移
            if symbols and len(symbols) > 0:
                print('==============正在生成 {} 的特征=============='.format(target))
                canGen = True

                file_exists = FILE_EXISTS_TEMPLATE.copy()
                file_exists['filename'] = target[str(target).index('/system'):]
                file_exists_digest = gen_digest(file_exists)
                file_exists_digests.append(file_exists_digest)
                base.update({file_exists_digest: file_exists})

                masks = []
                mask_digests = []
                for symbol in symbols:
                    addr = int(symbol['st_value']) - offset
                    if addr % 4 != 0: addr -= 1
                    addr = hex(addr)
                    length = hex(int(symbol['st_size']))
                    mask = make_mask(target, addr, length)
                    mask_feature = {
                        'filename': target[str(target).index('/system'):],
                        'signature': mask,
                        'symbol': symbol.name,
                        'testType': "MASK_SIGNATURE_SYMBOL"
                    }
                    if mask_feature in masks: continue
                    masks.append(mask_feature)
                    print('MASK_SIGNATURE_SYMBOL: {}'.format(mask))
                    print('SYMBOL: {}'.format(symbol.name))

                    for mask_feature in masks:
                        d = gen_digest(mask_feature)
                        if d not in mask_digests:
                            mask_digests.append(d)
                        base.update({d: mask_feature})
                mask_digests_list.append(mask_digests)

        basic_file = '{}-BASIC.json'.format(cve)

        if canGen:
            with open(basic_file, 'w') as f:
                f.write(json.dumps(base, indent=4))

        if len(file_exists_digests) == 1:
            if len(mask_digests_list[0]) == 1:
                cvefeature['testVulnerable']['subtests'] = [file_exists_digests[0], mask_digests_list[0][0]]
            else:
                mask_list = {
                    'subtests': [],
                    'testType': 'OR'
                }
                for d in mask_digests_list[0]:
                    mask_list['subtests'].append(d)
                cvefeature['testVulnerable']['subtests'].append(file_exists_digests[0])
                cvefeature['testVulnerable']['subtests'].append(mask_list)
        else:
            cvefeature['testVulnerable']['testType'] = 'OR'
            for i in range(len(file_exists_digests)):
                file_exists_digest = file_exists_digests[i]
                masks = mask_digests_list[i]
                feature_of_one_file = {
                    'subtests': [],
                    'testType': 'AND'
                }
                feature_of_one_file['subtests'].append(file_exists_digest)
                if len(masks) == 1:
                    feature_of_one_file['subtests'].append(masks[0])
                else:
                    mask_list = {
                        'subtests': masks,
                        'testType': 'OR'
                    }
                    feature_of_one_file['subtests'].append(mask_list)

                cvefeature['testVulnerable']['subtests'].append(feature_of_one_file)
        feature_file = '{}.json'.format(cve)

        if canGen:
            base = {}
            base.update({cve: cvefeature})
            with open(feature_file, 'w') as f:
                f.write(json.dumps(base, indent=4))

        for name in code_file_names:
            if os.path.exists('pre_' + name) and os.path.exists('post_' + name):
                os.remove('pre_' + name)
                os.remove('post_' + name)
        if not canGen:
            print('==================不能生成MASK_SIGNATURE_SYMBOL==================')
