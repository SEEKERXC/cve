from __future__ import print_function

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import requests
import re
import os
import subprocess
import sys
import json
import time
import warnings
import clang.cindex
from lxml import etree
from hashlib import blake2b

project_path = 'C:/Users/13319/PycharmProjects/autoMakeMask/'

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
# returns: 受补丁影响的函数名、代码文件名、代码完整路径、cve特征、修改后的代码的所有函数名、发布日期
def process_cve(cveid):
    bulletin_url = ''
    with open("cves-complete.json", 'r') as f:
        result = json.loads(f.read())['result']
    for item in result:
        if item['CVE'] == cveid:
            bulletin_url = item['url']
    cvefeature = CVE_TEMPLATE.copy()
    cvefeature['cve'] = cveid

    proxies = {
        'http': 'socks5://127.0.0.1:10010',
        'https': 'socks5://127.0.0.1:10010'
    }
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' \
                 'Chrome/51.0.2704.103 Safari/537.36 '
    headers = {"User-Agent": user_agent}
    diffuris = []

    func_names = []  # 被修改的函数名
    func_list = []  # 所有函数名
    filenames = []  # 代码文件名
    original_code_links = []  # 修改前代码路径
    patched_code_links = []  # 修改后代码路径
    updated_versions = []  # 影响版本
    serveid = None
    upverid = None
    levels = None
    patch_date = None

    html_r2 = requests.get(bulletin_url, timeout=60, headers=headers, proxies=proxies)
    html_text2 = etree.HTML(html_r2.text)
    tbs = html_text2.xpath('//table')

    tags = re.findall(r'([a-zA-Z \n\-\.\(\)]{0,})</p>\n{0,3}\<table\>(.*?)\</table\>', html_r2.text, re.S)
    summary: str = ''
    for t in tags:
        if cveid in t[1]:
            summary = t[0].replace('\n', ' ')
            break
    if summary and '<p>' in summary:
        summary = summary.split('<p>')[-1]
    cvefeature['title'] = summary
    # 解析公告页面，提出diff链接
    for tb in tbs:
        trs = tb.xpath('.//tr')
        for tr in trs:
            ths = tr.xpath('.//th')
            for thid in range(len(ths)):
                if ths[thid].text == "Severity": serveid = thid
                if "versions" in ths[thid].text:
                    upverid = thid
            tds = tr.xpath('.//td')
            for tdid in range(len(tds)):
                if len(tds) <= 3: continue
                if str(tds[tdid].text).strip() != cveid: continue
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
                levels = str(tds[serveid].text).strip()
                updated_versions = []
                if ',' in tds[upverid].text:
                    updated_versions = tds[upverid].text.split(', ')
                else:
                    if '5.1' in tds[upverid].text:
                        updated_versions.append('5.1')
                    elif '5.0' in tds[upverid].text:
                        updated_versions.append('5.0')
                    elif '6.0' in tds[upverid].text:
                        updated_versions.append('6.0')
                if len(updated_versions) == 0:
                    updated_versions = tds[upverid].text.split(".")
                for j in range(len(updated_versions)):
                    if 'and' in updated_versions[j]:
                        updated_versions[j] = str(updated_versions[j]).replace('and', '').strip()
                    updated_versions[j] = str(updated_versions[j]).strip()
                print("影响版本：{}".format(updated_versions))
    oneid = 0
    for vr in updated_versions:
        if vr.startswith("4"): oneid += 1
    cvefeature['minApiLevel'] = int(VERSION_LEVEL[str(float(updated_versions[oneid][:3]))])
    cvefeature['maxApiLevel'] = int(VERSION_LEVEL[str(float(updated_versions[-1][:3]))])
    cvefeature['severity'] = levels

    # diff页面
    for uri in diffuris:
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
        diffs = html_text4.xpath("//pre[@class='u-pre u-monospace Diff']")
        diff_unifies = html_text4.xpath("//pre[@class='u-pre u-monospace Diff-unified']")
        for k in range(len(diffs)):
            diff = diffs[k]
            diff_unified = diff_unifies[k]

            aa = diff.xpath('.//a')
            aa_texts = []
            for a in aa:
                aa_texts.append(a.text)

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
            spans = diff_unified.xpath("//span[@class='Diff-hunk']")  # hunk：猛男
            linenos = []  # 找到修改后的代码对应的行数
            for span in spans:
                if ',' not in str(span.text): continue
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

                f_pre = open('pre_' + name, 'w', encoding="utf-8")
                for tr in trs_pre:
                    code_spans = tr.xpath('td[2]/span')
                    line = ''
                    for s in code_spans:
                        if s is not None and s.text is not None:
                            line += s.text
                    if '::' in line:
                        ri = line.rindex('::')
                        if ' ' in line[0:ri]:
                            li = line.rindex(' ', 0, ri)
                            line = line[0: li + 1] + line[ri + 2: len(line)]
                    f_pre.write("{}\n".format(line))
                f_pre.flush()
                f_pre.close()

                f_post = open('post_' + name, 'w', encoding="utf-8")
                for tr in trs_post:
                    code_spans = tr.xpath('td[2]/span')
                    line = ''
                    for s in code_spans:
                        if s is not None and s.text is not None:
                            line += s.text
                    if '::' in line:
                        ri = line.rindex('::')
                        if ' ' in line[0:ri]:
                            li = line.rindex(' ', 0, ri)
                            line = line[0: li + 1] + line[ri + 2: len(line)]
                    f_post.write("{}\n".format(line))
                f_post.flush()
                f_post.close()

                # 从代码文件找到修改行对应的函数
                for lineno in linenos:
                    func_name, func_list = find_func_name_by_lineno('post_' + name, lineno)
                    if func_name and func_name not in func_names:
                        func_names.append(func_name)
    return func_names, filenames, patched_code_links, cvefeature, func_list, patch_date


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
    warnings.warn("This function performs badly. Using get_target_file() instead.", DeprecationWarning)
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


# 通过代码路径获取对应目标文件列表，再通过补丁日期确定相应的release，从而确定每个release的目标文件列表
# cve: CVE编号
# base_dir: 存放安卓文件夹的根目录
# code_links: 完整代码路径列表
# patch_date: 补丁发布日期，格式YYYY-mm-dd
def get_target_file(cve, base_dir, code_links, patch_date):
    file_paths = []  # 本地目标文件路径
    targets = []
    with open(project_path + 'targetfile.json', 'rb') as f:
        tt = json.loads(f.read())
        for i, item in tt.items():
            code_paths = item['codepath']
            for link in code_links:
                for code_path in code_paths:
                    if code_path in link:
                        targets = item['target']
    with open(project_path + 'release_date.json', 'r') as rdfile:
        release_date = json.loads(rdfile.read())
    with open(project_path + 'versions.json', 'r') as vf:
        version_json = json.loads(vf.read())
        versions = version_json[cve]
    patch_date_formatted = time.strptime(patch_date, "%Y-%m-%d")
    vulnerable_releases = []  # 存在漏洞的release版本列表
    for release in release_date:
        release_date_formatted = time.strptime(release_date[release], "%Y/%m/%d")
        if patch_date_formatted > release_date_formatted:
            vulnerable_releases.append(release)
    for t in targets:
        for vr in vulnerable_releases:
            for v in versions:
                if v in vr:
                    local_file_path = '{}/{}/out/target/product/generic_arm64{}'.format(base_dir, vr, t)
                    local_dir_path = local_file_path[0:local_file_path.rindex('/')]
                    if not os.path.exists(local_dir_path):
                        os.makedirs(local_dir_path)
                    if not os.path.exists(local_file_path):
                        server_file_path = '/media2_8T/android/{}/android/out/target/product/generic_arm64{}' \
                            .format(vr, t)
                        server_user = "xiaofei@172.16.124.75"
                        scp_cmd = "scp {}:{} {}".format(server_user, server_file_path, local_file_path)
                        # 复制服务器的目标文件到本地
                        print("复制文件：{}".format(server_file_path))
                        os.system(scp_cmd)
                        # todo subprocess
                    file_paths.append(local_file_path)
    return file_paths


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
        mask_digests_list = {}
        affected_funcs, code_file_names, code_links, cvefeature, func_list, patch_date = process_cve(cve)
        if not affected_funcs or len(affected_funcs) == 0:
            print('=============={}：没找到受影响函数=============='.format(cve))
            if code_file_names is not None:
                for name in code_file_names:
                    if os.path.exists('pre_' + name) and os.path.exists('post_' + name):
                        os.remove('pre_' + name)
                        os.remove('post_' + name)
            exit(0)
        print('Affected function names: ', affected_funcs)
        print('Function total: ', len(func_list))
        base_location = "D:/work_2021/android"
        target_files = get_target_file(cve, base_location, code_links, patch_date)
        print("Target files: ", target_files)
        if not target_files or len(target_files) == 0:
            print('=============={}：没找到目标文件=============='.format(cve))
            for name in code_file_names:
                if os.path.exists('pre_' + name) and os.path.exists('post_' + name):
                    os.remove('pre_' + name)
                    os.remove('post_' + name)
            exit(0)

        canGen = False
        base = {}
        mask_values = []
        file_exists = False
        for target in target_files:
            if not os.path.exists(target): file_exists = True
        if not file_exists:
            print("======没有目标文件======")
        for target in target_files:
            if not os.path.exists(target): continue
            symbols = get_symbol_of_target(target, affected_funcs)  # 受影响的函数符号
            if not symbols or len(symbols) == 0:
                print('==============找不到对应的函数符号=============='.format(target))
            offset = get_offset(target)  # 基础偏移
            if symbols and len(symbols) > 0:
                print('==============正在生成 {} 的特征=============='.format(target))
                canGen = True

                file_exists = FILE_EXISTS_TEMPLATE.copy()
                file_exists['filename'] = target[str(target).index('/system'):]
                file_exists_digest = gen_digest(file_exists)
                if file_exists_digest not in file_exists_digests:
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
                    if mask in mask_values: continue
                    mask_values.append(mask)
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
                if file_exists_digest in mask_digests_list:
                    mask_digests_list[file_exists_digest] += mask_digests
                else:
                    mask_digests_list[file_exists_digest] = mask_digests

        base_path = "D:/work_2021/CVE/automask"
        basic_file_path = '{}/{}/{}-BASIC.json'.format(base_path, cve, cve)

        if canGen:
            if not os.path.exists("{}/{}".format(base_path, cve)):
                os.mkdir("{}/{}".format(base_path, cve))
            with open(basic_file_path, 'w') as f:
                f.write(json.dumps(base, indent=4))

        if len(file_exists_digests) == 1:
            if len(mask_digests_list[file_exists_digests[0]]) == 1:
                cvefeature['testVulnerable']['subtests'] = [file_exists_digests[0],
                                                            mask_digests_list[file_exists_digests[0]][0]]
            else:
                mask_list = {
                    'subtests': [],
                    'testType': 'OR'
                }
                for d in mask_digests_list[file_exists_digests[0]]:
                    mask_list['subtests'].append(d)
                cvefeature['testVulnerable']['subtests'].append(file_exists_digests[0])
                cvefeature['testVulnerable']['subtests'].append(mask_list)
        else:
            cvefeature['testVulnerable']['testType'] = 'OR'
            for i in range(len(file_exists_digests)):
                file_exists_digest = file_exists_digests[i]
                masks = mask_digests_list[file_exists_digest]
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
        feature_file = '{}/{}/{}.json'.format(base_path, cve, cve)

        if canGen:
            base = {}
            base.update({cve: cvefeature})
            with open(feature_file, 'w') as f:
                f.write(json.dumps(base, indent=4))
            print('==================生成完毕==================')

        for name in code_file_names:
            if os.path.exists('pre_' + name) and os.path.exists('post_' + name):
                os.remove('pre_' + name)
                os.remove('post_' + name)
        if not canGen:
            print('==================不能生成MASK_SIGNATURE_SYMBOL==================')
