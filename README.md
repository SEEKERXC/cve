### 功能描述

此脚本可以通过输入CVE编号自动生成MASK_SIGNATURE_SYMBOL

### 环境搭建
安装python3

pip3 install pyelftools

pip3 install clang

pip3 install llvm

复制项目中的libclang.dll到c:\windows\system32文件夹

### 使用
python3 auto_make_mask.py [cveid] [filename]
在当前目录生成两个文件：基础特征json文件与cve特征json文件