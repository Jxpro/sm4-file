# -*- coding:utf-8 -*-

import json
import os.path
import re
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from crypto.sm4 import *


class SM4File:
    def __init__(self):
        self.config = {}
        # 读取配置
        if os.path.exists('config.json'):
            with open('config.json', 'r', encoding='utf-8') as f:
                self.config = json.load(f)

        # 调用Tk()创建主窗口
        self.window = tk.Tk()
        # 设置窗口居中
        self.window_center(488, 400)
        # 设置窗口不可拉伸
        self.window.resizable(False, False)
        # 设置窗口左上角的名字
        self.window.title('SM4文件加解密')
        # 设置窗口左上角的的icon图标
        self.window.iconbitmap('favicon.ico')

        # 方便下面调用时，省略self
        window = self.window

        # 绘制提示标签
        tk.Label(window, text='文件路径:', width=10, height=2, anchor='w').grid(row=0, column=0, padx=10,pady=5)
        tk.Label(window, text='输出路径:', width=10, height=2, anchor='w').grid(row=1, column=0, padx=10,pady=5)
        tk.Label(window, text='密钥 Key:', width=10, height=2, anchor='w').grid(row=2, column=0, padx=10,pady=5)
        tk.Label(window, text='初始向量 IV:', width=10, height=2, anchor='w').grid(row=3, column=0, padx=10,pady=5)
        tk.Label(window, text='计数 Nonce:', width=10, height=2, anchor='w').grid(row=4, column=0, padx=10,pady=5)
        tk.Label(window, text='加/解密进度:', width=10, height=2, anchor='w').grid(row=7, column=0, padx=10,pady=5)

        # 声明文本变量
        self.file_path = tk.StringVar()
        self.dic_path = tk.StringVar()
        self.key_string = tk.StringVar()
        self.iv_string = tk.StringVar()
        self.nonce_string = tk.StringVar()
        self.progress_string = tk.StringVar()

        # 设置提示文本
        self.file_path.set(self.config.get('file_path', '请选择待加密文件'))
        self.dic_path.set(self.config.get('dic_path', '请选择输出路径'))
        self.key_string.set(self.config.get('key', ''))
        self.iv_string.set(self.config.get('iv', ''))
        self.nonce_string.set(self.config.get('nonce', ''))

        # 设置进度条
        self.progress_string.set("")
        self.total_size_str = ""
        self.now_size_str = ""

        # 绘制路径文本框
        tk.Entry(window, text=self.file_path, width=42, state='readonly').grid(row=0, column=1, columnspan=3, pady=5)
        tk.Entry(window, text=self.dic_path, width=42, state='readonly').grid(row=1, column=1, columnspan=3, pady=5)

        # 绘制路径选择按钮
        tk.Button(window, text='选择文件', command=self.get_file_path).grid(row=0, column=4, padx=10, pady=5)
        tk.Button(window, text='选择路径', command=self.get_dic_path).grid(row=1, column=4, padx=10, pady=5)

        # 绘制随机生成按钮
        tk.Button(window, text='随机生成', command=lambda: self.random_num(0)).grid(row=2, column=4, padx=10, pady=5)
        tk.Button(window, text='随机生成', command=lambda: self.random_num(1)).grid(row=3, column=4, padx=10, pady=5)
        tk.Button(window, text='随机生成', command=lambda: self.random_num(2)).grid(row=4, column=4, padx=10, pady=5)

        # 绘制密钥文本框
        tk.Entry(window, text=self.key_string, width=42).grid(row=2, column=1, columnspan=3, pady=5)
        tk.Entry(window, text=self.iv_string, width=42).grid(row=3, column=1, columnspan=3, pady=5)
        tk.Entry(window, text=self.nonce_string, width=42).grid(row=4, column=1, columnspan=3, pady=5)

        # 绘制加密按钮
        tk.Button(window, text='ECB加密', command=lambda: self.crypt(SM4_ECB_MODE, True)).grid(row=5, column=0, pady=10)
        tk.Button(window, text='CBC加密', command=lambda: self.crypt(SM4_CBC_MODE, True)).grid(row=5, column=1, pady=10)
        tk.Button(window, text='CFB加密', command=lambda: self.crypt(SM4_CFB_MODE, True)).grid(row=5, column=2, pady=10)
        tk.Button(window, text='OFB加密', command=lambda: self.crypt(SM4_OFB_MODE, True)).grid(row=5, column=3, pady=10)
        tk.Button(window, text='CTR加密', command=lambda: self.crypt(SM4_CTR_MODE, True)).grid(row=5, column=4, pady=10)

        # 绘制加密按钮
        tk.Button(window, text='ECB解密', command=lambda: self.crypt(SM4_ECB_MODE, False)).grid(row=6, column=0)
        tk.Button(window, text='CBC解密', command=lambda: self.crypt(SM4_CBC_MODE, False)).grid(row=6, column=1)
        tk.Button(window, text='CFB解密', command=lambda: self.crypt(SM4_CFB_MODE, False)).grid(row=6, column=2)
        tk.Button(window, text='OFB解密', command=lambda: self.crypt(SM4_OFB_MODE, False)).grid(row=6, column=3)
        tk.Button(window, text='CTR解密', command=lambda: self.crypt(SM4_CTR_MODE, False)).grid(row=6, column=4)

        # 绘制进度条
        self.progress_bar = ttk.Progressbar(window, length=300)
        self.progress_bar.grid(row=7, column=1, columnspan=3, pady=20)
        tk.Label(window, textvariable=self.progress_string, width=12, height=2).grid(row=7, column=4)

        # 计算文件大小
        if self.config.get('file_path'):
            self.total_size_str = self.compute_size_str(os.path.getsize(str(self.config.get('file_path'))))
            self.progress_string.set("0/" + self.total_size_str)
            self.progress_bar['value'] = 0
            self.window.update()

        # 调用mainloop()显示主窗口
        window.mainloop()

        # 结束时更新配置
        with open('config.json', 'w', encoding='utf-8') as f:
            # ensure_ascii 参数保证中文不会变为Unicode编码
            # indent 参数表示缩减4个空格，保证不会将结果输出为一行
            json.dump(self.config, f, ensure_ascii=False, indent=4)

    def window_center(self, width, height):
        """
        设置窗口居中
        :param width: 窗口宽度
        :param height: 窗口高度
        :return: None
        """
        # 得到屏幕宽度
        screen_width = self.window.winfo_screenwidth()
        # 得到屏幕高度
        screen_height = self.window.winfo_screenheight()
        # 设置窗口居中
        x = (screen_width - width) / 2
        y = (screen_height - height) / 2
        self.window.geometry("%dx%d+%d+%d" % (width, height, x, y))

    def get_file_path(self):
        """
        获取文件路径
        :return: None
        """
        # 打开文件对话框
        file_path = filedialog.askopenfilename(title='请选择文件')

        # 返回文件路径并获取大小,并将输出目录默认为该目录
        if file_path:
            # 设置路径
            self.file_path.set(file_path)
            self.dic_path.set(os.path.dirname(file_path))
            self.config.update({'file_path': file_path})
            self.config.update({'dic_path': os.path.dirname(file_path)})

            # 计算文件大小
            self.total_size_str = self.compute_size_str(os.path.getsize(file_path))
            self.progress_string.set("0/" + self.total_size_str)
            self.progress_bar['value'] = 0
            self.window.update()

    def get_dic_path(self):
        """
        获取文件夹路径
        :return: None
        """
        # 打开文件对话框
        dic_path = filedialog.askdirectory(title='请选择文件夹')

        # 返回文件夹路径
        if dic_path:
            self.dic_path.set(dic_path)
            self.config.update({'dic_path': dic_path})

    def random_num(self, i):
        """
        产生并设置随机数
        :param i: 0-key，1-iv，2-nonce
        :return: None
        """
        random_str = os.urandom(16).hex()
        if i == 0:
            self.key_string.set(random_str)
        elif i == 1:
            self.iv_string.set(random_str)
        else:
            self.nonce_string.set(random_str)

    def crypt(self, mode, is_encrypt):
        """
        加密或解密
        :param mode: 加密模式
        :param is_encrypt: 是否加密
        :return: None
        """
        # 检查条件是否满足
        assert self.file_path.get() != '请选择待加密文件', messagebox.showinfo('警告', '请选择待加密文件')
        assert self.dic_path.get() != '请选择加密后文件路径', messagebox.showinfo('警告', '请选择加密后文件路径')
        assert len(self.key_string.get()) == 32, messagebox.showinfo('警告', '密钥长度需为16字节（32位十六进制数）')
        assert re.match(r'^[0-9a-fA-F]{32}$', self.key_string.get()), messagebox.showinfo('提示', '密钥需要为十六进制数')
        if mode == SM4_CTR_MODE:
            assert len(self.nonce_string.get()) == 32, messagebox.showinfo('警告', 'nonce长度需为16字节（32位十六进制数）')
            assert re.match(r'^[0-9a-fA-F]{32}$', self.nonce_string.get()), messagebox.showinfo('提示', 'nonce需要为十六进制数')
        if mode != SM4_ECB_MODE:
            assert len(self.iv_string.get()) == 32, messagebox.showinfo('警告', '初始向量长度需为16字节（32位十六进制数）')
            assert re.match(r'^[0-9a-fA-F]{32}$', self.iv_string.get()), messagebox.showinfo('提示', 'iv需要为十六进制数')

        # 更新配置
        self.config.update({'key': self.key_string.get()})
        if self.iv_string != '':
            self.config.update({'iv': self.iv_string.get()})
        if self.nonce_string != '':
            self.config.update({'nonce': self.nonce_string.get()})

        # 检查文件是否存在
        if not os.path.exists(self.file_path.get()):
            messagebox.showinfo('警告', '待加密文件不存在')
        if not os.path.exists(self.dic_path.get()):
            messagebox.showinfo('警告', '输出路径不存在')

        # 生成加密文件名
        if is_encrypt:
            data_out_path = self.dic_path.get() + "/" + os.path.basename(self.file_path.get()) + '.enc' + mode
            # data_out_path = self.dic_path.get() + "/" + os.path.basename(self.file_path.get()) + '.enc'
        elif os.path.basename(self.file_path.get()).endswith('.enc' + mode):  # endswith('.enc' + mode)
            data_out_path = self.dic_path.get() + "/" + os.path.basename(self.file_path.get())[:-13]
            # data_out_path = self.dic_path.get() + "/" + os.path.basename(self.file_path.get())[:-4]
        else:
            data_out_path = self.dic_path.get() + "/" + os.path.basename(self.file_path.get()) + '.dec'

        # 初始化加密/解密类
        sm4_suite = SM4Suite(self.key_string.get(), mode, iv=self.iv_string.get(), nonce=self.nonce_string.get())

        # 打开文件
        f_in = open(self.file_path.get(), 'rb')
        f_out = open(data_out_path, 'wb')

        # 设置进度条
        self.progress_bar['maximum'] = os.path.getsize(self.file_path.get())
        self.progress_bar['value'] = 0

        # 计时开始
        start_time = time.time()

        # 捕获加解密错误
        try:
            # 加密/解密
            if is_encrypt:
                while True:
                    data = f_in.read(10240)
                    if not data:
                        break
                    # 尝试使用多线程，但是效果不佳
                    # _thread.start_new_thread(lambda d: f_out.write(sm4_suite.encrypt(d)), (data,))
                    f_out.write(sm4_suite.encrypt(data))
                    self.progress_bar['value'] += len(data)
                    self.progress_string.set(
                        self.compute_size_str(self.progress_bar['value']) + "/" + self.total_size_str)
                    self.window.update()
            else:
                while True:
                    # 16位是可能的额外填充字节（12400+16）
                    data = f_in.read(10256)
                    if not data:
                        break
                    f_out.write(sm4_suite.decrypt(data))
                    self.progress_bar['value'] += len(data)
                    self.progress_string.set(
                        self.compute_size_str(self.progress_bar['value']) + "/" + self.total_size_str)
                    self.window.update()
        except:
            messagebox.showinfo('错误', '加密错误' if is_encrypt else '解密错误')
            return

        # 计时结束
        end_time = time.time()

        # 关闭文件
        f_in.close()
        f_out.close()

        # 提示
        messagebox.showinfo('提示', ('加密成功' if is_encrypt else '解密成功') + "，耗时: %d s" % (end_time - start_time))

    @staticmethod
    def compute_size_str(size):
        """
        计算文件大小的字符串形式
        :param size: int类型，文件大小，单位是Byte
        :return: B或KB或MB等形式的字符串表示形式
        """
        if size < 1024:
            size_str = str(size) + "B"
        elif size < 1024 * 1024:
            size_str = str(round(size / 1024, 1)) + "K"
        elif size < 1024 * 1024 * 1024:
            size_str = str(round(size / 1024 / 1024, 1)) + "M"
        else:
            size_str = str(round(size / 1024 / 1024 / 1024, 1)) + "G"
        return size_str


if __name__ == '__main__':
    SM4File()
