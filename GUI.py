# -*- coding: utf-8 -*-
import sm2, sm3, sm4
import tkinter as tk
from tkinter import ttk
from tkinter import *
from tkinter import messagebox
import base64,os
from logo import img


def on_combo_box_select(event):
    selected_value = combo_box.get()
    if selected_value == "SM2":
        combo_box1.config(values=["C1C3C2", "C1C2C3"])
        combo_box1.set("C1C3C2")
        label1.config(text="公钥 :")
        label2.config(text="私钥 :")
    elif selected_value == "SM3":
        combo_box1.config(values=["小写", "大写"])
        combo_box1.set("小写")
        label1.config(text="无需 :")
        label2.config(text="无需 :")
    else:
        combo_box1.config(values=["ECB", "CBC"])
        combo_box1.set("ECB")
        label1.config(text="KEY :")
        label2.config(text="I V :")


def encrypt():
    selected_value = combo_box.get()
    plaintext = fileText1.get("1.0", tk.END)  # 获取明文
    plaintext = plaintext.strip('\n')
    if plaintext:
        if selected_value == "SM2":
            sm2_public_key = entry_public.get()
            if sm2_public_key:
                if len(sm2_public_key) == 130:
                    mode = combo_box1.get()
                    if mode == "C1C3C2":
                        out_format = output_format.get()
                        ciphertext = sm2.encrypt_c1c3c2(plaintext, sm2_public_key)
                        if out_format == "hex":
                            fileText2.delete("1.0", tk.END)  # 清空原有内容
                            fileText2.insert(tk.END, ciphertext.hex())  # 将密文显示在fileText2中
                        else:
                            fileText2.delete("1.0", tk.END)  # 清空原有内容
                            fileText2.insert(tk.END, base64.b64encode(ciphertext).decode())  # 将密文显示在fileText2中
                    else:
                        out_format = output_format.get()
                        ciphertext = sm2.encrypt_c1c2c3(plaintext, sm2_public_key)
                        if out_format == "hex":
                            fileText2.delete("1.0", tk.END)  # 清空原有内容
                            fileText2.insert(tk.END, ciphertext.hex())  # 将密文显示在fileText2中
                        else:
                            fileText2.delete("1.0", tk.END)  # 清空原有内容
                            fileText2.insert(tk.END, base64.b64encode(ciphertext).decode())  # 将密文显示在fileText2中

                else:
                    messagebox.showinfo('提示', '加密失败！加密的公钥错误！')
            else:
                messagebox.showinfo('提示', '请填写公钥!')
        elif selected_value == "SM3":
            sm3hash = sm3.sm3_hash(plaintext)
            mode = combo_box1.get()
            if mode == "小写":
                fileText2.delete("1.0", tk.END)  # 清空原有内容
                fileText2.insert(tk.END, sm3hash)
            else:
                fileText2.delete("1.0", tk.END)  # 清空原有内容
                fileText2.insert(tk.END, sm3hash.upper())
        elif selected_value == "SM4":
            sm4_key = entry_public.get()
            if len(sm4_key) == 16:
                sm4_key = sm4_key.encode().hex()
            if sm4_key:
                if len(sm4_key) == 32:
                    sm4_mode = combo_box1.get()
                    if sm4_mode == "ECB":
                        ciphertext = sm4.sm4_encode(sm4_key, plaintext)
                        out_format = output_format.get()
                        if out_format == "hex":
                            fileText2.delete("1.0", tk.END)
                            fileText2.insert(tk.END, ciphertext.hex())
                        else:
                            fileText2.delete("1.0", tk.END)
                            fileText2.insert(tk.END, base64.b64encode(ciphertext).decode())
                    else:
                        iv = entry_private.get()
                        if len(iv) == 16:
                            iv = iv.encode().hex()
                        if iv:
                            if len(iv) == 32:
                                ciphertext = sm4.sm4_encode_cbc(sm4_key, plaintext, iv)
                                out_format = output_format.get()
                                if out_format == "hex":
                                    fileText2.delete("1.0", tk.END)
                                    fileText2.insert(tk.END, ciphertext.hex())
                                else:
                                    fileText2.delete("1.0", tk.END)
                                    fileText2.insert(tk.END, base64.b64encode(ciphertext).decode())
                            else:
                                messagebox.showinfo('提示', 'IV值不正确!')
                        else:
                            messagebox.showinfo('提示', 'CBC模式需要填写IV值!')
                else:
                    messagebox.showinfo('提示', '加密KEY不正确!')
            else:
                messagebox.showinfo('提示', '请填写加密KEY!')
        else:
            messagebox.showinfo('提示', '请选择加密模式！')

    else:
        messagebox.showinfo('提示', '请填写需要加密的数据!')


def decrypt():
    selected_value = combo_box.get()
    ciphertext = fileText2.get("1.0", tk.END)  # 获取明文
    ciphertext = ciphertext.strip('\n')
    if ciphertext:
        if selected_value == "SM2":
            sm2_private_key = entry_private.get()
            if sm2_private_key:
                if len(sm2_private_key) == 64:
                    mode = combo_box1.get()
                    if mode == "C1C3C2":
                        out_format = output_format.get()
                        if out_format == "base64":
                            ciphertext = base64.b64decode(ciphertext)
                            ciphertext = sm2.decrypt_c1c3c2(ciphertext, sm2_private_key).decode()
                            fileText1.delete("1.0", tk.END)  # 清空原有内容
                            fileText1.insert(tk.END, ciphertext)  # 将密文显示在fileText2中
                        else:
                            ciphertext = bytes.fromhex(ciphertext)
                            ciphertext = sm2.decrypt_c1c3c2(ciphertext, sm2_private_key).decode()
                            fileText1.delete("1.0", tk.END)  # 清空原有内容
                            fileText1.insert(tk.END, ciphertext)  # 将密文显示在fileText2中
                    else:
                        out_format = output_format.get()
                        if out_format == "base64":
                            ciphertext = base64.b64decode(ciphertext)
                            ciphertext = sm2.decrypt_c1c2c3(ciphertext, sm2_private_key).decode()
                            fileText1.delete("1.0", tk.END)  # 清空原有内容
                            fileText1.insert(tk.END, ciphertext)  # 将密文显示在fileText2中
                        else:
                            ciphertext = bytes.fromhex(ciphertext)
                            ciphertext = sm2.decrypt_c1c2c3(ciphertext, sm2_private_key).decode()
                            fileText1.delete("1.0", tk.END)  # 清空原有内容
                            fileText1.insert(tk.END, ciphertext)  # 将密文显示在fileText2中

                else:
                    messagebox.showinfo('提示', '解密失败！私钥错误！')
            else:
                messagebox.showinfo('提示', '请填写私钥!')
        elif selected_value == "SM3":
            fileText1.delete("1.0", tk.END)  # 清空原有内容
            fileText1.insert(tk.END, "老哥，SM3为杂凑算法，主要用于数字签名及验证、消息认证码生成及验证、随机数生成等，其安全性及效率与SHA-256相当，不可逆。")
        elif selected_value == "SM4":
            sm4_key = entry_public.get()
            if len(sm4_key) == 16:
                sm4_key = sm4_key.encode().hex()
            if sm4_key:
                if len(sm4_key) == 32:
                    sm4_mode = combo_box1.get()
                    if sm4_mode == "ECB":
                        out_format = output_format.get()
                        if out_format == "hex":
                            plaintext = sm4.sm4_decode(sm4_key, ciphertext)
                            fileText1.delete("1.0", tk.END)
                            fileText1.insert(tk.END, plaintext)
                        else:
                            ciphertext = base64.b64decode(ciphertext).hex()
                            plaintext = sm4.sm4_decode(sm4_key, ciphertext)
                            fileText1.delete("1.0", tk.END)
                            fileText1.insert(tk.END, plaintext)
                    else:
                        iv = entry_private.get()
                        if len(iv) == 16:
                            iv = iv.encode().hex()
                        if iv:
                            if len(iv) == 32:
                                out_format = output_format.get()
                                if out_format == "hex":
                                    plaintext = sm4.sm4_decode_cbc(sm4_key, ciphertext, iv)
                                    fileText1.delete("1.0", tk.END)
                                    fileText1.insert(tk.END, plaintext)
                                else:
                                    ciphertext = base64.b64decode(ciphertext).hex()
                                    plaintext = sm4.sm4_decode_cbc(sm4_key, ciphertext, iv)
                                    fileText1.delete("1.0", tk.END)
                                    fileText1.insert(tk.END, plaintext)
                            else:
                                messagebox.showinfo('提示', 'IV值不正确!')
                        else:
                            messagebox.showinfo('提示', 'CBC模式需要填写IV值!')
                else:
                    messagebox.showinfo('提示', 'KEY不正确!')
            else:
                messagebox.showinfo('提示', '请填写解密KEY!')
        else:
            messagebox.showinfo('提示', '请选择解密模式！')

    else:
        messagebox.showinfo('提示', '请填写需要解密的数据!')


if __name__ == '__main__':
    nw = tk.Tk()
    nw.title("国密（SM）系列加解密工具      © Yater")
    nw.geometry("850x600")
    nw.resizable(0, 0)
    icon = open("favicon.ico", "wb+")
    icon.write(base64.b64decode(img))  # 写入到临时文件中
    icon.close()
    nw.iconbitmap("favicon.ico")  # 设置图标
    os.remove("favicon.ico")  # 删除临时图标

    Key_module = tk.Frame(nw)
    Key_module.pack(padx=20, pady=2, side=tk.TOP, anchor=tk.W)
    label1 = tk.Label(Key_module, text="公钥 :")
    label1.grid(row=0, column=0, padx=5, pady=10)
    entry_public = tk.Entry(Key_module, width=100)
    entry_public.grid(row=0, column=1, padx=10, pady=10)

    label2 = tk.Label(Key_module, text="私钥 :")
    label2.grid(row=1, column=0, padx=5, pady=10)
    entry_private = tk.Entry(Key_module, width=100)
    entry_private.grid(row=1, column=1, padx=10, pady=10)

    data_format = tk.Frame(nw)
    data_format.pack(padx=50, side=tk.TOP, anchor=tk.E)
    label = tk.Label(data_format, text="明文")
    label.grid(row=0, column=0, padx=(0, 400))
    label = tk.Label(data_format, text="密文 :")
    label.grid(row=0, column=1, padx=5)
    output_format = tk.StringVar()
    radiobutton1 = tk.Radiobutton(data_format, text="hex", variable=output_format, value="hex")
    radiobutton1.grid(row=0, column=2, padx=5)
    radiobutton2 = tk.Radiobutton(data_format, text="base64", variable=output_format, value="base64")
    radiobutton2.grid(row=0, column=3, padx=5)
    output_format.set("hex")

    data_treat = tk.Frame(nw)
    data_treat.pack(padx=20, pady=2, side=tk.TOP, anchor=tk.W)

    # 创建加密部件
    fileText1 = tk.Text(data_treat, wrap=tk.WORD, width=45, height=30)
    fileText1.grid(row=0, column=0, padx=10, pady=10)
    scrollbar1 = tk.Scrollbar(data_treat, command=fileText1.yview)
    scrollbar1.grid(row=0, column=1, sticky='ns')
    fileText1.config(yscrollcommand=scrollbar1.set)

    # 创建下拉框和按钮的Frame
    dropdown_frame = tk.Frame(data_treat)
    dropdown_frame.grid(row=0, column=2, padx=10, pady=10)

    label = tk.Label(dropdown_frame, text="类型选择")
    label.pack(padx=5, pady=5)
    # 创建下拉框
    combo_box = ttk.Combobox(dropdown_frame, values=["SM2", "SM3", "SM4"], width=7)
    combo_box.pack(padx=5, pady=5)
    combo_box.bind("<<ComboboxSelected>>", on_combo_box_select)

    label = tk.Label(dropdown_frame, text="模式选择")
    label.pack(padx=5, pady=5)
    # 创建下拉框
    combo_box1 = ttk.Combobox(dropdown_frame, values=["ECB", "CBC"], width=7)
    combo_box1.pack(padx=5, pady=5)

    # 创建按钮
    fileButton1 = tk.Button(dropdown_frame, text="加密数据", command=encrypt, height=3)
    fileButton1.pack(padx=5, pady=20)

    fileButton2 = tk.Button(dropdown_frame, text="解密数据", command=decrypt, height=3, fg="#ff0000")
    fileButton2.pack(padx=5, pady=20)

    # 创建解密部件
    fileText2 = tk.Text(data_treat, wrap=tk.WORD, width=45, height=30)
    fileText2.grid(row=0, column=3, padx=10, pady=10)
    scrollbar2 = tk.Scrollbar(data_treat, command=fileText2.yview)
    scrollbar2.grid(row=0, column=4, sticky='ns')
    fileText2.config(yscrollcommand=scrollbar2.set)

    label3 = tk.Label(nw, text="加解密无反应则为失败，请检查公钥 私钥/KEY IV等是否正确。")
    label3.pack(padx=5, pady=5)
    nw.mainloop()
