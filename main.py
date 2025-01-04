import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import struct
import psutil
import time
import threading
from config import Config
from utils import CryptoUtils, MemoryMonitor, BufferManager
import json
from datetime import datetime

class PakUnpacker:
    BUFFER_SIZE = Config.BUFFER_SIZE

    def __init__(self, root):
        self.root = root
        self.root.title("PAK 解包工具")
        self.root.geometry("600x500")

        self.pak_files = []
        self.output_dir = tk.StringVar()
        self.progress = tk.DoubleVar()
        self.progress.set(0)
        self.encryption_key = tk.StringVar()
        self.encryption_algorithm = tk.StringVar(value=Config.DEFAULT_ENCRYPTION_ALGORITHM)
        self.is_paused = False
        self.is_cancelled = False
        self.current_file_index = 0
        self.current_file_progress = 0

        tk.Label(root, text="PAK 文件:").grid(row=0, column=0, padx=10, pady=10)
        self.file_listbox = tk.Listbox(root, width=50, height=10)
        self.file_listbox.grid(row=0, column=1, padx=10, pady=10, rowspan=2)
        tk.Button(root, text="选择文件", command=self.select_pak_files).grid(row=0, column=2, padx=10, pady=10)
        tk.Button(root, text="清除列表", command=self.clear_file_list).grid(row=1, column=2, padx=10, pady=10)

        tk.Label(root, text="输出目录:").grid(row=2, column=0, padx=10, pady=10)
        tk.Entry(root, textvariable=self.output_dir, width=50).grid(row=2, column=1, padx=10, pady=10)
        tk.Button(root, text="选择目录", command=self.select_output_dir).grid(row=2, column=2, padx=10, pady=10)

        tk.Label(root, text="加密算法:").grid(row=3, column=0, padx=10, pady=10)
        self.algorithm_menu = ttk.Combobox(root, textvariable=self.encryption_algorithm, state="readonly")
        self.algorithm_menu['values'] = list(Config.ENCRYPTION_ALGORITHMS.keys())
        self.algorithm_menu.grid(row=3, column=1, padx=10, pady=10)

        tk.Label(root, text="解密密钥:").grid(row=4, column=0, padx=10, pady=10)
        tk.Entry(root, textvariable=self.encryption_key, width=50).grid(row=4, column=1, padx=10, pady=10)

        self.progress_bar = ttk.Progressbar(root, variable=self.progress, maximum=100)
        self.progress_bar.grid(row=5, column=1, padx=10, pady=10)

        tk.Button(root, text="开始解包", command=self.start_unpack).grid(row=6, column=1, padx=10, pady=20)
        tk.Button(root, text="暂停/继续", command=self.toggle_pause).grid(row=6, column=0, padx=10, pady=20)
        tk.Button(root, text="取消", command=self.cancel_unpack).grid(row=6, column=2, padx=10, pady=20)
        tk.Button(root, text="导出日志", command=self.export_log).grid(row=7, column=1, padx=10, pady=20)

        self.unpack_status = {}
        self.timer = None
        self.buffer_manager = BufferManager(self.BUFFER_SIZE)

    def select_pak_files(self):
        file_paths = filedialog.askopenfilenames(filetypes=[("PAK 文件", "*.pak")])
        if file_paths:
            for file_path in file_paths:
                if self.is_encrypted(file_path):
                    self.pak_files.append(file_path)
                    self.file_listbox.insert(tk.END, os.path.basename(file_path))
                else:
                    messagebox.showerror("错误", f"文件 {os.path.basename(file_path)} 无法解包")

    def clear_file_list(self):
        self.pak_files.clear()
        self.file_listbox.delete(0, tk.END)

    def select_output_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.output_dir.set(dir_path)

    def is_encrypted(self, file_path):
        try:
            file_size = os.path.getsize(file_path)
            if file_size < 64:
                return False

            with open(file_path, 'rb') as f:
                header = f.read(64)
                if len(header) < 64:
                    return False

                for file_type, algorithm_config in Config.ENCRYPTION_ALGORITHMS.items():
                    magic_number = algorithm_config.get('magic_number', '').encode('utf-8')
                    if header.startswith(magic_number):
                        f.seek(0, os.SEEK_END)
                        file_size = f.tell()
                        f.seek(0)
                        if file_size % 16 != 0:
                            return False
                        return True

                return False
        except Exception as e:
            messagebox.showerror("错误", f"文件读取失败: {str(e)}")
            return False

    def start_unpack(self):
        if not self.pak_files or not self.output_dir.get():
            messagebox.showerror("错误", "请选择PAK文件和输出目录")
            return

        if not self.encryption_key.get():
            messagebox.showerror("错误", "请输入解密密钥")
            return

        self.is_cancelled = False
        self.is_paused = False
        self.current_file_index = 0
        self.current_file_progress = 0
        self.progress.set(0)
        self.unpack_status = {}

        self.timer = threading.Thread(target=self.update_progress)
        self.timer.daemon = True
        self.timer.start()

        unpack_thread = threading.Thread(target=self.unpack_pak)
        unpack_thread.start()

    def toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            messagebox.showinfo("暂停", "解包已暂停")
        else:
            messagebox.showinfo("继续", "解包已继续")

    def cancel_unpack(self):
        self.is_cancelled = True
        messagebox.showinfo("取消", "解包已取消")

    def update_progress(self):
        while not self.is_cancelled and self.current_file_index < len(self.pak_files):
            if not self.is_paused:
                total_progress = (self.current_file_index + self.current_file_progress) / len(self.pak_files) * 100
                self.progress.set(total_progress)
                self.root.update_idletasks()
            time.sleep(0.1)

    def unpack_pak(self):
        total_files = len(self.pak_files)
        unpack_success = False

        for i, pak_file in enumerate(self.pak_files):
            if self.is_cancelled:
                break

            while self.is_paused:
                time.sleep(0.1)

            self.current_file_index = i
            file_status = {
                "file_name": os.path.basename(pak_file),
                "status": "失败",
                "error": None,
                "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": None,
                "extracted_files": []
            }

            try:
                temp_file = os.path.join(Config.TEMP_DIR, f"temp_{i}.pak")
                CryptoUtils.decrypt_file(
                    pak_file,
                    temp_file,
                    algorithm=self.encryption_algorithm.get(),
                    key=self.encryption_key.get().encode('utf-8'),
                    chunk_size=self.BUFFER_SIZE
                )

                with open(temp_file, 'rb') as f:
                    header = f.read(4)
                    if header != b'PACK':
                        file_status["error"] = "无效的PAK文件"
                        self.unpack_status[pak_file] = file_status
                        messagebox.showerror("错误", f"文件 {os.path.basename(pak_file)} 无效的PAK文件")
                        continue

                    f.seek(8)
                    file_count = struct.unpack('<I', f.read(4))[0]
                    f.seek(12)

                    for j in range(file_count):
                        if self.is_cancelled:
                            break

                        while self.is_paused:
                            time.sleep(0.1)

                        file_name = f.read(56).decode('utf-8').rstrip('\x00')
                        file_offset = struct.unpack('<I', f.read(4))[0]
                        file_size = struct.unpack('<I', f.read(4))[0]

                        output_file_path = os.path.join(self.output_dir.get(), file_name)
                        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

                        with open(output_file_path, 'wb') as out_file:
                            f.seek(file_offset)
                            bytes_remaining = file_size
                            while bytes_remaining > 0:
                                if self.is_cancelled:
                                    break

                                while self.is_paused:
                                    time.sleep(0.1)

                                chunk_size = min(self.BUFFER_SIZE, bytes_remaining)
                                chunk = f.read(chunk_size)
                                out_file.write(chunk)
                                bytes_remaining -= chunk_size
                                self.current_file_progress = (file_size - bytes_remaining) / file_size
                                self.update_progress()

                                if MemoryMonitor.get_system_memory()['percent'] > Config.MEMORY_USAGE_THRESHOLD:
                                    self.is_paused = True
                                    messagebox.showwarning("内存警告", "内存使用过高，解包已暂停")

                        file_status["extracted_files"].append(file_name)

                file_status["status"] = "成功"
                unpack_success = True

            except Exception as e:
                file_status["error"] = str(e)
                messagebox.showerror("错误", f"解包失败: {str(e)}")

            file_status["end_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.unpack_status[pak_file] = file_status

        if unpack_success:
            messagebox.showinfo("成功", "解包完成")
        else:
            messagebox.showinfo("失败", "解包未完成")

        self.progress.set(0)
        self.show_status_report()

    def show_status_report(self):
        report = "解包状态报告:\n\n"
        for file_path, status in self.unpack_status.items():
            report += f"文件: {status['file_name']}\n"
            report += f"状态: {status['status']}\n"
            report += f"开始时间: {status['start_time']}\n"
            report += f"结束时间: {status['end_time']}\n"
            if status["error"]:
                report += f"错误信息: {status['error']}\n"
            report += f"解压文件数: {len(status['extracted_files'])}\n"
            report += "\n"

        messagebox.showinfo("解包状态报告", report)

    def export_log(self):
        if not self.unpack_status:
            messagebox.showerror("错误", "没有可导出的日志")
            return

        log_file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON 文件", "*.json")])
        if log_file:
            with open(log_file, 'w') as f:
                json.dump(self.unpack_status, f, indent=4)
            messagebox.showinfo("成功", "日志导出成功")

if __name__ == "__main__":
    root = tk.Tk()
    app = PakUnpacker(root)
    root.mainloop()
