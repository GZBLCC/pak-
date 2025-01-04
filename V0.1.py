import os
import tkinter as tk
from tkinter import filedialog, messagebox
import struct

class PakUnpacker:
    def __init__(self, root):
        self.root = root
        self.root.title("PAK 解包工具")
        self.root.geometry("400x200")

        self.pak_file_path = tk.StringVar()
        self.output_dir = tk.StringVar()

        tk.Label(root, text="PAK 文件:").grid(row=0, column=0, padx=10, pady=10)
        tk.Entry(root, textvariable=self.pak_file_path, width=30).grid(row=0, column=1, padx=10, pady=10)
        tk.Button(root, text="选择文件", command=self.select_pak_file).grid(row=0, column=2, padx=10, pady=10)

        tk.Label(root, text="输出目录:").grid(row=1, column=0, padx=10, pady=10)
        tk.Entry(root, textvariable=self.output_dir, width=30).grid(row=1, column=1, padx=10, pady=10)
        tk.Button(root, text="选择目录", command=self.select_output_dir).grid(row=1, column=2, padx=10, pady=10)

        tk.Button(root, text="开始解包", command=self.unpack_pak).grid(row=2, column=1, padx=10, pady=20)

    def select_pak_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PAK 文件", "*.pak")])
        if file_path:
            self.pak_file_path.set(file_path)

    def select_output_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.output_dir.set(dir_path)

    def unpack_pak(self):
        pak_file = self.pak_file_path.get()
        output_dir = self.output_dir.get()

        if not pak_file or not output_dir:
            messagebox.showerror("错误", "请选择PAK文件和输出目录")
            return

        try:
            with open(pak_file, 'rb') as f:
                header = f.read(4)
                if header != b'PACK':
                    messagebox.showerror("错误", "无效的PAK文件")
                    return

                f.seek(8)
                file_count = struct.unpack('<I', f.read(4))[0]
                f.seek(12)

                for _ in range(file_count):
                    file_name = f.read(56).decode('utf-8').rstrip('\x00')
                    file_offset = struct.unpack('<I', f.read(4))[0]
                    file_size = struct.unpack('<I', f.read(4))[0]

                    output_file_path = os.path.join(output_dir, file_name)
                    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

                    with open(output_file_path, 'wb') as out_file:
                        f.seek(file_offset)
                        out_file.write(f.read(file_size))

            messagebox.showinfo("成功", "解包完成")
        except Exception as e:
            messagebox.showerror("错误", f"解包失败: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PakUnpacker(root)
    root.mainloop()
