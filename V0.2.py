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

        tk.Button(root, text="开始解包", command=self.unpack_pak).grid(row=2    , column=1, padx=10, pady=20)

    def select_pak_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PAK 文件", "*.pak")])
        if file_path:
            if self.is_encrypted(file_path):
                messagebox.showerror("错误", "PAK文件已加密，无法解包")
                self.pak_file_path.set("")
            else:
                self.pak_file_path.set(file_path)

    def select_output_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.output_dir.set(dir_path)

    def is_encrypted(self, file_path):
        file_magic_numbers = {
            'PAK': b'PACK',
            'ENCR': b'ENCR',
            'CRYP': b'CRYP',
            'XOR_': b'XOR_',
            'ZIP': b'PK\x03\x04',
            'RAR': b'Rar!\x1A\x07\x00',
            '7Z': b'7z\xBC\xAF\x27\x1C',
            'PDF': b'%PDF',
            'PNG': b'\x89PNG\r\n\x1a\n',
            'JPEG': b'\xFF\xD8\xFF',
            'GIF': b'GIF89a',
            'BMP': b'BM',
            'MP3': b'ID3',
            'WAV': b'RIFF',
            'AVI': b'RIFF',
            'MP4': b'\x00\x00\x00\x18ftyp',
            'EXE': b'MZ',
            'ELF': b'\x7FELF',
            'PE': b'PE\x00\x00',
            'MACHO': b'\xFE\xED\xFA\xCE',
            'DLL': b'MZ',
            'ISO': b'\x01\xCD\x02',
            'TAR': b'ustar',
            'GZ': b'\x1F\x8B',
            'BZ2': b'BZh',
            'XZ': b'\xFD7zXZ\x00',
            'LZMA': b'\x5D\x00\x00',
            'Z': b'\x1F\x9D',
            'LZ': b'\x1F\xA0',
            'LZH': b'-lh',
            'ARJ': b'\x60\xEA',
            'CAB': b'MSCF',
            'CHM': b'ITSF',
            'SWF': b'FWS',
            'FLV': b'FLV',
            'MKV': b'\x1A\x45\xDF\xA3',
            'WEBM': b'\x1A\x45\xDF\xA3',
            'OGG': b'OggS',
            'MPG': b'\x00\x00\x01\xBA',
            'MPEG': b'\x00\x00\x01\xBA',
            'MOV': b'moov',
            'QT': b'ftyp',
            'RM': b'.RMF',
            'RMVB': b'.RMF',
            'ASF': b'\x30\x26\xB2\x75',
            'WMV': b'\x30\x26\xB2\x75',
            'VOB': b'\x00\x00\x01\xBA',
            'IFO': b'DVDVIDEO',
            'BUP': b'DVDVIDEO',
            'DAT': b'DVDVIDEO',
            'M2TS': b'\x47\x40\x00\x10',
            'TS': b'\x47\x40\x00\x10',
            'M4V': b'\x00\x00\x00\x18ftyp',
            'M4A': b'\x00\x00\x00\x18ftyp',
            'AAC': b'\xFF\xF1',
            'AC3': b'\x0B\x77',
            'DTS': b'\x7F\xFE\x80\x01',
            'FLAC': b'fLaC',
            'APE': b'MAC ',
            'WV': b'wvpk',
            'TTA': b'TTA1',
            'TAK': b'tBaK',
            'OFR': b'OFR ',
            'SHN': b'SHN\x03',
            'WMA': b'\x30\x26\xB2\x75',
            'MID': b'MThd',
            'MIDI': b'MThd',
            'AIFF': b'FORM',
            'AU': b'.snd',
            'SND': b'.snd',
            'VOC': b'Creative Voice File',
            'MOD': b'IMPM',
            'XM': b'Extended Module',
            'IT': b'Impulse Tracker',
            'S3M': b'SCRM',
            'MTM': b'MTM\x10',
            '669': b'if\x1A',
            'AMF': b'AMF\x00',
            'DSM': b'DSM\x00',
            'FAR': b'FAR\x00',
            'GDM': b'GDM\x00',
            'IMF': b'IMF\x00',
            'OKT': b'OKT\x00',
            'PTM': b'PTM\x00',
            'STM': b'STM\x00',
            'ULT': b'ULT\x00',
            'UNI': b'UNI\x00',
            'DMF': b'DMF\x00',
            'MDL': b'MDL\x00',
            'MED': b'MED\x00',
            'MT2': b'MT2\x00',
            'PSM': b'PSM\x00',
            'SFX': b'SFX\x00',
            'STX': b'STX\x00',
            'SYN': b'SYN\x00',
            'TRE': b'TRE\x00',
            'WOW': b'WOW\x00',
            'XMF': b'XMF\x00',
            'YMF': b'YMF\x00',
            'ZIPX': b'PK\x07\x08',
            'JAR': b'PK\x03\x04',
            'WAR': b'PK\x03\x04',
            'EAR': b'PK\x03\x04',
            'SAR': b'PK\x03\x04',
            'RAR5': b'Rar!\x1A\x07\x01',
            '7ZIP': b'7z\xBC\xAF\x27\x1C',
            'TAR.GZ': b'\x1F\x8B',
            'TAR.BZ2': b'BZh',
            'TAR.XZ': b'\xFD7zXZ\x00',
            'TAR.LZMA': b'\x5D\x00\x00',
            'TAR.Z': b'\x1F\x9D',
            'TAR.LZ': b'\x1F\xA0',
            'TAR.LZH': b'-lh',
            'TAR.ARJ': b'\x60\xEA',
            'TAR.CAB': b'MSCF',
            'TAR.CHM': b'ITSF',
            'TAR.SWF': b'FWS',
            'TAR.FLV': b'FLV',
            'TAR.MKV': b'\x1A\x45\xDF\xA3',
            'TAR.WEBM': b'\x1A\x45\xDF\xA3',
            'TAR.OGG': b'OggS',
            'TAR.MPG': b'\x00\x00\x01\xBA',
            'TAR.MPEG': b'\x00\x00\x01\xBA',
            'TAR.MOV': b'moov',
            'TAR.QT': b'ftyp',
            'TAR.RM': b'.RMF',
            'TAR.RMVB': b'.RMF',
            'TAR.ASF': b'\x30\x26\xB2\x75',
            'TAR.WMV': b'\x30\x26\xB2\x75',
            'TAR.VOB': b'\x00\x00\x01\xBA',
            'TAR.IFO': b'DVDVIDEO',
            'TAR.BUP': b'DVDVIDEO',
            'TAR.DAT': b'DVDVIDEO',
            'TAR.M2TS': b'\x47\x40\x00\x10',
            'TAR.TS': b'\x47\x40\x00\x10',
            'TAR.M4V': b'\x00\x00\x00\x18ftyp',
            'TAR.M4A': b'\x00\x00\x00\x18ftyp',
            'TAR.AAC': b'\xFF\xF1',
            'TAR.AC3': b'\x0B\x77',
            'TAR.DTS': b'\x7F\xFE\x80\x01',
            'TAR.FLAC': b'fLaC',
            'TAR.APE': b'MAC ',
            'TAR.WV': b'wvpk',
            'TAR.TTA': b'TTA1',
            'TAR.TAK': b'tBaK',
            'TAR.OFR': b'OFR ',
            'TAR.SHN': b'SHN\x03',
            'TAR.WMA': b'\x30\x26\xB2\x75',
            'TAR.MID': b'MThd',
            'TAR.MIDI': b'MThd',
            'TAR.AIFF': b'FORM',
            'TAR.AU': b'.snd',
            'TAR.SND': b'.snd',
            'TAR.VOC': b'Creative Voice File',
            'TAR.MOD': b'IMPM',
            'TAR.XM': b'Extended Module',
            'TAR.IT': b'Impulse Tracker',
            'TAR.S3M': b'SCRM',
            'TAR.MTM': b'MTM\x10',
            'TAR.669': b'if\x1A',
            'TAR.AMF': b'AMF\x00',
            'TAR.DSM': b'DSM\x00',
            'TAR.FAR': b'FAR\x00',
            'TAR.GDM': b'GDM\x00',
            'TAR.IMF': b'IMF\x00',
            'TAR.OKT': b'OKT\x00',
            'TAR.PTM': b'PTM\x00',
            'TAR.STM': b'STM\x00',
            'TAR.ULT': b'ULT\x00',
            'TAR.UNI': b'UNI\x00',
            'TAR.DMF': b'DMF\x00',
            'TAR.MDL': b'MDL\x00',
            'TAR.MED': b'MED\x00',
            'TAR.MT2': b'MT2\x00',
            'TAR.PSM': b'PSM\x00',
            'TAR.SFX': b'SFX\x00',
            'TAR.STX': b'STX\x00',
            'TAR.SYN': b'SYN\x00',
            'TAR.TRE': b'TRE\x00',
            'TAR.WOW': b'WOW\x00',
            'TAR.XMF': b'XMF\x00',
            'TAR.YMF': b'YMF\x00',
            'TAR.ZIPX': b'PK\x07\x08',
            'TAR.JAR': b'PK\x03\x04',
            'TAR.WAR': b'PK\x03\x04',
            'TAR.EAR': b'PK\x03\x04',
            'TAR.SAR': b'PK\x03\x04',
            'TAR.RAR5': b'Rar!\x1A\x07\x01',
            'TAR.7ZIP': b'7z\xBC\xAF\x27\x1C',
        }

        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                if len(header) < 16:
                    messagebox.showerror("错误", "文件大小不足，无法进行加密检测")
                    return False

                for file_type, magic_number in file_magic_numbers.items():
                    if header.startswith(magic_number):
                        if file_type in ['ENCR', 'CRYP', 'XOR_']:
                            messagebox.showerror("错误", f"文件类型为 {file_type}，已加密，无法解包")
                            return True
                        elif file_type != 'PAK':
                            messagebox.showerror("错误", f"文件类型为 {file_type}，不是有效的PAK文件")
                            return False

                if not header.startswith(b'PACK'):
                    messagebox.showerror("错误", "无效的PAK文件格式")
                    return False

                file_size = os.path.getsize(file_path)
                if file_size < 20:
                    messagebox.showerror("错误", "文件大小过小，无法进行解包")
                    return False

                return False
        except Exception as e:
            messagebox.showerror("错误", f"文件读取失败: {str(e)}")
            return False

    def unpack_pak(self):
        pak_file = self.pak_file_path.get()
        output_dir = self.output_dir.get()

        if not pak_file or not output_dir:
            messagebox.showerror("错误", "请选择PAK文件和输出目录")
            return

        if self.is_encrypted(pak_file):
            messagebox.showerror("错误", "PAK文件已加密，无法解包")
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
