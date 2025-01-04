import os
import psutil
import base64
from config import Config

class BufferManager:
    def __init__(self, buffer_size=1024 * 1024):  # 默认1MB缓冲区
        self.buffer_size = buffer_size

    def read_in_chunks(self, file_object):
        while True:
            data = file_object.read(self.buffer_size)
            if not data:
                break
            yield data

    def write_in_chunks(self, file_object, data):
        for chunk in self.read_in_chunks(data):
            file_object.write(chunk)

class FileUtils:
    @staticmethod
    def check_file_size(file_path, min_size=0, max_size=None):
        try:
            file_size = os.path.getsize(file_path)
            if min_size and file_size < min_size:
                return False, f"文件大小小于 {min_size} 字节"
            if max_size and file_size > max_size:
                return False, f"文件大小超过 {max_size} 字节"
            return True, f"文件大小 {file_size} 字节"
        except Exception as e:
            return False, f"文件大小检查失败: {str(e)}"

    @staticmethod
    def check_file_format(file_path, allowed_formats=None):
        if allowed_formats is None:
            allowed_formats = ['.pak']
        try:
            file_extension = os.path.splitext(file_path)[1].lower()
            if file_extension not in allowed_formats:
                return False, f"文件格式不支持，仅支持 {', '.join(allowed_formats)} 格式"
            return True, f"文件格式 {file_extension} 支持"
        except Exception as e:
            return False, f"文件格式检查失败: {str(e)}"

    @staticmethod
    def check_file_permissions(file_path, mode='r'):
        try:
            if mode == 'r' and not os.access(file_path, os.R_OK):
                return False, "文件不可读"
            if mode == 'w' and not os.access(file_path, os.W_OK):
                return False, "文件不可写"
            if mode == 'x' and not os.access(file_path, os.X_OK):
                return False, "文件不可执行"
            return True, f"文件权限检查通过，模式: {mode}"
        except Exception as e:
            return False, f"文件权限检查失败: {str(e)}"

class MemoryMonitor:
    @staticmethod
    def get_memory_usage():
        process = psutil.Process(os.getpid())
        return process.memory_info().rss  # 返回当前进程的内存使用量（字节）

    @staticmethod
    def get_system_memory():
        mem = psutil.virtual_memory()
        return {
            'total': mem.total,
            'available': mem.available,
            'used': mem.used,
            'free': mem.free,
            'percent': mem.percent
        }

class CryptoUtils:
    @staticmethod
    def xor_decrypt(data, key):
        decrypted_data = bytearray()
        key_length = len(key)
        for i in range(len(data)):
            decrypted_data.append(data[i] ^ key[i % key_length])
        return bytes(decrypted_data)

    @staticmethod
    def aes_decrypt(encrypted_data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_data, AES.block_size)

    @staticmethod
    def des_decrypt(encrypted_data, key, iv):
        cipher = DES.new(key, DES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_data, DES.block_size)

    @staticmethod
    def blowfish_decrypt(encrypted_data, key, iv):
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        return unpad(decrypted_data, Blowfish.block_size)

    @staticmethod
    def decrypt_file(file_path, output_path, algorithm='AES', key=None, iv=None, chunk_size=1024 * 1024):
        if not key:
            key = Config.ENCRYPTION_KEY.encode('utf-8')
        if not iv:
            iv = get_random_bytes(16)

        def decrypt_chunk(chunk, cipher):
            return cipher.decrypt(chunk)

        with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            if algorithm == 'AES':
                cipher = AES.new(key, AES.MODE_CBC, iv)
            elif algorithm == 'DES':
                cipher = DES.new(key, DES.MODE_CBC, iv)
            elif algorithm == 'BLOWFISH':
                cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            elif algorithm == 'XOR':
                cipher = None
            else:
                raise ValueError(f"不支持的加密算法: {algorithm}")

            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break

                if algorithm == 'XOR':
                    decrypted_chunk = CryptoUtils.xor_decrypt(chunk, key)
                else:
                    decrypted_chunk = decrypt_chunk(chunk, cipher)

                f_out.write(decrypted_chunk)

            if algorithm != 'XOR':
                f_out.seek(-cipher.block_size, os.SEEK_END)
                last_chunk = f_out.read(cipher.block_size)
                unpadded_chunk = unpad(last_chunk, cipher.block_size)
                f_out.seek(-cipher.block_size, os.SEEK_END)
                f_out.write(unpadded_chunk)

        return output_path
