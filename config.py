import os
import tempfile

class Config:
    # 缓冲区大小配置 (1MB)
    BUFFER_SIZE = 1024 * 1024

    # 最大文件大小限制 (100MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024

    # 内存使用阈值设置 (80%)
    MEMORY_USAGE_THRESHOLD = 80

    # 临时文件存储路径
    TEMP_DIR = os.path.join(tempfile.gettempdir(), "inscode_temp")

    # 加密算法配置
    ENCRYPTION_ALGORITHMS = {
        'AES': {
            'key_size': 256,  # 密钥长度
            'mode': 'CBC',    # 加密模式
            'iv_size': 16,    # 初始化向量大小
            'magic_number': 'AES_MAGIC'  # 文件头识别
        },
        'RSA': {
            'key_size': 2048,  # 密钥长度
            'padding': 'OAEP', # 填充模式
            'hash_algorithm': 'SHA-256',  # 哈希算法
            'magic_number': 'RSA_MAGIC'  # 文件头识别
        },
        'DES': {
            'key_size': 64,   # 密钥长度
            'mode': 'CBC',    # 加密模式
            'iv_size': 8,     # 初始化向量大小
            'magic_number': 'DES_MAGIC'  # 文件头识别
        },
        'BLOWFISH': {
            'key_size': 448,  # 密钥长度
            'mode': 'CBC',    # 加密模式
            'iv_size': 8,     # 初始化向量大小
            'magic_number': 'BLOWFISH_MAGIC'  # 文件头识别
        }
    }

    # 默认加密算法
    DEFAULT_ENCRYPTION_ALGORITHM = 'AES'

    # 加密密钥
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'default_encryption_key')

    # 性能优化相关配置
    CHUNK_SIZE = 1024 * 1024  # 分块大小 (1MB)
    PROGRESS_UPDATE_INTERVAL = 0.1  # 进度更新间隔 (秒)
    MEMORY_CHECK_INTERVAL = 1  # 内存检查间隔 (秒)
    MAX_MEMORY_USAGE = 90  # 最大内存使用百分比
    PAUSE_ON_MEMORY_THRESHOLD = True  # 内存超过阈值时是否暂停

    @staticmethod
    def ensure_temp_dir():
        if not os.path.exists(Config.TEMP_DIR):
            os.makedirs(Config.TEMP_DIR, mode=0o700, exist_ok=True)
