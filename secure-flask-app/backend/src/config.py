# Limite de tentativas
import time
from collections import defaultdict

SECRET_KEY = '65a8e27d8879283831b664bd8b7f0ad4'
login_attempts = defaultdict(lambda: {'attempts': 0, 'timestamp': time.time()})
ATTEMPT_LIMIT = 5
BLOCK_TIME = 600  # Tempo em segundos que o usuario ficará bloqueado