# Bounded threads keep speculative/partial HTTP connections from consuming both
# workers. Upload locking still bounds writers across processes and threads.
workers = 2
worker_class = 'gthread'
threads = 4
worker_connections = 64
timeout = 30
graceful_timeout = 10
limit_request_line = 4094
limit_request_fields = 32
limit_request_field_size = 4096
accesslog = None
errorlog = '-'
logger_class = 'artifact_host.server_logging.RedactedLogger'
forwarded_allow_ips = ''
max_requests = 2000
max_requests_jitter = 100
