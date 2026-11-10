# Two synchronous processes let revocation proceed during one slow upload.
# flock bounds uploads across processes; timeout terminates a stalled worker.
workers = 2
worker_class = 'sync'
threads = 1
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
