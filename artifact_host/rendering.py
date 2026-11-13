"""Pre-render small Markdown documents in a resource-limited subprocess."""
import subprocess
import sys
import time
from pathlib import Path

MAX_MARKDOWN = 256 * 1024
MAX_HTML = 2 * 1024 * 1024
CACHE_DIR = '.artifact-render'

def render_bundle(directory, capacity, cache_dir=CACHE_DIR):
    # Snapshot the walk: generated files must never become new inputs.
    inputs = [p for p in directory.rglob('*') if p.is_file() and p.suffix.lower() == '.md' and not any(part.startswith('.artifact-') for part in p.relative_to(directory).parts)]
    deadline = time.monotonic() + 10
    if len(inputs) > 20:
        raise ValueError('At most 20 Markdown files per bundle')
    from artifact_host.storage import tree_usage
    used = tree_usage(directory)
    for source in inputs:
        if source.stat().st_size > MAX_MARKDOWN:
            continue  # Large Markdown remains available as a download.
        relative = source.relative_to(directory)
        target = directory / cache_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        remaining = min(MAX_HTML, capacity - used - 32768)
        if remaining <= 0:
            raise ValueError('No space for rendered output')
        try:
            subprocess.run([sys.executable, '-m', 'artifact_host.rendering', str(source), str(target), str(remaining)],
                           check=True, timeout=max(0.01, min(5, deadline - time.monotonic())), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except (subprocess.SubprocessError, OSError):
            raise ValueError('Markdown rendering exceeded limits or input is invalid') from None
        used = tree_usage(directory)

def main():
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    if sys.platform == 'linux':
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    maximum = min(MAX_HTML, int(sys.argv[3]))
    resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
    import nh3
    import markdown
    from html import escape
    source, target = map(Path, sys.argv[1:3])
    text = source.read_bytes()
    if len(text) > MAX_MARKDOWN:
        raise ValueError('Markdown too large')
    html = markdown.markdown(text.decode('utf-8'), extensions=['tables', 'fenced_code', 'codehilite'])
    html = nh3.clean(html,
        tags={'a','abbr','acronym','b','blockquote','em','i','li','ol','strong','ul'} | {'h1','h2','h3','h4','h5','h6','p','pre','code','div','span','table','thead','tbody','tr','td','th','img','hr','br'},
        attributes={'*':{'class'}, 'a':{'href','title'}, 'img':{'src','alt'}}, url_schemes={'https','http'})
    assets = Path(__file__).parent
    css = (assets / 'markdown.css').read_text()
    script = (assets / 'markdown.js').read_text()
    title = escape(source.name)
    result = ('<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+title+'</title><style>'+css+'</style></head><body><header class="document-bar"><span class="document-name">'+title+'</span><select id="document-theme" aria-label="文档显示模式"><option value="system">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option></select></header><main class="document"><article>'+html+'</article><footer class="document-footer">Published with Artifact Host</footer></main><script id="document-theme-controller">'+script+'</script></body></html>').encode()
    if len(result) > maximum:
        raise ValueError('Rendered output too large')
    target.write_bytes(result)

if __name__ == '__main__':
    main()
