'use strict';
const element = id => document.getElementById(id);
let offset = 0;
let files = [];
async function api(method, path) {
  const response = await fetch(path, {method, credentials: 'omit', cache: 'no-store', redirect: 'error',
    headers: {Authorization: 'Bearer ' + element('key').value}});
  if (!response.ok) throw new Error(response.status === 401 ? '凭证无效或已撤销，请检查 Owner token。' : '操作失败：HTTP ' + response.status);
  return response.status === 204 ? null : response.json();
}
function action(label, fn) {
  const button = document.createElement('button'); button.textContent = label;
  button.addEventListener('click', () => run(fn)); return button;
}
async function run(fn) {
  try { element('status').textContent = ''; await fn(); }
  catch (error) { element('status').textContent = error.message; }
}
function text(tag, value, className) {
  const node = document.createElement(tag); node.textContent = value;
  if (className) node.className = className;
  return node;
}
function state(file) { return file.revoked ? 'revoked' : file.expires && file.expires <= Date.now()/1000 ? 'expired' : 'active'; }
function render() {
  const query = element('search').value.trim().toLowerCase();
  const filter = element('filter').value;
  const visible = files.filter(file => (filter === 'all' || state(file) === filter) &&
    [file.entry,file.short_slug,file.slug].some(value => (value || '').toLowerCase().includes(query)));
  element('artifacts').replaceChildren();
  element('count').textContent = visible.length + ' 项';
  element('empty').hidden = visible.length > 0;
  element('empty').textContent = '没有符合条件的内容。';
  for (const file of visible) {
    const row = document.createElement('p'); row.className = 'file-row';
    const kind = (file.entry.split('.').pop() || 'FILE').toUpperCase();
    const info = document.createElement('span'); info.className = 'file-info';
    info.append(text('span',kind.slice(0,4),'file-icon'));
    const name = document.createElement('span'); name.className = 'file-text';
    name.append(text('span',file.short_slug || file.entry,'file-name'));
    name.append(text('span',file.short_slug ? '/' + file.short_slug + '/' : file.entry,'file-path'));
    info.append(name);row.append(info,text('span',kind,'muted'));
    row.append(text('span',file.size >= 1048576 ? (file.size/1048576).toFixed(1)+' MB' : Math.ceil(file.size/1024)+' KB','muted'));
    const status = state(file);
    row.append(text('span',{active:'可访问',revoked:'已撤销',expired:'已到期'}[status],'state-'+status));
    const controls = document.createElement('span'); controls.className = 'row-actions';
    if (status === 'active') {
      const link = document.createElement('a'); link.textContent = '查看'; link.href = file.url;
      link.target = '_blank'; link.rel = 'noopener noreferrer';controls.append(link);
    }
    const remove = action(file.revoked ? '清理文件' : '撤销', async () => {
      if (window.confirm('撤销这个分享链接并删除文件？已下载的副本无法收回。')) {
        await api('DELETE', '/api/artifacts/' + encodeURIComponent(file.id)); await load();
      }
    });
    remove.disabled = !!file.revoked && file.size === 0;
    controls.append(remove);row.append(controls);element('artifacts').append(row);
  }
}
async function load() {
  const artifacts = await api('GET', '/api/artifacts?offset=' + offset);
  const tokens = await api('GET', '/api/tokens');
  files = artifacts;render();element('tokens').replaceChildren();
  element('connection').textContent = '已连接 · Owner';
  element('previous').disabled = offset === 0;
  element('next').disabled = artifacts.length < 100;
  element('page-label').textContent = '第 ' + (Math.floor(offset/100)+1) + ' 页 · 当前页 ' + artifacts.length + ' 项';
  for (const token of tokens) {
    const row = document.createElement('p'); row.className = 'token-row';
    row.append(text('span',token.id + (token.owner ? ' · Owner' : ' · Agent')));
    if (!token.owner) row.append(action('撤销凭证', async () => {
      if (window.confirm('撤销此 Agent token？它将无法继续上传或管理文件。')) {
        await api('DELETE', '/api/tokens/' + encodeURIComponent(token.id)); await load();
      }
    }));element('tokens').append(row);
  }
}
element('load').addEventListener('click', () => run(load));
element('refresh').addEventListener('click', () => run(load));
element('search').addEventListener('input',render);
element('filter').addEventListener('change',render);
element('new-token').addEventListener('click', () => run(async () => {
  const token = await api('POST', '/api/tokens'); await load();
  element('status').textContent = '请立即保存，token 仅显示一次：' + token.token;
}));
element('forget').addEventListener('click', () => {
  element('key').value = ''; files = [];element('artifacts').replaceChildren();
  element('tokens').replaceChildren();element('status').textContent = '';offset = 0;
  element('connection').textContent = '尚未连接';element('count').textContent = '—';
  element('empty').textContent = '连接后，在这里查看你的文件和分享链接。';element('empty').hidden = false;
});
element('previous').addEventListener('click', () => run(async () => { offset = Math.max(0, offset - 100); await load(); }));
element('next').addEventListener('click', () => run(async () => { offset += 100; await load(); }));
