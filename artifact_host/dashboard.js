'use strict';
// Tokens stay in memory/input only. Untrusted names always use textContent.
const element = id => document.getElementById(id);
let offset = 0;
async function api(method, path) {
  const response = await fetch(path, {method, credentials: 'omit', cache: 'no-store', redirect: 'error',
    headers: {Authorization: 'Bearer ' + element('key').value}});
  if (!response.ok) throw new Error('Request failed: HTTP ' + response.status);
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
async function load() {
  const artifacts = await api('GET', '/api/artifacts?offset=' + offset);
  element('artifacts').replaceChildren();
  for (const artifact of artifacts) {
    const row = document.createElement('p');
    row.textContent = (artifact.slug || artifact.entry) + (artifact.revoked ? ' (revoked) ' : ' ');
    const link = document.createElement('a'); link.textContent = 'View'; link.href = artifact.url;
    link.target = '_blank'; link.rel = 'noopener noreferrer'; row.append(link);
    row.append(action('Revoke and delete', async () => {
      if (window.confirm('Revoke this link and delete its files?')) {
        await api('DELETE', '/api/artifacts/' + encodeURIComponent(artifact.id)); await load();
      }
    })); element('artifacts').append(row);
  }
  const tokens = await api('GET', '/api/tokens'); element('tokens').replaceChildren();
  for (const token of tokens) {
    const row = document.createElement('p'); row.textContent = token.id + (token.owner ? ' (owner)' : ' ');
    if (!token.owner) row.append(action('Revoke token', async () => {
      await api('DELETE', '/api/tokens/' + encodeURIComponent(token.id)); await load();
    })); element('tokens').append(row);
  }
}
element('load').addEventListener('click', () => run(load));
element('new-token').addEventListener('click', () => run(async () => {
  const token = await api('POST', '/api/tokens'); await load();
  element('status').textContent = 'Save this token now. It is shown once: ' + token.token;
}));
element('forget').addEventListener('click', () => {
  element('key').value = ''; element('artifacts').replaceChildren();
  element('tokens').replaceChildren(); element('status').textContent = ''; offset = 0;
});
element('previous').addEventListener('click', () => run(async () => { offset = Math.max(0, offset - 100); await load(); }));
element('next').addEventListener('click', () => run(async () => { offset += 100; await load(); }));
