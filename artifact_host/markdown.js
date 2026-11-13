(()=>{'use strict';
const picker=document.getElementById('document-theme');
const valid=value=>['system','light','dark'].includes(value);
let preference='system';
try{const stored=localStorage.getItem('artifact-document-theme');if(valid(stored))preference=stored;}catch(_){}
const fragment=new URLSearchParams(location.hash.slice(1)).get('theme');
if(valid(fragment))preference=fragment;
picker.value=preference;
const system=matchMedia('(prefers-color-scheme: dark)');
function apply(){document.documentElement.dataset.theme=preference==='system'?(system.matches?'dark':'light'):preference;}
apply();system.addEventListener('change',apply);
picker.addEventListener('change',()=>{preference=picker.value;apply();try{localStorage.setItem('artifact-document-theme',preference);}catch(_){}location.hash='theme='+preference;});
})();
