'use strict';
const $=id=>document.getElementById(id);
let state=null,stream=null,selected=null,loading=false,again=false;
const handlingPending=new Set();
const autoText=p=>p?({running:"自动复测中",completed:"已自动复测",skipped:"自动复测已跳过",failed:"自动复测失败",interrupted:"自动复测已中断"}[p.state]||p.state)+" · "+fmt(p.started):"尚未自动复测";
const fmt=t=>new Date(t*1000).toLocaleString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
const node=(tag,text,cls)=>{const e=document.createElement(tag);e.textContent=text;if(cls)e.className=cls;return e;};
async function api(path,body){const res=await fetch(path,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await res.json();if(!res.ok){if(res.status===401&&path!='/api/login')showLogin();throw new Error(data.error||'请求失败');}return data;}
function showLogin(){$('login').hidden=false;$('dashboard').hidden=true;$('logout').hidden=true;if(stream){stream.close();stream=null;}if($('detail').open)$('detail').close();}
function showDashboard(){$('login').hidden=true;$('dashboard').hidden=false;$('logout').hidden=false;if(!stream){stream=new EventSource('/api/events');stream.addEventListener('refresh',refresh);stream.addEventListener('expired',showLogin);stream.onerror=()=>{$('notice').textContent='与监控服务的实时连接中断，正在重连；当前显示可能不是最新数据。';};stream.onopen=()=>{$('notice').textContent='';refresh();};}}
async function refresh(){if(loading){again=true;return;}loading=true;try{const view=$('handlingView').value;const next=await api('/api/state?view='+view);if(view!==$('handlingView').value){again=true;return;}state=next;showDashboard();render();if(selected&&$('detail').open)await loadDetail();}catch(e){$('notice').textContent=e.message;}finally{loading=false;if(again){again=false;refresh();}}}
function render(){$('onlyIssues').disabled=$('handlingView').value==='handled';const rows=state.rows||[];$('domains').textContent=rows.length;$('candidates').textContent=rows.filter(r=>!r.handled&&r.priority>0).length;$('errors').textContent=rows.reduce((n,r)=>n+r.directErrors,0);$('unknown').textContent=state.unknown;
 const healthy=state.states.connections?.connected&&state.states.logs?.connected&&state.states.storage?.connected!==false;const age=state.lastFrame.connections?state.now-state.lastFrame.connections:null;
 $('live').textContent=healthy&&age!==null&&age<30?'●  正在观测':'●  采集连接待检查';$('live').classList.toggle('bad',!healthy||age===null||age>=30);
 $('healthDetail').textContent='连接快照：'+(state.lastFrame.connections?fmt(state.lastFrame.connections):'尚未收到')+' · 未归类警告 '+state.unparsed+' 条'+Object.entries(state.states).filter(([,v])=>v.message).map(([k,v])=>' · '+k+': '+v.message).join('');
 $('autoStatus').textContent='自动复测已开启：10 分钟内 2 次新错误 · 每域名仅一次 · 今日 '+state.auto.used+'/'+state.auto.limit+' 轮（北京时间） · 间隔至少 3 分钟';
 $('progress').textContent=state.probing?'正在复测 '+state.probeDomain+'，最多约70秒；未修改你的规则。':'标记已处理后隐藏；有新的实际错误时自动回到待处理。';
 const search=$('search').value.trim().toLowerCase();const visible=rows.filter(r=>(r.domain+' '+r.sources).toLowerCase().includes(search)&&(!$('onlyIssues').checked||(!r.handled&&r.priority>0))).sort((a,b)=>b.priority-a.priority||b.seen-a.seen);
 $('rows').replaceChildren();$('empty').hidden=visible.length>0;$('empty').textContent=rows.length?'没有符合筛选条件的域名。':$('handlingView').value==='handled'?'最近24小时没有已处理的域名。':'当前清单为空。已处理域名会隐藏，只有新的实际错误才会重新出现。';
 for(const r of visible){const tr=node('tr','');const domain=node('td','');domain.append(node('div',r.domain,'domain'),node('small',fmt(r.seen)));if(r.handled)domain.append(node('span','已处理','badge handled'));else if(r.newErrors>0)domain.append(node('span','新增 '+r.newErrors+' 条错误','badge reopened'));const route=node('td','');for(const item of r.routes.split(','))route.append(node('span',item,'badge'));route.append(node('small',r.sources||'来源未知'));const count=node('td',r.connections+' 连接 / '+r.errors+' 错误');count.append(node('small',r.directErrors+' 条直连错误'));const advice=node('td',r.handled?'已处理 · '+fmt(r.handledAt):r.advice,!r.handled&&r.priority?'issue':'');if(r.auto)advice.append(node('small',autoText(r.auto)));const action=node('td','');const btn=node('button','查看');btn.setAttribute('aria-label','查看 '+r.domain);btn.onclick=()=>openDetail(r.domain);const done=node('button',r.handled?'恢复到清单':'标记已处理');done.setAttribute('aria-label',(r.handled?'恢复到清单 ':'标记已处理 ')+r.domain);done.disabled=handlingPending.has(r.domain);done.onclick=()=>changeHandling(r);action.className='row-actions';action.append(btn,done);tr.append(domain,route,count,advice,action);$('rows').append(tr);}
}
async function openDetail(domain){selected=domain;$('detailTitle').textContent=domain;$('probeMessage').textContent='';$('detail').showModal();await loadDetail();}
async function loadDetail(){const domain=selected;if(!domain)return;try{const d=await api('/api/detail?domain='+encodeURIComponent(domain));if(domain!==selected)return;const row=state.rows.find(r=>r.domain===domain);$('autoDetail').textContent=autoText(row?.auto)+(row?.auto?(row.auto.reason?' · '+row.auto.reason:'')+(row.auto.state==='running'?' · 完成后仍可手动复测。':' · 仍可手动复测。'):' · 满足触发条件后自动执行一轮。');$('detailAdvice').textContent=(row?.advice||'')+' · 命中规则：'+(row?.rules||'未知');$('handleDomain').disabled=!row||handlingPending.has(domain);$('handleDomain').textContent=row?.handled?'恢复到清单':'标记已处理';$('handleDomain').onclick=()=>row&&changeHandling(row);$('probe').disabled=state.probing;$('probe').textContent=state.probing?'正在复测…':'开始三路复测';$('probeResults').replaceChildren();$('errorResults').replaceChildren();
 if(!d.probes.length)$('probeResults').append(node('p','尚未复测。点击上方按钮执行三路对照。'));
 for(const p of d.probes){const line=node('div','', 'result');line.append(node('strong',p.route+' · '+p.node+' · '+(p.status==='reachable'?p.delay+' ms（收到响应）':p.status==='failed'?'探测失败':'无法判定')),node('br',''),node('small',fmt(p.time)));$('probeResults').append(line);}
 if(!d.errors.length)$('errorResults').append(node('p','最近24小时没有捕获到该域名的可归类错误。'));
 for(const e of d.errors){const line=node('div','', 'result');line.append(node('strong',e.route+' · '+e.error),node('br',''),node('small',fmt(e.time)+' · '+e.source+' · '+e.rule));$('errorResults').append(line);}
 }catch(e){$('probeMessage').textContent=e.message;}}
async function changeHandling(row){
 if(handlingPending.has(row.domain))return;handlingPending.add(row.domain);render();
 try{await api('/api/handling',{domain:row.domain,handled:!row.handled,expectedErrorRevision:row.errorRevision});if(selected===row.domain&&$('detail').open)$('detail').close();$('notice').textContent=row.domain+(row.handled?' 已恢复到待处理清单。':' 已标记处理；新错误出现时会自动回来。');}
 catch(e){$('notice').textContent=e.message;}
 finally{handlingPending.delete(row.domain);await refresh();}
}
$('loginForm').onsubmit=async e=>{e.preventDefault();const btn=e.target.querySelector('button');btn.disabled=true;try{await api('/api/login',{password:$('password').value});$('password').value='';$('loginError').textContent='';await refresh();}catch(err){$('loginError').textContent=err.message;}finally{btn.disabled=false;}};
$('logout').onclick=async()=>{try{await api('/api/logout',{});}finally{showLogin();}};
$('handlingView').onchange=()=>{if($('handlingView').value==='handled')$('onlyIssues').checked=false;if($('detail').open)$('detail').close();refresh();};
$('search').oninput=()=>state&&render();$('onlyIssues').onchange=()=>state&&render();$('closeDetail').onclick=()=>{$('detail').close();selected=null;};$('detail').addEventListener('close',()=>{selected=null;});
$('probe').onclick=async()=>{$('probe').disabled=true;try{await api('/api/probe',{domain:selected});$('probeMessage').textContent='复测已开始。结果会逐条显示，不会自动修改任何规则。';await refresh();}catch(e){$('probeMessage').textContent=e.message;$('probe').disabled=false;}};
refresh();
