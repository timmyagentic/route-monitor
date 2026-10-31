'use strict';
const $=id=>document.getElementById(id);
let state=null,stream=null,selected=null,loading=false,again=false;
const handlingPending=new Set();
let handlingRow=null,selectedCorrection=null;
const proxyLabel=r=>r.handled?'复测：代理可达':r.recommendProxy?'建议走代理':'代理可达 · 已走代理';
const autoText=p=>p?({running:"自动复测中",completed:"已自动复测",skipped:"自动复测已跳过",failed:"自动复测失败",interrupted:"自动复测已中断"}[p.state]||p.state)+" · "+fmt(p.started):"尚未自动复测";
const fmt=t=>new Date(t*1000).toLocaleString('zh-CN',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
const node=(tag,text,cls)=>{const e=document.createElement(tag);e.textContent=text;if(cls)e.className=cls;return e;};
async function api(path,body){const res=await fetch(path,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await res.json();if(!res.ok){if(res.status===401&&path!='/api/login')showLogin();throw new Error(data.error||'请求失败');}return data;}
function showLogin(){$('login').hidden=false;$('dashboard').hidden=true;$('logout').hidden=true;if(stream){stream.close();stream=null;}if($('detail').open)$('detail').close();if($('handlingDialog').open)$('handlingDialog').close();if($('correctionDetail').open)$('correctionDetail').close();}
function showDashboard(){$('login').hidden=true;$('dashboard').hidden=false;$('logout').hidden=false;if(!stream){stream=new EventSource('/api/events');stream.addEventListener('refresh',refresh);stream.addEventListener('expired',showLogin);stream.onerror=()=>{$('notice').textContent='与监控服务的实时连接中断，正在重连；当前显示可能不是最新数据。';};stream.onopen=()=>{$('notice').textContent='';refresh();};}}
async function refresh(){if(loading){again=true;return;}loading=true;try{const view=$('handlingView').value;const next=await api('/api/state?view='+view);if(view!==$('handlingView').value){again=true;return;}state=next;showDashboard();render();if(selected&&$('detail').open)await loadDetail();}catch(e){$('notice').textContent=e.message;}finally{loading=false;if(again){again=false;refresh();}}}
function render(){renderCorrection();$('onlyIssues').disabled=$('handlingView').value==='handled';const rows=state.rows||[];$('domains').textContent=rows.length;$('candidates').textContent=rows.filter(r=>!r.handled&&r.priority>0).length;$('errors').textContent=rows.reduce((n,r)=>n+r.directErrors,0);$('unknown').textContent=state.unknown;
 const healthy=state.states.connections?.connected&&state.states.logs?.connected&&state.states.storage?.connected!==false;const age=state.lastFrame.connections?state.now-state.lastFrame.connections:null;
 $('live').textContent=healthy&&age!==null&&age<30?'●  正在观测':'●  采集连接待检查';$('live').classList.toggle('bad',!healthy||age===null||age>=30);
 $('healthDetail').textContent='连接快照：'+(state.lastFrame.connections?fmt(state.lastFrame.connections):'尚未收到')+' · 未归类警告 '+state.unparsed+' 条'+Object.entries(state.states).filter(([,v])=>v.message).map(([k,v])=>' · '+k+': '+v.message).join('');
 $('autoStatus').hidden=state.correction?.mode!=='off';$('autoStatus').textContent='旧版自动复测：10 分钟内 2 次新错误 · 每域名仅一次 · 今日 '+state.auto.used+'/'+state.auto.limit+' 轮（北京时间） · 间隔至少 3 分钟';
 $('progress').textContent=state.bulk?.state==='running'?'批量复测 '+state.bulk.done+'/'+state.bulk.total+' · '+(state.bulk.current||'准备中')+' · 每路 2 次':state.bulk?.state==='completed'?'批量复测完成：'+state.bulk.completed+' 个已测，'+state.bulk.skipped+' 个跳过，'+state.bulk.failed+' 个执行失败。':state.probing?(state.correction?.mode==='off'?'正在参考复测 '+state.probeDomain+'，每路 2 次。':'正在处理纠偏任务，进度见上方。'):'默认只显示最近24小时真实连接报错；正常访问在“全部观察”中。';
 const search=$('search').value.trim().toLowerCase();const visible=rows.filter(r=>(r.domain+' '+r.sources).toLowerCase().includes(search)&&(!$('onlyIssues').checked||(!r.handled&&r.priority>0))).sort((a,b)=>b.priority-a.priority||b.seen-a.seen);
 $('rows').replaceChildren();$('empty').hidden=visible.length>0;$('empty').textContent=rows.length?'没有符合筛选条件的域名。':$('handlingView').value==='handled'?'最近24小时没有已处理的域名。':$('handlingView').value==='all'?'最近24小时还没有可归属域名的观察记录。':'最近24小时没有未处理的真实连接错误。正常访问可在“全部观察”中查看。';
 for(const r of visible){const tr=node('tr','');const domain=node('td','');domain.append(node('div',r.domain,'domain'),node('small',fmt(r.seen)));if(r.handled)domain.append(node('span','已处理','badge handled'));else if(r.newErrors>0)domain.append(node('span','出现新的错误类型或出口','badge reopened'));const route=node('td','');for(const item of r.routes.split(','))route.append(node('span',item,'badge'));route.append(node('small',r.sources||'来源未知'));const count=node('td',r.connections+' 连接 / '+r.errors+' 错误');count.append(node('small',r.directErrors+' 条直连错误'));const advice=node('td','',!r.handled&&r.priority?'issue':'');if(r.proxyEvidence)advice.append(node('strong',proxyLabel(r),'badge proxy-mark'));advice.append(node('div',r.handled?'已处理 · '+fmt(r.handledAt):r.advice));if(r.handled||r.handledReason)advice.append(node('div',(r.handled?'处理原因：':'上次处理原因：')+(r.handledReason||'历史标记，未填写原因'),'handling-reason'));if(r.auto)advice.append(node('small',autoText(r.auto)));const action=node('td','');const btn=node('button','查看');btn.setAttribute('aria-label','查看 '+r.domain);btn.onclick=()=>openDetail(r.domain);const done=node('button',r.handled?'恢复到清单':'标记已处理');done.setAttribute('aria-label',(r.handled?'恢复到清单 ':'标记已处理 ')+r.domain);done.disabled=handlingPending.has(r.domain);done.onclick=()=>changeHandling(r);action.className='row-actions';action.append(btn,done);if(r.handled){const edit=node('button','编辑原因');edit.setAttribute('aria-label','编辑处理原因 '+r.domain);edit.onclick=()=>openHandling(rowFor(r.domain)||r);action.append(edit);}tr.append(domain,route,count,advice,action);$('rows').append(tr);}
}
async function openDetail(domain){selected=domain;$('detailTitle').textContent=domain;$('probeMessage').textContent='';$('detail').showModal();await loadDetail();}
async function loadDetail(){const domain=selected;if(!domain)return;try{const d=await api('/api/detail?domain='+encodeURIComponent(domain));if(domain!==selected)return;const row=state.rows.find(r=>r.domain===domain);$('proxyMark').hidden=!row?.proxyEvidence;$('proxyMark').textContent=row?.proxyEvidence?proxyLabel(row):'';$('autoDetail').textContent=autoText(row?.auto)+(row?.auto?(row.auto.reason?' · '+row.auto.reason:'')+(row.auto.state==='running'?' · 完成后仍可手动复测。':' · 仍可手动复测。'):' · 满足触发条件后自动执行一轮。');$('detailReason').hidden=!(row?.handled||row?.handledReason);$('detailReason').textContent=(row?.handled?'处理原因：':'上次处理原因：')+(row?.handledReason||'历史标记，未填写原因');$('editReason').hidden=!row?.handled;$('editReason').onclick=()=>row&&openHandling(row);$('detailAdvice').textContent=(row?.advice||'')+' · 命中规则：'+(row?.rules||'未知');$('handleDomain').disabled=!row||handlingPending.has(domain);$('handleDomain').textContent=row?.handled?'恢复到清单':'标记已处理';$('handleDomain').onclick=()=>row&&changeHandling(row);$('probe').disabled=state.probing||state.bulk?.state==='running';$('probe').textContent=state.bulk?.state==='running'?'批量复测中…':state.probing?'正在复测…':'开始三路复测';$('probeResults').replaceChildren();$('errorResults').replaceChildren();
 if(!d.probes.length)$('probeResults').append(node('p','尚未复测。点击上方按钮执行三路对照。'));
 for(const p of d.probes){const line=node('div','', 'result');line.append(node('strong',p.route+' · '+p.node+' · '+(p.status==='reachable'?p.delay+' ms（收到响应）':p.status==='failed'?'探测失败':'无法判定')),node('br',''),node('small',fmt(p.time)));$('probeResults').append(line);}
 if(!d.errors.length)$('errorResults').append(node('p','最近24小时没有捕获到该域名的可归类错误。'));
 for(const e of d.errors){const line=node('div','', 'result');line.append(node('strong',e.route+' · '+e.error),node('br',''),node('small',fmt(e.time)+' · '+e.source+' · '+e.rule));$('errorResults').append(line);}
 }catch(e){$('probeMessage').textContent=e.message;}}
function rowFor(domain){return state?.rows.find(r=>r.domain===domain);}
function openHandling(row){
 if(handlingPending.has(row.domain))return;
 if($('detail').open)$('detail').close();
 handlingRow=row;$('handlingTitle').textContent=row.handled?'编辑处理原因':'标记已处理';$('handlingDomain').textContent=row.domain;
 $('handlingReason').value=row.handledReason||'';$('handlingError').textContent='';$('confirmHandling').disabled=false;
 $('handlingDialog').showModal();$('handlingReason').focus();
}
async function changeHandling(row){
 if(!row.handled){openHandling(row);return;}
 await saveHandling(row,false,'');
}
async function saveHandling(row,handled,reason){
 if(handlingPending.has(row.domain))return;handlingPending.add(row.domain);render();
 try{await api('/api/handling',{domain:row.domain,handled,reason,expectedErrorRevision:row.errorRevision});
 if($('handlingDialog').open)$('handlingDialog').close();if(selected===row.domain&&$('detail').open)$('detail').close();
 $('notice').textContent=row.domain+(handled?' 已保存处理原因；同类错误不再重复提醒。':' 已恢复到待处理清单。');
 }catch(e){if($('handlingDialog').open)$('handlingError').textContent=e.message+'；请检查最新记录后重新打开标记窗口。';else $('notice').textContent=e.message;}
 finally{handlingPending.delete(row.domain);$('confirmHandling').disabled=false;await refresh();}
}
$('handlingForm').onsubmit=async e=>{e.preventDefault();const reason=$('handlingReason').value.trim();if(!reason){$('handlingError').textContent='请填写处理原因。';return;}if(!handlingRow)return;$('confirmHandling').disabled=true;await saveHandling(handlingRow,true,reason);};
$('cancelHandling').onclick=()=>{if(!handlingRow||!handlingPending.has(handlingRow.domain))$('handlingDialog').close();};
$('closeHandling').onclick=$('cancelHandling').onclick;
$('handlingDialog').addEventListener('close',()=>{handlingRow=null;});
$('loginForm').onsubmit=async e=>{e.preventDefault();const btn=e.target.querySelector('button');btn.disabled=true;try{await api('/api/login',{password:$('password').value});$('password').value='';$('loginError').textContent='';await refresh();}catch(err){$('loginError').textContent=err.message;}finally{btn.disabled=false;}};
$('logout').onclick=async()=>{try{await api('/api/logout',{});}finally{showLogin();}};
$('handlingView').onchange=()=>{if($('handlingView').value!=='active')$('onlyIssues').checked=false;if($('detail').open)$('detail').close();refresh();};
$('search').oninput=()=>state&&render();$('onlyIssues').onchange=()=>state&&render();$('closeDetail').onclick=()=>{$('detail').close();selected=null;};$('detail').addEventListener('close',()=>{selected=null;});
$('probe').onclick=async()=>{$('probe').disabled=true;try{await api('/api/probe',{domain:selected});$('probeMessage').textContent='参考复测已开始。此按钮只收集参考结果，不直接触发规则发布。';await refresh();}catch(e){$('probeMessage').textContent=e.message;$('probe').disabled=false;}};
const correctionLabels={queued:'等待初测',probing:'正在取证',confirming:'等待分时确认',planning:'发布前校验',suggested:'建议已就绪',prepared:'等待继续',publishing:'确认发布结果',applying:'路由器加载中',verifying:'待完成复验',watching:'等待真实流量',confirmed:'链路已确认',rollback:'正在撤回',rolled_back:'已撤回',blocked:'受保护',inconclusive:'证据不足',resolved:'本轮结束',attention:'需要处理'};
function renderCorrection(){
 const c=state.correction||{mode:'off',cases:[]};const active=c.mode!=='off';
 $('modeBadge').textContent=c.mode==='auto'?(c.paused?'已暂停新增调整':'自动纠偏'):c.mode==='observe'?'观察决策 · 不发布':'只观察 · 不改规则';
 $('correctionMode').textContent=c.error||(c.mode==='auto'?'自动模式：证据、发布、加载与复验分别跟踪。':c.mode==='observe'?'观察模式：持续复测并生成建议，尚未开启规则发布。':'持续纠偏尚未配置。现有采集与参考复测继续运行。');
 $('correctionScope').textContent=active?'10 分钟内同一设备、协议和端口出现 2 次新错误后取证；确认间隔 '+c.confirmDelaySeconds+' 秒，不同域名串行取证。每日最多 '+c.dailyProbeLimit+' 轮普通探测、'+c.dailyChangeLimit+' 次新增调整；已应用规则的复验独立计数，上限 '+c.verificationLimit+' 次。暂停新增调整后，已开始发送的调整仍会完成应用、验证或撤回。':'需配置路由器探测程序和规则服务后启用；启用自动模式需要在本机明确设置。';
 $('correctionPause').hidden=!active;$('correctionPause').textContent=c.paused?'继续新增调整':'暂停新增调整';
 $('correctionCases').replaceChildren();const cases=c.cases||[];$('correctionEmpty').hidden=cases.length>0;
 for(const item of cases.slice(0,12)){
  const card=node('article','', 'correction-card');const head=node('div','', 'correction-card-head');head.append(node('strong',item.domain,'domain'),node('span',correctionLabels[item.state]||item.state,'badge '+(['attention','blocked','inconclusive'].includes(item.state)?'reopened':item.state==='confirmed'?'handled':'')));
  const direction=item.decision.action==='PROXY'?'直连 → 代理':item.decision.action==='DIRECT'?'代理 → 直连':'保持当前规则';
  card.append(head,node('p',direction,'correction-direction'),node('p',item.reason),node('small',item.source+' · '+(item.network||'未知协议').toUpperCase()+':'+item.port+' · '+fmt(item.updated)));
  if(item.next>0)card.append(node('small','下次处理：'+fmt(item.next)));
  if(item.appliedAt)card.append(node('small','自动复验：'+(item.verificationAttempts||0)+'/'+c.verificationLimit+' 次'));
  const button=node('button','查看证据');button.setAttribute('aria-label','查看纠偏证据 '+item.domain);button.onclick=()=>{selectedCorrection=item.id;$('correctionDetail').showModal();renderCorrectionDetail(item);};card.append(button);if(active&&['attention','blocked','inconclusive','suggested'].includes(item.state)){const retry=node('button','重新核对');retry.onclick=async()=>{retry.disabled=true;try{await api('/api/correction/retry',{domain:item.domain,id:item.id});await refresh();}catch(e){$('notice').textContent=e.message;retry.disabled=false;}};card.append(retry);}$('correctionCases').append(card);
 }
 if(selectedCorrection&&$('correctionDetail').open){const item=cases.find(x=>x.id===selectedCorrection);if(item)renderCorrectionDetail(item);}
}
function renderCorrectionDetail(item){
 $('correctionDomain').textContent=item.domain;$('correctionReason').textContent=item.reason;$('correctionTimeline').replaceChildren();
 const steps=[['分时证据',item.decision.confirmed],['云端已发布',!!item.receipt],['路由器已加载',!!item.appliedAt],['路径复验通过',['watching','confirmed'].includes(item.state)],['真实连接接收数据',!!item.observedAt]];
 for(const [label,done]of steps)$('correctionTimeline').append(node('span',(done?'✓ ':'○ ')+label,done?'complete':''));
 if(item.rollbackReceipt)$('correctionTimeline').append(node('span','↶ 已发布撤回版本','complete'));
 $('correctionEvidence').replaceChildren();
 for(const [i,ev]of [...(item.evidence||[]),...(item.verification||[])].entries()){
  const section=node('section','', 'evidence-round');section.append(node('h3','第 '+(i+1)+' 轮 · '+fmt(ev.finished)));
  for(const route of ['DIRECT','JP','HK']){
   const samples=(ev.samples||[]).filter(x=>x.route===route&&!x.control);const controls=(ev.samples||[]).filter(x=>x.route===route&&x.control);
   const text=samples.map(s=>s.status==='response'?'HTTP '+s.httpStatus+' / '+s.millis+' ms':({dns:'DNS',connect:'连接',tls:'TLS',tls_certificate:'证书',http:'HTTP'}[s.stage]||s.stage)+' · '+({failed:'失败',unknown:'无法判定',unsafe:'拒绝探测'}[s.status]||s.status)).join('；');
   const line=node('div','', 'result');line.append(node('strong',route+' · '+(text||'未完成')),node('small','对照目标：'+controls.filter(s=>s.status==='response').length+'/'+controls.length+' 收到响应'));section.append(line);
  }
  $('correctionEvidence').append(section);
 }
 if(!(item.evidence||[]).length)$('correctionEvidence').append(node('p','尚无完整探测证据。'));
}
$('correctionPause').onclick=async()=>{const b=$('correctionPause');b.disabled=true;try{await api('/api/correction/pause',{paused:!state.correction.paused});await refresh();}catch(e){$('notice').textContent=e.message;}finally{b.disabled=false;}};
$('closeCorrection').onclick=()=>$('correctionDetail').close();$('correctionDetail').addEventListener('close',()=>{selectedCorrection=null;});
refresh();
