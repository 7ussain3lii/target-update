'use strict';
/* Read-only reconciliation with a separately controlled agent submission area. */
let verificationAgent=null;
let verificationReveal=false;
let verificationData=null;

function verificationPage(){
 const elevated=canSeeAll();
 const ids=state.agents.filter(a=>a.role==='agent');
 if(!verificationAgent || (!elevated && verificationAgent!==state.me.username)){
   verificationAgent=elevated?(selected && ids.some(a=>a.username===selected)?selected:(ids[0]||{}).username):state.me.username;
 }
 let options=elevated?'<label class="verify-field">Sales agent <select id="verification-agent">'+ids.map(a=>'<option value="'+esc(a.username)+'" '+(a.username===verificationAgent?'selected':'')+'>'+esc(a.name)+' · '+esc(a.username)+'</option>').join('')+'</select></label>':'';
 return title('SALES VERIFICATION','Subscriber-level sales check','Compare official reports against agent-submitted daily sales. Submissions never affect official target achievements.',monthControl())+
 '<div class="verify-toolbar">'+options+'<label class="verify-reveal"><input type="checkbox" id="verification-reveal" '+(verificationReveal?'checked':'')+'> Show subscriber numbers</label><button class="btn secondary" id="verification-refresh">Refresh comparison</button></div>'+
 '<div id="verification-root"><div class="loading">Loading verification records…</div></div>';
}

function verificationStatus(s){
 let cls=s==='Matched'?'good':s==='Missing from report'?'missing':'neutral';
 return '<span class="verify-status '+cls+'">'+esc(s)+'</span>';
}
function verificationOfficial(rows){
 return '<section class="panel"><div class="panel-head"><div><h2>Official reported transactions</h2><div class="sub">Only scored and unscored transactions from the latest official reports</div></div><span class="pill">'+rows.length+' records</span></div><div class="table-wrap"><table><thead><tr><th>Subscriber</th><th>Date</th><th>Activity</th><th>Points</th><th>Reconciliation</th></tr></thead><tbody>'+
 (rows.map(x=>'<tr><td>'+esc(x.subscriber)+'</td><td>'+esc(x.date)+'</td><td>'+esc(x.segment)+'</td><td>'+(x.points===null?'Pending':fmt(x.points))+'</td><td>'+verificationStatus(x.status)+'</td></tr>').join('')||'<tr><td colspan="5" class="empty">No official transactions found for this agent and month.</td></tr>')+
 '</tbody></table></div></section>';
}
function verificationSubmitted(rows){
 const own=state.me.role==='agent';
 return '<section class="panel"><div class="panel-head"><div><h2>Daily sales submissions</h2><div class="sub">Agent entries are for reconciliation only and do not award points</div></div><span class="pill">'+rows.length+' submissions</span></div><div class="table-wrap"><table><thead><tr><th>Subscriber</th><th>Date</th><th>Activity</th><th>Status</th>'+(own?'<th>Action</th>':'')+'</tr></thead><tbody>'+
 (rows.map(x=>'<tr><td>'+esc(x.subscriber)+'</td><td>'+esc(x.date)+'</td><td>'+esc(x.category)+'</td><td>'+verificationStatus(x.status)+'</td>'+(own?'<td><button class="btn ghost" data-verification-delete="'+esc(x.id)+'">Remove</button></td>':'')+'</tr>').join('')||'<tr><td colspan="'+(own?'5':'4')+'" class="empty">No daily sales submissions yet.</td></tr>')+
 '</tbody></table></div></section>';
}
function verificationInput(){
 if(state.me.role!=='agent')return '<div class="banner">This account has read-only access to agent daily sales. Agents can submit transactions under their own login.</div>';
 const categories=['POST','BB','Migration','Upgrade','Locking','Family'];
 const day=new Intl.DateTimeFormat('en-CA',{timeZone:'Asia/Bahrain',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
 // ISO date from individual date parts, independent of browser locale.
 const parts=new Intl.DateTimeFormat('en',{timeZone:'Asia/Bahrain',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date());
 const iso=['year','month','day'].map(t=>parts.find(p=>p.type===t).value).join('-');
 return '<section class="panel"><div class="panel-head"><div><h2>Add my daily sales</h2><div class="sub">Only you can submit or remove sales under your account</div></div></div>'+
 '<div class="panel-body"><form id="verification-add-form" class="verification-form"><label>Subscriber number<input name="subno" inputmode="numeric" pattern="[0-9]{5,20}" maxlength="20" required placeholder="Enter SUBNO"></label>'+
 '<label>Transaction date<input name="date" type="date" max="'+iso+'" value="'+iso+'" required></label>'+
 '<label>Activity<select name="category">'+categories.map(c=>'<option>'+c+'</option>').join('')+'</select></label>'+
 '<button type="submit" class="btn">Add sale</button></form>'+
 '<div class="verify-csv"><strong>Or upload daily sales CSV</strong><p>Columns: SUBNO, TRANSDATE, SEGMENT. Up to 500 rows. Uploads are kept separate from official sales reports.</p>'+
 '<form id="verification-csv-form"><input type="file" name="file" accept=".csv,text/csv" required><button class="btn secondary" type="submit">Upload my CSV</button></form></div></div></section>';
}
async function loadVerification(){
 const root=document.querySelector('#verification-root');
 if(!root||!state||view!=='verification')return;
 const agent=verificationAgent;
 const monthAtLoad=month;
 root.innerHTML='<div class="loading">Loading subscriber comparison…</div>';
 try{
  const params=new URLSearchParams({agent,month:monthAtLoad,reveal:verificationReveal?'1':'0'});
  const result=await api('verification?'+params);
  if(view!=='verification'||agent!==verificationAgent||monthAtLoad!==month)return;
  verificationData=result;
  const stats=result.summary;
  root.innerHTML='<div class="verify-stat-grid">'+
  [['Official report',stats.official],['Agent submitted',stats.submitted],['Matched',stats.matched],['Missing from report',stats.missing]].map(([name,num])=>
  '<div class="verify-stat"><small>'+esc(name)+'</small><strong>'+fmt(num)+'</strong></div>').join('')+
  '</div>'+verificationInput()+'<div class="verify-grids">'+verificationOfficial(result.official)+verificationSubmitted(result.submitted)+'</div>';
 }catch(e){if(root.isConnected)root.innerHTML='<div class="banner warn">'+esc(e.message)+'</div>';}
}
document.addEventListener('change',async e=>{
 if(e.target.id==='verification-agent'){verificationAgent=e.target.value;verificationReveal=false;render();}
 if(e.target.id==='verification-reveal'){verificationReveal=e.target.checked;await loadVerification();}
});
document.addEventListener('click',async e=>{
 if(e.target.id==='verification-refresh'){await loadVerification();}
 const id=e.target.closest('[data-verification-delete]')?.dataset.verificationDelete;
 if(id){
  if(!confirm('Remove this daily sale submission? Official report data will not change.'))return;
  try{await api('daily-delete',{id});await loadVerification();toast('Submission removed.');}catch(err){toast(err.message);}
 }
 if(e.target.closest('[data-action="inspect-subscribers"]')){
  verificationAgent=selected||state.me.username;
  verificationReveal=false;
  view='verification';render();
 }
});
document.addEventListener('submit',async e=>{
 if(!['verification-add-form','verification-csv-form'].includes(e.target.id))return;
 e.preventDefault();e.stopImmediatePropagation();
 const form=e.target,btn=form.querySelector('button[type="submit"]');
 btn.disabled=true;
 try{
  if(form.id==='verification-add-form'){
   const data=Object.fromEntries(new FormData(form));
   const result=await api('daily-add',data);
   toast(result.added?'Daily sale submitted.':'Subscriber already submitted.');
  }else{
   const file=form.elements.file.files[0];
   if(!file||file.size>500000)throw Error('Choose a daily sales CSV under 500 KB.');
   const result=await api('daily-csv',{content:await file.text()});
   toast(result.added+' daily sales uploaded; '+result.duplicates+' duplicates skipped.');
  }
  await loadVerification();
 }catch(err){toast(err.message);}
 finally{btn.disabled=false;}
},true);
