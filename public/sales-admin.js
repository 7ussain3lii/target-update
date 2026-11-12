'use strict';
/* Admin-only exclusion / restore of official report transactions. */
let officialSalesData=null;
let officialSalesReveal=false;
let officialSalesSubscriber='';
let officialSalesFilter='all';
let officialSalesTerm='';

function officialSalesPage(){
 return title('OFFICIAL SALES','Manage Transactions','Find individual official sales, exclude incorrect transactions from achievements, or restore them. Exclusions survive future uploads.',monthControl())+
 '<section class="panel"><div class="panel-body"><form id="official-sales-search" class="sales-manager-controls">'+
 '<label>Exact subscriber number<input id="official-sales-subscriber" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="20" placeholder="Search SUBNO" value="'+esc(officialSalesSubscriber)+'"></label>'+
 '<button class="btn secondary" type="submit">Search subscriber</button>'+
 '<button class="btn ghost" type="button" id="official-sales-clear">Clear search</button>'+
 '<label class="sales-manager-reveal"><input type="checkbox" id="official-sales-reveal" '+(officialSalesReveal?'checked':'')+'> Show subscriber numbers</label>'+
 '</form><p class="muted sales-manager-note">Only official report transactions are shown. Agent daily submissions are not affected.</p></div></section>'+
 '<div id="official-sales-root"><div class="loading">Loading transactions…</div></div>';
}
function renderOfficialSales(){
 const root=$('#official-sales-root');if(!root||!officialSalesData)return;
 const list=officialSalesData.records.filter(e=>(officialSalesFilter==='all'||officialSalesFilter===e.status.toLowerCase())&&
 (!officialSalesTerm||[e.agent,e.agent_name,e.category,e.segment,e.file,e.date].join(' ').toLowerCase().includes(officialSalesTerm.toLowerCase())));
 root.innerHTML='<div class="verify-stat-grid">'+
 [['Counted',officialSalesData.active],['Excluded',officialSalesData.excluded],['Displayed',list.length]].map(([label,val])=>
 '<div class="verify-stat"><small>'+esc(label)+'</small><strong>'+fmt(val)+'</strong></div>').join('')+'</div>'+
 '<section class="panel"><div class="panel-head"><div><h2>Official transactions</h2><div class="sub">Current uploaded sales snapshot · '+esc(month)+'</div></div></div>'+
 '<div class="panel-body sales-manager-filters"><label>Filter transactions <select id="official-sales-status">'+
 ['all','counted','excluded'].map(v=>'<option value="'+v+'" '+(officialSalesFilter===v?'selected':'')+'>'+esc(v==='all'?'All transactions':v[0].toUpperCase()+v.slice(1))+'</option>').join('')+
 '</select></label><label>Agent, category, file or date<input id="official-sales-text" placeholder="Filter displayed rows…" value="'+esc(officialSalesTerm)+'"></label></div>'+
 '<div class="table-wrap"><table><thead><tr><th>Subscriber</th><th>Date</th><th>Agent</th><th>Category</th><th>Report</th><th>Points</th><th>Status</th><th>Action</th></tr></thead><tbody>'+
 (list.map(e=>'<tr><td><strong>'+esc(e.subscriber)+'</strong></td><td>'+esc(e.date)+'</td><td>'+esc(e.agent_name)+'<small class="sales-manager-agent">'+esc(e.agent)+'</small></td><td>'+esc(e.category)+'</td><td>'+esc(e.file)+'</td><td>'+(e.points==null?'Pending':fmt(e.points))+'</td>'+
 '<td>'+ (e.status==='Excluded'?'<span class="verify-status missing">Excluded</span><small class="sales-manager-agent" title="'+esc(e.reason)+'">'+esc(e.reason)+'</small>':'<span class="verify-status good">Counted</span>')+'</td><td>'+
 (state.me.role==='admin'?'<button type="button" class="btn '+(e.status==='Excluded'?'secondary':'ghost')+'" data-official-id="'+esc(e.id)+'" data-official-operation="'+(e.status==='Excluded'?'restore':'exclude')+'">'+(e.status==='Excluded'?'Restore':'Exclude')+'</button>':'Read only')+'</td></tr>').join('')||
 '<tr><td colspan="8" class="empty">No transactions match your filters.</td></tr>')+'</tbody></table></div></section>';
}
async function loadOfficialSales(){
 const root=$('#official-sales-root');if(!root||view!=='official-sales')return;
 const m=month,subno=officialSalesSubscriber,reveal=officialSalesReveal;
 root.innerHTML='<div class="loading">Loading transactions…</div>';
 try {
  const params=new URLSearchParams({month:m,reveal:reveal?'1':'0',subscriber:subno});
  const data=await api('official-sales?'+params);
  if(view!=='official-sales'||month!==m||subno!==officialSalesSubscriber||reveal!==officialSalesReveal)return;
  officialSalesData=data;renderOfficialSales();
 }catch(err){if(root.isConnected)root.innerHTML='<div class="banner warn">'+esc(err.message)+'</div>';}
}
document.addEventListener('submit',async e=>{
 if(e.target.id!=='official-sales-search')return;
 e.preventDefault();e.stopImmediatePropagation();
 const subno=$('#official-sales-subscriber').value.trim();
 if(subno&&!/^\d{5,20}$/.test(subno)){toast('Enter an exact subscriber number (5–20 digits).');return;}
 officialSalesSubscriber=subno;officialSalesTerm='';await loadOfficialSales();
},true);
document.addEventListener('click',async e=>{
 if(e.target.id==='official-sales-clear'){
  officialSalesSubscriber='';officialSalesTerm='';officialSalesFilter='all';render();return;
 }
 const btn=e.target.closest('[data-official-operation]');
 if(!btn)return;
 e.preventDefault();e.stopImmediatePropagation();
 const id=btn.dataset.officialId,operation=btn.dataset.officialOperation;
 const record=officialSalesData?.records.find(x=>x.id===id);
 if(!record)return;
 let reason='';
 if(operation==='exclude'){
  reason=prompt('Reason for excluding this official sale ('+record.agent+' · '+record.category+' · '+record.date+')?');
  if(reason===null)return;
  reason=reason.trim();
  if(reason.length<3||reason.length>250){toast('Please enter a reason of 3–250 characters.');return;}
  if(!confirm('Exclude this official sale from achievements and daily trends? It will remain available for restoration.'))return;
 }else if(!confirm('Restore this official transaction to achievements?'))return;
 btn.disabled=true;
 try{
  await api('official-sale',{id,operation,reason});
  await refresh();
  await loadOfficialSales();
  toast(operation==='exclude'?'Official transaction excluded.':'Official transaction restored.');
 }catch(err){toast(err.message);btn.disabled=false;}
},true);
document.addEventListener('change',e=>{
 if(e.target.id==='official-sales-reveal'){officialSalesReveal=e.target.checked;loadOfficialSales();}
 if(e.target.id==='official-sales-status'){officialSalesFilter=e.target.value;renderOfficialSales();}
});
document.addEventListener('input',e=>{
 if(e.target.id==='official-sales-text'){officialSalesTerm=e.target.value;renderOfficialSales();const el=$('#official-sales-text');el?.focus();el?.setSelectionRange(officialSalesTerm.length,officialSalesTerm.length);}
});
