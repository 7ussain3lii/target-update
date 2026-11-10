'use strict';
/* Independent daily sales trends. Official report and agent input data never mix. */
const DAILY_ACTIVITY_GROUPS=[
 {title:'Migration',categories:['Migration']},
 {title:'Upgrade + Locking',categories:['Upgrade','Locking']},
 {title:'Migration + Upgrade + Locking',categories:['Migration','Upgrade','Locking']},
 {title:'POST',categories:['POST']},
 {title:'BB',categories:['BB']},
 {title:'POST + BB',categories:['POST','BB']}
];
function dailySalesTrendPanel(rows, heading, subtitle){
 const safeRows=Array.isArray(rows)?rows:[];
 const groups=DAILY_ACTIVITY_GROUPS.map(group=>{
  const total=safeRows.reduce((n,day)=>n+group.categories.reduce((sum,key)=>sum+Number(day[key]||0),0),0);
  return '<section class="panel daily-trend-panel">'+
   '<div class="panel-head"><div><h2>'+esc(group.title)+'</h2><div class="sub">Daily transactions · '+esc(month)+'</div></div><span class="pill">Month total: '+fmt(total)+'</span></div>'+
   '<div class="table-wrap"><table><thead><tr><th>Date</th><th>Daily sales</th><th>Month-to-date</th></tr></thead><tbody>'+
   (()=>{let running=0;return safeRows.map(day=>{const value=group.categories.reduce((n,key)=>n+Number(day[key]||0),0);running+=value;return '<tr><td>'+esc(day.date)+'</td><td>'+fmt(value)+'</td><td>'+fmt(running)+'</td></tr>';}).join('')})()+
   '</tbody></table></div></section>';
 }).join('');
 return '<section class="daily-trend-section"><div class="daily-trend-intro"><h2>'+esc(heading)+'</h2><p>'+esc(subtitle)+'</p></div><div class="daily-trend-grid">'+groups+'</div></section>';
}
function officialTeamDailyTrends(){
 if(!canSeeAll()||current())return '';
 return dailySalesTrendPanel(state.daily_trends?.official,'Official report — Daily performance trends','Daily transaction counts from the uploaded official reports. These totals do not include agent-submitted sales.');
}
function individualOfficialDailyTrends(){
 const person=current()||(state.me.role==='agent'?state.me:null);
 if(!person)return '';
 const records=state.agent_daily_trends?.[person.username];
 if(!records)return '';
 return dailySalesTrendPanel(records,person.name+' — Daily sales trend','Daily sales from the official uploaded reports for this performance view only. Agent submissions are not included.');
}
function agentsDailyTrendPage(){
 return title('AGENT SUBMISSIONS','Agents Daily Trend','Daily sales reported by agents, independent of the official reports and official achievement calculations.',monthControl())+
 dailySalesTrendPanel(state.daily_trends?.agent_inputs,'Agents Daily Trend','Daily transaction counts from agents’ own entries only. These do not award points or change targets.');
}
