import { motion } from 'framer-motion';
import { Shield, ShieldAlert, ShieldCheck, Activity, Users, Ban, Loader2, ArrowUpRight, Globe, AlertTriangle, CheckCircle2, Server } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts';
import { useQuery } from '@tanstack/react-query';
import api from '../services/api';

const fetchStats = async () => {
  const { data } = await api.get('/admin/stats/');
  return data;
};

const fetchMonitoring = async () => {
  const { data } = await api.get('/monitoring/overview/');
  return data;
};

export default function Dashboard() {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['dashboardStats'],
    queryFn: fetchStats,
    refetchInterval: 60000,
  });

  const { data: monitoring, isLoading: monitoringLoading } = useQuery({
    queryKey: ['monitoringOverview'],
    queryFn: fetchMonitoring,
    refetchInterval: 30000,
  });

  const stats = data?.stats || {};
  const trends_percent = data?.trend_percentages || {};
  
  const cards = [
    { title: 'إجمالي الفحوصات', value: stats.total_scans, icon: Activity, color: '#3b82f6', trend: trends_percent.total_scans || '+0%', label: 'Scans' },
    { title: 'روابط آمنة', value: stats.safe_scans, icon: ShieldCheck, color: '#22c55e', trend: trends_percent.safe_scans || '+0%', label: 'Safe' },
    { title: 'روابط خطيرة', value: stats.threat_scans, icon: ShieldAlert, color: '#ef4444', trend: trends_percent.threat_scans || '+0%', label: 'Threats' },
    { title: 'روابط مشبوهة', value: stats.suspicious, icon: Shield, color: '#f59e0b', trend: trends_percent.suspicious || '+0%', label: 'Suspicious' },
    { title: 'المستخدمين', value: stats.total_users, icon: Users, color: '#a855f7', trend: trends_percent.total_users || '+0%', label: 'Users' },
    { title: 'القائمة السوداء', value: stats.total_blacklisted, icon: Ban, color: '#64748b', trend: trends_percent.total_blacklisted || '+0%', label: 'Blacklist' },
  ];

  if (isError) {
    return (
      <div className="flex flex-col items-center justify-center p-12 glass-card border-red-500/20">
        <AlertTriangle className="w-12 h-12 text-red-500 mb-4" />
        <h3 className="text-xl font-bold text-slate-100">فشل تحميل البيانات</h3>
        <p className="text-slate-400 mt-2">يرجى التحقق من اتصالك بالسيرفر والمحاولة مرة أخرى.</p>
      </div>
    );
  }

  return (
    <div className="space-y-8 text-right" dir="rtl">
      {/* Header with Status */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-3xl font-black text-slate-100 tracking-tight">نظرة عامة على النظام</h2>
          <p className="text-slate-400 text-sm mt-1">متابعة حية لنشاط الفحص والتهديدات المكتشفة في الوقت الحقيقي</p>
        </div>
        <div className="flex items-center gap-3 bg-dark-900/50 border border-dark-800 px-4 py-2 rounded-2xl shadow-sm">
          <div className="relative">
            <div className="w-2.5 h-2.5 rounded-full bg-green-500"></div>
            <div className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-green-500 animate-ping"></div>
          </div>
          <span className="text-sm font-bold text-slate-300">حالة النظام: متصل</span>
        </div>
      </div>

      {/* Stats Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {cards.map((card, i) => (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            key={card.title}
            className="group relative glass-card p-6 overflow-hidden hover:border-slate-700/50 transition-all cursor-default"
          >
            {/* Background Gradient */}
            <div 
              className="absolute -right-4 -top-4 w-24 h-24 blur-3xl opacity-10 transition-opacity group-hover:opacity-20"
              style={{ backgroundColor: card.color }}
            ></div>
            
            <div className="flex justify-between items-start relative z-10">
              <div className="space-y-4">
                <div className="p-2.5 rounded-xl inline-flex bg-dark-950/50 border border-dark-800 group-hover:scale-110 transition-transform">
                  <card.icon className="w-6 h-6" style={{ color: card.color }} />
                </div>
                <div>
                  <p className="text-slate-500 text-xs font-bold uppercase tracking-widest mb-1">{card.title}</p>
                  <div className="flex items-end gap-3">
                    {isLoading ? (
                      <div className="h-9 bg-dark-800 rounded w-28 animate-pulse"></div>
                    ) : (
                      <h3 className="text-4xl font-black text-slate-100 tracking-tighter">
                        {card.value?.toLocaleString() || 0}
                      </h3>
                    )}
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-md flex items-center gap-0.5 mb-1.5 ${
                      card.trend.startsWith('+') ? 'text-green-500 bg-green-500/10' : 'text-red-500 bg-red-500/10'
                    }`}>
                      <ArrowUpRight className="w-2.5 h-2.5" /> {card.trend}
                    </span>
                  </div>
                </div>
              </div>
              
              {/* Mini Chart Mockup (Visual decoration) */}
              <div className="opacity-20 flex items-end gap-1 h-12 pt-4">
                {[40, 70, 45, 90, 65].map((h, j) => (
                  <div 
                    key={j} 
                    className="w-1.5 rounded-full" 
                    style={{ height: `${h}%`, backgroundColor: card.color }}
                  ></div>
                ))}
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Activity Chart */}
        <motion.div
          initial={{ opacity: 0, scale: 0.98 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3 }}
          className="lg:col-span-2 glass-card p-6 h-[450px] relative overflow-hidden"
        >
          <div className="flex justify-between items-center mb-8 relative z-10">
            <div>
              <h3 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                <Activity className="w-5 h-5 text-primary-500" /> اتجاهات الفحص
              </h3>
              <p className="text-slate-400 text-xs mt-1">تحليل النشاط الأسبوعي للفحوصات والتهديدات</p>
            </div>
            <div className="flex gap-4 text-xs font-bold">
              <div className="flex items-center gap-1.5 text-blue-500">
                <div className="w-2.5 h-2.5 rounded-full bg-blue-500"></div> الفحوصات
              </div>
              <div className="flex items-center gap-1.5 text-red-500">
                <div className="w-2.5 h-2.5 rounded-full bg-red-500"></div> التهديدات
              </div>
            </div>
          </div>

          <div className="h-[320px] w-full">
            {isLoading ? (
              <div className="w-full h-full flex flex-col items-center justify-center gap-4">
                <Loader2 className="w-10 h-10 text-primary-500 animate-spin" />
                <span className="text-slate-500 font-bold">جاري تحميل البيانات الإحصائية...</span>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data?.trends || []}>
                  <defs>
                    <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                    </linearGradient>
                    <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} opacity={0.5} />
                  <XAxis 
                    dataKey="date" 
                    stroke="#475569" 
                    tick={{ fontSize: 10, fontWeight: 700 }} 
                    tickLine={false} 
                    axisLine={false}
                    dy={10}
                  />
                  <YAxis 
                    stroke="#475569" 
                    tick={{ fontSize: 10, fontWeight: 700 }} 
                    tickLine={false} 
                    axisLine={false}
                    dx={-10}
                  />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: '#0f172a', 
                      borderColor: '#1e293b', 
                      borderRadius: '16px',
                      boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)',
                      padding: '12px'
                    }}
                    itemStyle={{ color: '#e2e8f0', fontSize: '12px', fontWeight: 'bold' }}
                    labelStyle={{ marginBottom: '8px', color: '#64748b', fontSize: '10px' }}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="scans" 
                    name="الفحوصات" 
                    stroke="#3b82f6" 
                    strokeWidth={4} 
                    fillOpacity={1} 
                    fill="url(#colorScans)"
                    animationDuration={2000}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="threats" 
                    name="التهديدات" 
                    stroke="#ef4444" 
                    strokeWidth={4} 
                    fillOpacity={1} 
                    fill="url(#colorThreats)"
                    animationDuration={2000}
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </motion.div>

        {/* Breakdown Card */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
          className="glass-card p-6 h-[450px] flex flex-col"
        >
          <h3 className="text-xl font-bold text-slate-100 mb-6">توزيع المخاطر</h3>
          <div className="flex-1 w-full min-h-[250px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={[
                { name: 'آمن', value: stats.safe_scans || 0, color: '#22c55e' },
                { name: 'مشبوه', value: stats.suspicious || 0, color: '#f59e0b' },
                { name: 'خطير', value: stats.threat_scans || 0, color: '#ef4444' }
              ]}>
                <XAxis dataKey="name" stroke="#475569" tickLine={false} axisLine={false} tick={{ fontSize: 12, fontWeight: 700 }} />
                <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} contentStyle={{ backgroundColor: '#0f172a', border: 'none', borderRadius: '8px' }} />
                <Bar dataKey="value" radius={[8, 8, 0, 0]} barSize={40}>
                  {[0, 1, 2].map((_, index) => (
                    <Cell key={`cell-${index}`} fill={['#22c55e', '#f59e0b', '#ef4444'][index]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-4 space-y-3">
             <div className="flex justify-between items-center text-sm">
                <span className="text-slate-400">معدل الاكتشاف</span>
                <span className="text-red-500 font-bold">%{stats.total_scans ? ((stats.threat_scans / stats.total_scans) * 100).toFixed(1) : 0}</span>
             </div>
             <div className="w-full bg-dark-800 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="bg-red-500 h-full rounded-full transition-all duration-1000" 
                  style={{ width: `${stats.total_scans ? (stats.threat_scans / stats.total_scans) * 100 : 0}%` }}
                ></div>
             </div>
          </div>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Monitoring Widget */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.45 }}
          className="lg:col-span-1 glass-card p-6 flex flex-col shadow-2xl"
        >
          <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2 mb-4">
            <Server className="w-5 h-5 text-indigo-500" /> صحة المحركات
          </h3>
          {monitoringLoading ? (
             <div className="flex-1 flex items-center justify-center"><Loader2 className="w-8 h-8 text-indigo-500 animate-spin" /></div>
          ) : (
             <div className="space-y-4 flex-1">
               <div className="p-4 bg-dark-900/50 rounded-xl border border-dark-800">
                 <div className="text-xs text-slate-400 mb-1">متوسط الاستجابة</div>
                 <div className="text-2xl font-bold text-slate-100">{monitoring?.avg_latency_ms || 0} <span className="text-sm text-slate-500">ms</span></div>
               </div>
               <div className="p-4 bg-dark-900/50 rounded-xl border border-dark-800">
                 <div className="text-xs text-slate-400 mb-1">نسبة الأخطاء (آخر ساعة)</div>
                 <div className={`text-2xl font-bold ${monitoring?.error_rate_pct > 5 ? 'text-red-500' : 'text-green-500'}`}>
                   {monitoring?.error_rate_pct || 0}%
                 </div>
               </div>
               {monitoring?.degraded_engines?.length > 0 && (
                 <div className="p-3 bg-orange-500/10 border border-orange-500/20 rounded-xl">
                   <div className="text-xs text-orange-400 font-bold mb-1">⚠️ بطء استجابة:</div>
                   <div className="text-sm text-slate-300">{monitoring.degraded_engines.join('، ')}</div>
                 </div>
               )}
             </div>
          )}
        </motion.div>

        {/* Recent Threats Table */}
        <motion.div
           initial={{ opacity: 0, y: 20 }}
           animate={{ opacity: 1, y: 0 }}
           transition={{ delay: 0.5 }}
           className="lg:col-span-3 glass-card overflow-hidden shadow-2xl"
        >
          <div className="p-6 border-b border-dark-800 flex justify-between items-center bg-dark-900/20">
          <div>
            <h3 className="text-xl font-bold text-slate-100">أحدث التهديدات المكتشفة</h3>
            <p className="text-slate-400 text-xs mt-1">آخر 10 روابط تم تصنيفها كتهديدات خطيرة</p>
          </div>
          <button className="text-primary-500 text-xs font-bold hover:underline">عرض الكل</button>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-right min-w-[800px]">
            <thead className="bg-dark-900/50 border-b border-dark-800 text-slate-400 text-[10px] uppercase tracking-widest">
              <tr>
                <th className="p-4 font-bold">الرابط المهدد</th>
                <th className="p-4 font-bold text-center">النطاق</th>
                <th className="p-4 font-bold text-center">درجة الخطورة</th>
                <th className="p-4 font-bold text-center">توقيت الكشف</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {isLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="p-4"><div className="h-4 bg-dark-800 rounded w-64"></div></td>
                    <td className="p-4"><div className="h-4 bg-dark-800 rounded w-32 mx-auto"></div></td>
                    <td className="p-4"><div className="h-6 bg-dark-800 rounded-full w-20 mx-auto"></div></td>
                    <td className="p-4"><div className="h-4 bg-dark-800 rounded w-24 mx-auto"></div></td>
                  </tr>
                ))
              ) : data?.recent_threats?.length === 0 ? (
                <tr>
                  <td colSpan={4} className="p-12 text-center">
                    <div className="flex flex-col items-center gap-3">
                      <CheckCircle2 className="w-10 h-10 text-green-500/50" />
                      <span className="text-slate-500 font-bold">لم يتم اكتشاف تهديدات جديدة مؤخراً</span>
                    </div>
                  </td>
                </tr>
              ) : (
                data?.recent_threats?.map((threat: any, i: number) => (
                  <motion.tr 
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.6 + (i * 0.05) }}
                    key={threat.id} 
                    className="hover:bg-red-500/[0.02] transition-colors group"
                  >
                    <td className="p-4">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-red-500/10 rounded-lg group-hover:scale-110 transition-transform">
                          <Globe className="w-4 h-4 text-red-500" />
                        </div>
                        <div className="max-w-[300px]">
                          <div className="text-slate-200 font-mono text-sm truncate" dir="ltr">{threat.url}</div>
                          <div className="text-[10px] text-red-400 font-bold mt-0.5">Phishing Pattern Detected</div>
                        </div>
                      </div>
                    </td>
                    <td className="p-4 text-center">
                      <span className="text-slate-400 text-xs font-mono" dir="ltr">{threat.domain_name}</span>
                    </td>
                    <td className="p-4 text-center">
                      <div className="flex flex-col items-center gap-1.5">
                        <span className="text-[10px] font-bold text-slate-300">{threat.safety_score}% Safety Score</span>
                        <div className="w-full bg-dark-800 rounded-full h-1 mt-1">
                          <div className={`h-full rounded-full ${threat.safety_score < 40 ? 'bg-red-500' : threat.safety_score < 80 ? 'bg-amber-500' : 'bg-emerald-500'}`} style={{ width: `${threat.safety_score}%` }}></div>
                        </div>
                      </div>
                    </td>
                    <td className="p-4 text-center">
                      <div className="text-slate-400 text-xs font-mono" dir="ltr">
                        {threat.created_at ? threat.created_at.replace('T', ' ').split('.')[0] : ''}
                      </div>
                    </td>
                  </motion.tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </motion.div>
      </div>
    </div>
  );
}
