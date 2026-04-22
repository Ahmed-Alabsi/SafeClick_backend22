import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Database, MessageSquareWarning, Calendar, Link as LinkIcon, Clock, ChevronRight, ChevronLeft, Loader2, Server, Activity } from 'lucide-react';
import { useDataList } from '../hooks/useData';
import { useDebounce } from '../hooks/useDebounce';
import EmptyState from '../components/EmptyState';

export default function Logs() {
  const [activeTab, setActiveTab] = useState<'cache' | 'reports' | 'monitoring'>('cache');
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebounce(search, 500);

  React.useEffect(() => {
    setPage(1);
  }, [debouncedSearch, activeTab]);

  const endpoint = activeTab === 'cache' 
    ? '/admin/cache/' 
    : activeTab === 'reports' 
      ? '/admin/reports/' 
      : '/monitoring/logs/';
  
  const { data, isLoading, isFetching } = useDataList(endpoint, { 
    page, 
    search: debouncedSearch 
  });

  const logs = data?.results || [];
  const totalPages = data?.count ? Math.ceil(data.count / 20) : 1;

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6 relative">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            <Database className="w-6 h-6 text-purple-500" /> سجلات النظام والتقارير
            {isFetching && <Loader2 className="w-5 h-5 text-purple-500 animate-spin" />}
          </h2>
          <p className="text-slate-400 text-sm mt-1">مراقبة الذاكرة المؤقتة وتقارير المستخدمين</p>
        </div>
        
        <div className="flex gap-4 w-full md:w-auto">
          <div className="relative w-full md:w-64">
            <Search className="w-5 h-5 absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
            <input 
              type="text" 
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="ابحث في السجلات..." 
              className="w-full bg-dark-900 border border-dark-800 rounded-lg pr-10 pl-4 py-2 text-slate-200 focus:outline-none focus:border-purple-500 transition-colors"
            />
          </div>
        </div>
      </div>

      <div className="flex gap-2 border-b border-dark-800 pb-2">
        <button 
          onClick={() => setActiveTab('cache')}
          className={`px-4 py-2 rounded-lg font-medium transition-all ${activeTab === 'cache' ? 'bg-purple-500/20 text-purple-400' : 'text-slate-400 hover:text-slate-200 hover:bg-dark-800'}`}
        >
          <div className="flex items-center gap-2"><Database className="w-4 h-4" /> الكاش (Cache)</div>
        </button>
        <button 
          onClick={() => setActiveTab('reports')}
          className={`px-4 py-2 rounded-lg font-medium transition-all ${activeTab === 'reports' ? 'bg-orange-500/20 text-orange-400' : 'text-slate-400 hover:text-slate-200 hover:bg-dark-800'}`}
        >
          <div className="flex items-center gap-2"><MessageSquareWarning className="w-4 h-4" /> تقارير المستخدمين</div>
        </button>
        <button 
          onClick={() => setActiveTab('monitoring')}
          className={`px-4 py-2 rounded-lg font-medium transition-all ${activeTab === 'monitoring' ? 'bg-indigo-500/20 text-indigo-400' : 'text-slate-400 hover:text-slate-200 hover:bg-dark-800'}`}
        >
          <div className="flex items-center gap-2"><Activity className="w-4 h-4" /> مراقبة المحركات</div>
        </button>
      </div>

      <div className={`glass-card overflow-hidden border-t-4 ${activeTab === 'cache' ? 'border-t-purple-500' : activeTab === 'reports' ? 'border-t-orange-500' : 'border-t-indigo-500'}`}>
        <div className="overflow-x-auto">
          <table className="w-full text-right min-w-[800px]">
            <thead className="bg-dark-900/50 border-b border-dark-800 text-slate-400 text-sm">
              <tr>
                {activeTab === 'monitoring' ? (
                  <>
                    <th className="p-4 font-medium">المحرك</th>
                    <th className="p-4 font-medium">الحالة</th>
                    <th className="p-4 font-medium">الاستجابة (ms)</th>
                    <th className="p-4 font-medium">الرابط المفحوص</th>
                    <th className="p-4 font-medium">توقيت الفحص</th>
                  </>
                ) : activeTab === 'cache' ? (
                  <>
                    <th className="p-4 font-medium">الرابط المخزن</th>
                    <th className="p-4 font-medium">النتيجة</th>
                    <th className="p-4 font-medium">وقت التخزين</th>
                    <th className="p-4 font-medium">وقت الانتهاء</th>
                  </>
                ) : (
                  <>
                    <th className="p-4 font-medium">الرابط المُبلغ عنه</th>
                    <th className="p-4 font-medium">المستخدم</th>
                    <th className="p-4 font-medium">التعليق/السبب</th>
                    <th className="p-4 font-medium">التاريخ</th>
                  </>
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {isLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="p-4"><div className="h-4 bg-dark-800 rounded w-48"></div></td>
                    <td className="p-4"><div className="h-4 bg-dark-800 rounded w-24"></div></td>
                    <td className="p-4"><div className="h-4 bg-dark-800 rounded w-32"></div></td>
                    <td className="p-4"><div className="h-4 bg-dark-800 rounded w-32"></div></td>
                  </tr>
                ))
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="p-0">
                    <EmptyState 
                      icon={activeTab === 'cache' ? Database : activeTab === 'reports' ? MessageSquareWarning : Server}
                      title="لا توجد سجلات"
                      description="لم نتمكن من العثور على أي سجلات أو تقارير في هذا القسم."
                    />
                  </td>
                </tr>
              ) : (
                logs.map((log: any, i: number) => (
                  <motion.tr 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.05 }}
                    key={log.id} 
                    className="hover:bg-dark-800/30 transition-colors"
                  >
                    {activeTab === 'monitoring' ? (
                      <>
                        <td className="p-4 text-slate-200 font-bold text-sm">
                          {log.engine_label}
                        </td>
                        <td className="p-4">
                           <span className={`inline-flex px-2 py-1 rounded text-xs font-bold ${log.status === 'ok' ? 'bg-green-500/10 text-green-500' : log.status === 'degraded' ? 'bg-orange-500/10 text-orange-500' : 'bg-red-500/10 text-red-500'}`}>
                             {log.status_label}
                           </span>
                        </td>
                        <td className="p-4 text-slate-300 font-mono text-sm" dir="ltr">{log.latency_ms ? `${log.latency_ms} ms` : '—'}</td>
                        <td className="p-4 text-slate-400 font-mono text-xs max-w-[200px] truncate" dir="ltr" title={log.scan_url || ''}>{log.scan_url || '—'}</td>
                        <td className="p-4 text-slate-400 text-sm" dir="ltr"><div className="flex items-center gap-1 justify-end"><Clock className="w-3 h-3 text-indigo-400"/> {log.checked_at?.replace('T', ' ').split('.')[0]}</div></td>
                      </>
                    ) : activeTab === 'cache' ? (
                      <>
                        <td className="p-4 text-slate-300 font-mono text-sm max-w-xs truncate" dir="ltr" title={log.url}><div className="flex items-center gap-2"><LinkIcon className="w-4 h-4 text-slate-500 shrink-0"/> {log.url}</div></td>
                        <td className="p-4">
                          <span className={`inline-flex px-2 py-1 rounded text-xs font-bold ${log.result === 'safe' ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'}`}>
                            {log.result}
                          </span>
                        </td>
                        <td className="p-4 text-slate-400 text-sm" dir="ltr"><div className="flex items-center gap-1 justify-end"><Calendar className="w-3 h-3"/> {log.scanned_at?.replace('T', ' ').split('.')[0]}</div></td>
                        <td className="p-4 text-slate-400 text-sm" dir="ltr"><div className="flex items-center gap-1 justify-end"><Clock className="w-3 h-3 text-orange-400"/> {log.expires_at?.replace('T', ' ').split('.')[0]}</div></td>
                      </>
                    ) : (
                      <>
                        <td className="p-4 text-slate-300 font-mono text-sm max-w-xs truncate" dir="ltr" title={log.scan_url}><div className="flex items-center gap-2"><LinkIcon className="w-4 h-4 text-slate-500 shrink-0"/> {log.scan_url || 'N/A'}</div></td>
                        <td className="p-4 text-slate-400 text-sm" dir="ltr">{log.user_email || 'مستخدم غير معروف'}</td>
                        <td className="p-4 text-slate-200 text-sm max-w-md">{log.comment}</td>
                        <td className="p-4 text-slate-400 text-sm" dir="ltr"><div className="flex items-center gap-1 justify-end"><Calendar className="w-3 h-3"/> {log.created_at?.replace('T', ' ').split('.')[0]}</div></td>
                      </>
                    )}
                  </motion.tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="p-4 border-t border-dark-800 flex items-center justify-between bg-dark-900/30">
            <span className="text-sm text-slate-400">
              الصفحة <span className="font-bold text-slate-200">{page}</span> من <span className="font-bold text-slate-200">{totalPages}</span>
            </span>
            <div className="flex gap-2">
              <button 
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-2 rounded-lg bg-dark-800 text-slate-300 hover:bg-dark-700 disabled:opacity-50 transition-colors"
              >
                <ChevronRight className="w-5 h-5" />
              </button>
              <button 
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-2 rounded-lg bg-dark-800 text-slate-300 hover:bg-dark-700 disabled:opacity-50 transition-colors"
              >
                <ChevronLeft className="w-5 h-5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </motion.div>
  );
}
