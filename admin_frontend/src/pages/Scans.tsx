import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, AlertTriangle, CheckCircle, ShieldAlert, ChevronRight, ChevronLeft, Loader2, Filter, ChevronDown, ChevronUp, Server } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import { useDataList } from '../hooks/useData';
import { useDebounce } from '../hooks/useDebounce';
import EmptyState from '../components/EmptyState';
import api from '../services/api';

const ScanDetails = ({ scanId }: { scanId: string }) => {
  const { data, isLoading } = useQuery({
    queryKey: ['scanDetails', scanId],
    queryFn: async () => {
      const res = await api.get(`/admin/scans/${scanId}/`);
      return res.data;
    }
  });

  if (isLoading) return <div className="p-8 flex justify-center"><Loader2 className="w-6 h-6 text-primary-500 animate-spin" /></div>;
  if (!data) return null;

  return (
    <div className="p-6 bg-dark-950 border-b border-dark-800 text-right" dir="rtl">
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-1 space-y-4">
          <div>
            <span className="text-xs text-slate-500 block mb-1">الرقم التعريفي (ID)</span>
            <span className="text-xs text-slate-300 font-mono bg-dark-900 px-2 py-1 rounded" dir="ltr">{data.id}</span>
          </div>
          <div>
            <span className="text-xs text-slate-500 block mb-1">IP المستخدم</span>
            <span className="text-sm text-slate-200 font-mono">{data.ip_address || '—'}</span>
          </div>
          <div>
            <span className="text-xs text-slate-500 block mb-1">سيناريو الفحص</span>
            <span className="text-sm text-slate-200">{data.scan_scenario || '—'}</span>
          </div>
          <div>
            <span className="text-xs text-slate-500 block mb-1">السبب (Reason)</span>
            <span className="text-sm text-slate-200">{data.reason || '—'}</span>
          </div>
        </div>

        <div className="lg:col-span-3">
          <h4 className="font-bold text-slate-200 mb-4 flex items-center gap-2">
            <Server className="w-4 h-4 text-primary-500" /> تفاصيل نتائج المحركات
          </h4>
          {data.source_results && data.source_results.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
              {data.source_results.map((res: any, idx: number) => {
                const isMalicious = res.verdict === 'malicious';
                const isSuspicious = res.verdict === 'suspicious';
                return (
                  <div key={idx} className={`p-4 rounded-xl border ${isMalicious ? 'bg-red-500/5 border-red-500/20' : isSuspicious ? 'bg-orange-500/5 border-orange-500/20' : 'bg-dark-900 border-dark-800'}`}>
                    <div className="flex justify-between items-center mb-3">
                      <span className="font-bold text-sm text-slate-200 uppercase tracking-wider">{res.source_type}</span>
                      <span className="text-[10px] text-slate-500 font-mono">{res.latency_ms} ms</span>
                    </div>
                    <div className="space-y-1.5 text-xs">
                      <div className="flex justify-between">
                        <span className="text-slate-400">النتيجة:</span>
                        <span className={`font-bold ${isMalicious ? 'text-red-400' : isSuspicious ? 'text-orange-400' : 'text-green-400'}`}>{res.verdict}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">الخطورة:</span>
                        <span className="text-slate-200 font-mono">{res.safety_score}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">الثقة (الوزن):</span>
                        <span className="text-slate-200 font-mono">{res.confidence} ({res.source_weight})</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="text-sm text-slate-500 italic">لا توجد تفاصيل محركات متاحة لهذا الفحص.</div>
          )}
        </div>
      </div>
    </div>
  );
};

export default function Scans() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [verdict, setVerdict] = useState('');
  const [scanLevel, setScanLevel] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  
  const debouncedSearch = useDebounce(search, 500);

  // Reset page when filters change
  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value);
    setPage(1);
  };

  const handleFilterChange = (setter: React.Dispatch<React.SetStateAction<string>>) => (e: React.ChangeEvent<HTMLSelectElement | HTMLInputElement>) => {
    setter(e.target.value);
    setPage(1);
  };

  const toggleExpand = (id: string) => {
    setExpandedId(prev => prev === id ? null : id);
  };

  const params = {
    page,
    search: debouncedSearch,
    verdict: verdict || undefined,
    scan_level: scanLevel || undefined,
    date_from: dateFrom || undefined,
    date_to: dateTo || undefined,
  };

  const { data, isLoading, isFetching } = useDataList('/admin/scans/', params);

  const scans = data?.results || [];
  const totalPages = data?.count ? Math.ceil(data.count / 20) : 1;

  const SkeletonRow = () => (
    <tr className="animate-pulse border-b border-dark-800">
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-48"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-24"></div></td>
      <td className="p-4"><div className="h-6 bg-dark-800 rounded-full w-24"></div></td>
      <td className="p-4"><div className="h-6 bg-dark-800 rounded-full w-20"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-32"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-4"></div></td>
    </tr>
  );

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6 relative" dir="rtl">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            سجل الفحوصات
            {isFetching && <Loader2 className="w-5 h-5 text-primary-500 animate-spin" />}
          </h2>
          <p className="text-slate-400 text-sm mt-1">عرض جميع الفحوصات مع إمكانية الفلترة والبحث المتقدم</p>
        </div>
      </div>

      {/* Advanced Filters Bar */}
      <div className="glass-card p-4 flex flex-col xl:flex-row items-center gap-4">
        <div className="relative w-full xl:w-80">
          <Search className="w-5 h-5 absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
          <input 
            type="text" 
            value={search}
            onChange={handleSearchChange}
            placeholder="ابحث برابط أو دومين..." 
            className="w-full bg-dark-900 border border-dark-800 rounded-lg pr-10 pl-4 py-2 text-slate-200 focus:outline-none focus:border-primary-500 transition-colors"
          />
        </div>

        <div className="flex flex-wrap xl:flex-nowrap w-full xl:w-auto items-center gap-4 flex-1 xl:justify-end">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500">من</span>
            <input 
              type="date" 
              value={dateFrom}
              onChange={handleFilterChange(setDateFrom)}
              className="bg-dark-900 border border-dark-800 text-slate-200 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 p-2"
            />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-500">إلى</span>
            <input 
              type="date" 
              value={dateTo}
              onChange={handleFilterChange(setDateTo)}
              className="bg-dark-900 border border-dark-800 text-slate-200 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 p-2"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-400" />
            <select 
              value={scanLevel}
              onChange={handleFilterChange(setScanLevel)}
              className="bg-dark-900 border border-dark-800 text-slate-200 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 block p-2"
            >
              <option value="">جميع المستويات</option>
              <option value="basic">سريع (Basic)</option>
              <option value="standard">متوازن (Standard)</option>
              <option value="deep">عميق (Deep)</option>
            </select>
          </div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-slate-400" />
            <select 
              value={verdict}
              onChange={handleFilterChange(setVerdict)}
              className="bg-dark-900 border border-dark-800 text-slate-200 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 block p-2"
            >
              <option value="">جميع الحالات</option>
              <option value="safe">آمن (Safe)</option>
              <option value="suspicious">مشبوه (Suspicious)</option>
              <option value="malicious">خطير (Malicious)</option>
            </select>
          </div>
        </div>
      </div>

      <div className="glass-card overflow-hidden border-t-4 border-t-primary-500">
        <div className="overflow-x-auto">
          <table className="w-full text-right min-w-[1000px]">
            <thead className="bg-dark-900/50 border-b border-dark-800 text-slate-400 text-sm">
              <tr>
                <th className="p-4 font-medium">الرابط (URL)</th>
                <th className="p-4 font-medium">المستوى</th>
                <th className="p-4 font-medium">الدومين</th>
                <th className="p-4 font-medium">الخطورة</th>
                <th className="p-4 font-medium">القرار</th>
                <th className="p-4 font-medium">التاريخ</th>
                <th className="p-4 font-medium"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} />)
              ) : scans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-0">
                    <EmptyState 
                      icon={Search}
                      title="لا توجد فحوصات مطابقة"
                      description="لم نتمكن من العثور على أي فحوصات تتطابق مع معايير البحث والفلترة الخاصة بك."
                    />
                  </td>
                </tr>
              ) : (
                scans.map((scan: any, i: number) => {
                  const isHighRisk = scan.safety_score < 40;
                  const isSuspicious = scan.safety_score >= 40 && scan.safety_score < 80;
                  const isExpanded = expandedId === scan.id;

                  return (
                    <React.Fragment key={scan.id}>
                      <motion.tr 
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: i * 0.03 }}
                        onClick={() => toggleExpand(scan.id)}
                        className={`hover:bg-dark-800/50 transition-colors cursor-pointer group ${isExpanded ? 'bg-dark-800/30' : ''}`}
                      >
                        <td className="p-4">
                          <div className="text-slate-300 font-mono text-sm max-w-[200px] lg:max-w-xs truncate" dir="ltr" title={scan.url}>
                            {scan.url}
                          </div>
                        </td>
                        <td className="p-4">
                           <span className="text-[10px] uppercase font-bold bg-dark-900 border border-dark-800 px-2 py-1 rounded text-slate-400 tracking-wider">
                             {scan.scan_level || 'standard'}
                           </span>
                        </td>
                        <td className="p-4 text-slate-400 text-sm" dir="ltr">{scan.domain_name}</td>
                        <td className="p-4">
                          <div className="flex items-center gap-3">
                            <div className="w-full bg-dark-900 border border-dark-800 rounded-full h-2 max-w-[80px] overflow-hidden">
                              <motion.div 
                                initial={{ width: 0 }}
                                animate={{ width: `${scan.safety_score}%` }}
                                transition={{ duration: 1, ease: "easeOut" }}
                                className={`h-full rounded-full ${
                                  isHighRisk ? 'bg-gradient-to-r from-red-600 to-red-400' : 
                                  isSuspicious ? 'bg-gradient-to-r from-orange-600 to-orange-400' : 
                                  'bg-gradient-to-r from-green-600 to-green-400'
                                }`} 
                              />
                            </div>
                            <span className="text-xs font-bold text-slate-300">{scan.safety_score}%</span>
                          </div>
                        </td>
                        <td className="p-4">
                          {scan.final_verdict === 'malicious' && <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-bold"><ShieldAlert className="w-3 h-3" /> خطير</span>}
                          {scan.final_verdict === 'suspicious' && <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-orange-500/20 text-orange-400 border border-orange-500/30 text-xs font-bold"><AlertTriangle className="w-3 h-3" /> مشبوه</span>}
                          {scan.final_verdict === 'safe' && <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-green-500/20 text-green-400 border border-green-500/30 text-xs font-bold"><CheckCircle className="w-3 h-3" /> آمن</span>}
                        </td>
                        <td className="p-4 text-slate-400 text-xs font-mono" dir="ltr">{scan.created_at?.replace('T', ' ').split('.')[0]}</td>
                        <td className="p-4 text-slate-500">
                          {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                        </td>
                      </motion.tr>
                      <AnimatePresence>
                        {isExpanded && (
                          <motion.tr
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="bg-dark-950"
                          >
                            <td colSpan={7} className="p-0 border-b border-dark-800">
                               <ScanDetails scanId={scan.id} />
                            </td>
                          </motion.tr>
                        )}
                      </AnimatePresence>
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
        
        {/* Pagination Controls */}
        {totalPages > 1 && (
          <div className="p-4 border-t border-dark-800 flex items-center justify-between bg-dark-900/30">
            <span className="text-sm text-slate-400">
              الصفحة <span className="font-bold text-slate-200">{page}</span> من <span className="font-bold text-slate-200">{totalPages}</span>
              {' '}(إجمالي {data?.count} فحص)
            </span>
            <div className="flex gap-2">
              <button 
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-dark-800 text-slate-300 hover:bg-dark-700 disabled:opacity-50 transition-colors text-sm font-medium"
              >
                <ChevronRight className="w-4 h-4" />
                السابق
              </button>
              <button 
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-dark-800 text-slate-300 hover:bg-dark-700 disabled:opacity-50 transition-colors text-sm font-medium"
              >
                التالي
                <ChevronLeft className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </motion.div>
  );
}
