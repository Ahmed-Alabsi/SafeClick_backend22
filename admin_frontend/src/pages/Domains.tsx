import { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Globe, Lock, ShieldAlert, CheckCircle, ChevronRight, ChevronLeft, Loader2, ArrowUpDown } from 'lucide-react';
import { useDataList } from '../hooks/useData';
import { useDebounce } from '../hooks/useDebounce';
import EmptyState from '../components/EmptyState';

export default function Domains() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [minRisk, setMinRisk] = useState('');
  const [ordering, setOrdering] = useState('-last_checked');

  const debouncedSearch = useDebounce(search, 500);

  // Reset to page 1 when any filter changes
  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value);
    setPage(1);
  };

  const handleMinRiskChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setMinRisk(e.target.value);
    setPage(1);
  };

  const handleOrderingChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setOrdering(e.target.value);
    setPage(1);
  };

  const { data, isLoading, isFetching } = useDataList('/admin/domains/', { 
    page, 
    search: debouncedSearch,
    min_risk: minRisk || undefined,
    ordering
  });

  const domains = data?.results || [];
  const totalPages = data?.count ? Math.ceil(data.count / 20) : 1;

  // Render a skeleton table row for loading state
  const SkeletonRow = () => (
    <tr className="animate-pulse border-b border-dark-800">
      <td className="p-4"><div className="flex items-center gap-3"><div className="w-8 h-8 bg-dark-800 rounded-full"></div><div className="h-4 bg-dark-800 rounded w-32"></div></div></td>
      <td className="p-4"><div className="h-6 bg-dark-800 rounded-full w-16"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-20"></div></td>
      <td className="p-4"><div className="h-6 bg-dark-800 rounded-full w-20"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-32"></div></td>
    </tr>
  );

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            ذكاء النطاقات (Domains Intel)
            {isFetching && <Loader2 className="w-5 h-5 text-primary-500 animate-spin" />}
          </h2>
          <p className="text-slate-400 text-sm mt-1">إدارة وفحص ذكاء جميع النطاقات المسجلة في النظام</p>
        </div>
      </div>

      {/* Advanced Filters Bar */}
      <div className="glass-card p-4 flex flex-col lg:flex-row items-center gap-4">
        {/* Search */}
        <div className="relative w-full lg:w-96">
          <Search className="w-5 h-5 absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
          <input 
            type="text" 
            value={search}
            onChange={handleSearchChange}
            placeholder="ابحث عن دومين..." 
            className="w-full bg-dark-900 border border-dark-800 rounded-lg pr-10 pl-4 py-2 text-slate-200 focus:outline-none focus:border-primary-500 transition-colors"
          />
        </div>

        <div className="flex w-full lg:w-auto items-center gap-4 flex-1 lg:justify-end">
          {/* Risk Filter */}
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-slate-400" />
            <select 
              value={minRisk}
              onChange={handleMinRiskChange}
              className="bg-dark-900 border border-dark-800 text-slate-200 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 block w-full p-2"
            >
              <option value="">جميع المستويات (All)</option>
              <option value="1">مشبوه جزئياً (&gt; 0%)</option>
              <option value="50">خطر عالي (&gt; 50%)</option>
              <option value="80">خطر حرج (&gt; 80%)</option>
            </select>
          </div>

          {/* Ordering */}
          <div className="flex items-center gap-2">
            <ArrowUpDown className="w-4 h-4 text-slate-400" />
            <select 
              value={ordering}
              onChange={handleOrderingChange}
              className="bg-dark-900 border border-dark-800 text-slate-200 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 block w-full p-2"
            >
              <option value="-last_checked">أحدث فحص</option>
              <option value="-safety_ratio">الأقل أماناً</option>
              <option value="-total_scans">الأكثر فحصاً</option>
              <option value="last_checked">أقدم فحص</option>
            </select>
          </div>
        </div>
      </div>

      {/* Professional Table */}
      <div className="glass-card overflow-hidden border-t-4 border-t-primary-500">
        <div className="overflow-x-auto">
          <table className="w-full text-right min-w-[900px]">
            <thead className="bg-dark-900/50 border-b border-dark-800 text-slate-400 text-sm">
              <tr>
                <th className="p-4 font-medium">اسم النطاق (Domain)</th>
                <th className="p-4 font-medium">نسبة الأمان</th>
                <th className="p-4 font-medium">عمر الدومين</th>
                <th className="p-4 font-medium">إجمالي الفحوصات</th>
                <th className="p-4 font-medium">حالة الأمان (SSL)</th>
                <th className="p-4 font-medium">آخر فحص</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} />)
              ) : domains.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-0">
                    <EmptyState 
                      icon={Globe}
                      title="لا توجد نطاقات"
                      description="لم يتم العثور على أي بيانات ذكاء للنطاقات تتطابق مع بحثك والفلاتر الحالية."
                    />
                  </td>
                </tr>
              ) : (
                domains.map((domain: any, i: number) => {
                  const safetyPercentage = Math.round((domain.safety_ratio || 0) * 100);
                  const isHighSafety = safetyPercentage >= 80;
                  const isLowSafety = safetyPercentage < 40;
                  const isModerateSafety = safetyPercentage >= 40 && safetyPercentage < 80;

                  return (
                    <motion.tr 
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.03 }}
                      key={domain.id}
                      className="hover:bg-dark-800/30 transition-colors group cursor-default"
                    >
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <div className={`p-2 rounded-lg transition-colors ${
                            isLowSafety ? 'bg-red-500/10 text-red-500' : 
                            isModerateSafety ? 'bg-amber-500/10 text-amber-500' : 
                            'bg-emerald-500/10 text-emerald-500'
                          }`}>
                            <Globe className="w-4 h-4" />
                          </div>
                          <span className="font-bold text-slate-200" dir="ltr">{domain.domain}</span>
                        </div>
                      </td>
                      <td className="p-4">
                        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold ${
                          isLowSafety ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 
                          isModerateSafety ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' : 
                          'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {isLowSafety ? <ShieldAlert className="w-3 h-3" /> : <CheckCircle className="w-3 h-3" />}
                          {isLowSafety ? 'خطر' : isModerateSafety ? 'مشبوه' : 'آمن'}
                        </span>
                      </td>
                      <td className="p-4 text-slate-300">
                        {domain.age_days ? (
                          <div className="flex flex-col">
                            <span dir="ltr">{domain.age_days} days</span>
                            {domain.age_days < 30 && (
                              <span className="text-[10px] text-red-400 font-bold mt-0.5">⚠️ نطاق جديد!</span>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-500">غير معروف</span>
                        )}
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-3">
                          <div className="flex-grow bg-dark-900 border border-dark-800 rounded-full h-2 max-w-[80px] overflow-hidden">
                            <motion.div 
                              initial={{ width: 0 }}
                              animate={{ width: `${safetyPercentage}%` }}
                              transition={{ duration: 1, ease: "easeOut" }}
                              className={`h-full rounded-full ${
                                isLowSafety ? 'bg-red-500' : isModerateSafety ? 'bg-amber-500' : 'bg-emerald-500'
                              }`} 
                            />
                          </div>
                          <span className="text-xs font-bold text-slate-300">{safetyPercentage}%</span>
                        </div>
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                          <div className="w-full bg-dark-800 rounded-full h-1.5 max-w-[60px]">
                            <div className="bg-primary-500 h-1.5 rounded-full" style={{ width: `${Math.min(domain.total_scans * 2, 100)}%` }}></div>
                          </div>
                          <span className="font-medium text-slate-300">{domain.total_scans}</span>
                        </div>
                      </td>
                      <td className="p-4">
                        {domain.has_ssl ? (
                          <span className="inline-flex items-center gap-1.5 text-xs text-green-400 bg-green-500/10 px-2.5 py-1 rounded-lg">
                            <Lock className="w-3 h-3" /> مشفر
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-xs text-red-400 bg-red-500/10 px-2.5 py-1 rounded-lg">
                            <ShieldAlert className="w-3 h-3" /> غير مشفر
                          </span>
                        )}
                      </td>
                      <td className="p-4 text-slate-400 text-sm" dir="ltr">
                        {domain.last_checked ? domain.last_checked.replace('T', ' ').split('.')[0] : '—'}
                      </td>
                    </motion.tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Professional Pagination */}
        {totalPages > 1 && (
          <div className="p-4 border-t border-dark-800 flex items-center justify-between bg-dark-900/30">
            <span className="text-sm text-slate-400">
              الصفحة <span className="font-bold text-slate-200">{page}</span> من <span className="font-bold text-slate-200">{totalPages}</span>
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
