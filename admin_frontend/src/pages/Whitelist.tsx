import { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, CheckCircle, Plus, Trash2, ShieldCheck, ChevronRight, ChevronLeft, Loader2, Calendar } from 'lucide-react';
import { useQueryClient, useMutation } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { useDataList } from '../hooks/useData';
import { useDebounce } from '../hooks/useDebounce';
import api from '../services/api';
import Modal from '../components/Modal';
import EmptyState from '../components/EmptyState';
import ConfirmDialog from '../components/ConfirmDialog';

export default function Whitelist() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newDomain, setNewDomain] = useState('');
  const [confirmDelete, setConfirmDelete] = useState<{ isOpen: boolean; id: string | null; domain: string }>({
    isOpen: false,
    id: null,
    domain: '',
  });
  
  const debouncedSearch = useDebounce(search, 500);
  const queryClient = useQueryClient();

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value);
    setPage(1);
  };

  const { data, isLoading, isFetching } = useDataList('/admin/whitelist/', { 
    page, 
    search: debouncedSearch 
  });

  const items = data?.results || [];
  const totalPages = data?.count ? Math.ceil(data.count / 20) : 1;

  const addMutation = useMutation({
    mutationFn: async (domain: string) => {
      const res = await api.post('/admin/whitelist/', { domain, source: 'admin' });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/admin/whitelist/'] });
      toast.success('تم الإضافة للقائمة البيضاء بنجاح');
      setIsModalOpen(false);
      setNewDomain('');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.domain?.[0] || 'حدث خطأ أثناء الإضافة');
    }
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/admin/whitelist/${id}/`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/admin/whitelist/'] });
      toast.success('تم الحذف بنجاح');
      setConfirmDelete({ isOpen: false, id: null, domain: '' });
    },
    onError: () => {
      toast.error('حدث خطأ أثناء الحذف');
    }
  });

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDomain.trim()) return toast.error('الرجاء إدخال اسم النطاق');
    addMutation.mutate(newDomain);
  };

  const SkeletonRow = () => (
    <tr className="animate-pulse border-b border-dark-800">
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-48"></div></td>
      <td className="p-4"><div className="h-6 bg-dark-800 rounded-full w-32"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-32"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-24"></div></td>
      <td className="p-4 text-center"><div className="h-8 bg-dark-800 rounded w-8 inline-block"></div></td>
    </tr>
  );

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6 relative text-right" dir="rtl">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <CheckCircle className="w-6 h-6 text-green-500" /> القائمة البيضاء
            {isFetching && <Loader2 className="w-5 h-5 text-green-500 animate-spin" />}
          </h2>
          <p className="text-slate-400 text-sm mt-1">إدارة النطاقات الموثوقة لتجاوز الفحوصات العميقة وتسريع النظام</p>
        </div>
        
        <div className="flex flex-col sm:flex-row gap-4 w-full md:w-auto">
          <div className="relative w-full sm:w-64">
            <Search className="w-5 h-5 absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
            <input 
              type="text" 
              value={search}
              onChange={handleSearchChange}
              placeholder="ابحث عن نطاق..." 
              className="w-full bg-dark-900 border border-dark-800 rounded-lg pr-10 pl-4 py-2 text-slate-200 focus:outline-none focus:border-green-500 transition-colors"
            />
          </div>
          <button 
            onClick={() => setIsModalOpen(true)}
            className="flex items-center justify-center gap-2 bg-green-600 hover:bg-green-700 text-white rounded-lg px-4 py-2 transition-all font-bold shadow-lg shadow-green-500/20 whitespace-nowrap active:scale-95"
          >
            <Plus className="w-5 h-5" />
            إضافة موثوقة
          </button>
        </div>
      </div>

      <div className="glass-card overflow-hidden border-t-4 border-t-green-500 shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-right min-w-[800px]">
            <thead className="bg-dark-900/50 border-b border-dark-800 text-slate-400 text-sm">
              <tr>
                <th className="p-4 font-medium">النطاق (Domain)</th>
                <th className="p-4 font-medium">المصدر</th>
                <th className="p-4 font-medium">تاريخ الإضافة</th>
                <th className="p-4 font-medium">الانتهاء</th>
                <th className="p-4 font-medium text-center">إجراءات</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} />)
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-0">
                    <EmptyState 
                      icon={CheckCircle}
                      title="القائمة البيضاء فارغة"
                      description="لم يتم العثور على أي نطاقات موثوقة تطابق بحثك الحالي."
                    />
                  </td>
                </tr>
              ) : (
                items.map((item: any, i: number) => (
                  <motion.tr 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.03 }}
                    key={item.id} 
                    className="hover:bg-dark-800/30 transition-colors group"
                  >
                    <td className="p-4 text-slate-200 font-mono text-sm max-w-[250px] truncate" dir="ltr" title={item.domain}>
                      {item.domain}
                    </td>
                    <td className="p-4">
                      <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold border ${
                        item.source === 'admin' 
                        ? 'bg-primary-500/10 text-primary-400 border-primary-500/20' 
                        : 'bg-green-500/10 text-green-400 border-green-500/20'
                      }`}>
                        <ShieldCheck className="w-3 h-3" /> {item.source === 'admin' ? 'إضافة يدوية' : 'تلقائي'}
                      </span>
                    </td>
                    <td className="p-4 text-slate-400 text-xs font-mono" dir="ltr">{item.created_at?.replace('T', ' ').split('.')[0]}</td>
                    <td className="p-4">
                      <div className="flex items-center gap-2 text-slate-400 text-xs font-mono" dir="ltr">
                        {!item.expires_at ? (
                          <span className="text-green-500 font-bold px-2 py-0.5 bg-green-500/10 rounded border border-green-500/20">دائم</span>
                        ) : (
                          <>
                            <Calendar className="w-3 h-3" />
                            {item.expires_at.replace('T', ' ').split('.')[0]}
                          </>
                        )}
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex justify-center">
                        <button 
                          onClick={() => setConfirmDelete({ isOpen: true, id: item.id, domain: item.domain })}
                          className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all active:scale-90"
                          title="حذف من القائمة"
                        >
                          <Trash2 className="w-5 h-5" />
                        </button>
                      </div>
                    </td>
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

      <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title="إضافة للقائمة البيضاء">
        <form onSubmit={handleAdd} className="space-y-4 mt-2">
          <div>
            <label className="block text-xs font-bold text-slate-400 mb-1.5 uppercase tracking-wider font-mono text-left">النطاق (Domain)</label>
            <input 
              type="text"
              required
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="google.com"
              dir="ltr"
              className="w-full bg-dark-950 border border-dark-800 text-slate-200 rounded-lg px-4 py-2.5 focus:outline-none focus:border-green-500 placeholder-slate-600 text-left font-mono transition-colors"
            />
          </div>
          <div className="p-4 bg-green-500/5 border border-green-500/10 rounded-xl text-xs leading-relaxed text-green-400/80">
            <div className="flex items-center gap-2 font-bold mb-1 text-green-400">
              <ShieldCheck className="w-4 h-4" /> تنبيه أمني
            </div>
            النطاقات المضافة يدوياً يتم اعتبارها موثوقة دائماً وتتجاوز جميع اختبارات التهديدات العميقة لتسريع أداء النظام.
          </div>
          <div className="pt-2">
            <button
              type="submit"
              disabled={addMutation.isPending}
              className="w-full flex items-center justify-center gap-2 bg-green-600 hover:bg-green-700 text-white font-bold py-3 rounded-lg transition-all active:scale-95 disabled:opacity-70 shadow-lg shadow-green-500/20"
            >
              {addMutation.isPending ? <Loader2 className="w-5 h-5 animate-spin" /> : <><Plus className="w-4 h-4" /> إضافة للقائمة</>}
            </button>
          </div>
        </form>
      </Modal>

      <ConfirmDialog
        isOpen={confirmDelete.isOpen}
        onClose={() => setConfirmDelete({ ...confirmDelete, isOpen: false })}
        onConfirm={() => confirmDelete.id && deleteMutation.mutate(confirmDelete.id)}
        isLoading={deleteMutation.isPending}
        title="حذف من القائمة البيضاء"
        message={`هل أنت متأكد من حذف النطاق الموثوق "${confirmDelete.domain}"؟ سيتعين على النظام إعادة فحص هذا النطاق بشكل كامل في المرات القادمة.`}
        confirmText="نعم، حذف"
        isDestructive={true}
      />
    </motion.div>
  );
}
