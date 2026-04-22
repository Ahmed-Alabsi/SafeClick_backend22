import { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Ban, Plus, Trash2, ShieldAlert, ChevronRight, ChevronLeft, Loader2, Globe, Link as LinkIcon, Wifi } from 'lucide-react';
import { useQueryClient, useMutation } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { useDataList } from '../hooks/useData';
import { useDebounce } from '../hooks/useDebounce';
import api from '../services/api';
import Modal from '../components/Modal';
import EmptyState from '../components/EmptyState';
import ConfirmDialog from '../components/ConfirmDialog';

// Map severity integer from backend to display label
const SEVERITY_MAP: Record<number, { label: string; style: string }> = {
  1: { label: 'منخفض', style: 'bg-slate-500/20 text-slate-400 border-slate-500/30' },
  2: { label: 'متوسط', style: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  3: { label: 'عالي', style: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  4: { label: 'خطير', style: 'bg-red-500/20 text-red-400 border-red-500/30' },
  5: { label: 'حرج', style: 'bg-red-600/20 text-red-300 border-red-600/30' },
};

// Map threat_type to display icon
const TYPE_ICON: Record<string, React.ElementType> = {
  blocked_domain: Globe,
  blocked_url: LinkIcon,
  blocked_ip: Wifi,
};

export default function Blacklist() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<{ isOpen: boolean; id: string | null; name: string }>({
    isOpen: false,
    id: null,
    name: '',
  });
  const [newItem, setNewItem] = useState({ type: 'domain', value: '', severity: 'high', reason: '' });
  
  const debouncedSearch = useDebounce(search, 500);
  const queryClient = useQueryClient();

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value);
    setPage(1);
  };

  const { data, isLoading, isFetching } = useDataList('/admin/blacklist/', { 
    page, 
    search: debouncedSearch 
  });

  const items = data?.results || [];
  const totalPages = data?.count ? Math.ceil(data.count / 20) : 1;

  // Add Item Mutation
  const addMutation = useMutation({
    mutationFn: async (newItemData: any) => {
      const res = await api.post('/admin/blacklist/', newItemData);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/admin/blacklist/'] });
      toast.success('تم الإضافة للقائمة السوداء بنجاح');
      setIsModalOpen(false);
      setNewItem({ type: 'domain', value: '', severity: 'high', reason: '' });
    },
    onError: (error: any) => {
      const detail = error.response?.data;
      let msg = 'حدث خطأ أثناء الإضافة';
      if (detail) {
        if (typeof detail === 'string') msg = detail;
        else if (detail.detail) msg = detail.detail;
        else if (detail.value) msg = detail.value[0];
        else if (detail.non_field_errors) msg = detail.non_field_errors[0];
      }
      toast.error(msg);
    }
  });

  // Delete Item Mutation
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/admin/blacklist/${id}/`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/admin/blacklist/'] });
      toast.success('تم الحذف بنجاح');
      setConfirmDelete({ isOpen: false, id: null, name: '' });
    },
    onError: () => {
      toast.error('حدث خطأ أثناء الحذف');
    }
  });

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newItem.value.trim()) return toast.error('الرجاء إدخال القيمة');
    addMutation.mutate(newItem);
  };

  const SkeletonRow = () => (
    <tr className="animate-pulse border-b border-dark-800">
      <td className="p-4"><div className="h-6 bg-dark-800 rounded w-20"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-48"></div></td>
      <td className="p-4"><div className="h-6 bg-dark-800 rounded-full w-20"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-24"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-32"></div></td>
      <td className="p-4 text-center"><div className="h-8 bg-dark-800 rounded w-8 inline-block"></div></td>
    </tr>
  );

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6 relative text-right" dir="rtl">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <Ban className="w-6 h-6 text-red-500" /> القائمة السوداء
            {isFetching && <Loader2 className="w-5 h-5 text-red-500 animate-spin" />}
          </h2>
          <p className="text-slate-400 text-sm mt-1">إدارة النطاقات والروابط المحظورة بشكل قاطع في النظام</p>
        </div>
        
        <div className="flex flex-col sm:flex-row gap-4 w-full md:w-auto">
          <div className="relative w-full sm:w-64">
            <Search className="w-5 h-5 absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
            <input 
              type="text" 
              value={search}
              onChange={handleSearchChange}
              placeholder="ابحث في القائمة..." 
              className="w-full bg-dark-900 border border-dark-800 rounded-lg pr-10 pl-4 py-2 text-slate-200 focus:outline-none focus:border-red-500 transition-colors"
            />
          </div>
          <button 
            onClick={() => setIsModalOpen(true)}
            className="flex items-center justify-center gap-2 bg-red-600 hover:bg-red-700 text-white rounded-lg px-4 py-2 transition-all font-bold shadow-lg shadow-red-500/20 whitespace-nowrap active:scale-95"
          >
            <Plus className="w-5 h-5" />
            إضافة للحظر
          </button>
        </div>
      </div>

      <div className="glass-card overflow-hidden border-t-4 border-t-red-500 shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-right min-w-[800px]">
            <thead className="bg-dark-900/50 border-b border-dark-800 text-slate-400 text-sm">
              <tr>
                <th className="p-4 font-medium">النوع</th>
                <th className="p-4 font-medium">النطاق / الرابط / IP</th>
                <th className="p-4 font-medium">الخطورة</th>
                <th className="p-4 font-medium">المصدر</th>
                <th className="p-4 font-medium">تاريخ الإضافة</th>
                <th className="p-4 font-medium text-center">إجراءات</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} />)
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-0">
                    <EmptyState 
                      icon={Ban}
                      title="القائمة السوداء فارغة"
                      description="لم يتم العثور على أي نطاقات أو روابط محظورة تطابق بحثك الحالي."
                    />
                  </td>
                </tr>
              ) : (
                items.map((item: any, i: number) => {
                  const sev = SEVERITY_MAP[item.severity] || SEVERITY_MAP[3];
                  const TypeIcon = TYPE_ICON[item.threat_type] || Globe;
                  const itemValue = item.domain || item.link || item.ip || '';

                  return (
                    <motion.tr 
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: i * 0.03 }}
                      key={item.id} 
                      className="hover:bg-dark-800/30 transition-colors group"
                    >
                      <td className="p-4">
                        <span className="inline-flex items-center gap-1.5 bg-dark-900 border border-dark-800 text-slate-300 px-3 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider">
                          <TypeIcon className="w-3 h-3 text-red-500" />
                          {item.threat_type?.replace('blocked_', '') || 'domain'}
                        </span>
                      </td>
                      <td className="p-4">
                        <div className="text-slate-200 font-mono text-sm max-w-[250px] truncate" dir="ltr" title={itemValue}>
                          {itemValue}
                        </div>
                        {item.reason && <div className="text-slate-500 text-[10px] mt-1 max-w-[200px] truncate">{item.reason}</div>}
                      </td>
                      <td className="p-4">
                        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold border ${sev.style}`}>
                          <ShieldAlert className="w-3 h-3" /> {sev.label}
                        </span>
                      </td>
                      <td className="p-4 text-slate-400 text-sm">{item.source || 'نظام'}</td>
                      <td className="p-4 text-slate-400 text-xs font-mono" dir="ltr">{item.added_at?.replace('T', ' ').split('.')[0]}</td>
                      <td className="p-4">
                        <div className="flex justify-center">
                          <button 
                            onClick={() => setConfirmDelete({ isOpen: true, id: item.id, name: itemValue })}
                            className="p-2 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-all active:scale-90"
                            title="حذف من القائمة"
                          >
                            <Trash2 className="w-5 h-5" />
                          </button>
                        </div>
                      </td>
                    </motion.tr>
                  );
                })
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

      <Modal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} title="إضافة للقائمة السوداء">
        <form onSubmit={handleAdd} className="space-y-4 mt-2">
          <div>
            <label className="block text-xs font-bold text-slate-400 mb-1.5 uppercase tracking-wider">نوع الحظر</label>
            <select 
              value={newItem.type}
              onChange={(e) => setNewItem({ ...newItem, type: e.target.value })}
              className="w-full bg-dark-950 border border-dark-800 text-slate-200 rounded-lg px-4 py-2.5 focus:outline-none focus:border-red-500 transition-colors"
            >
              <option value="domain">دومين (Domain)</option>
              <option value="url">رابط كامل (URL)</option>
              <option value="ip">عنوان IP</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-bold text-slate-400 mb-1.5 uppercase tracking-wider">القيمة</label>
            <input 
              type="text"
              required
              value={newItem.value}
              onChange={(e) => setNewItem({ ...newItem, value: e.target.value })}
              placeholder={newItem.type === 'domain' ? 'malicious-site.com' : newItem.type === 'url' ? 'https://site.com/phish' : '1.2.3.4'}
              dir="ltr"
              className="w-full bg-dark-950 border border-dark-800 text-slate-200 rounded-lg px-4 py-2.5 focus:outline-none focus:border-red-500 placeholder-slate-600 text-left font-mono"
            />
          </div>
          <div>
            <label className="block text-xs font-bold text-slate-400 mb-1.5 uppercase tracking-wider">مستوى الخطورة</label>
            <select 
              value={newItem.severity}
              onChange={(e) => setNewItem({ ...newItem, severity: e.target.value })}
              className="w-full bg-dark-950 border border-dark-800 text-slate-200 rounded-lg px-4 py-2.5 focus:outline-none focus:border-red-500 transition-colors"
            >
              <option value="3">عالي (High)</option>
              <option value="4">خطير (Critical)</option>
              <option value="5">حرج (Emergency)</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-bold text-slate-400 mb-1.5 uppercase tracking-wider">سبب الحظر (اختياري)</label>
            <textarea 
              value={newItem.reason}
              onChange={(e) => setNewItem({ ...newItem, reason: e.target.value })}
              placeholder="اكتب سبب حظر هذا العنصر..."
              className="w-full bg-dark-950 border border-dark-800 text-slate-200 rounded-lg px-4 py-2.5 focus:outline-none focus:border-red-500 placeholder-slate-600 resize-none h-20 text-sm"
            />
          </div>
          <div className="pt-2">
            <button
              type="submit"
              disabled={addMutation.isPending}
              className="w-full flex items-center justify-center gap-2 bg-red-600 hover:bg-red-700 text-white font-bold py-3 rounded-lg transition-all active:scale-95 disabled:opacity-70 shadow-lg shadow-red-500/20"
            >
              {addMutation.isPending ? <Loader2 className="w-5 h-5 animate-spin" /> : <><Ban className="w-4 h-4" /> تأكيد الحظر</>}
            </button>
          </div>
        </form>
      </Modal>

      <ConfirmDialog
        isOpen={confirmDelete.isOpen}
        onClose={() => setConfirmDelete({ ...confirmDelete, isOpen: false })}
        onConfirm={() => confirmDelete.id && deleteMutation.mutate(confirmDelete.id)}
        isLoading={deleteMutation.isPending}
        title="حذف من القائمة السوداء"
        message={`هل أنت متأكد من أنك تريد حذف "${confirmDelete.name}" من القائمة السوداء؟ سيتم التوقف عن حظر هذا العنصر فوراً.`}
        confirmText="نعم، حذف"
        isDestructive={true}
      />
    </motion.div>
  );
}
