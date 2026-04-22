import { useState } from 'react';
import { motion } from 'framer-motion';
import { Search, Users as UsersIcon, Shield, ShieldOff, Activity, ChevronRight, ChevronLeft, Loader2, UserCheck, UserX } from 'lucide-react';
import { useDataList } from '../hooks/useData';
import { useDebounce } from '../hooks/useDebounce';
import EmptyState from '../components/EmptyState';
import ConfirmDialog from '../components/ConfirmDialog';
import api from '../services/api';
import toast from 'react-hot-toast';
import { useQueryClient } from '@tanstack/react-query';

export default function Users() {
  const queryClient = useQueryClient();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [role, setRole] = useState('');
  const [status, setStatus] = useState('');
  const [confirmModal, setConfirmModal] = useState<{ isOpen: boolean; userId: string | null; userName: string; currentStatus: boolean }>({
    isOpen: false,
    userId: null,
    userName: '',
    currentStatus: true,
  });
  const [isToggling, setIsToggling] = useState(false);

  const debouncedSearch = useDebounce(search, 500);

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearch(e.target.value);
    setPage(1);
  };

  const handleRoleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setRole(e.target.value);
    setPage(1);
  };

  const handleStatusChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setStatus(e.target.value);
    setPage(1);
  };

  const { data, isLoading, isFetching } = useDataList('/admin/users/', { 
    page, 
    search: debouncedSearch,
    role: role || undefined,
    status: status || undefined
  });

  const users = data?.results || [];
  const totalPages = data?.count ? Math.ceil(data.count / 20) : 1;

  const handleToggleStatus = async () => {
    if (!confirmModal.userId) return;
    setIsToggling(true);
    try {
      await api.post(`/admin/users/${confirmModal.userId}/toggle_status/`);
      toast.success(`تم ${confirmModal.currentStatus ? 'إيقاف' : 'تفعيل'} حساب ${confirmModal.userName} بنجاح`);
      queryClient.invalidateQueries({ queryKey: ['/admin/users/'] });
    } catch (err: any) {
      toast.error(err.response?.data?.error || 'فشل تغيير حالة الحساب');
    } finally {
      setIsToggling(false);
      setConfirmModal({ ...confirmModal, isOpen: false });
    }
  };

  const SkeletonRow = () => (
    <tr className="animate-pulse border-b border-dark-800">
      <td className="p-4"><div className="flex flex-col gap-2"><div className="h-4 bg-dark-800 rounded w-32"></div><div className="h-3 bg-dark-800 rounded w-48"></div></div></td>
      <td className="p-4"><div className="flex flex-col gap-2"><div className="h-3 bg-dark-800 rounded w-20"></div><div className="h-3 bg-dark-800 rounded w-20"></div></div></td>
      <td className="p-4"><div className="h-6 bg-dark-800 rounded-full w-24"></div></td>
      <td className="p-4"><div className="h-4 bg-dark-800 rounded w-16"></div></td>
      <td className="p-4 text-center"><div className="h-8 bg-dark-800 rounded w-24 mx-auto"></div></td>
    </tr>
  );

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6 relative">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-2xl font-bold text-slate-100 flex items-center gap-3">
            <UsersIcon className="w-6 h-6 text-primary-500" /> إدارة المستخدمين
            {isFetching && <Loader2 className="w-5 h-5 text-primary-500 animate-spin" />}
          </h2>
          <p className="text-slate-400 text-sm mt-1">عرض وتحليل نشاط مستخدمي المنصة وإدارة صلاحياتهم</p>
        </div>
      </div>

      {/* Advanced Filters Bar */}
      <div className="glass-card p-4 flex flex-col lg:flex-row items-center gap-4">
        <div className="relative w-full lg:w-80">
          <Search className="w-5 h-5 absolute right-3 top-1/2 transform -translate-y-1/2 text-slate-400" />
          <input 
            type="text" 
            value={search}
            onChange={handleSearchChange}
            placeholder="ابحث بالاسم أو البريد..." 
            className="w-full bg-dark-900 border border-dark-800 rounded-lg pr-10 pl-4 py-2 text-slate-200 focus:outline-none focus:border-primary-500 transition-colors"
          />
        </div>

        <div className="flex w-full lg:w-auto items-center gap-4 flex-1 lg:justify-end flex-wrap">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-slate-400" />
            <select 
              value={role}
              onChange={handleRoleChange}
              className="bg-dark-900 border border-dark-800 text-slate-200 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 block p-2 min-w-[120px]"
            >
              <option value="">كل الرتب</option>
              <option value="admin">المشرفين</option>
              <option value="user">المستخدمين</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-slate-400" />
            <select 
              value={status}
              onChange={handleStatusChange}
              className="bg-dark-900 border border-dark-800 text-slate-200 text-sm rounded-lg focus:ring-primary-500 focus:border-primary-500 block p-2 min-w-[120px]"
            >
              <option value="">كل الحالات</option>
              <option value="active">نشط</option>
              <option value="inactive">موقوف</option>
            </select>
          </div>
        </div>
      </div>

      <div className="glass-card overflow-hidden border-t-4 border-t-primary-500">
        <div className="overflow-x-auto">
          <table className="w-full text-right min-w-[800px]">
            <thead className="bg-dark-900/50 border-b border-dark-800 text-slate-400 text-sm">
              <tr>
                <th className="p-4 font-medium">المستخدم</th>
                <th className="p-4 font-medium">النشاط (فحوصات / تهديدات)</th>
                <th className="p-4 font-medium">الصلاحية</th>
                <th className="p-4 font-medium">الحالة</th>
                <th className="p-4 font-medium text-center">الإجراءات</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-800">
              {isLoading ? (
                Array.from({ length: 10 }).map((_, i) => <SkeletonRow key={i} />)
              ) : users.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-0">
                    <EmptyState 
                      icon={UsersIcon}
                      title="لا يوجد مستخدمين"
                      description="لم يتم العثور على أي مستخدمين يتطابقون مع معايير البحث والفلترة."
                    />
                  </td>
                </tr>
              ) : (
                users.map((user: any, i: number) => (
                  <motion.tr 
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.03 }}
                    key={user.id} 
                    className="hover:bg-dark-800/30 transition-colors group"
                  >
                    <td className="p-4">
                      <div className="flex flex-col">
                        <span className="font-bold text-slate-200">{user.name}</span>
                        <span className="text-slate-400 text-xs mt-1 font-mono" dir="ltr">{user.email}</span>
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex flex-col gap-1">
                        <span className="text-sm text-slate-300 flex items-center gap-1.5">
                          <Activity className="w-3.5 h-3.5 text-primary-400" />
                          <span className="font-bold text-primary-400">{user.scanned_links}</span> فحص
                        </span>
                        <span className="text-xs text-red-400 flex items-center gap-1.5">
                          <ShieldOff className="w-3.5 h-3.5 text-red-500" />
                          <span className="font-bold text-red-500">{user.detected_threats}</span> تهديد
                        </span>
                      </div>
                    </td>
                    <td className="p-4">
                      {user.is_staff ? (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-primary-500/20 text-primary-400 text-xs font-bold border border-primary-500/30">
                          <Shield className="w-3 h-3" /> مشرف
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-dark-800 text-slate-400 text-xs font-bold border border-dark-700">
                          مستخدم عادي
                        </span>
                      )}
                    </td>
                    <td className="p-4">
                      {user.is_active ? (
                        <span className="flex items-center gap-1.5 text-green-500 font-bold text-sm">
                          <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse"></div>
                          نشط
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 text-red-500 font-bold text-sm">
                          <div className="w-1.5 h-1.5 rounded-full bg-red-500"></div>
                          موقوف
                        </span>
                      )}
                    </td>
                    <td className="p-4">
                      <div className="flex justify-center">
                        <button
                          onClick={() => setConfirmModal({
                            isOpen: true,
                            userId: user.id,
                            userName: user.name,
                            currentStatus: user.is_active
                          })}
                          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-bold transition-all ${
                            user.is_active 
                            ? 'bg-red-500/10 text-red-500 hover:bg-red-500/20' 
                            : 'bg-green-500/10 text-green-500 hover:bg-green-500/20'
                          }`}
                        >
                          {user.is_active ? (
                            <><UserX className="w-3.5 h-3.5" /> إيقاف الحساب</>
                          ) : (
                            <><UserCheck className="w-3.5 h-3.5" /> تفعيل الحساب</>
                          )}
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

      <ConfirmDialog
        isOpen={confirmModal.isOpen}
        onClose={() => setConfirmModal({ ...confirmModal, isOpen: false })}
        onConfirm={handleToggleStatus}
        isLoading={isToggling}
        title={confirmModal.currentStatus ? 'إيقاف حساب' : 'تفعيل حساب'}
        message={`هل أنت متأكد من أنك تريد ${confirmModal.currentStatus ? 'إيقاف' : 'تفعيل'} حساب المستخدم ${confirmModal.userName}؟`}
        confirmText={confirmModal.currentStatus ? 'نعم، إيقاف' : 'نعم، تفعيل'}
        isDestructive={confirmModal.currentStatus}
      />
    </motion.div>
  );
}
