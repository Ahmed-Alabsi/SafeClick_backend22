import { useState } from 'react';
import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom';
import { Shield, LayoutDashboard, Globe, Ban, CheckCircle, LogOut, Users, Database, Menu, X, Bell, Search, Settings } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import api from '../services/api';
import { motion, AnimatePresence } from 'framer-motion';

export default function Layout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  // Fetch real admin data
  const { data: adminData } = useQuery({
    queryKey: ['adminMe'],
    queryFn: async () => {
      const { data } = await api.get('/admin/me/');
      return data;
    },
    staleTime: 10 * 60 * 1000,
  });

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    navigate('/login');
  };

  const navItems = [
    { name: 'الرئيسية', path: '/', icon: LayoutDashboard },
    { name: 'المستخدمين', path: '/users', icon: Users },
    { name: 'الفحوصات', path: '/scans', icon: Shield },
    { name: 'الدومينات', path: '/domains', icon: Globe },
    { name: 'القائمة السوداء', path: '/blacklist', icon: Ban },
    { name: 'القائمة البيضاء', path: '/whitelist', icon: CheckCircle },
    { name: 'سجلات النظام', path: '/logs', icon: Database },
  ];

  const adminName = adminData?.name || 'مدير النظام';
  const adminEmail = adminData?.email || '';
  const adminInitials = adminName.slice(0, 2).toUpperCase();

  return (
    <div className="min-h-screen flex bg-[#020617] text-slate-200 font-sans selection:bg-primary-500/30" dir="rtl">
      {/* Mobile Overlay */}
      <AnimatePresence>
        {sidebarOpen && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/80 backdrop-blur-md z-40 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <aside className={`
        fixed lg:static inset-y-0 right-0 z-50 w-72 glass border-l border-white/5 flex flex-col
        transform transition-all duration-500 cubic-bezier(0.4, 0, 0.2, 1)
        ${sidebarOpen ? 'translate-x-0' : 'translate-x-full lg:translate-x-0'}
      `}>
        <div className="p-8 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative group">
              <div className="absolute -inset-1 bg-gradient-to-r from-primary-600 to-primary-400 rounded-xl blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
              <div className="relative bg-dark-900 p-2.5 rounded-xl border border-white/10">
                <Shield className="w-6 h-6 text-primary-500" />
              </div>
            </div>
            <h1 className="text-2xl font-black text-white tracking-tighter">SafeClick</h1>
          </div>
          <button 
            onClick={() => setSidebarOpen(false)} 
            className="lg:hidden p-2 text-slate-500 hover:text-white transition-colors bg-white/5 rounded-lg"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="flex-1 px-4 py-4 space-y-1.5 overflow-y-auto">
          <div className="px-4 mb-4">
            <span className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">القائمة الرئيسية</span>
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = location.pathname === item.path;
            return (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => setSidebarOpen(false)}
                className={`flex items-center gap-4 px-4 py-3.5 rounded-xl transition-all duration-300 relative group ${
                  isActive 
                    ? 'text-primary-400 bg-primary-500/5' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-white/5'
                }`}
              >
                {isActive && (
                  <motion.div 
                    layoutId="activeNav"
                    className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 bg-primary-500 rounded-r-full shadow-[0_0_15px_rgba(59,130,246,0.5)]"
                  />
                )}
                <Icon className={`w-5 h-5 transition-transform group-hover:scale-110 ${isActive ? 'text-primary-500' : ''}`} />
                <span className="font-bold text-sm tracking-tight">{item.name}</span>
              </Link>
            );
          })}
        </nav>

        <div className="p-6 space-y-4 border-t border-white/5">
          <button 
            onClick={handleLogout}
            className="flex items-center gap-4 px-4 py-3.5 w-full rounded-xl text-slate-500 hover:bg-red-500/10 hover:text-red-500 transition-all duration-300 group"
          >
            <LogOut className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
            <span className="font-bold text-sm">تسجيل الخروج</span>
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col h-screen overflow-hidden">
        {/* Topbar */}
        <header className="h-20 lg:h-24 bg-[#020617]/50 backdrop-blur-xl border-b border-white/5 flex items-center justify-between px-6 lg:px-10 z-30">
          <div className="flex items-center gap-6">
            <button 
              onClick={() => setSidebarOpen(true)} 
              className="lg:hidden p-3 text-slate-400 hover:text-white hover:bg-white/5 rounded-xl transition-all"
            >
              <Menu className="w-6 h-6" />
            </button>
            <div className="flex flex-col">
              <h2 className="text-xl lg:text-2xl font-black text-white tracking-tight">
                {navItems.find((n) => n.path === location.pathname)?.name || 'لوحة التحكم'}
              </h2>
              <div className="flex items-center gap-2 mt-1">
                <div className="w-1.5 h-1.5 rounded-full bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]"></div>
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">النظام يعمل بكفاءة</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4 lg:gap-8">
            {/* Action Icons */}
            <div className="hidden md:flex items-center gap-2 bg-white/5 p-1.5 rounded-2xl border border-white/5">
               <button className="p-2.5 text-slate-400 hover:text-white hover:bg-white/10 rounded-xl transition-all"><Search className="w-5 h-5" /></button>
               <button className="p-2.5 text-slate-400 hover:text-white hover:bg-white/10 rounded-xl transition-all relative">
                 <Bell className="w-5 h-5" />
                 <span className="absolute top-2.5 right-2.5 w-2 h-2 bg-primary-500 rounded-full border-2 border-[#020617]"></span>
               </button>
               <button className="p-2.5 text-slate-400 hover:text-white hover:bg-white/10 rounded-xl transition-all"><Settings className="w-5 h-5" /></button>
            </div>

            {/* Profile */}
            <div className="flex items-center gap-4 bg-white/5 p-1.5 pr-4 rounded-2xl border border-white/5 hover:bg-white/10 transition-all cursor-pointer group">
              <div className="flex flex-col text-left">
                <span className="text-sm font-black text-white group-hover:text-primary-400 transition-colors">{adminName}</span>
                <span className="text-[10px] font-bold text-slate-500" dir="ltr">{adminEmail}</span>
              </div>
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-primary-700 flex items-center justify-center text-white font-black text-sm shadow-lg shadow-primary-500/20 group-hover:scale-105 transition-transform">
                {adminInitials}
              </div>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <div className="flex-1 overflow-y-auto p-6 lg:p-10 relative custom-scrollbar">
          {/* Ambient Background Glows */}
          <div className="absolute top-[-10%] right-[-5%] w-[600px] h-[600px] bg-primary-600/10 blur-[150px] rounded-full pointer-events-none" />
          <div className="absolute bottom-[-5%] left-[-10%] w-[500px] h-[500px] bg-indigo-600/10 blur-[130px] rounded-full pointer-events-none" />
          
          <div className="relative z-10 max-w-7xl mx-auto">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
}
