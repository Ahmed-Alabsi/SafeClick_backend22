import { motion } from 'framer-motion';
import { ShieldAlert, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="min-h-[80vh] flex items-center justify-center">
      <motion.div 
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        className="glass-card p-12 text-center max-w-lg"
      >
        <div className="inline-flex items-center justify-center w-24 h-24 bg-red-500/10 text-red-500 rounded-full mb-6">
          <ShieldAlert className="w-12 h-12" />
        </div>
        <h1 className="text-6xl font-bold text-slate-100 mb-4">404</h1>
        <h2 className="text-2xl font-bold text-slate-200 mb-4">الصفحة غير موجودة</h2>
        <p className="text-slate-400 mb-8 leading-relaxed">
          عذراً، المسار الذي تحاول الوصول إليه غير موجود أو تم حظره بواسطة بروتوكولات الأمان.
        </p>
        <Link 
          to="/"
          className="inline-flex items-center gap-2 px-6 py-3 bg-primary-600 hover:bg-primary-500 text-white rounded-xl transition-all shadow-lg shadow-primary-500/20 font-bold"
        >
          العودة للوحة التحكم
          <ArrowRight className="w-5 h-5 rotate-180" />
        </Link>
      </motion.div>
    </div>
  );
}
