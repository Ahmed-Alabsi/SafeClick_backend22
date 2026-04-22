import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, Lock, User, ArrowLeft } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import toast from 'react-hot-toast';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const res = await api.post('/auth/login/', { email, password });
      
      if (res.data?.tokens) {
        localStorage.setItem('access_token', res.data.tokens.access);
        localStorage.setItem('refresh_token', res.data.tokens.refresh);
        
        // Verify admin privileges
        try {
          await api.get('/admin/me/');
          toast.success('\u062a\u0645 \u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644 \u0628\u0646\u062c\u0627\u062d');
          navigate('/');
        } catch (adminErr) {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          toast.error('\u0644\u064a\u0633 \u0644\u062f\u064a\u0643 \u0635\u0644\u0627\u062d\u064a\u0629 \u0627\u0644\u0645\u0634\u0631\u0641 \u0644\u0644\u062f\u062e\u0648\u0644 \u0647\u0646\u0627');
        }
      } else {
        throw new Error('Invalid response');
      }
    } catch (err: any) {
      let errorMessage = '\u0628\u064a\u0627\u0646\u0627\u062a \u0627\u0644\u062f\u062e\u0648\u0644 \u063a\u064a\u0631 \u0635\u062d\u064a\u062d\u0629';
      if (err.response?.data?.message) {
        const msgs = err.response.data.message;
        if (msgs.non_field_errors) errorMessage = msgs.non_field_errors[0];
        else if (msgs.email) errorMessage = msgs.email[0];
        else if (msgs.password) errorMessage = msgs.password[0];
        else if (typeof msgs === 'string') errorMessage = msgs;
      }
      toast.error(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-dark-950 flex items-center justify-center relative overflow-hidden font-sans" dir="rtl">
      {/* Animated Background Gradients */}
      <div className="absolute top-[-10%] right-[-5%] w-[500px] h-[500px] bg-primary-600/20 blur-[120px] rounded-full pointer-events-none" />
      <div className="absolute bottom-[-10%] left-[-5%] w-[600px] h-[600px] bg-red-600/10 blur-[150px] rounded-full pointer-events-none" />
      
      <motion.div 
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: "easeOut" }}
        className="w-full max-w-md relative z-10"
      >
        <div className="glass-card p-10">
          <div className="flex flex-col items-center mb-8">
            <motion.div 
              initial={{ scale: 0.5, rotate: -20 }}
              animate={{ scale: 1, rotate: 0 }}
              transition={{ delay: 0.2, type: "spring", stiffness: 200 }}
              className="bg-primary-500/10 p-4 rounded-2xl mb-4 border border-primary-500/20 shadow-[0_0_30px_rgba(59,130,246,0.3)]"
            >
              <Shield className="w-12 h-12 text-primary-500" />
            </motion.div>
            <h1 className="text-3xl font-bold text-white tracking-wider">SafeClick</h1>
            <p className="text-slate-400 mt-2 text-sm text-center">{'\u0628\u0648\u0627\u0628\u0629 \u0627\u0644\u0625\u062f\u0627\u0631\u0629 \u0627\u0644\u0645\u0631\u0643\u0632\u064a\u0629 (Central Admin Portal)'}</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-6">
            <div className="space-y-4">
              <div className="relative">
                <div className="absolute inset-y-0 right-0 pr-4 flex items-center pointer-events-none">
                  <User className="h-5 w-5 text-slate-500" />
                </div>
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-dark-900 border border-dark-800 text-slate-200 rounded-xl pr-12 pl-4 py-3 focus:outline-none focus:ring-2 focus:ring-primary-500/50 focus:border-primary-500 transition-all placeholder-slate-500"
                  placeholder={'\u0627\u0644\u0628\u0631\u064a\u062f \u0627\u0644\u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a'}
                  dir="ltr"
                />
              </div>

              <div className="relative">
                <div className="absolute inset-y-0 right-0 pr-4 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-slate-500" />
                </div>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-dark-900 border border-dark-800 text-slate-200 rounded-xl pr-12 pl-4 py-3 focus:outline-none focus:ring-2 focus:ring-primary-500/50 focus:border-primary-500 transition-all placeholder-slate-500"
                  placeholder={'\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631'}
                  dir="ltr"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-primary-600 hover:bg-primary-500 text-white rounded-xl py-3 px-4 font-bold transition-all shadow-[0_0_20px_rgba(37,99,235,0.4)] hover:shadow-[0_0_30px_rgba(59,130,246,0.6)] flex items-center justify-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed"
            >
              {loading ? (
                <div className="w-6 h-6 border-2 border-white border-t-transparent rounded-full animate-spin" />
              ) : (
                <>
                  {'\u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644'}
                  <ArrowLeft className="w-5 h-5" />
                </>
              )}
            </button>
          </form>

          <div className="mt-8 text-center border-t border-dark-800 pt-6">
            <p className="text-slate-500 text-xs">
              {'\u0647\u0630\u0627 \u0627\u0644\u0646\u0638\u0627\u0645 \u0645\u062e\u0635\u0635 \u0641\u0642\u0637 \u0644\u0645\u062f\u0631\u0627\u0621 \u0627\u0644\u0623\u0645\u0646 \u0627\u0644\u0633\u064a\u0628\u0631\u0627\u0646\u064a \u0641\u064a SafeClick. \u0627\u0644\u062f\u062e\u0648\u0644 \u063a\u064a\u0631 \u0627\u0644\u0645\u0635\u0631\u062d \u0628\u0647 \u064a\u062a\u0645 \u062a\u0633\u062c\u064a\u0644\u0647 \u0642\u0627\u0646\u0648\u0646\u064a\u0627\u064b.'}
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
