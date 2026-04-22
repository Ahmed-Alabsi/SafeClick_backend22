import Modal from './Modal';
import { AlertTriangle, Loader2 } from 'lucide-react';

interface ConfirmDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  title: string;
  message: string;
  confirmText?: string;
  cancelText?: string;
  isDestructive?: boolean;
  isLoading?: boolean;
}

export default function ConfirmDialog({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmText = 'تأكيد',
  cancelText = 'إلغاء',
  isDestructive = true,
  isLoading = false,
}: ConfirmDialogProps) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title={title}>
      <div className="flex flex-col gap-6">
        <div className="flex items-start gap-4 text-slate-300">
          <div className={`p-3 rounded-full flex-shrink-0 ${isDestructive ? 'bg-red-500/10 text-red-500' : 'bg-primary-500/10 text-primary-500'}`}>
            <AlertTriangle className="w-6 h-6" />
          </div>
          <p className="text-sm leading-relaxed mt-1">{message}</p>
        </div>

        <div className="flex gap-3 mt-2">
          <button
            onClick={onConfirm}
            disabled={isLoading}
            className={`flex-1 px-4 py-2 rounded-lg font-bold transition-all flex items-center justify-center gap-2 ${
              isDestructive 
                ? 'bg-red-500 hover:bg-red-600 text-white disabled:bg-red-500/50' 
                : 'bg-primary-500 hover:bg-primary-600 text-white disabled:bg-primary-500/50'
            }`}
          >
            {isLoading && <Loader2 className="w-4 h-4 animate-spin" />}
            {confirmText}
          </button>
          <button
            onClick={onClose}
            disabled={isLoading}
            className="flex-1 px-4 py-2 rounded-lg font-bold bg-dark-800 text-slate-300 hover:bg-dark-700 transition-colors disabled:opacity-50"
          >
            {cancelText}
          </button>
        </div>
      </div>
    </Modal>
  );
}
