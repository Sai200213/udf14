import React, { useState, useEffect, useMemo } from 'react';
import { 
  RecycleBinItem, 
  RecycleBinItemType, 
  subscribeToRecycleBin, 
  restoreFromRecycleBin, 
  permanentDeleteFromRecycleBin, 
  emptyRecycleBin 
} from '../src/services/recycleBinService';
import { 
  Trash2, RotateCcw, Search, Filter, ShieldAlert, CheckCircle, 
  Building, User, Users, FileText, Link2, Briefcase, AlertTriangle, 
  Clock, ArrowUpDown, Loader2, Sparkles, XCircle 
} from 'lucide-react';
import Button from './common/Button';
import Modal from './common/Modal';

interface AdminRecycleBinPageProps {
  onNotify: (msg: string, type?: 'success' | 'error' | 'info' | 'warning') => void;
  isSuperAdmin: boolean;
  onRefreshData?: () => void;
}

const TYPE_CONFIG: Record<RecycleBinItemType, { label: string; icon: React.ReactNode; color: string; bgColor: string }> = {
  SITE: {
    label: 'Client Site',
    icon: <Building size={14} />,
    color: 'text-indigo-700',
    bgColor: 'bg-indigo-50 border-indigo-200'
  },
  STAFF: {
    label: 'Staff Account',
    icon: <User size={14} />,
    color: 'text-blue-700',
    bgColor: 'bg-blue-50 border-blue-200'
  },
  EMPLOYEE: {
    label: 'Employee',
    icon: <Users size={14} />,
    color: 'text-emerald-700',
    bgColor: 'bg-emerald-50 border-emerald-200'
  },
  SUBMISSION: {
    label: 'Submission',
    icon: <FileText size={14} />,
    color: 'text-amber-700',
    bgColor: 'bg-amber-50 border-amber-200'
  },
  INVITE: {
    label: 'Referral Invite',
    icon: <Link2 size={14} />,
    color: 'text-purple-700',
    bgColor: 'bg-purple-50 border-purple-200'
  },
  VACANCY: {
    label: 'Job Vacancy',
    icon: <Briefcase size={14} />,
    color: 'text-teal-700',
    bgColor: 'bg-teal-50 border-teal-200'
  },
  ROLE: {
    label: 'Role Definition',
    icon: <ShieldAlert size={14} />,
    color: 'text-rose-700',
    bgColor: 'bg-rose-50 border-rose-200'
  },
  DESIGNATION: {
    label: 'Designation',
    icon: <Briefcase size={14} />,
    color: 'text-violet-700',
    bgColor: 'bg-violet-50 border-violet-200'
  }
};

const AdminRecycleBinPage: React.FC<AdminRecycleBinPageProps> = ({
  onNotify,
  isSuperAdmin,
  onRefreshData
}) => {
  const [items, setItems] = useState<RecycleBinItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('ALL');

  // Modal States
  const [itemToPurge, setItemToPurge] = useState<RecycleBinItem | null>(null);
  const [isPurgeModalOpen, setIsPurgeModalOpen] = useState(false);
  const [isPurging, setIsPurging] = useState(false);

  const [isEmptyModalOpen, setIsEmptyModalOpen] = useState(false);
  const [isEmptying, setIsEmptying] = useState(false);

  const [restoringId, setRestoringId] = useState<string | null>(null);

  // Real-time subscription to recycle bin
  useEffect(() => {
    setIsLoading(true);
    const unsubscribe = subscribeToRecycleBin((fetchedItems) => {
      setItems(fetchedItems);
      setIsLoading(false);
    });
    return () => unsubscribe();
  }, []);

  // Filtered Items
  const filteredItems = useMemo(() => {
    return items.filter(item => {
      // Type Filter
      if (selectedType !== 'ALL' && item.itemType !== selectedType) {
        return false;
      }
      // Search Filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const itemName = (item.name || (item as any).title || '').toLowerCase();
        const matchesName = itemName.includes(q);
        const matchesDeleter = (item.deletedByName || (item as any).deletedByEmail || '').toLowerCase().includes(q);
        const matchesId = (item.originalId || '').toLowerCase().includes(q);
        if (!matchesName && !matchesDeleter && !matchesId) {
          return false;
        }
      }
      return true;
    });
  }, [items, selectedType, searchQuery]);

  // Statistics
  const stats = useMemo(() => {
    const total = items.length;
    const sites = items.filter(i => i.itemType === 'SITE').length;
    const staff = items.filter(i => i.itemType === 'STAFF').length;
    const employees = items.filter(i => i.itemType === 'EMPLOYEE').length;
    const others = total - (sites + staff + employees);
    return { total, sites, staff, employees, others };
  }, [items]);

  // Handle Restore
  const handleRestore = async (item: RecycleBinItem) => {
    setRestoringId(item.id);
    try {
      const res = await restoreFromRecycleBin(item.id);
      onNotify(res.message, 'success');
      if (onRefreshData) onRefreshData();
    } catch (err: any) {
      onNotify(err.message || 'Failed to restore item', 'error');
    } finally {
      setRestoringId(null);
    }
  };

  // Handle Permanent Delete
  const handleConfirmPurge = async () => {
    if (!itemToPurge) return;
    setIsPurging(true);
    try {
      await permanentDeleteFromRecycleBin(itemToPurge.id);
      onNotify(`Permanently erased "${itemToPurge.name}".`, 'info');
      setIsPurgeModalOpen(false);
      setItemToPurge(null);
    } catch (err: any) {
      onNotify(err.message || 'Failed to permanently erase item', 'error');
    } finally {
      setIsPurging(false);
    }
  };

  // Handle Empty Recycle Bin
  const handleConfirmEmpty = async () => {
    setIsEmptying(true);
    try {
      const count = await emptyRecycleBin();
      onNotify(`Permanently erased all ${count} items from the Recycle Bin.`, 'success');
      setIsEmptyModalOpen(false);
    } catch (err: any) {
      onNotify(err.message || 'Failed to empty Recycle Bin', 'error');
    } finally {
      setIsEmptying(false);
    }
  };

  // Calculate days remaining before auto-purge
  const getDaysRemaining = (expiresAtStr: string) => {
    try {
      const expires = new Date(expiresAtStr).getTime();
      const now = new Date().getTime();
      const diffDays = Math.ceil((expires - now) / (1000 * 60 * 60 * 24));
      return Math.max(0, diffDays);
    } catch {
      return 30;
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white p-5 rounded-xl border border-gray-200 shadow-xs">
        <div>
          <h2 className="text-lg font-black text-gray-900 tracking-tight flex items-center gap-2">
            <Trash2 size={22} className="text-rose-600" /> Recycle Bin & Universal Undo Vault
          </h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Recover deleted client sites, staff accounts, employees, submissions, and referral links within 30 days.
          </p>
        </div>

        {isSuperAdmin && items.length > 0 && (
          <Button
            variant="danger"
            onClick={() => setIsEmptyModalOpen(true)}
            className="text-xs font-bold flex items-center justify-center gap-1.5 py-2 px-3 whitespace-nowrap"
          >
            <Trash2 size={14} />
            Empty Recycle Bin
          </Button>
        )}
      </div>

      {/* 2. Key Metrics Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Total in Trash</p>
            <p className="text-2xl font-black text-gray-900 mt-1">{stats.total}</p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-rose-50 text-rose-600 flex items-center justify-center font-bold">
            <Trash2 size={20} />
          </div>
        </div>

        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Deleted Sites</p>
            <p className="text-2xl font-black text-indigo-900 mt-1">{stats.sites}</p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center font-bold">
            <Building size={20} />
          </div>
        </div>

        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Deleted Staff</p>
            <p className="text-2xl font-black text-blue-900 mt-1">{stats.staff}</p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center font-bold">
            <User size={20} />
          </div>
        </div>

        <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs flex items-center justify-between">
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Deleted Employees</p>
            <p className="text-2xl font-black text-emerald-900 mt-1">{stats.employees}</p>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center font-bold">
            <Users size={20} />
          </div>
        </div>
      </div>

      {/* 3. Search and Type Filter Bar */}
      <div className="bg-white p-4 rounded-xl border border-gray-200 shadow-xs flex flex-col md:flex-row gap-3 items-center justify-between">
        {/* Search */}
        <div className="relative w-full md:w-80">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search by name, ID, or deleted by..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-gray-50 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>

        {/* Type Filter Pills */}
        <div className="flex flex-wrap gap-1.5 w-full md:w-auto">
          {[
            { id: 'ALL', label: 'All Items' },
            { id: 'SITE', label: 'Sites' },
            { id: 'STAFF', label: 'Staff' },
            { id: 'EMPLOYEE', label: 'Employees' },
            { id: 'DESIGNATION', label: 'Designations' },
            { id: 'SUBMISSION', label: 'Submissions' },
            { id: 'INVITE', label: 'Invites' }
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setSelectedType(tab.id)}
              className={`px-3 py-1 text-xs font-bold rounded-lg transition-colors ${
                selectedType === tab.id
                  ? 'bg-slate-900 text-white shadow-2xs'
                  : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* 4. Recycle Bin Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-xs overflow-hidden">
        {isLoading ? (
          <div className="p-12 text-center text-gray-400 flex flex-col items-center justify-center gap-2">
            <Loader2 size={28} className="animate-spin text-blue-600" />
            <p className="text-xs font-semibold">Loading Recycle Bin items...</p>
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="p-12 text-center text-gray-400 flex flex-col items-center justify-center gap-3">
            <div className="w-12 h-12 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center">
              <Sparkles size={24} />
            </div>
            <div>
              <p className="text-sm font-bold text-gray-700">Recycle Bin is Empty</p>
              <p className="text-xs text-gray-400 mt-0.5">
                {searchQuery || selectedType !== 'ALL'
                  ? 'No deleted records matched your filter criteria.'
                  : 'No deleted items found. All portal records are currently active!'}
              </p>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-gray-50/80 border-b border-gray-200 text-[11px] font-black text-gray-500 uppercase tracking-wider">
                  <th className="py-3 px-4">Item Name / Identity</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Deleted By</th>
                  <th className="py-3 px-4">Deleted Date</th>
                  <th className="py-3 px-4">Auto-Purge In</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 text-xs">
                {filteredItems.map(item => {
                  const typeConf = TYPE_CONFIG[item.itemType] || TYPE_CONFIG.SITE;
                  const daysLeft = getDaysRemaining(item.expiresAt || (item as any).autoPurgeAt);
                  const isRestoring = restoringId === item.id;

                  return (
                    <tr key={item.id} className="hover:bg-gray-50/60 transition-colors">
                      {/* Name & ID */}
                      <td className="py-3.5 px-4">
                        <div className="font-bold text-gray-900">{item.name || (item as any).title || 'Unnamed Item'}</div>
                        <div className="text-[11px] text-gray-400 font-mono mt-0.5">
                          ID: {item.originalId}
                        </div>
                      </td>

                      {/* Type Badge */}
                      <td className="py-3.5 px-4">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold border ${typeConf.bgColor} ${typeConf.color}`}>
                          {typeConf.icon}
                          {typeConf.label}
                        </span>
                      </td>

                      {/* Deleted By */}
                      <td className="py-3.5 px-4">
                        <div className="font-medium text-gray-700">{item.deletedByName || 'Admin'}</div>
                      </td>

                      {/* Deleted Date */}
                      <td className="py-3.5 px-4 text-gray-500">
                        {item.deletedAt ? new Date(item.deletedAt).toLocaleString('en-IN', {
                          day: '2-digit',
                          month: 'short',
                          year: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        }) : 'N/A'}
                      </td>

                      {/* Days Left */}
                      <td className="py-3.5 px-4">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-bold ${
                          daysLeft <= 3 
                            ? 'bg-rose-50 text-rose-700 border border-rose-200' 
                            : 'bg-gray-100 text-gray-600'
                        }`}>
                          <Clock size={11} />
                          {daysLeft} days left
                        </span>
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleRestore(item)}
                            disabled={isRestoring}
                            className="inline-flex items-center gap-1 bg-emerald-50 hover:bg-emerald-100 text-emerald-700 font-bold px-2.5 py-1.5 rounded-lg border border-emerald-200 transition-colors text-xs"
                            title="Restore back to original state"
                          >
                            {isRestoring ? (
                              <Loader2 size={13} className="animate-spin" />
                            ) : (
                              <RotateCcw size={13} />
                            )}
                            Restore
                          </button>

                          {isSuperAdmin && (
                            <button
                              onClick={() => {
                                setItemToPurge(item);
                                setIsPurgeModalOpen(true);
                              }}
                              className="inline-flex items-center gap-1 bg-rose-50 hover:bg-rose-100 text-rose-700 font-bold px-2 py-1.5 rounded-lg border border-rose-200 transition-colors text-xs"
                              title="Permanently erase now"
                            >
                              <Trash2 size={13} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 5. Permanent Delete Single Confirmation Modal */}
      {isPurgeModalOpen && itemToPurge && (
        <Modal
          isOpen={isPurgeModalOpen}
          onClose={() => { setIsPurgeModalOpen(false); setItemToPurge(null); }}
          title="Permanently Erase Record?"
          footer={
            <div className="flex justify-end gap-2">
              <Button
                variant="secondary"
                onClick={() => { setIsPurgeModalOpen(false); setItemToPurge(null); }}
                disabled={isPurging}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={handleConfirmPurge}
                disabled={isPurging}
              >
                {isPurging ? <Loader2 size={14} className="animate-spin mr-1" /> : <Trash2 size={14} className="mr-1" />}
                Permanently Erase
              </Button>
            </div>
          }
        >
          <div className="space-y-3">
            <div className="flex items-start gap-3 p-3 bg-rose-50 border border-rose-200 rounded-xl text-rose-900">
              <AlertTriangle size={24} className="text-rose-600 shrink-0 mt-0.5" />
              <div className="text-xs">
                <p className="font-bold text-rose-950">Warning: Permanent Data Destruction</p>
                <p className="mt-1 text-rose-800">
                  Are you sure you want to permanently erase <strong>"{itemToPurge.name}"</strong>? Once erased from the Recycle Bin, this record cannot be recovered.
                </p>
              </div>
            </div>
          </div>
        </Modal>
      )}

      {/* 6. Empty Recycle Bin Modal */}
      {isEmptyModalOpen && (
        <Modal
          isOpen={isEmptyModalOpen}
          onClose={() => setIsEmptyModalOpen(false)}
          title="Empty Entire Recycle Bin?"
          footer={
            <div className="flex justify-end gap-2">
              <Button
                variant="secondary"
                onClick={() => setIsEmptyModalOpen(false)}
                disabled={isEmptying}
              >
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={handleConfirmEmpty}
                disabled={isEmptying}
              >
                {isEmptying ? <Loader2 size={14} className="animate-spin mr-1" /> : <Trash2 size={14} className="mr-1" />}
                Yes, Empty All
              </Button>
            </div>
          }
        >
          <div className="space-y-3">
            <div className="flex items-start gap-3 p-3 bg-rose-50 border border-rose-200 rounded-xl text-rose-900">
              <AlertTriangle size={24} className="text-rose-600 shrink-0 mt-0.5" />
              <div className="text-xs">
                <p className="font-bold text-rose-950">Irreversible Action</p>
                <p className="mt-1 text-rose-800">
                  This will permanently erase all <strong>{items.length} items</strong> currently in the Recycle Bin. No records can be restored after this operation.
                </p>
              </div>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};

export default AdminRecycleBinPage;
