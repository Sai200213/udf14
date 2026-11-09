import React, { useState, useEffect, useMemo } from 'react';
import { BgvRecord, BgvStatus, Site, Role, User, Permission, FormSection, PortalConfig } from '../types';
import Button from './common/Button';
import Input from './common/Input';
import Modal from './common/Modal';
import SecureDocumentLink from '../src/components/common/SecureDocumentLink';
import { getSecureURL } from '../src/services/storageService';
import { updatePortalConfig } from '../src/services/adminService';
import {
  subscribeToBgvRecords,
  syncBgvCandidates,
  markBgvUnderProcess,
  vendorSubmitBgvReport,
  staffApproveBgv,
  staffDirectCompleteBgv,
  staffRejectBgv
} from '../src/services/bgvService';
import {
  ShieldCheck,
  ShieldAlert,
  Clock,
  Send,
  FileCheck,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Search,
  Filter,
  Copy,
  Check,
  ExternalLink,
  Upload,
  X,
  RefreshCw,
  Building,
  Phone,
  UserCheck,
  Eye,
  AlertCircle,
  FileSpreadsheet,
  User as UserIcon,
  Calendar,
  Layers,
  Settings2,
  Sliders,
  Sparkles,
  Lock
} from 'lucide-react';
import log from '../src/utils/logger';

interface AdminBgvManagementPageProps {
  authUser: User | null;
  isSuperAdmin: boolean;
  userRole?: Role;
  sites: Site[];
  formSections?: FormSection[];
  portalConfig?: PortalConfig;
  setPortalConfig?: React.Dispatch<React.SetStateAction<PortalConfig>>;
  onNotify: (msg: string, type?: 'success' | 'error' | 'info' | 'warning') => void;
  logAction?: (actionType: any, targetModule: any, details: string) => void;
  allowedSiteIds?: string[];
}

export const AdminBgvManagementPage: React.FC<AdminBgvManagementPageProps> = ({
  authUser,
  isSuperAdmin,
  userRole,
  sites,
  formSections = [],
  portalConfig,
  setPortalConfig,
  onNotify,
  logAction,
  allowedSiteIds
}) => {
  const [records, setRecords] = useState<BgvRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [isSyncing, setIsSyncing] = useState(false);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSiteFilter, setSelectedSiteFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | BgvStatus>('ALL');

  // Granular RBAC Permissions
  const hasPermission = (p: Permission) => {
    if (isSuperAdmin) return true;
    if (userRole?.isDisabled === true) return false;
    const overrides = (authUser as any)?.permissionOverrides;
    if (overrides && overrides[p] !== undefined) {
      return Boolean(overrides[p]);
    }
    return Boolean(userRole?.permissions?.includes(p));
  };
  const isVendor = !isSuperAdmin && hasPermission(Permission.BGV_VENDOR);

  const canViewDossier = isSuperAdmin || hasPermission(Permission.BGV_VIEW_DOSSIER) || hasPermission(Permission.BGV_MANAGE) || isVendor;
  const canCopyDossier = isSuperAdmin || hasPermission(Permission.BGV_COPY_DOSSIER) || hasPermission(Permission.BGV_MANAGE);
  const canDispatch = isSuperAdmin || (!isVendor && (hasPermission(Permission.BGV_DISPATCH_VENDOR) || hasPermission(Permission.BGV_MANAGE)));
  const canUpload = isSuperAdmin || hasPermission(Permission.BGV_UPLOAD_CERTIFICATE) || hasPermission(Permission.BGV_MANAGE) || isVendor;
  const canApproveReject = isSuperAdmin || (!isVendor && (hasPermission(Permission.BGV_APPROVE_REJECT) || hasPermission(Permission.BGV_MANAGE)));
  const canConfigureFields = isSuperAdmin || hasPermission(Permission.BGV_CONFIGURE_FIELDS) || hasPermission(Permission.MANAGE_SYSTEM);
  const hasScopeAll = isSuperAdmin || hasPermission(Permission.BGV_VIEW_SCOPE_ALL);

  // Modals state
  const [selectedCandidate, setSelectedCandidate] = useState<BgvRecord | null>(null);
  const [isPacketModalOpen, setIsPacketModalOpen] = useState(false);
  const [isSendVendorModalOpen, setIsSendVendorModalOpen] = useState(false);
  const [isReviewModalOpen, setIsReviewModalOpen] = useState(false);
  const [isDirectCompleteModalOpen, setIsDirectCompleteModalOpen] = useState(false);
  const [isVendorSubmitModalOpen, setIsVendorSubmitModalOpen] = useState(false);
  const [isConfigFieldsModalOpen, setIsConfigFieldsModalOpen] = useState(false);

  // Extraction configuration state
  const configuredFieldIds = useMemo(() => {
    return portalConfig?.bgvConfig?.extractedFieldIds || [];
  }, [portalConfig?.bgvConfig?.extractedFieldIds]);

  const [selectedExtractionFieldIds, setSelectedExtractionFieldIds] = useState<string[]>(configuredFieldIds);
  const [isSavingConfig, setIsSavingConfig] = useState(false);

  // Form states
  const [vendorNameInput, setVendorNameInput] = useState('HP Investigative Service');
  const [vendorCaseIdInput, setVendorCaseIdInput] = useState('');
  const [actionNotesInput, setActionNotesInput] = useState('');
  const [rejectionReasonInput, setRejectionReasonInput] = useState('');
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [isSubmittingAction, setIsSubmittingAction] = useState(false);
  const [copiedCandidateId, setCopiedCandidateId] = useState<string | null>(null);

  // Private photo blob URL cache
  const [photoBlobUrls, setPhotoBlobUrls] = useState<Record<string, string>>({});

  // 1. Subscribe to real-time BGV records
  useEffect(() => {
    setLoading(true);
    const unsubscribe = subscribeToBgvRecords((data) => {
      setRecords(data);
      setLoading(false);
    });
    return () => unsubscribe();
  }, []);

  // Sync state with portalConfig when opened
  useEffect(() => {
    if (portalConfig?.bgvConfig?.extractedFieldIds) {
      setSelectedExtractionFieldIds(portalConfig.bgvConfig.extractedFieldIds);
    }
  }, [portalConfig?.bgvConfig?.extractedFieldIds]);

  // 2. Fetch secure photo blob when packet modal is opened
  useEffect(() => {
    if (selectedCandidate && selectedCandidate.photoUrl && !photoBlobUrls[selectedCandidate.id]) {
      getSecureURL(selectedCandidate.photoUrl)
        .then(blobUrl => {
          if (blobUrl) {
            setPhotoBlobUrls(prev => ({ ...prev, [selectedCandidate.id]: blobUrl }));
          }
        })
        .catch(err => log.error('Failed to resolve photo blob:', err));
    }
  }, [selectedCandidate]);

  // Sites requiring BGV
  const bgvMandatedSites = useMemo(() => {
    return sites.filter(s => s.requiresBgv === true);
  }, [sites]);

  // Handle Syncing candidates from active employees using configured fields
  const handleSyncCandidates = async () => {
    setIsSyncing(true);
    try {
      const added = await syncBgvCandidates(
        sites,
        records,
        undefined,
        selectedExtractionFieldIds,
        formSections
      );
      if (added > 0) {
        onNotify(`Successfully enrolled ${added} active candidates for BGV clearance.`, 'success');
        if (logAction) logAction('CREATE', 'EMPLOYEES', `Enrolled ${added} employees into BGV tracking`);
      } else {
        onNotify('All active employees at BGV sites are already enrolled with configured fields.', 'info');
      }
    } catch (err: any) {
      log.error('BGV candidate sync error:', err);
      onNotify(`Sync failed: ${err.message || 'Unknown error'}`, 'error');
    } finally {
      setIsSyncing(false);
    }
  };

  // Save Extraction Fields Configuration
  const handleSaveExtractionFields = async () => {
    if (!canConfigureFields) return;
    setIsSavingConfig(true);
    try {
      const currentConfig = portalConfig || {
        enableLeaves: true,
        enableAccountUpdates: true,
        enableResignations: true,
        enableDisciplinary: true
      };

      const updatedConfig: PortalConfig = {
        ...currentConfig,
        bgvConfig: {
          extractedFieldIds: selectedExtractionFieldIds,
          instructions: 'Configured by SuperAdmin for 3rd-party BGV clearance dossier extraction.'
        }
      };

      await updatePortalConfig(updatedConfig);
      if (setPortalConfig) setPortalConfig(updatedConfig);

      if (logAction) {
        logAction('UPDATE', 'SYSTEM', `Updated BGV dossier extraction fields: ${selectedExtractionFieldIds.length} fields selected`);
      }

      // Automatically re-sync candidates to apply new field extraction
      await syncBgvCandidates(
        sites,
        records,
        undefined,
        selectedExtractionFieldIds,
        formSections
      );

      onNotify(`Saved BGV extraction config with ${selectedExtractionFieldIds.length} field(s). Candidate dossiers refreshed!`, 'success');
      setIsConfigFieldsModalOpen(false);
    } catch (err: any) {
      log.error('Failed to save BGV extraction config:', err);
      onNotify(`Failed to save configuration: ${err.message}`, 'error');
    } finally {
      setIsSavingConfig(false);
    }
  };

  // Filter records
  const filteredRecords = useMemo(() => {
    return records.filter(record => {
      // Scope to allowed sites if supervisor and doesn't have BGV_VIEW_SCOPE_ALL
      if (!hasScopeAll && allowedSiteIds && allowedSiteIds.length > 0 && !allowedSiteIds.includes(record.siteId)) {
        return false;
      }

      // If user is a vendor, restrict to cases dispatched to their vendor name (if set)
      if (isVendor && authUser?.name) {
        if (record.vendorName && !record.vendorName.toLowerCase().includes(authUser.name.toLowerCase())) {
          return false;
        }
      }

      // Site filter
      if (selectedSiteFilter !== 'ALL' && record.siteId !== selectedSiteFilter && record.siteName !== selectedSiteFilter) {
        return false;
      }

      // Status filter
      if (statusFilter !== 'ALL' && record.status !== statusFilter) {
        return false;
      }

      // Search Query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesName = record.employeeName?.toLowerCase().includes(q);
        const matchesId = record.employeeId?.toLowerCase().includes(q);
        const matchesSite = record.siteName?.toLowerCase().includes(q);
        const matchesAadhaar = record.aadhaarNumber?.includes(q);
        const matchesPhone = record.phoneNumber?.includes(q);
        const matchesVendor = record.vendorName?.toLowerCase().includes(q) || record.vendorCaseId?.toLowerCase().includes(q);
        return matchesName || matchesId || matchesSite || matchesAadhaar || matchesPhone || matchesVendor;
      }

      return true;
    });
  }, [records, hasScopeAll, allowedSiteIds, isVendor, authUser?.name, selectedSiteFilter, statusFilter, searchQuery]);

  // Statistics calculation
  const stats = useMemo(() => {
    const total = filteredRecords.length;
    const pending = filteredRecords.filter(r => r.status === BgvStatus.PENDING).length;
    const underProcess = filteredRecords.filter(r => r.status === BgvStatus.UNDER_PROCESS).length;
    const vendorSubmitted = filteredRecords.filter(r => r.status === BgvStatus.VENDOR_SUBMITTED).length;
    const completed = filteredRecords.filter(r => r.status === BgvStatus.COMPLETED).length;
    const failed = filteredRecords.filter(r => r.status === BgvStatus.FAILED).length;
    return { total, pending, underProcess, vendorSubmitted, completed, failed };
  }, [filteredRecords]);

  // Check if a field is hidden by Role permissions
  const isFieldHiddenForRole = (fieldId: string) => {
    if (isSuperAdmin) return false;
    const bgvRule = userRole?.bgvFieldVisibility?.[fieldId];
    if (bgvRule === 'HIDDEN') return true;
    const generalRule = userRole?.fieldVisibility?.[fieldId];
    if (generalRule === 'HIDDEN') return true;
    return false;
  };

  // Action: Copy packet details for email
  const handleCopyPacket = (candidate: BgvRecord) => {
    if (!canCopyDossier) {
      onNotify('You do not have permission to copy verification dossiers.', 'warning');
      return;
    }

    const lines: string[] = [
      `=== 3RD-PARTY BACKGROUND VERIFICATION DOSSIER ===`,
      `Candidate Name     : ${candidate.employeeName}`,
      `Employee / Badge ID: ${candidate.employeeId}`,
      `Client Site        : ${candidate.siteName}`,
      `Designation        : ${candidate.designation || 'Security Guard'}`
    ];

    if (!isFieldHiddenForRole('phone') && candidate.phoneNumber) {
      lines.push(`Phone Number       : ${candidate.phoneNumber}`);
    }
    if (!isFieldHiddenForRole('aadhaar') && candidate.aadhaarNumber) {
      lines.push(`Aadhaar Number     : ${candidate.aadhaarNumber}`);
    }
    if (!isFieldHiddenForRole('dob') && candidate.dob) {
      lines.push(`Date of Birth      : ${candidate.dob}`);
    }
    if (!isFieldHiddenForRole('fatherName') && candidate.fatherName) {
      lines.push(`Father's Name      : ${candidate.fatherName}`);
    }
    if (!isFieldHiddenForRole('address') && candidate.permanentAddress) {
      lines.push(`Permanent Address  : ${candidate.permanentAddress}`);
    }

    // Append SuperAdmin-configured custom extracted fields
    if (candidate.customFields) {
      lines.push(`--- ADDITIONAL CONFIGURED DETAILS ---`);
      Object.entries(candidate.customFields).forEach(([fId, dataRaw]) => {
        const data = dataRaw as { label: string; value: any; isFile?: boolean };
        if (!isFieldHiddenForRole(fId) && data.value) {
          const raw = data.value;
          if (data.isFile || (typeof raw === 'object' && raw !== null && ('storagePath' in raw || 'path' in raw || 'name' in raw))) {
            const name = typeof raw === 'object' && raw.name ? raw.name : 'Attached Document';
            lines.push(`${data.label.padEnd(19)}: [Document: ${name}]`);
          } else if (typeof raw === 'object') {
            lines.push(`${data.label.padEnd(19)}: [Attached]`);
          } else {
            lines.push(`${data.label.padEnd(19)}: ${String(raw)}`);
          }
        }
      });
    }

    lines.push(`Requested By       : ${authUser?.name || 'HR Operations Team'}`);
    lines.push(`Date Generated     : ${new Date().toLocaleDateString('en-IN')}`);
    lines.push(`=================================================`);

    navigator.clipboard.writeText(lines.join('\n'));
    setCopiedCandidateId(candidate.id);
    onNotify(`Copied verification dossier for ${candidate.employeeName} to clipboard!`, 'success');
    setTimeout(() => setCopiedCandidateId(null), 3000);
  };

  // Action: Submit to Vendor (Mark Under Process)
  const handleConfirmSendToVendor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCandidate || !canDispatch) return;
    if (!vendorNameInput.trim()) {
      onNotify('Please specify the verification vendor name.', 'warning');
      return;
    }
    setIsSubmittingAction(true);
    try {
      await markBgvUnderProcess(
        selectedCandidate.id,
        vendorNameInput.trim(),
        vendorCaseIdInput.trim(),
        actionNotesInput.trim()
      );
      if (logAction) {
        logAction('UPDATE', 'EMPLOYEES', `Dispatched BGV for ${selectedCandidate.employeeName} to ${vendorNameInput}`);
      }
      onNotify(`Case for ${selectedCandidate.employeeName} marked Under Process with ${vendorNameInput}.`, 'success');
      setIsSendVendorModalOpen(false);
      setSelectedCandidate(null);
      setActionNotesInput('');
      setVendorCaseIdInput('');
    } catch (err: any) {
      log.error('Failed to send to vendor:', err);
      onNotify(`Failed to update status: ${err.message}`, 'error');
    } finally {
      setIsSubmittingAction(false);
    }
  };

  // Action: Staff Direct Complete (Mode A - Staff received certificate by email)
  const handleConfirmDirectComplete = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCandidate || !canUpload) return;
    if (!uploadedFile) {
      onNotify('Please select the BGV certificate file (PDF or Image).', 'warning');
      return;
    }
    setIsSubmittingAction(true);
    try {
      await staffDirectCompleteBgv(
        selectedCandidate.id,
        selectedCandidate.employeeId,
        uploadedFile,
        authUser?.name || 'Staff Admin',
        vendorNameInput.trim(),
        vendorCaseIdInput.trim(),
        actionNotesInput.trim()
      );
      if (logAction) {
        logAction('APPROVAL', 'EMPLOYEES', `Uploaded BGV certificate and completed clearance for ${selectedCandidate.employeeName}`);
      }
      onNotify(`BGV clearance completed successfully for ${selectedCandidate.employeeName}!`, 'success');
      setIsDirectCompleteModalOpen(false);
      setSelectedCandidate(null);
      setUploadedFile(null);
      setActionNotesInput('');
      setVendorCaseIdInput('');
    } catch (err: any) {
      log.error('Direct complete error:', err);
      onNotify(`Upload failed: ${err.message}`, 'error');
    } finally {
      setIsSubmittingAction(false);
    }
  };

  // Action: Vendor Self-Submission (Mode B - Vendor logs in directly)
  const handleConfirmVendorSubmission = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCandidate) return;
    if (!uploadedFile) {
      onNotify('Please select your BGV report/certificate to submit.', 'warning');
      return;
    }
    setIsSubmittingAction(true);
    try {
      await vendorSubmitBgvReport(
        selectedCandidate.id,
        selectedCandidate.employeeId,
        uploadedFile,
        actionNotesInput.trim()
      );
      onNotify(`Certificate submitted successfully. It is now awaiting staff review.`, 'success');
      setIsVendorSubmitModalOpen(false);
      setSelectedCandidate(null);
      setUploadedFile(null);
      setActionNotesInput('');
    } catch (err: any) {
      log.error('Vendor report submission failed:', err);
      onNotify(`Submission failed: ${err.message}`, 'error');
    } finally {
      setIsSubmittingAction(false);
    }
  };

  // Action: Staff Approve Vendor-Submitted Report
  const handleApproveVendorReport = async () => {
    if (!selectedCandidate || !canApproveReject) return;
    setIsSubmittingAction(true);
    try {
      await staffApproveBgv(
        selectedCandidate.id,
        authUser?.name || 'Staff Admin',
        actionNotesInput.trim(),
        selectedCandidate.employeeId
      );
      if (logAction) {
        logAction('APPROVAL', 'EMPLOYEES', `Approved vendor BGV report for ${selectedCandidate.employeeName}`);
      }
      onNotify(`Vendor report approved! ${selectedCandidate.employeeName} is now marked BGV Completed.`, 'success');
      setIsReviewModalOpen(false);
      setSelectedCandidate(null);
      setActionNotesInput('');
    } catch (err: any) {
      log.error('Approval failed:', err);
      onNotify(`Approval failed: ${err.message}`, 'error');
    } finally {
      setIsSubmittingAction(false);
    }
  };

  // Action: Staff Reject / Flag Adverse Findings
  const handleRejectVendorReport = async () => {
    if (!selectedCandidate || !canApproveReject) return;
    if (!rejectionReasonInput.trim()) {
      onNotify('Please provide a reason or describe adverse findings.', 'warning');
      return;
    }
    setIsSubmittingAction(true);
    try {
      await staffRejectBgv(
        selectedCandidate.id,
        authUser?.name || 'Staff Admin',
        rejectionReasonInput.trim(),
        selectedCandidate.employeeId
      );
      if (logAction) {
        logAction('REJECTION', 'EMPLOYEES', `Flagged BGV adverse/failed for ${selectedCandidate.employeeName}: ${rejectionReasonInput}`);
      }
      onNotify(`BGV record for ${selectedCandidate.employeeName} marked as FAILED / ADVERSE.`, 'error');
      setIsReviewModalOpen(false);
      setSelectedCandidate(null);
      setRejectionReasonInput('');
    } catch (err: any) {
      log.error('Rejection failed:', err);
      onNotify(`Rejection failed: ${err.message}`, 'error');
    } finally {
      setIsSubmittingAction(false);
    }
  };

  const getStatusBadge = (status: BgvStatus) => {
    switch (status) {
      case BgvStatus.PENDING:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-200">
            <Clock size={12} className="text-amber-600 animate-pulse" /> Pending Dispatch
          </span>
        );
      case BgvStatus.UNDER_PROCESS:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-blue-100 text-blue-800 border border-blue-200">
            <Send size={12} className="text-blue-600" /> With Vendor
          </span>
        );
      case BgvStatus.VENDOR_SUBMITTED:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-purple-100 text-purple-800 border border-purple-200 animate-pulse">
            <AlertCircle size={12} className="text-purple-600" /> Review Needed
          </span>
        );
      case BgvStatus.COMPLETED:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200">
            <CheckCircle2 size={12} className="text-emerald-600" /> Cleared & Completed
          </span>
        );
      case BgvStatus.FAILED:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-rose-100 text-rose-800 border border-rose-200">
            <ShieldAlert size={12} className="text-rose-600" /> Failed / Adverse
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Header */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 text-white rounded-2xl p-6 sm:p-8 shadow-xl relative overflow-hidden">
        <div className="absolute right-0 top-0 bottom-0 w-96 bg-radial from-purple-500/20 to-transparent pointer-events-none" />
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="px-3 py-1 rounded-full bg-purple-500/20 border border-purple-400/30 text-purple-300 text-xs font-black uppercase tracking-wider flex items-center gap-1.5">
                <ShieldCheck size={14} className="text-purple-400" /> Client Mandate System
              </span>
              {isVendor && (
                <span className="px-2.5 py-1 rounded-full bg-amber-500/20 border border-amber-400/30 text-amber-300 text-xs font-bold uppercase">
                  Vendor Portal Mode
                </span>
              )}
              {bgvMandatedSites.length > 0 && (
                <span className="px-2.5 py-1 rounded-full bg-white/10 text-slate-300 text-xs font-medium">
                  {bgvMandatedSites.length} Client Sites Enforced
                </span>
              )}
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              3rd-Party BGV Clearance Tracker
            </h1>
            <p className="text-slate-300 text-sm max-w-2xl leading-relaxed">
              External background verification management for personnel deployed to high-security client premises (Wipro, Capgemini, etc.). Extract SuperAdmin-configured onboarding fields, dispatch to verification vendors, track case progress, and audit completion certificates.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            {canConfigureFields && (
              <Button
                variant="secondary"
                onClick={() => setIsConfigFieldsModalOpen(true)}
                className="bg-white/10 hover:bg-white/20 text-white border-white/20 text-xs font-bold px-3 py-2.5 rounded-xl transition-all"
                title="Configure which fields from the Onboarding Form are extracted into candidate BGV dossiers"
              >
                <Sliders size={15} className="mr-1.5 text-purple-300" />
                Configure Extraction Fields ({selectedExtractionFieldIds.length})
              </Button>
            )}

            {!isVendor && (
              <Button
                variant="primary"
                onClick={handleSyncCandidates}
                disabled={isSyncing}
                className="bg-purple-600 hover:bg-purple-700 text-white border-0 shadow-lg shadow-purple-600/30 font-bold px-4 py-2.5 rounded-xl transition-all"
              >
                <RefreshCw size={16} className={`mr-2 ${isSyncing ? 'animate-spin' : ''}`} />
                {isSyncing ? 'Syncing...' : 'Sync Active Candidates'}
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 sm:gap-4">
        {/* Total */}
        <div
          onClick={() => setStatusFilter('ALL')}
          className={`cursor-pointer bg-white p-4 rounded-xl border transition-all ${statusFilter === 'ALL' ? 'ring-2 ring-indigo-500 shadow-md' : 'hover:border-slate-300'}`}
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider">Total Pipeline</span>
            <Layers size={16} className="text-slate-500" />
          </div>
          <div className="text-2xl font-black text-slate-900">{stats.total}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">Enrolled guards</div>
        </div>

        {/* Pending Dispatch */}
        <div
          onClick={() => setStatusFilter(BgvStatus.PENDING)}
          className={`cursor-pointer bg-white p-4 rounded-xl border transition-all ${statusFilter === BgvStatus.PENDING ? 'ring-2 ring-amber-500 shadow-md' : 'hover:border-amber-200'}`}
        >
          <div className="flex items-center justify-between text-amber-500 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider">Pending Dispatch</span>
            <Clock size={16} />
          </div>
          <div className="text-2xl font-black text-amber-700">{stats.pending}</div>
          <div className="text-[10px] text-amber-600 mt-0.5">Send packet to vendor</div>
        </div>

        {/* Under Process */}
        <div
          onClick={() => setStatusFilter(BgvStatus.UNDER_PROCESS)}
          className={`cursor-pointer bg-white p-4 rounded-xl border transition-all ${statusFilter === BgvStatus.UNDER_PROCESS ? 'ring-2 ring-blue-500 shadow-md' : 'hover:border-blue-200'}`}
        >
          <div className="flex items-center justify-between text-blue-500 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider">With Vendor</span>
            <Send size={16} />
          </div>
          <div className="text-2xl font-black text-blue-700">{stats.underProcess}</div>
          <div className="text-[10px] text-blue-600 mt-0.5">In progress / follow-up</div>
        </div>

        {/* Review Needed */}
        <div
          onClick={() => setStatusFilter(BgvStatus.VENDOR_SUBMITTED)}
          className={`cursor-pointer bg-white p-4 rounded-xl border transition-all ${statusFilter === BgvStatus.VENDOR_SUBMITTED ? 'ring-2 ring-purple-500 shadow-md' : 'hover:border-purple-200'}`}
        >
          <div className="flex items-center justify-between text-purple-500 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider">Pending Review</span>
            <AlertCircle size={16} />
          </div>
          <div className="text-2xl font-black text-purple-700">{stats.vendorSubmitted}</div>
          <div className="text-[10px] text-purple-600 mt-0.5">Report submitted</div>
        </div>

        {/* Completed */}
        <div
          onClick={() => setStatusFilter(BgvStatus.COMPLETED)}
          className={`cursor-pointer bg-white p-4 rounded-xl border transition-all ${statusFilter === BgvStatus.COMPLETED ? 'ring-2 ring-emerald-500 shadow-md' : 'hover:border-emerald-200'}`}
        >
          <div className="flex items-center justify-between text-emerald-500 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider">Cleared & Verified</span>
            <CheckCircle2 size={16} />
          </div>
          <div className="text-2xl font-black text-emerald-700">{stats.completed}</div>
          <div className="text-[10px] text-emerald-600 mt-0.5">Clearance approved</div>
        </div>

        {/* Adverse / Failed */}
        <div
          onClick={() => setStatusFilter(BgvStatus.FAILED)}
          className={`cursor-pointer bg-white p-4 rounded-xl border transition-all ${statusFilter === BgvStatus.FAILED ? 'ring-2 ring-rose-500 shadow-md' : 'hover:border-rose-200'}`}
        >
          <div className="flex items-center justify-between text-rose-500 mb-2">
            <span className="text-[11px] font-bold uppercase tracking-wider">Adverse / Failed</span>
            <ShieldAlert size={16} />
          </div>
          <div className="text-2xl font-black text-rose-700">{stats.failed}</div>
          <div className="text-[10px] text-rose-600 mt-0.5">Issues detected</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white p-4 rounded-xl shadow-xs border border-slate-200 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="flex-1 relative">
          <Search size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            placeholder="Search by guard name, badge ID, Aadhaar, phone, or vendor..."
            className="w-full pl-10 pr-4 py-2 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500/20 focus:border-purple-500"
          />
          {searchQuery && (
            <button
              onClick={() => setSearchQuery('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
            >
              <X size={14} />
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Site Filter */}
          <div className="flex items-center gap-1.5">
            <Building size={14} className="text-slate-400" />
            <select
              value={selectedSiteFilter}
              onChange={e => setSelectedSiteFilter(e.target.value)}
              className="text-xs font-semibold py-2 px-3 border border-slate-200 rounded-lg bg-slate-50 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
            >
              <option value="ALL">All Mandated Sites ({bgvMandatedSites.length})</option>
              {bgvMandatedSites.map(s => (
                <option key={s.id} value={s.id}>{s.name}</option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value as any)}
            className="text-xs font-semibold py-2 px-3 border border-slate-200 rounded-lg bg-slate-50 focus:outline-none focus:ring-2 focus:ring-purple-500/20"
          >
            <option value="ALL">All Statuses</option>
            <option value={BgvStatus.PENDING}>Pending Dispatch ({stats.pending})</option>
            <option value={BgvStatus.UNDER_PROCESS}>With Vendor ({stats.underProcess})</option>
            <option value={BgvStatus.VENDOR_SUBMITTED}>Review Needed ({stats.vendorSubmitted})</option>
            <option value={BgvStatus.COMPLETED}>Completed ({stats.completed})</option>
            <option value={BgvStatus.FAILED}>Failed ({stats.failed})</option>
          </select>
        </div>
      </div>

      {/* Main Table */}
      <div className="bg-white rounded-xl shadow-xs border border-slate-200 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-slate-500 flex flex-col items-center justify-center gap-3">
            <RefreshCw size={24} className="animate-spin text-purple-600" />
            <span className="text-sm font-medium">Loading background verification records...</span>
          </div>
        ) : filteredRecords.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <div className="w-14 h-14 rounded-2xl bg-purple-50 text-purple-600 flex items-center justify-center mx-auto">
              <ShieldCheck size={28} />
            </div>
            <h3 className="text-base font-bold text-slate-800">No BGV records found</h3>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              {bgvMandatedSites.length === 0
                ? "No sites are currently flagged with 'Mandate 3rd-Party BGV Clearance'. Enable this in Site Management first."
                : records.length === 0
                  ? "Click 'Sync Active Candidates' above to enroll active guards assigned to your client sites (Wipro, Capgemini, etc.)."
                  : "No candidates match your current search and filter criteria."}
            </p>
            {bgvMandatedSites.length > 0 && records.length === 0 && !isVendor && (
              <Button
                variant="primary"
                onClick={handleSyncCandidates}
                disabled={isSyncing}
                className="mt-2 bg-purple-600 text-white font-bold"
              >
                Sync Active Guards Now
              </Button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-[10px] font-black uppercase tracking-wider text-slate-500">
                  <th className="px-5 py-3.5">Candidate & Badge</th>
                  <th className="px-4 py-3.5">Assigned Site</th>
                  <th className="px-4 py-3.5">Identification</th>
                  <th className="px-4 py-3.5">Status</th>
                  <th className="px-4 py-3.5">Vendor & Case ID</th>
                  <th className="px-5 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 text-xs">
                {filteredRecords.map((item) => {
                  const isCopied = copiedCandidateId === item.id;
                  return (
                    <tr key={item.id} className="hover:bg-slate-50/70 transition-colors">
                      {/* Candidate */}
                      <td className="px-5 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-full bg-purple-100 text-purple-700 flex items-center justify-center font-bold text-xs shrink-0 overflow-hidden border border-purple-200">
                            {item.photoUrl ? (
                              <img
                                src={photoBlobUrls[item.id] || item.photoUrl}
                                alt={item.employeeName}
                                className="w-full h-full object-cover"
                                onError={(e) => {
                                  (e.target as HTMLElement).style.display = 'none';
                                }}
                              />
                            ) : (
                              item.employeeName.charAt(0).toUpperCase()
                            )}
                          </div>
                          <div>
                            <div className="font-bold text-slate-900 flex items-center gap-1.5">
                              {item.employeeName}
                              {canCopyDossier && (
                                <button
                                  onClick={() => handleCopyPacket(item)}
                                  className={`text-[10px] p-1 rounded transition-colors ${isCopied ? 'text-emerald-600 bg-emerald-50' : 'text-slate-400 hover:text-slate-700'}`}
                                  title="Copy Verification Dossier for Email"
                                >
                                  {isCopied ? <Check size={12} /> : <Copy size={12} />}
                                </button>
                              )}
                            </div>
                            <div className="text-[11px] text-slate-500 flex items-center gap-1 mt-0.5">
                              <span className="font-mono bg-slate-100 px-1 py-0.5 rounded text-[10px] font-semibold text-slate-700">{item.employeeId}</span>
                              <span>•</span>
                              <span>{item.designation || 'Guard'}</span>
                            </div>
                          </div>
                        </div>
                      </td>

                      {/* Site */}
                      <td className="px-4 py-4">
                        <div className="flex items-center gap-1.5 font-semibold text-slate-800">
                          <Building size={13} className="text-purple-600 shrink-0" />
                          <span>{item.siteName}</span>
                        </div>
                      </td>

                      {/* Identification */}
                      <td className="px-4 py-4">
                        <div className="space-y-0.5">
                          {!isFieldHiddenForRole('aadhaar') && (
                            <div className="font-mono text-slate-700 font-medium text-[11px]">
                              {item.aadhaarNumber ? `Aadhaar: ${item.aadhaarNumber.replace(/(\d{4})(\d{4})(\d{4})/, '$1 $2 $3')}` : <span className="text-slate-400 italic">No Aadhaar</span>}
                            </div>
                          )}
                          {!isFieldHiddenForRole('phone') && item.phoneNumber && (
                            <div className="text-slate-500 text-[11px] flex items-center gap-1">
                              <Phone size={10} className="text-slate-400" /> {item.phoneNumber}
                            </div>
                          )}
                        </div>
                      </td>

                      {/* Status */}
                      <td className="px-4 py-4">
                        {getStatusBadge(item.status)}
                        {item.approvedDate && (
                          <div className="text-[10px] text-emerald-600 font-medium mt-1">
                            Cleared {new Date(item.approvedDate).toLocaleDateString()}
                          </div>
                        )}
                        {item.sentToVendorDate && item.status === BgvStatus.UNDER_PROCESS && (
                          <div className="text-[10px] text-slate-400 mt-1">
                            Sent {new Date(item.sentToVendorDate).toLocaleDateString()}
                          </div>
                        )}
                      </td>

                      {/* Vendor Details */}
                      <td className="px-4 py-4">
                        {item.vendorName ? (
                          <div>
                            <span className="font-bold text-slate-800">{item.vendorName}</span>
                            {item.vendorCaseId && (
                              <div className="font-mono text-[10px] text-slate-500">
                                Ref: {item.vendorCaseId}
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-slate-400 italic">Unassigned</span>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="px-5 py-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          {/* 1. View Packet */}
                          {canViewDossier && (
                            <Button
                              variant="secondary"
                              size="sm"
                              onClick={() => {
                                setSelectedCandidate(item);
                                setIsPacketModalOpen(true);
                              }}
                              className="bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs px-2.5 py-1"
                              title="View Full Candidate Packet"
                            >
                              <Eye size={13} className="mr-1" /> Dossier
                            </Button>
                          )}

                          {/* 2. Pending -> Send to Vendor */}
                          {item.status === BgvStatus.PENDING && canDispatch && (
                            <Button
                              variant="primary"
                              size="sm"
                              onClick={() => {
                                setSelectedCandidate(item);
                                setVendorNameInput('HP Investigative Service');
                                setVendorCaseIdInput('');
                                setActionNotesInput('');
                                setIsSendVendorModalOpen(true);
                              }}
                              className="bg-blue-600 hover:bg-blue-700 text-white text-xs px-2.5 py-1 font-bold"
                            >
                              <Send size={13} className="mr-1" /> Send to Vendor
                            </Button>
                          )}

                          {/* 3. Under Process -> Upload BGV Certificate received via email */}
                          {item.status === BgvStatus.UNDER_PROCESS && canUpload && !isVendor && (
                            <Button
                              variant="primary"
                              size="sm"
                              onClick={() => {
                                setSelectedCandidate(item);
                                setUploadedFile(null);
                                setVendorNameInput(item.vendorName || 'HP Investigative Service');
                                setVendorCaseIdInput(item.vendorCaseId || '');
                                setActionNotesInput('');
                                setIsDirectCompleteModalOpen(true);
                              }}
                              className="bg-emerald-600 hover:bg-emerald-700 text-white text-xs px-2.5 py-1 font-bold"
                            >
                              <Upload size={13} className="mr-1" /> Upload BGV
                            </Button>
                          )}

                          {/* 4. Vendor Mode: Vendor Self-Submission */}
                          {isVendor && item.status === BgvStatus.UNDER_PROCESS && (
                            <Button
                              variant="primary"
                              size="sm"
                              onClick={() => {
                                setSelectedCandidate(item);
                                setUploadedFile(null);
                                setActionNotesInput('');
                                setIsVendorSubmitModalOpen(true);
                              }}
                              className="bg-purple-600 hover:bg-purple-700 text-white text-xs px-2.5 py-1"
                            >
                              <Upload size={13} className="mr-1" /> Submit Certificate
                            </Button>
                          )}

                          {/* 5. Vendor Submitted -> Review & Approve */}
                          {item.status === BgvStatus.VENDOR_SUBMITTED && canApproveReject && (
                            <Button
                              variant="primary"
                              size="sm"
                              onClick={() => {
                                setSelectedCandidate(item);
                                setActionNotesInput('');
                                setRejectionReasonInput('');
                                setIsReviewModalOpen(true);
                              }}
                              className="bg-purple-600 hover:bg-purple-700 text-white text-xs px-2.5 py-1 font-bold animate-pulse"
                            >
                              <FileCheck size={13} className="mr-1" /> Review Certificate
                            </Button>
                          )}

                          {/* 6. Completed -> View Certificate */}
                          {item.status === BgvStatus.COMPLETED && item.bgvDocumentUrl && (
                            <SecureDocumentLink
                              fileUrl={item.bgvDocumentUrl}
                              className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-bold rounded bg-emerald-50 text-emerald-700 hover:bg-emerald-100 border border-emerald-200 transition-colors"
                            >
                              <FileText size={13} /> View Certificate
                            </SecureDocumentLink>
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

      {/* ========================================================================= */}
      {/* MODAL 0: Configure BGV Extraction Fields (SuperAdmin Power Tool)           */}
      {/* ========================================================================= */}
      {isConfigFieldsModalOpen && canConfigureFields && (
        <Modal
          isOpen={isConfigFieldsModalOpen}
          onClose={() => setIsConfigFieldsModalOpen(false)}
          title="Configure BGV Dossier Extraction Fields"
          size="lg"
        >
          <div className="space-y-4 text-xs">
            <div className="p-3.5 bg-purple-50 border border-purple-200 rounded-xl">
              <p className="font-bold text-purple-900 text-sm flex items-center gap-1.5">
                <Sliders size={16} className="text-purple-600" />
                Select Which Onboarding Fields to Extract
              </p>
              <p className="text-[11px] text-purple-700 mt-1 leading-relaxed">
                As SuperAdmin, choose the exact fields from your Onboarding Form that should be extracted from employee records and included in the BGV candidate packet for vendors.
              </p>
            </div>

            <div className="flex items-center justify-between pt-1">
              <span className="font-bold text-slate-700">
                Selected: <span className="text-purple-600 font-extrabold">{selectedExtractionFieldIds.length}</span> field(s)
              </span>
            </div>

            {/* Form Sections & Fields Tree */}
            <div className="max-h-96 overflow-y-auto space-y-4 pr-1 border border-slate-200 rounded-xl p-3 bg-slate-50/50">
              {formSections.length === 0 ? (
                <div className="text-center text-slate-400 py-6">No form sections available.</div>
              ) : (
                formSections.map(sec => (
                  <div key={sec.id} className="bg-white rounded-lg border border-slate-200 p-3">
                    <div className="flex items-center justify-between border-b border-slate-100 pb-2 mb-2">
                      <span className="font-extrabold text-slate-800 uppercase tracking-wider text-[11px]">
                        {sec.name}
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          const secFieldIds = (sec.fields || []).map(f => f.id);
                          const allSelected = secFieldIds.every(id => selectedExtractionFieldIds.includes(id));
                          if (allSelected) {
                            setSelectedExtractionFieldIds(prev => prev.filter(id => !secFieldIds.includes(id)));
                          } else {
                            setSelectedExtractionFieldIds(prev => Array.from(new Set([...prev, ...secFieldIds])));
                          }
                        }}
                        className="text-[10px] text-blue-600 hover:underline font-semibold"
                      >
                        Toggle All Section
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {(sec.fields || []).map(field => {
                        const isChecked = selectedExtractionFieldIds.includes(field.id);
                        return (
                          <label
                            key={field.id}
                            className={`flex items-start space-x-2 p-2 rounded-lg border cursor-pointer transition-all ${
                              isChecked
                                ? 'bg-purple-50/80 border-purple-200 text-purple-950 font-semibold'
                                : 'bg-white border-slate-100 text-slate-600 hover:border-slate-300'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={isChecked}
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedExtractionFieldIds(prev => [...prev, field.id]);
                                } else {
                                  setSelectedExtractionFieldIds(prev => prev.filter(id => id !== field.id));
                                }
                              }}
                              className="w-4 h-4 text-purple-600 rounded border-slate-300 focus:ring-purple-500 mt-0.5"
                            />
                            <div className="flex flex-col">
                              <span className="text-xs leading-snug">{field.label}</span>
                              <span className="text-[9px] text-slate-400 font-mono">{field.type}</span>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))
              )}
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
              <Button variant="secondary" onClick={() => setIsConfigFieldsModalOpen(false)}>
                Cancel
              </Button>
              <Button
                variant="primary"
                onClick={handleSaveExtractionFields}
                disabled={isSavingConfig}
                className="bg-purple-600 hover:bg-purple-700 text-white font-bold"
              >
                {isSavingConfig ? 'Saving & Refreshing...' : 'Save & Refresh All Dossiers'}
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* MODAL 1: Candidate Dossier / Packet Modal                                  */}
      {/* ========================================================================= */}
      {isPacketModalOpen && selectedCandidate && (
        <Modal
          isOpen={isPacketModalOpen}
          onClose={() => {
            setIsPacketModalOpen(false);
            setSelectedCandidate(null);
          }}
          title="Candidate Verification Dossier"
          size="lg"
        >
          <div className="space-y-5">
            {/* Header with Photo & Name */}
            <div className="flex items-start gap-4 p-4 rounded-xl bg-slate-50 border border-slate-100">
              <div className="w-16 h-20 rounded-lg bg-purple-100 text-purple-700 flex items-center justify-center font-bold text-xl overflow-hidden border border-purple-200 shrink-0 shadow-xs">
                {selectedCandidate.photoUrl && !isFieldHiddenForRole('photo') ? (
                  <img
                    src={photoBlobUrls[selectedCandidate.id] || selectedCandidate.photoUrl}
                    alt={selectedCandidate.employeeName}
                    className="w-full h-full object-cover"
                  />
                ) : (
                  <UserIcon size={32} />
                )}
              </div>
              <div className="flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-black text-slate-900">{selectedCandidate.employeeName}</h3>
                  {getStatusBadge(selectedCandidate.status)}
                </div>
                <div className="text-xs text-slate-500 space-y-0.5 mt-1">
                  <div>Badge ID: <span className="font-mono font-bold text-slate-800">{selectedCandidate.employeeId}</span></div>
                  <div>Client Site: <span className="font-semibold text-purple-700">{selectedCandidate.siteName}</span></div>
                  <div>Designation: <span className="font-medium text-slate-700">{selectedCandidate.designation || 'Security Guard'}</span></div>
                </div>
              </div>
            </div>

            {/* Core Verification Essentials */}
            {(() => {
              const displayAadhaarDoc = selectedCandidate.aadhaarDocPath || (() => {
                for (const item of Object.values(selectedCandidate.customFields || {})) {
                  const entry = item as any;
                  if (entry?.label && (entry.label.toLowerCase().includes('aadhar') || entry.label.toLowerCase().includes('aadhaar'))) {
                    const v = entry.value;
                    if (typeof v === 'object' && v !== null) {
                      return (v as any).storagePath || (v as any).path || (v as any).url || (v as any).downloadUrl || '';
                    }
                    if (typeof v === 'string' && v.length > 5) return v;
                  }
                }
                return '';
              })();

              const displayDob = selectedCandidate.dob || (() => {
                for (const item of Object.values(selectedCandidate.customFields || {})) {
                  const entry = item as any;
                  if (entry?.label && (entry.label.toLowerCase().includes('birth') || entry.label.toLowerCase().includes('dob'))) return String(entry.value);
                }
                return 'Not provided';
              })();

              const displayFatherName = selectedCandidate.fatherName || (() => {
                for (const item of Object.values(selectedCandidate.customFields || {})) {
                  const entry = item as any;
                  if (entry?.label && entry.label.toLowerCase().includes('father')) return String(entry.value);
                }
                return 'Not provided';
              })();

              return (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  {!isFieldHiddenForRole('aadhaar') && (
                    <div className="p-3 rounded-lg border border-slate-100 bg-white">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">Aadhaar Card Number</span>
                      <span className="font-mono font-bold text-slate-800 text-sm">
                        {selectedCandidate.aadhaarNumber || 'Not provided'}
                      </span>
                      {displayAadhaarDoc ? (
                        <div className="mt-2">
                          <SecureDocumentLink
                            path={displayAadhaarDoc}
                            className="inline-flex items-center gap-1 text-[11px] font-bold text-purple-600 hover:text-purple-800"
                          >
                            <Eye size={12} /> View Uploaded Aadhaar Card (Private)
                          </SecureDocumentLink>
                        </div>
                      ) : null}
                    </div>
                  )}

                  {!isFieldHiddenForRole('phone') && (
                    <div className="p-3 rounded-lg border border-slate-100 bg-white">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">Contact Number</span>
                      <span className="font-semibold text-slate-800 text-sm">
                        {selectedCandidate.phoneNumber || 'Not provided'}
                      </span>
                    </div>
                  )}

                  {!isFieldHiddenForRole('dob') && (
                    <div className="p-3 rounded-lg border border-slate-100 bg-white">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">Date of Birth</span>
                      <span className="font-semibold text-slate-800">
                        {displayDob}
                      </span>
                    </div>
                  )}

                  {!isFieldHiddenForRole('fatherName') && (
                    <div className="p-3 rounded-lg border border-slate-100 bg-white">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">Father's Name</span>
                      <span className="font-semibold text-slate-800">
                        {displayFatherName}
                      </span>
                    </div>
                  )}

                  {!isFieldHiddenForRole('address') && selectedCandidate.permanentAddress && (
                    <div className="sm:col-span-2 p-3 rounded-lg border border-slate-100 bg-white">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">Permanent Address</span>
                      <span className="font-medium text-slate-700 leading-relaxed">
                        {selectedCandidate.permanentAddress}
                      </span>
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Additional Configured Custom Fields */}
            {selectedCandidate.customFields && Object.keys(selectedCandidate.customFields).length > 0 && (
              <div className="space-y-2 pt-2 border-t border-slate-100">
                <span className="text-[10px] uppercase font-extrabold text-slate-500 tracking-wider flex items-center gap-1">
                  <Sliders size={12} className="text-purple-600" /> Additional Configured Fields
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  {Object.entries(selectedCandidate.customFields).map(([fId, dataRaw]) => {
                    const data = dataRaw as { label: string; value: any; isFile?: boolean };
                    if (isFieldHiddenForRole(fId)) return null;

                    const raw = data.value;
                    const isObj = typeof raw === 'object' && raw !== null;
                    const docPath = isObj
                      ? (raw.storagePath || raw.path || raw.url || raw.downloadUrl || raw.fileUrl || '')
                      : (typeof raw === 'string' ? raw : '');
                    
                    const isDocument = data.isFile ||
                      (isObj && Boolean(raw.storagePath || raw.path || raw.url || raw.downloadUrl || raw.name)) ||
                      (typeof raw === 'string' && (raw.includes('firebasestorage') || raw.endsWith('.pdf') || raw.endsWith('.jpg') || raw.endsWith('.png')));

                    const docName = isObj && raw.name ? raw.name : undefined;

                    return (
                      <div key={fId} className="p-2.5 rounded-lg border border-slate-100 bg-slate-50/50">
                        <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider truncate mb-1">
                          {data.label}
                        </span>
                        {isDocument && docPath ? (
                          <div className="mt-1 flex items-center justify-between gap-2">
                            <SecureDocumentLink
                              path={docPath}
                              className="inline-flex items-center gap-1 text-[11px] font-bold text-purple-600 hover:text-purple-800"
                            >
                              <Eye size={12} /> View Document
                            </SecureDocumentLink>
                            {docName && <span className="text-[10px] text-slate-400 truncate max-w-[120px]" title={docName}>{docName}</span>}
                          </div>
                        ) : isObj ? (
                          <span className="font-medium text-slate-600 text-xs italic">
                            {raw.name || raw.label || 'Attached'}
                          </span>
                        ) : (
                          <span className="font-semibold text-slate-800 break-words">
                            {String(raw || 'Not provided')}
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Vendor Case Info if already dispatched */}
            {selectedCandidate.vendorName && !isVendor && (
              <div className="p-3 rounded-xl border border-blue-100 bg-blue-50/50 text-xs space-y-1">
                <div className="font-bold text-blue-900 flex items-center gap-1.5">
                  <Send size={14} className="text-blue-600" />
                  Vendor Assignment Details
                </div>
                <div className="text-blue-800">Vendor: <span className="font-semibold">{selectedCandidate.vendorName}</span></div>
                {selectedCandidate.vendorCaseId && <div className="text-blue-800">Case ID: <span className="font-mono">{selectedCandidate.vendorCaseId}</span></div>}
                {selectedCandidate.sentToVendorDate && <div className="text-blue-600 text-[11px]">Dispatched on: {new Date(selectedCandidate.sentToVendorDate).toLocaleString()}</div>}
                {selectedCandidate.notes && <div className="text-slate-600 text-[11px] pt-1">Notes: {selectedCandidate.notes}</div>}
              </div>
            )}

            {/* Actions */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-100">
              {canCopyDossier ? (
                <Button
                  variant="secondary"
                  onClick={() => handleCopyPacket(selectedCandidate)}
                  className="w-full sm:w-auto bg-purple-50 hover:bg-purple-100 text-purple-700 border-purple-200 font-bold"
                >
                  <Copy size={14} className="mr-1.5" />
                  {copiedCandidateId === selectedCandidate.id ? 'Copied to Clipboard!' : 'Copy Dossier for Email'}
                </Button>
              ) : <div />}

              <div className="flex gap-2 w-full sm:w-auto justify-end">
                <Button variant="secondary" onClick={() => setIsPacketModalOpen(false)}>
                  Close
                </Button>
              </div>
            </div>
          </div>
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* MODAL 2: Send to Vendor / Mark In-Progress                                 */}
      {/* ========================================================================= */}
      {isSendVendorModalOpen && selectedCandidate && (
        <Modal
          isOpen={isSendVendorModalOpen}
          onClose={() => {
            setIsSendVendorModalOpen(false);
            setSelectedCandidate(null);
          }}
          title="Dispatch Verification to 3rd-Party Vendor"
        >
          <form onSubmit={handleConfirmSendToVendor} className="space-y-4 text-xs">
            <div className="p-3 bg-blue-50 border border-blue-100 rounded-lg text-blue-900">
              Candidate: <strong>{selectedCandidate.employeeName}</strong> ({selectedCandidate.employeeId})
              <div className="text-[11px] text-blue-700 mt-0.5">Site: {selectedCandidate.siteName}</div>
            </div>

            <div className="p-3 bg-purple-50/60 border border-purple-200 rounded-xl flex items-center justify-between">
              <div>
                <span className="text-[10px] uppercase font-bold text-purple-700 tracking-wider block">Verification Agency</span>
                <span className="text-sm font-black text-slate-900 flex items-center gap-1.5 mt-0.5">
                  <Building size={14} className="text-purple-600 shrink-0" />
                  HP Investigative Service
                </span>
              </div>
              <span className="px-2.5 py-1 rounded-full bg-purple-100 text-purple-800 font-bold text-[10px] border border-purple-200">
                Official Agency
              </span>
            </div>

            <div>
              <label className="block font-bold text-slate-700 mb-1">Vendor Case Reference / Token ID (Optional)</label>
              <Input
                value={vendorCaseIdInput}
                onChange={e => setVendorCaseIdInput(e.target.value)}
                placeholder="e.g. HP-2026-98124"
              />
            </div>

            <div>
              <label className="block font-bold text-slate-700 mb-1">Internal Remarks / Tracking Notes</label>
              <textarea
                value={actionNotesInput}
                onChange={e => setActionNotesInput(e.target.value)}
                rows={3}
                placeholder="e.g. Packet emailed to HP Investigative Service coordinator. Awaiting turnaround."
                className="w-full p-2.5 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20"
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
              <Button variant="secondary" onClick={() => setIsSendVendorModalOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={isSubmittingAction} className="bg-blue-600 hover:bg-blue-700 text-white font-bold">
                {isSubmittingAction ? 'Updating...' : 'Confirm Dispatch to HP'}
              </Button>
            </div>
          </form>
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* MODAL 3: Direct Complete (Upload Certificate & Complete)                  */}
      {/* ========================================================================= */}
      {isDirectCompleteModalOpen && selectedCandidate && (
        <Modal
          isOpen={isDirectCompleteModalOpen}
          onClose={() => {
            setIsDirectCompleteModalOpen(false);
            setSelectedCandidate(null);
          }}
          title="Complete Verification & Upload Certificate"
        >
          <form onSubmit={handleConfirmDirectComplete} className="space-y-4 text-xs">
            <div className="p-3 bg-emerald-50 border border-emerald-100 rounded-lg text-emerald-900">
              Candidate: <strong>{selectedCandidate.employeeName}</strong> ({selectedCandidate.employeeId})
              <div className="text-[11px] text-emerald-700 mt-0.5">Site: {selectedCandidate.siteName}</div>
            </div>

            <div>
              <label className="block font-bold text-slate-700 mb-1">
                Upload BGV Clearance Certificate (PDF or Image) *
              </label>
              <input
                type="file"
                accept=".pdf,image/*"
                required
                onChange={e => setUploadedFile(e.target.files?.[0] || null)}
                className="w-full text-xs text-slate-500 file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-bold file:bg-emerald-50 file:text-emerald-700 hover:file:bg-emerald-100 cursor-pointer border border-slate-200 rounded-lg p-1"
              />
              {uploadedFile && (
                <div className="mt-1.5 flex items-center justify-between text-[11px] text-emerald-800 bg-emerald-50/70 px-2.5 py-1.5 rounded border border-emerald-100">
                  <span className="truncate max-w-[280px]">Selected: <strong>{uploadedFile.name}</strong></span>
                  <span className="font-semibold text-emerald-600">{(uploadedFile.size / 1024 / 1024).toFixed(2)} MB {uploadedFile.type === 'application/pdf' || uploadedFile.name.toLowerCase().endsWith('.pdf') ? '• Auto-Compressing PDF' : ''}</span>
                </div>
              )}
              <p className="text-[11px] text-slate-400 mt-1">This report will be securely archived and accessible strictly to authorized staff.</p>
            </div>

            <div>
              <label className="block font-bold text-slate-700 mb-1">Issuing Vendor Name</label>
              <Input
                value={vendorNameInput}
                onChange={e => setVendorNameInput(e.target.value)}
                placeholder="e.g. HP Investigative Service"
              />
            </div>

            <div>
              <label className="block font-bold text-slate-700 mb-1">Vendor Case Reference ID (Optional)</label>
              <Input
                value={vendorCaseIdInput}
                onChange={e => setVendorCaseIdInput(e.target.value)}
                placeholder="e.g. AB-2026-98124"
              />
            </div>

            <div>
              <label className="block font-bold text-slate-700 mb-1">Audit Remarks</label>
              <textarea
                value={actionNotesInput}
                onChange={e => setActionNotesInput(e.target.value)}
                rows={2}
                placeholder="e.g. All checks (criminal, address, identity) cleared green."
                className="w-full p-2.5 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-emerald-500/20"
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
              <Button variant="secondary" onClick={() => setIsDirectCompleteModalOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={isSubmittingAction || !uploadedFile} className="bg-emerald-600 hover:bg-emerald-700 text-white font-bold">
                {isSubmittingAction ? 'Optimizing & Uploading...' : 'Mark BGV Cleared & Completed'}
              </Button>
            </div>
          </form>
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* MODAL 4: Review Vendor Submission & Approve / Reject                      */}
      {/* ========================================================================= */}
      {isReviewModalOpen && selectedCandidate && (
        <Modal
          isOpen={isReviewModalOpen}
          onClose={() => {
            setIsReviewModalOpen(false);
            setSelectedCandidate(null);
          }}
          title="Review Vendor BGV Certificate"
          size="lg"
        >
          <div className="space-y-4 text-xs">
            <div className="p-3 bg-purple-50 border border-purple-100 rounded-lg text-purple-900">
              Candidate: <strong>{selectedCandidate.employeeName}</strong> ({selectedCandidate.employeeId})
              <div className="text-[11px] text-purple-700 mt-0.5">Site: {selectedCandidate.siteName} • Vendor: {selectedCandidate.vendorName || 'External Vendor'}</div>
            </div>

            {/* Certificate Preview Link */}
            {selectedCandidate.bgvDocumentUrl && (
              <div className="p-4 rounded-xl border border-slate-200 bg-slate-50 flex items-center justify-between">
                <div>
                  <div className="font-bold text-slate-800 flex items-center gap-1.5">
                    <FileText size={16} className="text-purple-600" />
                    Uploaded Report: {selectedCandidate.bgvDocumentName || 'BGV_Certificate.pdf'}
                  </div>
                  {selectedCandidate.vendorSubmittedDate && (
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      Submitted on {new Date(selectedCandidate.vendorSubmittedDate).toLocaleString()}
                    </div>
                  )}
                </div>
                <SecureDocumentLink
                  fileUrl={selectedCandidate.bgvDocumentUrl}
                  className="px-3 py-1.5 rounded-lg bg-purple-600 text-white font-bold hover:bg-purple-700 transition-colors inline-flex items-center gap-1.5 shadow-xs"
                >
                  <Eye size={14} /> Open Private Document
                </SecureDocumentLink>
              </div>
            )}

            {/* Vendor notes */}
            {selectedCandidate.notes && (
              <div className="p-3 rounded-lg border border-slate-100 bg-white">
                <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider mb-1">Vendor Remarks</span>
                <p className="text-slate-700 italic">{selectedCandidate.notes}</p>
              </div>
            )}

            {/* Approval Notes */}
            <div>
              <label className="block font-bold text-slate-700 mb-1">Staff Verification Notes (Optional)</label>
              <textarea
                value={actionNotesInput}
                onChange={e => setActionNotesInput(e.target.value)}
                rows={2}
                placeholder="e.g. Certificate verified against original details. Approved for client site."
                className="w-full p-2.5 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500/20"
              />
            </div>

            {/* Flag Adverse / Rejection Option */}
            <div className="pt-2 border-t border-slate-100">
              <label className="block font-bold text-rose-700 mb-1">If Rejecting / Flagging Adverse Findings:</label>
              <textarea
                value={rejectionReasonInput}
                onChange={e => setRejectionReasonInput(e.target.value)}
                rows={2}
                placeholder="Enter adverse findings or reason for rejection (e.g. Identity mismatch, criminal record found)..."
                className="w-full p-2.5 border border-rose-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-rose-500/20 bg-rose-50/30 text-rose-900"
              />
            </div>

            {/* Action Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 border-t border-slate-100">
              <Button
                variant="secondary"
                onClick={handleRejectVendorReport}
                disabled={isSubmittingAction || !rejectionReasonInput.trim()}
                className="w-full sm:w-auto bg-rose-50 hover:bg-rose-100 text-rose-700 border-rose-200 font-bold"
              >
                <ShieldAlert size={14} className="mr-1.5" /> Flag Adverse / Reject
              </Button>

              <div className="flex gap-2 w-full sm:w-auto justify-end">
                <Button variant="secondary" onClick={() => setIsReviewModalOpen(false)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleApproveVendorReport}
                  disabled={isSubmittingAction}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white font-bold"
                >
                  <CheckCircle2 size={14} className="mr-1.5" /> Approve & Mark Cleared
                </Button>
              </div>
            </div>
          </div>
        </Modal>
      )}

      {/* ========================================================================= */}
      {/* MODAL 5: Vendor Self-Submission Modal                                     */}
      {/* ========================================================================= */}
      {isVendorSubmitModalOpen && selectedCandidate && (
        <Modal
          isOpen={isVendorSubmitModalOpen}
          onClose={() => {
            setIsVendorSubmitModalOpen(false);
            setSelectedCandidate(null);
          }}
          title="Submit Verification Report (Vendor Portal)"
        >
          <form onSubmit={handleConfirmVendorSubmission} className="space-y-4 text-xs">
            <div className="p-3 bg-purple-50 border border-purple-100 rounded-lg text-purple-900">
              Candidate: <strong>{selectedCandidate.employeeName}</strong> ({selectedCandidate.employeeId})
              <div className="text-[11px] text-purple-700 mt-0.5">Site: {selectedCandidate.siteName}</div>
            </div>

            <div>
              <label className="block font-bold text-slate-700 mb-1">
                Upload Verification Certificate / Report (PDF or Image) *
              </label>
              <input
                type="file"
                accept=".pdf,image/*"
                required
                onChange={e => setUploadedFile(e.target.files?.[0] || null)}
                className="w-full text-xs text-slate-500 file:mr-3 file:py-2 file:px-3 file:rounded-lg file:border-0 file:text-xs file:font-bold file:bg-purple-50 file:text-purple-700 hover:file:bg-purple-100 cursor-pointer border border-slate-200 rounded-lg p-1"
              />
              {uploadedFile && (
                <div className="mt-1.5 flex items-center justify-between text-[11px] text-purple-800 bg-purple-50/70 px-2.5 py-1.5 rounded border border-purple-100">
                  <span className="truncate max-w-[280px]">Selected: <strong>{uploadedFile.name}</strong></span>
                  <span className="font-semibold text-purple-600">{(uploadedFile.size / 1024 / 1024).toFixed(2)} MB {uploadedFile.type === 'application/pdf' || uploadedFile.name.toLowerCase().endsWith('.pdf') ? '• Auto-Compressing PDF' : ''}</span>
                </div>
              )}
            </div>

            <div>
              <label className="block font-bold text-slate-700 mb-1">Vendor Remarks / Clearance Summary</label>
              <textarea
                value={actionNotesInput}
                onChange={e => setActionNotesInput(e.target.value)}
                rows={3}
                placeholder="e.g. Criminal, Identity, and Address checks completed successfully with no adverse records."
                className="w-full p-2.5 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-purple-500/20"
              />
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-slate-100">
              <Button variant="secondary" onClick={() => setIsVendorSubmitModalOpen(false)}>
                Cancel
              </Button>
              <Button
                type="submit"
                variant="primary"
                disabled={isSubmittingAction || !uploadedFile}
                className="bg-purple-600 hover:bg-purple-700 text-white font-bold"
              >
                {isSubmittingAction ? 'Optimizing & Submitting...' : 'Submit Report for Staff Review'}
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </div>
  );
};

export default AdminBgvManagementPage;
