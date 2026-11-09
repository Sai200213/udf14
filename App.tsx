import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';

// SECURITY: Enforce official custom domain to prevent Cloudflare WAF bypass via .web.app or .firebaseapp.com
if (typeof window !== 'undefined') {
  const h = window.location.hostname;
  if (h && (h.endsWith('.web.app') || h.endsWith('.firebaseapp.com') || h.includes('.web.app') || h.includes('.firebaseapp.com'))) {
    let target = 'udfonline.in';
    if (h.includes('-admin')) target = 'admin.udfonline.in';
    else if (h.includes('-employee')) target = 'employee.udfonline.in';
    window.location.replace('https://' + target + window.location.pathname + window.location.search + window.location.hash);
  }
}

import { v4 as uuidv4 } from 'uuid';
import toast from 'react-hot-toast';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from './src/context/AuthContext';
import { useData } from './src/contexts/DataContext';
import { useNotifications } from './src/contexts/NotificationContext';
import AppRoutes from './src/routes/AppRoutes';
import CookieConsent from './components/common/CookieConsent';
import {
  FormSection, FormField, SubmittedFormData, SubmissionStatus, User, UserType,
  LeaveRequest, AccountUpdateRequest, ResignationRequest, RequestStatus, FieldType,
  Role, StaffUser, Permission, WorkflowConfig, ApprovalHistoryEntry, Site,
  LeaveBalance, LeaveType, DisciplinaryAction, DisciplinaryActionType, LeavePolicy, PortalConfig, Notification
} from './types';
import { logSystemAction } from './src/services/auditService';
import { getApplicantName } from './utils/formDataHelper';
import Button from './components/common/Button';
import Input from './components/common/Input';
import Modal from './components/common/Modal';
import { ArrowLeft, ShieldAlert, ChevronRight, RotateCcw, Trash2, Loader2, Lock, ShieldCheck, Clock } from 'lucide-react';
import { useFormBuilder } from './hooks/useFormBuilder';
import {
  defaultRoles,
  defaultStaff,
  defaultWorkflows,
  defaultSites,
  defaultFormSections,
  defaultEditableFields,
  defaultLeavePolicy,
  defaultPortalConfig
} from './src/constants/defaults';

// Firebase Services
import { loginUser, logoutUser, getCurrentUser, loginWithGoogle } from './src/services/authService';
import {
  submitEmployeeForm,
  subscribeToSubmissions,
  subscribeToEmployees,
  updateSubmissionStatus,
  updateEmployeeLeaveBalance,
  uploadToDrive,
  updateSubmissionEmployeeId,
  revertSubmissionWorkflow, deleteSubmission,
  saveFormDraft, getFormDraft, deleteFormDraft, discardFormDraft,
  softDeleteSubmission, softDeleteEmployee, restoreEmployee,
  subscribeToEmployeeByUid, subscribeToSubmissionsByUid, syncDriveFolder,
  bulkSoftDeleteSubmissions, bulkPermanentDeleteSubmissions,
  deleteWorkflowRequest, deleteDisciplinaryAction,
  findSubmissionIdByEmployeeId, permanentDeleteEmployee, getEmployeeRecordCounts, checkEmployeeIdExists,
  resolveEmployeeFullContext, EmployeeFullContext,
  relieveEmployee, rejoinEmployee, isPortalId, setEmployeeNoticePeriod
} from './src/services/employeeService';
import { uploadSubmissionDocument } from './src/services/storageService';
import { FirestoreEmployee } from './types';
import {
  seedInitialData,
  subscribeToRoles, updateRoles,
  subscribeToSites, updateSites,
  subscribeToWorkflows, updateWorkflows,
  subscribeToPortalConfig, updatePortalConfig,
  subscribeToFormSections, updateFormSections,
  subscribeToEditableFields, updateEditableFields,
  subscribeToLeavePolicy, updateLeavePolicy,
  subscribeToStaffUsers, updateStaffUsers
} from './src/services/adminService';
import {
  submitLeaveRequest, updateLeaveRequest,
  submitAccountUpdateRequest, updateAccountUpdateRequest,
  submitResignationRequest, updateResignationRequest, processDueResignations,
  addDisciplinaryAction,
  revertWorkflowRequest
} from './src/services/requestService';
import { doc, getDoc, setDoc, updateDoc, onSnapshot, collection, query, where, getDocs, deleteDoc, addDoc, serverTimestamp } from 'firebase/firestore';
import { db, auth } from './src/firebase/config';
import log from './src/utils/logger';
import { onAuthStateChanged } from 'firebase/auth';
import { getEffectiveApprovalLevel } from './src/utils/workflowHelper';


export enum AppView {
  LANDING = 'LANDING',
  SETUP_ACCOUNT = 'SETUP_ACCOUNT', // NEW
  // Admin Views
  ADMIN_LOGIN = 'ADMIN_LOGIN',
  ADMIN_DASHBOARD = 'ADMIN_DASHBOARD', // NEW
  ADMIN_AUDIT_LOGS = 'ADMIN_AUDIT_LOGS', // NEW
  ADMIN_PORTAL_FORM_BUILDER = 'ADMIN_PORTAL_FORM_BUILDER',
  ADMIN_PORTAL_SUBMISSION_REVIEW = 'ADMIN_PORTAL_SUBMISSION_REVIEW',
  ADMIN_PORTAL_LEAVE_MANAGEMENT = 'ADMIN_PORTAL_LEAVE_MANAGEMENT',
  ADMIN_PORTAL_ACCOUNT_UPDATE_MANAGEMENT = 'ADMIN_PORTAL_ACCOUNT_UPDATE_MANAGEMENT',
  ADMIN_PORTAL_RESIGNATION_MANAGEMENT = 'ADMIN_PORTAL_RESIGNATION_MANAGEMENT',
  ADMIN_PORTAL_DISCIPLINARY_MANAGEMENT = 'ADMIN_PORTAL_DISCIPLINARY_MANAGEMENT',
  ADMIN_PORTAL_STAFF_MANAGEMENT = 'ADMIN_PORTAL_STAFF_MANAGEMENT',
  ADMIN_PORTAL_ROLE_MANAGEMENT = 'ADMIN_PORTAL_ROLE_MANAGEMENT',
  ADMIN_PORTAL_WORKFLOW_CONFIG = 'ADMIN_PORTAL_WORKFLOW_CONFIG',
  ADMIN_PORTAL_PORTAL_MODULES = 'ADMIN_PORTAL_PORTAL_MODULES',
  ADMIN_PORTAL_SITE_MANAGEMENT = 'ADMIN_PORTAL_SITE_MANAGEMENT',
  ADMIN_PORTAL_PROFILE = 'ADMIN_PORTAL_PROFILE',
  ADMIN_PORTAL_CLIENT_ID_LIBRARY = 'ADMIN_PORTAL_CLIENT_ID_LIBRARY',
  ADMIN_PORTAL_MASTER_EMPLOYEE_LIST = 'ADMIN_PORTAL_MASTER_EMPLOYEE_LIST',
  ADMIN_PORTAL_DRAFTS = 'ADMIN_PORTAL_DRAFTS',
  ADMIN_PORTAL_CORRECTION_REQUESTS = 'ADMIN_PORTAL_CORRECTION_REQUESTS',
  ADMIN_PORTAL_TIMELINE_SEARCH = 'ADMIN_PORTAL_TIMELINE_SEARCH',
  ADMIN_VACANCY_MANAGER = 'ADMIN_VACANCY_MANAGER',
  ADMIN_PORTAL_EMPLOYEE_TIMELINE = 'ADMIN_PORTAL_EMPLOYEE_TIMELINE',
  ADMIN_PORTAL_INVITES = 'ADMIN_PORTAL_INVITES',
  ADMIN_PORTAL_WEBSITE_MANAGER = 'ADMIN_PORTAL_WEBSITE_MANAGER',
  ADMIN_LEGACY_SYSTEMS = 'ADMIN_LEGACY_SYSTEMS',
  ADMIN_PORTAL_BGV_MANAGEMENT = 'ADMIN_PORTAL_BGV_MANAGEMENT',
  ADMIN_PORTAL_GRIEVANCES = 'ADMIN_PORTAL_GRIEVANCES',
  ADMIN_PORTAL_RECYCLE_BIN = 'ADMIN_PORTAL_RECYCLE_BIN',
  // Employee Views
  EMPLOYEE_LOGIN = 'EMPLOYEE_LOGIN',
  EMPLOYEE_DASHBOARD = 'EMPLOYEE_DASHBOARD',
  EMPLOYEE_PROFILE = 'EMPLOYEE_PROFILE',
  EMPLOYEE_LEAVE_REQUESTS = 'EMPLOYEE_LEAVE_REQUESTS',
  EMPLOYEE_ACCOUNT_UPDATES = 'EMPLOYEE_ACCOUNT_UPDATES',
  EMPLOYEE_RESIGNATION = 'EMPLOYEE_RESIGNATION',
  EMPLOYEE_DISCIPLINARY = 'EMPLOYEE_DISCIPLINARY',
  // New Joiner
  EMPLOYEE_JOINING_FORM = 'EMPLOYEE_JOINING_FORM',
  DOCUMENT_UPLOAD = 'DOCUMENT_UPLOAD',
}

export const ADMIN_TAB_SLUGS: Record<string, AppView> = {
  'dashboard': AppView.ADMIN_DASHBOARD,
  'invites': AppView.ADMIN_PORTAL_INVITES,
  'employees': AppView.ADMIN_PORTAL_MASTER_EMPLOYEE_LIST,
  'submissions': AppView.ADMIN_PORTAL_SUBMISSION_REVIEW,
  'leaves': AppView.ADMIN_PORTAL_LEAVE_MANAGEMENT,
  'updates': AppView.ADMIN_PORTAL_ACCOUNT_UPDATE_MANAGEMENT,
  'resignations': AppView.ADMIN_PORTAL_RESIGNATION_MANAGEMENT,
  'disciplinary': AppView.ADMIN_PORTAL_DISCIPLINARY_MANAGEMENT,
  'staff': AppView.ADMIN_PORTAL_STAFF_MANAGEMENT,
  'roles': AppView.ADMIN_PORTAL_ROLE_MANAGEMENT,
  'workflows': AppView.ADMIN_PORTAL_WORKFLOW_CONFIG,
  'sites': AppView.ADMIN_PORTAL_SITE_MANAGEMENT,
  'vacancies': AppView.ADMIN_VACANCY_MANAGER,
  'form-builder': AppView.ADMIN_PORTAL_FORM_BUILDER,
  'drafts': AppView.ADMIN_PORTAL_DRAFTS,
  'corrections': AppView.ADMIN_PORTAL_CORRECTION_REQUESTS,
  'timeline': AppView.ADMIN_PORTAL_TIMELINE_SEARCH,
  'employee-timeline': AppView.ADMIN_PORTAL_EMPLOYEE_TIMELINE,
  'audit-logs': AppView.ADMIN_AUDIT_LOGS,
  'website': AppView.ADMIN_PORTAL_WEBSITE_MANAGER,
  'legacy': AppView.ADMIN_LEGACY_SYSTEMS,
  'profile': AppView.ADMIN_PORTAL_PROFILE,
  'bgv': AppView.ADMIN_PORTAL_BGV_MANAGEMENT,
  'grievances': AppView.ADMIN_PORTAL_GRIEVANCES,
  'recycle-bin': AppView.ADMIN_PORTAL_RECYCLE_BIN,
  'modules': AppView.ADMIN_PORTAL_PORTAL_MODULES,
  'portal-modules': AppView.ADMIN_PORTAL_PORTAL_MODULES,
  'client-ids': AppView.ADMIN_PORTAL_CLIENT_ID_LIBRARY,
  'client-id-library': AppView.ADMIN_PORTAL_CLIENT_ID_LIBRARY,
};

export const SLUG_BY_ADMIN_VIEW: Record<string, string> = Object.entries(ADMIN_TAB_SLUGS).reduce(
  (acc, [slug, view]) => ({ ...acc, [view]: slug }),
  {}
);

const App: React.FC = () => {
  const [currentView, setCurrentView] = useState<AppView>(() => {
    const appTarget = (import.meta as any).env?.VITE_APP_TARGET;
    
    // 1. Resolve from URL query parameter ?tab= or ?view=
    try {
      const searchParams = new URLSearchParams(window.location.search);
      const tabParam = searchParams.get('tab') || searchParams.get('view');
      if (tabParam) {
        const lower = tabParam.toLowerCase();
        if (ADMIN_TAB_SLUGS[lower]) {
          return ADMIN_TAB_SLUGS[lower];
        }
        if (Object.values(AppView).includes(tabParam as AppView)) {
          return tabParam as AppView;
        }
      }
    } catch (e) {}

    // 2. Resolve from sessionStorage memory
    try {
      if (appTarget === 'admin') {
        const saved = sessionStorage.getItem('activeAdminView') as AppView;
        if (saved && Object.values(AppView).includes(saved) && saved.startsWith('ADMIN_')) {
          return saved;
        }
        return AppView.ADMIN_DASHBOARD;
      }
      if (appTarget === 'employee') {
        const saved = sessionStorage.getItem('activeEmployeeView') as AppView;
        if (saved && Object.values(AppView).includes(saved) && saved.startsWith('EMPLOYEE_')) {
          return saved;
        }
        return AppView.EMPLOYEE_DASHBOARD;
      }
    } catch (e) {}

    if (appTarget === 'admin') return AppView.ADMIN_DASHBOARD;
    if (appTarget === 'employee') return AppView.EMPLOYEE_DASHBOARD;
    return AppView.LANDING;
  });

  const [adminUsername, setAdminUsername] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [adminLoginError, setAdminLoginError] = useState('');
  const [showTroubleshoot, setShowTroubleshoot] = useState(false);
  const [connectivityStatus, setConnectivityStatus] = useState<Record<string, 'Testing' | 'Success' | 'Fail'>>({});
  const [timelineEmployeeId, setTimelineEmployeeId] = useState<string | null>(() => {
    try {
      return sessionStorage.getItem('activeTimelineEmployeeId');
    } catch {
      return null;
    }
  });

  // Get auth state from AuthContext
  const { user: authUser, loading: authLoading, setUser: setAuthUser } = useAuth();
  const [sessionExpiredInfo, setSessionExpiredInfo] = useState<{ isOpen: boolean; minutes: number } | null>(null);
  const navigate = useNavigate();
  const location = useLocation();

  // Keep currentView aligned with route on load / reload or browser navigation
  useEffect(() => {
    const path = location.pathname;
    const searchParams = new URLSearchParams(location.search);
    const tabParam = searchParams.get('tab') || searchParams.get('view');

    if (tabParam) {
      const lower = tabParam.toLowerCase();
      const resolved = ADMIN_TAB_SLUGS[lower] || (Object.values(AppView).includes(tabParam as AppView) ? tabParam as AppView : null);
      if (resolved) {
        setCurrentView(resolved);
        try {
          if (resolved.startsWith('ADMIN_')) sessionStorage.setItem('activeAdminView', resolved);
          else if (resolved.startsWith('EMPLOYEE_')) sessionStorage.setItem('activeEmployeeView', resolved);
        } catch (e) {}
        return;
      }
    }

    if (path === '/dashboard' || path === '/admin' || path === '/admin/dashboard') {
      if (authUser?.type === UserType.ADMIN || (import.meta as any).env?.VITE_APP_TARGET === 'admin') {
        setCurrentView(AppView.ADMIN_DASHBOARD);
        try {
          sessionStorage.setItem('activeAdminView', AppView.ADMIN_DASHBOARD);
        } catch (e) {}
      }
    }
  }, [location.pathname, location.search, authUser?.type]);

  // Dynamic SEO canonical tag updates on route change
  useEffect(() => {
    let canonical = document.querySelector("link[rel='canonical']");
    if (!canonical) {
      canonical = document.createElement('link');
      canonical.setAttribute('rel', 'canonical');
      document.head.appendChild(canonical);
    }
    const cleanPath = location.pathname === '/' ? '' : location.pathname;
    canonical.setAttribute('href', `https://udfonline.in${cleanPath}`);
  }, [location.pathname]);

  const [isLoading, setIsLoading] = useState(true);

  // Debug: Track recursive render count (safeguard)
  const renderCount = useRef(0);
  const lastRenderReset = useRef(Date.now());
  useEffect(() => {
    const now = Date.now();
    if (now - lastRenderReset.current > 1000) {
      renderCount.current = 0;
      lastRenderReset.current = now;
    }
    renderCount.current++;
    if (renderCount.current > 50) {
      log.error('Infinite render detected in App.tsx (over 50 renders in a single second)');
    }
  });

  const isSuperAdmin = useMemo(() => {
    if (!authUser) return false;
    // Super Admin means: 
    // 1. Hardcoded ID (legacy/emergency)
    // 2. Role ID is 'role-super-admin' 
    return authUser.id === 'super-admin' ||
      authUser.roleId === 'role-super-admin';
  }, [authUser]);

  // Get data from DataContext
  const {
    submittedForms, setSubmittedForms,
    leaveRequests, setLeaveRequests,
    accountUpdateRequests, setAccountUpdateRequests,
    resignationRequests, setResignationRequests,
    disciplinaryActions, setDisciplinaryActions,
    leaveBalances, setLeaveBalances,
    employees, setEmployees,
    drafts,
    notifications,
    roles,
    staffUsers,
    workflowConfigs,
    sites,
    sections: formSections,
    editableFieldIds,
    leavePolicy,
    portalConfig,
    allowedSiteIds,
    isRolesLoaded,
    isSitesLoaded,
    isStaffLoaded,
    setRoles,
    setStaffUsers,
    setWorkflowConfigs,
    setSites,
    setSections: setFormSections,
    setEditableFieldIds,
    setLeavePolicy,
    setPortalConfig,
    refreshGlobalStats
  } = useData();

  // Resolve employee data from submissions or primary employee record
  const employeeData = useMemo(() => {
    if (!authUser || authUser.type !== UserType.EMPLOYEE) return null;

    const authEmployeeId = (authUser as any).employeeId;

    // 1. Try to find in master employee records FIRST (Source of truth for approved docs)
    // Check authUser.id AND authUser.employeeId since authUser.id can be a submission ID (e.g. SUB-xxx)
    const emp = employees.find(e =>
      e.id === authUser.id || e.uid === authUser.id || e.employeeId === authUser.id ||
      (authEmployeeId && (e.id === authEmployeeId || e.employeeId === authEmployeeId))
    );
    if (emp) {
      // Spread emp first, then override specific fields for SubmittedFormData compatibility
      return {
        ...emp,
        id: emp.id || emp.employeeId,
        employeeId: emp.employeeId,
        data: emp.profileData || (emp as any).data || {},
      } as unknown as SubmittedFormData;
    }

    // 2. Fallback to onboarding submissions (For pending self-onboarded users)
    const sub = submittedForms.find(sf => sf.id === authUser.id || (sf as any).uid === authUser.id || sf.employeeId === authUser.id);
    if (sub) {
      return {
        ...sub,
        data: sub.data || (sub as any).formData || {}
      } as SubmittedFormData;
    }

    return null;
  }, [authUser, submittedForms, employees]);

  const [activeDraft, setActiveDraft] = useState<{ id: string; data: any; sectionIndex: number; inviteId?: string | null } | null>(null);

  // --- INTERACTIVE DELETION STATE ---
  const [deletionSummary, setDeletionSummary] = useState<{ id: string, name: string, counts: Record<string, number>, context?: EmployeeFullContext } | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [scanLoading, setScanLoading] = useState<{ isScanning: boolean; name?: string; targetId?: string } | null>(null);

  // CRITICAL: Ref-based state tracking to prevent stale closures in async firestore handlers
  const sectionsRef = React.useRef<FormSection[]>(formSections);

  useEffect(() => {
    sectionsRef.current = formSections;
  }, [formSections]);

  // Roles ref: always holds latest roles without being a reactive dependency
  // (roles array gets a new reference on every Firestore snapshot — putting it in a
  // useEffect dep array would cause infinite re-subscriptions and ERR_INSUFFICIENT_RESOURCES)
  const rolesRef = useRef<any[]>(roles);
  useEffect(() => { rolesRef.current = roles; }, [roles]);

  // Get notifications from NotificationContext
  const {
    sendNotification,
    markNotificationAsRead,
    markAllNotificationsAsRead
  } = useNotifications();

  // Hydration Gate: Hold loading state until real permissions and site scoping arrive from Firestore
  useEffect(() => {
    if (authLoading) return;

    // Unauthenticated visitors, Guests, or Employees don't require staff/roles hydration
    if (!authUser || authUser.type === UserType.EMPLOYEE) {
      setIsLoading(false);
      return;
    }

    // Super Admin bypasses roles and only needs sites loaded
    if (isSuperAdmin) {
      if (isSitesLoaded) {
        setIsLoading(false);
      }
      return;
    }

    // Management / Staff accounts (HR Manager, Field Officer, Manager, etc.)
    // Wait until real roles, sites, and staff are loaded so zero flickers occur
    if (isRolesLoaded && isSitesLoaded && isStaffLoaded) {
      setIsLoading(false);
    }
  }, [authLoading, authUser, isSuperAdmin, isRolesLoaded, isSitesLoaded, isStaffLoaded]);

  // Safety fallback: Never keep user stuck on loading screen longer than 4s if network is slow/offline
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsLoading(false);
    }, 4000);
    return () => clearTimeout(timer);
  }, []);

  const testConnectivity = useCallback(async () => {
    const domains = {
      'Firestore API': 'https://firestore.googleapis.com',
      'Firebase Auth API': 'https://www.googleapis.com/identitytoolkit',
      'App Domain': window.location.origin
    };

    const results: Record<string, 'Testing' | 'Success' | 'Fail'> = {};
    for (const [name, url] of Object.entries(domains)) {
      results[name] = 'Testing';
      setConnectivityStatus({ ...results });
      try {
        // Use a simple HEAD request to check availability without triggering 400/403 errors on specific API paths
        await fetch(url, { mode: 'no-cors', method: 'HEAD' });
        results[name] = 'Success';
      } catch (e) {
        results[name] = 'Fail';
      }
      setConnectivityStatus({ ...results });
    }
  }, []);

  // Loading Timeout for Troubleshoot UI
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isLoading) {
      timer = setTimeout(() => {
        setShowTroubleshoot(true);
        testConnectivity();
      }, 10000); // 10 seconds
    } else {
      setShowTroubleshoot(false);
    }
    return () => clearTimeout(timer);
  }, [isLoading, testConnectivity]);

  // Removed local editableFieldIds state (moved to persistent state)
  // Notification functions are now provided by NotificationContext

  const notifyRole = useCallback((roleId: string, message: string, type: 'success' | 'error' | 'info' = 'info', link?: AppView, targetSiteId?: string) => {
    const targets = staffUsers.filter(u => {
      if (u.roleId !== roleId) return false;
      if (targetSiteId) {
        const isManaged = u.sitesManaged?.includes(targetSiteId);
        const isSupervisor = sites.some(s => s.id === targetSiteId && s.supervisorId === u.id);
        return isManaged || isSupervisor;
      }
      return true;
    });
    if (targets.length > 0) {
      targets.forEach(t => sendNotification(t.id, message, type, link));
    } else {
      // Fallback for employee/candidate sessions where staffUsers list is empty (UDF13-09)
      sendNotification(`ROLE:${roleId}`, message, type, link);
    }
  }, [staffUsers, sites, sendNotification]);

  // SMART NOTIFICATION HELPER
  const notifyApprovers = useCallback((employeeId: string, targetRoleId: string, message: string, link?: AppView, directSiteId?: string) => {
    let site = directSiteId ? sites.find(s => s.id === directSiteId || s.name === directSiteId) : undefined;
    
    if (!site && employeeData && (employeeData.employeeId === employeeId || employeeData.id === employeeId)) {
      const empSite = employeeData.currentSiteId || employeeData.siteId || employeeData.unit;
      if (empSite) site = sites.find(s => s.id === empSite || s.name === empSite);
    }

    if (!site) {
      const employeeForm = submittedForms.find(f => f.employeeId === employeeId || f.id === employeeId);
      if (employeeForm && employeeForm.data) {
        const sections = employeeForm.originalFormSections || [];
        const unitField = sections
          .flatMap(s => s.fields || [])
          .find(f => f && f.label && (f.label.toLowerCase().includes('unit') || f.label.toLowerCase().includes('facility')));
        const unitName = unitField ? String(employeeForm.data[unitField.id] || '') : '';
        site = sites.find(s => s.name === unitName || s.id === unitName);
      }
    }

    if (site && site.supervisorId) {
      const supervisor = staffUsers.find(s => s.id === site!.supervisorId);
      if (supervisor && supervisor.roleId === targetRoleId) {
        sendNotification(supervisor.id, message, 'info', link);
        return;
      }
    }
    notifyRole(targetRoleId, message, 'info', link, site?.id);
  }, [submittedForms, sites, staffUsers, employeeData, notifyRole, sendNotification]);

  // Persistent Admin Handlers
  const handleUpdateRoles = async (newRoles: Role[] | ((prev: Role[]) => Role[])) => {
    const updated = typeof newRoles === 'function' ? newRoles(roles) : newRoles;
    await updateRoles(updated);
  };
  const handleUpdateSites = async (newSites: Site[] | ((prev: Site[]) => Site[])) => {
    const updated = typeof newSites === 'function' ? newSites(sites) : newSites;
    await updateSites(updated);
  };
  const handleUpdateWorkflows = async (newConfigs: WorkflowConfig[] | ((prev: WorkflowConfig[]) => WorkflowConfig[])) => {
    const updated = typeof newConfigs === 'function' ? newConfigs(workflowConfigs) : newConfigs;
    await updateWorkflows(updated);
  };
  const handleUpdatePortalConfig = async (newCfg: PortalConfig | ((prev: PortalConfig) => PortalConfig)) => {
    const updated = typeof newCfg === 'function' ? newCfg(portalConfig) : newCfg;
    await updatePortalConfig(updated);
  };
  const handleUpdateEditableFields = async (newIds: string[] | ((prev: string[]) => string[])) => {
    const updated = typeof newIds === 'function' ? newIds(editableFieldIds) : newIds;
    await updateEditableFields(updated);
  };
  const handleUpdateStaffUsers = async (newStaff: StaffUser[] | ((prev: StaffUser[]) => StaffUser[])) => {
    const updated = typeof newStaff === 'function' ? newStaff(staffUsers) : newStaff;
    await updateStaffUsers(updated);
  };
  const handleUpdateLeavePolicy = async (newPol: LeavePolicy | ((prev: LeavePolicy) => LeavePolicy)) => {
    const updatedPolicy = typeof newPol === 'function' ? newPol(leavePolicy) : newPol;
    await updateLeavePolicy(updatedPolicy);
    logSystemAction('UPDATE', 'SYSTEM', `Updated leave policy quotas.`);
    setLeaveBalances(prevBalances => prevBalances.map(empBalance => {
      const newBalances = { ...empBalance.balances };
      updatedPolicy.leaveTypes.forEach(policyType => {
        if (newBalances[policyType.typeId]) {
          newBalances[policyType.typeId] = { ...newBalances[policyType.typeId], total: policyType.defaultQuota };
        } else {
          newBalances[policyType.typeId] = { total: policyType.defaultQuota, used: 0 };
        }
      });
      const activeTypeIds = updatedPolicy.leaveTypes.map(t => t.typeId);
      Object.keys(newBalances).forEach(key => { if (!activeTypeIds.includes(key)) delete newBalances[key]; });
      return { ...empBalance, balances: newBalances };
    }));
  };

  // Universal Log Action (Replaced logAdminAction)
  // Imported from auditService

  // --- Persistent Form Builder Helpers (Ref-safe) ---
  const addSection = useCallback(async (name: string) => {
    try {
      sendNotification(authUser?.id || 'admin', `Saving section "${name}"...`, 'info');
      const current = sectionsRef.current;
      const newSection: FormSection = { id: uuidv4(), name, order: current.length, fields: [], isDisabled: false };
      const nextSections = [...current, newSection];
      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Section "${name}" saved!`, 'success');
    } catch (err: any) {
      sendNotification(authUser?.id || 'admin', `Failed to save section: ${err.message}`, 'error');
    }
  }, [authUser]);

  const updateSectionName = useCallback(async (id: string, name: string) => {
    try {
      sendNotification(authUser?.id || 'admin', `Saving section name...`, 'info');
      const nextSections = sectionsRef.current.map(s => s.id === id ? { ...s, name } : s);
      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Section renamed to "${name}".`, 'success');
    } catch (err: any) {
      sendNotification(authUser?.id || 'admin', `Failed to rename section: ${err.message}`, 'error');
    }
  }, [authUser]);

  const deleteSection = useCallback(async (id: string) => {
    if (!window.confirm("Are you sure? This will delete all fields in this section.")) return;
    try {
      sendNotification(authUser?.id || 'admin', `Deleting section...`, 'info');
      const nextSections = sectionsRef.current.filter(s => s.id !== id).map((s, i) => ({ ...s, order: i }));
      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Section deleted successfully.`, 'success');
    } catch (err: any) {
      sendNotification(authUser?.id || 'admin', `Failed to delete section: ${err.message}`, 'error');
    }
  }, [authUser]);

  const toggleSectionStatus = useCallback(async (id: string) => {
    try {
      const current = sectionsRef.current;
      const target = current.find(s => s.id === id);
      if (!target) return;
      const newState = !target.isDisabled;
      sendNotification(authUser?.id || 'admin', `${newState ? 'Disabling' : 'Enabling'} section...`, 'info');
      const nextSections = current.map(s => s.id === id ? { ...s, isDisabled: newState } : s);
      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Section ${newState ? 'disabled' : 'enabled'}.`, 'success');
    } catch (err: any) {
      sendNotification(authUser?.id || 'admin', `Failed to update section status: ${err.message}`, 'error');
    }
  }, [authUser]);

  const reorderSections = useCallback(async (src: number, dest: number) => {
    try {
      sendNotification(authUser?.id || 'admin', `Moving section...`, 'info');
      const res = Array.from(sectionsRef.current);
      const [rem] = res.splice(src, 1);
      res.splice(dest, 0, rem);
      const nextSections = res.map((s, i) => ({ ...s as any, order: i }));
      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Section order updated.`, 'success');
    } catch (err: any) {
      sendNotification(authUser?.id || 'admin', `Failed to reorder: ${err.message}`, 'error');
    }
  }, [authUser]);

  const addField = useCallback(async (sId: string, data: Record<string, any>) => {
    try {
      sendNotification(authUser?.id || 'admin', `Adding field "${data.label}"...`, 'info');
      const nextSections = sectionsRef.current.map(s => s.id === sId ? { ...s, fields: [...s.fields, { ...data, id: uuidv4(), order: s.fields.length, isDisabled: false }] } : s);
      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Field "${data.label}" added.`, 'success');
    } catch (err: any) {
      sendNotification(authUser?.id || 'admin', `Failed to add field: ${err.message}`, 'error');
    }
  }, [authUser]);

  const updateField = useCallback(async (sId: string, fId: string, upds: Record<string, any>) => {
    try {
      sendNotification(authUser?.id || 'admin', `Saving field changes to cloud...`, 'info');

      // CRITICAL: Pull latest version from Ref to ensure no property loss
      const current = sectionsRef.current;
      const nextSections = current.map(s => {
        if (s.id === sId) {
          return {
            ...s,
            fields: s.fields.map(f => {
              if (f.id === fId) {
                // EXPLICIT MERGE: Ensure all keys in 'upds' are committed
                const updatedField = { ...f, ...upds };
                log.log("FINAL FIELD OBJECT FOR DB:", JSON.stringify(updatedField));
                return updatedField;
              }
              return f;
            })
          };
        }
        return s;
      });

      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Database save complete!`, 'success');
    } catch (err: any) {
      log.error("FIELD UPDATE ERROR:", err);
      sendNotification(authUser?.id || 'admin', `Cloud Database Error: ${err.message}`, 'error');
    }
  }, [authUser]);

  const deleteField = useCallback(async (sId: string, fId: string) => {
    try {
      sendNotification(authUser?.id || 'admin', `Deleting field...`, 'info');
      const nextSections = sectionsRef.current.map(s => s.id === sId ? { ...s, fields: s.fields.filter(f => f.id !== fId).map((f, i) => ({ ...f, order: i })) } : s);
      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Field deleted.`, 'success');
    } catch (err: any) {
      sendNotification(authUser?.id || 'admin', `Failed to delete field: ${err.message}`, 'error');
    }
  }, [authUser]);

  const toggleFieldStatus = useCallback(async (sId: string, fId: string) => {
    try {
      sendNotification(authUser?.id || 'admin', `Updating field status...`, 'info');
      const current = sectionsRef.current;
      const nextSections = current.map(s => s.id === sId ? {
        ...s,
        fields: s.fields.map(f => f.id === fId ? { ...f, isDisabled: !f.isDisabled } : f)
      } : s);
      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Field status updated.`, 'success');
    } catch (err: any) {
      sendNotification(authUser?.id || 'admin', `Failed to update field status.`, 'error');
    }
  }, [authUser]);

  const reorderFields = useCallback(async (sId: string, src: number, dest: number) => {
    try {
      sendNotification(authUser?.id || 'admin', `Moving field...`, 'info');
      const nextSections = sectionsRef.current.map(s => {
        if (s.id === sId) {
          const f = [...s.fields].sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
          const [rem] = f.splice(src, 1);
          f.splice(dest, 0, rem);
          return { ...s as any, fields: f.map((x, i) => ({ ...x as any, order: i })) };
        }
        return s;
      });
      await updateFormSections(nextSections);
      sendNotification(authUser?.id || 'admin', `Field order updated.`, 'success');
    } catch (err: any) {
      sendNotification(authUser?.id || 'admin', `Failed to reorder fields.`, 'error');
    }
  }, [authUser]);

  const formBuilder = {
    sections: formSections,
    setSections: (val: any) => { log.warn("Direct setSections deprecated"); },
    addSection, updateSectionName, deleteSection, toggleSectionStatus, reorderSections,
    addField, updateField, deleteField, toggleFieldStatus, reorderFields
  };

  const syncedSections = useMemo(() => {
    if (!formSections || !Array.isArray(formSections)) return [];

    const activeSiteNames = sites.filter(s => s && s.status === 'Active').map(s => s.name);
    return formSections.map(section => {
      if (!section) return null;
      let fields = (section.fields || []).map(field => {
        if (!field) return null;
        if (field.label === 'Unit or Facility' || field.id === '52ae217b-2602-4337-a1cd-a1f9bd36a4b0') {
          return { ...field, options: activeSiteNames };
        }
        return field;
      }).filter(Boolean) as FormField[];

      // In Job Details, guarantee Unit or Facility (order 1) comes before Post of Apply (order 2)
      if (section.id === 'eb4bf8a6-a8bd-4563-817d-792716e6474c' || section.name === 'Job Details') {
        const unitField = fields.find(f => f.id === '52ae217b-2602-4337-a1cd-a1f9bd36a4b0' || f.label === 'Unit or Facility');
        const postField = fields.find(f => f.id === 'db307195-cf54-4a6e-9056-f3974b050c4d' || f.label === 'Post of Apply' || f.label === 'Designation');
        if (unitField && postField) {
          unitField.order = 1;
          postField.order = 2;
        }
        fields.sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
      }

      return {
        ...section,
        fields
      };
    }).filter(Boolean) as FormSection[];
  }, [formSections, sites]);

  const handleAdminLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    localStorage.setItem('portalType', 'management'); // HINT: Lock AuthContext to Admin/Staff scope
    setAdminLoginError('');
    setIsLoading(true);

    // Diagnostic: Check if environment variables are loaded
    const envKeys = [
      'VITE_FIREBASE_API_KEY',
      'VITE_FIREBASE_AUTH_DOMAIN',
      'VITE_FIREBASE_PROJECT_ID',
      'VITE_FIREBASE_STORAGE_BUCKET',
      'VITE_FIREBASE_MESSAGING_SENDER_ID',
      'VITE_FIREBASE_APP_ID'
    ];
    const missingKeys = envKeys.filter(key => !(import.meta as any).env[key]);
    if (missingKeys.length > 0) {
      log.error("CRITICAL: Missing environment variables on client:", missingKeys);
    }

    const normalizedUser = adminUsername.trim().toLowerCase();
    const normalizedPass = adminPassword.trim();

    // SECURITY: No backdoor credentials. All login must go through Firebase Auth.

    try {
      const { loginUser, getAdminProfile, getStaffProfile } = await import('./src/services/authService');
      const { auth } = await import('./src/firebase/config');

      await loginUser(normalizedUser, normalizedPass);
      const firebaseUser = auth.currentUser;

      if (firebaseUser) {
        // STRICT SCOPE: Only check Admin and Staff collections
        const admin = await getAdminProfile(firebaseUser);
        const staff = await getStaffProfile(firebaseUser);
        const user = admin || staff;

        if (user) {
          setAuthUser(user);
          logSystemAction('LOGIN', 'AUTH', `User logged in: ${user.name}`, { id: user.id || 'unknown', name: user.name || 'Unknown' });

          navigateTo(AppView.ADMIN_DASHBOARD); // Strictly management dashboard

          setAdminUsername('');
          setAdminPassword('');
        } else {
          // STRICT ISOLATION: Check if they are an Employee trying to access Admin
          const { getEmployeeProfile, logoutUser } = await import('./src/services/authService');
          const employee = await getEmployeeProfile(firebaseUser);

          if (employee) {
            setAdminLoginError('Employee accounts are not permitted on the Management Portal.');
          } else {
            setAdminLoginError('Auth successful, but no Admin or Staff record was found.');
          }

          const { logoutUser: logout } = await import('./src/services/authService');
          await logout();
          setIsLoading(false);
        }
      } else {
        setAdminLoginError('Authentication failed to establish a session.');
        setIsLoading(false);
      }
    } catch (error: any) {
      log.error("Login failed", error);
      const msg = error.code === 'auth/invalid-email' ? 'Please use a valid email address.' :
        error.code === 'auth/user-not-found' ? 'User not found in Firebase.' :
          error.code === 'auth/wrong-password' ? 'Incorrect password.' :
            error.code === 'auth/invalid-credential' ? 'Invalid credentials (email or password).' :
              `Login failed (${error.code}). Please try again.`;
      setAdminLoginError(msg);
      setIsLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    log.log("App.tsx: handleGoogleLogin triggered");
    localStorage.setItem('portalType', 'management'); // HINT: Lock AuthContext to Admin/Staff scope
    setAdminLoginError('');
    setIsLoading(true);
    try {
      const { loginWithGoogle, getAdminProfile, getStaffProfile, logoutUser } = await import('./src/services/authService');
      const firebaseUser = await loginWithGoogle();

      log.log("App.tsx: loginWithGoogle returned firebase user:", firebaseUser?.uid);
      if (firebaseUser) {
        // STRICT SCOPE: Only check Admin and Staff collections
        const admin = await getAdminProfile(firebaseUser);
        const staff = await getStaffProfile(firebaseUser);
        const user = admin || staff;

        if (user) {
          setAuthUser(user);
          setAuthUser(user); // Sync Context immediately
          logSystemAction('LOGIN', 'AUTH', `User logged in via Google: ${user.name}`, { id: user.id || 'unknown', name: user.name || 'Unknown' });
          log.log("App.tsx: Navigating to dashboard...");
          navigateTo(AppView.ADMIN_DASHBOARD);
        } else {
          // STRICT ISOLATION: Check if they are an Employee trying to access Admin
          const { getEmployeeProfile, logoutUser } = await import('./src/services/authService');
          const employee = await getEmployeeProfile(firebaseUser);

          if (employee) {
            setAdminLoginError('Employee accounts are not permitted on the Management Portal.');
          } else {
            setAdminLoginError('Auth successful, but no Admin or Staff record was found for this Google account.');
          }

          const { logoutUser: logout } = await import('./src/services/authService');
          await logout();
          setIsLoading(false);
        }
      } else {
        setAdminLoginError('Google sign-in returned no user session.');
        setIsLoading(false);
      }
    } catch (error: any) {
      log.error("App.tsx: Google login error:", error);
      if (error.code !== 'auth/popup-closed-by-user') {
        setAdminLoginError(`Google login failed: ${error.message}`);
      }
      setIsLoading(false);
    }
  };

  const navigateTo = useCallback((view: AppView) => {
    setCurrentView(view);

    // Persist to sessionStorage for reload safety
    try {
      if (view.startsWith('ADMIN_')) {
        sessionStorage.setItem('activeAdminView', view);
      } else if (view.startsWith('EMPLOYEE_')) {
        sessionStorage.setItem('activeEmployeeView', view);
      }
    } catch (e) {}

    // Determine the browser URL path corresponding to the AppView
    let path = '/';
    if (view === AppView.LANDING) {
      path = '/';
    } else if (view === AppView.ADMIN_LOGIN) {
      path = '/admin/login';
    } else if (view === AppView.EMPLOYEE_LOGIN) {
      path = '/login';
    } else if (view === AppView.EMPLOYEE_JOINING_FORM) {
      path = '/join';
    } else if (view === AppView.SETUP_ACCOUNT) {
      path = '/setup-account';
    } else if (view.startsWith('ADMIN_')) {
      const slug = SLUG_BY_ADMIN_VIEW[view];
      path = (!slug || slug === 'dashboard') ? '/dashboard' : `/dashboard?tab=${slug}`;
    } else if (view.startsWith('EMPLOYEE_')) {
      path = view === AppView.EMPLOYEE_DASHBOARD ? '/employee/dashboard' : `/employee/dashboard?tab=${view.replace('EMPLOYEE_', '').toLowerCase()}`;
    }

    const currentUrl = window.location.pathname + (window.location.search || '');
    if (currentUrl !== path) {
      navigate(path);
    }
  }, [navigate]);

  const handleLogout = useCallback(async () => {
    const userSnapshot = authUser;

    // 1. Synchronously purge all local state and tokens (0ms delay)
    localStorage.removeItem('portalType');
    localStorage.removeItem('udf_user_last_active');
    try {
      sessionStorage.removeItem('activeAdminView');
      sessionStorage.removeItem('activeEmployeeView');
      sessionStorage.removeItem('adminInvitesActiveTab');
    } catch (e) {}

    // Immediately evict user from React state so protected pages unmount right away
    setAuthUser(null);
    setCurrentView(AppView.LANDING);
    navigateTo(AppView.LANDING);

    // 2. Perform server-side audit logging and Firebase sign-out in the background
    try {
      if (userSnapshot) {
        logSystemAction('LOGOUT', 'AUTH', `User logged out: ${userSnapshot.name}`).catch(() => {});
      }
      const { logoutUser } = await import('./src/services/authService');
      await logoutUser();
    } catch (err: any) {
      log.error("Background logout error", err);
    }
  }, [authUser, logSystemAction, navigateTo, setAuthUser]);

  // ─── Universal Inactivity Auto-Logout (60 Min for Admin, 120 Min for Employee) ───
  useEffect(() => {
    if (!authUser) {
      localStorage.removeItem('udf_user_last_active');
      return;
    }

    const ADMIN_TIMEOUT_MS = 60 * 60 * 1000; // 60 minutes
    const EMPLOYEE_TIMEOUT_MS = 120 * 60 * 1000; // 2 hours
    const timeoutDuration = authUser.type === UserType.ADMIN ? ADMIN_TIMEOUT_MS : EMPLOYEE_TIMEOUT_MS;
    const timeoutMinutes = authUser.type === UserType.ADMIN ? 60 : 120;

    // Initialize or touch timestamp on login / active state
    if (!localStorage.getItem('udf_user_last_active')) {
      localStorage.setItem('udf_user_last_active', Date.now().toString());
    }

    let isTimedOut = false;
    let lastThrottledTouch = 0;
    const touchActivity = () => {
      if (isTimedOut) return;
      const now = Date.now();
      // Throttle localStorage writes to at most once every 10 seconds
      if (now - lastThrottledTouch > 10000) {
        lastThrottledTouch = now;
        localStorage.setItem('udf_user_last_active', now.toString());
      }
    };

    window.addEventListener('keydown', touchActivity, { passive: true });
    window.addEventListener('click', touchActivity, { passive: true });
    window.addEventListener('touchstart', touchActivity, { passive: true });
    window.addEventListener('scroll', touchActivity, { passive: true });

    const checker = setInterval(() => {
      if (isTimedOut) return;
      const raw = localStorage.getItem('udf_user_last_active');
      if (raw) {
        const lastActive = parseInt(raw, 10);
        if (!isNaN(lastActive) && (Date.now() - lastActive) >= timeoutDuration) {
          isTimedOut = true;
          log.warn(`[InactivityTimeout] User ${authUser.name} (${authUser.type}) timed out due to ${timeoutMinutes}m inactivity.`);

          // 1. Immediately detach listeners so interactions cannot revive the session
          window.removeEventListener('keydown', touchActivity);
          window.removeEventListener('click', touchActivity);
          window.removeEventListener('touchstart', touchActivity);
          window.removeEventListener('scroll', touchActivity);
          clearInterval(checker);

          // 2. Synchronously wipe all credentials and session caches
          localStorage.removeItem('udf_user_last_active');
          localStorage.removeItem('portalType');
          try {
            sessionStorage.removeItem('activeAdminView');
            sessionStorage.removeItem('activeEmployeeView');
            sessionStorage.removeItem('adminInvitesActiveTab');
          } catch (e) {}

          const timedOutUser = authUser;

          // 3. Instantly evict user from React state — protected UI components unmount immediately
          setAuthUser(null);
          setCurrentView(AppView.LANDING);

          // 4. Background Firebase signOut and audit logging
          import('./src/services/authService').then(({ logoutUser }) => {
            logoutUser().catch(() => {});
          }).catch(() => {});
          if (timedOutUser) {
            logSystemAction('LOGOUT', 'AUTH', `User ${timedOutUser.name} session expired due to ${timeoutMinutes}m inactivity`).catch(() => {});
          }

          // 5. Instantly display full-screen blocking modal overlay (zero interaction permitted underneath)
          setSessionExpiredInfo({ isOpen: true, minutes: timeoutMinutes });
        }
      }
    }, 10 * 1000); // Check every 10 seconds

    return () => {
      window.removeEventListener('keydown', touchActivity);
      window.removeEventListener('click', touchActivity);
      window.removeEventListener('touchstart', touchActivity);
      window.removeEventListener('scroll', touchActivity);
      clearInterval(checker);
    };
  }, [authUser, logSystemAction, setAuthUser]);



  // Redundant Auth Sink removed to prevent race conditions with AuthContext

  // Initial Seeding for Super Admin (Subscriptions are managed centrally by DataContext)
  useEffect(() => {
    if (authUser?.type === UserType.ADMIN && isSuperAdmin) {
      const defaultEditableFields = [
        'eb3617dc-9f1d-475d-a2db-005b6bc2500c',
        '8532f460-7bcf-4831-ab62-96375b80e6ab',
        '1a35eaa7-d302-4e49-8649-e85cab8b3b77',
        '3519c111-aaa6-4fe0-8d83-d03dd7612e28',
        '86854000-7727-40bb-9932-09e28e443ad8'
      ];
      seedInitialData(
        defaultRoles, defaultSites, defaultWorkflows, defaultPortalConfig as any,
        defaultLeavePolicy, defaultStaff, defaultFormSections, defaultEditableFields
      );
    }
  }, [authUser?.type, isSuperAdmin]);


  // Employee-specific Subscriptions (Personal Record & Submission) are centrally managed by DataContext
  useEffect(() => {
    if (!authUser || authUser.type !== UserType.EMPLOYEE) {
      if (!authUser) setEmployees([]);
    }
  }, [authUser, setEmployees]);


  // Compute Leave Balances from Employees and Policy
  useEffect(() => {
    if (employees.length === 0) return;

    const keyMap: Record<string, string> = {
      'casual': LeaveType.CASUAL,
      'sick': LeaveType.SICK,
      'earned': LeaveType.EARNED, // Handle both 'earned' and 'privilege' for backward compatibility
      'privilege': LeaveType.EARNED
    };

    const balances: LeaveBalance[] = employees.map(emp => {
      const empBalances: Record<string, any> = {};

      // Initialize with policy defaults
      leavePolicy.leaveTypes.forEach(lt => {
        empBalances[lt.typeId] = {
          total: lt.defaultQuota,
          used: 0,
          remaining: lt.defaultQuota
        };
      });

      // Overlay with actual remaining balance from Firestore
      if (emp.leaveBalance) {
        Object.entries(emp.leaveBalance).forEach(([dbKey, remaining]) => {
          const typeId = keyMap[dbKey] || dbKey;
          if (empBalances[typeId]) {
            empBalances[typeId].remaining = remaining;
            // In our current model, 'used' is calculated as total - remaining
            empBalances[typeId].used = Math.max(0, empBalances[typeId].total - (remaining as number));
          }
        });
      }

      return {
        employeeId: emp.employeeId,
        year: new Date().getFullYear(),
        balances: empBalances
      };
    });

    setLeaveBalances(balances);
  }, [employees, leavePolicy]);

  // Submissions subscription - On-demand for ADMINS (loads when tab opens, then cached for session)
  // EMPLOYEES get only their own submissions
  const hasSubmissionsSubscribedRef = useRef(false);
  useEffect(() => {
    if (!authUser) {
      hasSubmissionsSubscribedRef.current = false;
      setSubmittedForms([]);
      return;
    }

    let unsubSubmissions = () => { };

    if (authUser.type === UserType.ADMIN) {
      // Enterprise Segregation: Candidate Onboarding pipeline loads on-demand for candidate views only
      const shouldSubscribe = 
        currentView === AppView.ADMIN_PORTAL_SUBMISSION_REVIEW || 
        currentView === AppView.ADMIN_PORTAL_DRAFTS || 
        currentView === AppView.ADMIN_PORTAL_SITE_MANAGEMENT || 
        currentView === AppView.ADMIN_DASHBOARD ||
        hasSubmissionsSubscribedRef.current;

      if (shouldSubscribe) {
        hasSubmissionsSubscribedRef.current = true;
        unsubSubmissions = subscribeToSubmissions((data) => {
          const mapped = data.map(d => ({
            ...d,
            data: d.formData,
            submissionDate: typeof d.timestamp === 'object' ? new Date().toISOString() : d.timestamp,
          } as unknown as SubmittedFormData));
          setSubmittedForms(mapped);
        });
      }
    } else if (authUser.type === UserType.EMPLOYEE) {
      log.log(`Setting up personal submission subscription for Employee: ${authUser.id}`);
      unsubSubmissions = subscribeToSubmissionsByUid(authUser.id, (data) => {
        const mapped = data.map(d => ({
          ...d,
          data: d.formData,
          submissionDate: typeof d.timestamp === 'object' ? new Date().toISOString() : d.timestamp,
        } as unknown as SubmittedFormData));
        setSubmittedForms(mapped);
      });
    } else {
      setSubmittedForms([]);
    }

    return () => {
      unsubSubmissions();
    };
  }, [authUser, setSubmittedForms, currentView]);





  const checkWritesBlock = useCallback(() => {
    const isDbReadOnly = portalConfig?.manualReadOnly === true || portalConfig?.blockWritesOnLimit === true;
    if (isDbReadOnly) {
      toast.error("Database is in Read-Only Mode. Submissions are temporarily disabled.");
      return true;
    }
    return false;
  }, [portalConfig]);

  const handleEmployeeFormSubmit = useCallback(async (
    formData: Record<string, any>,
    formSections: FormSection[],
    linkedUid?: string,
    onProgress?: (fieldId: string, status: 'loading' | 'done' | 'error', percent?: number) => void,
    legacyImportId?: string,
    selectedPassword?: string
  ) => {
    if (checkWritesBlock()) return;
    // Save to Firebase
    try {
      // Create a copy of formData to inject semantic fields
      const processedFormData = { ...formData };

      const SITE_FIELD_ID = '52ae217b-2602-4337-a1cd-a1f9bd36a4b0';
      const SUBUNIT_FIELD_ID = '68a2a893-0100-4740-9602-9988452377c8';

      // Map Site Name and ID
      const siteVal = processedFormData[SITE_FIELD_ID];
      if (siteVal) {
        const site = sites.find(s => s.name === siteVal || s.id === siteVal);
        if (site) {
          processedFormData.siteId = site.id;
          processedFormData.siteName = site.name;
          processedFormData[SITE_FIELD_ID] = site.name;

          // Map Sub-Unit Name to ID
          const subUnitName = processedFormData[SUBUNIT_FIELD_ID];
          if (subUnitName && site.subUnits) {
            const subUnit = site.subUnits.find(u => u.name === subUnitName || u.id === subUnitName);
            if (subUnit) {
              processedFormData.subUnitId = subUnit.id;
            }
          }
        }
      }

      const invId = (processedFormData as any)?.__referralInviteId || activeDraft?.inviteId || (typeof window !== 'undefined' ? (sessionStorage.getItem('referralInviteId') || localStorage.getItem('referralInviteId') || null) : null);
      if (invId && !processedFormData.__referralInviteId) {
        processedFormData.__referralInviteId = invId;
      }
      const draftIdToClean = (processedFormData as any)?.draftId || activeDraft?.id;
      const firebaseId = await submitEmployeeForm(processedFormData, formSections, linkedUid, onProgress, legacyImportId, selectedPassword, draftIdToClean);
      console.log("Form submitted to Firebase with ID:", firebaseId);

      const applicantName = getApplicantName(processedFormData, formSections) || 'Applicant';

      // Notify Level 1 for Submissions
      const config = workflowConfigs.find(c => c.moduleId === 'SUBMISSIONS');
      const level1 = config?.levels.find(l => l.level === 1);
      if (level1) {
        // Use the injected siteId if available, or fallback to name lookup
        const siteId = processedFormData.siteId;
        const site = sites.find(s => s.id === siteId);

        if (site && site.supervisorId) {
          const supervisor = staffUsers.find(s => s.id === site.supervisorId);
          if (supervisor && supervisor.roleId === level1.roleId) {
            sendNotification(supervisor.id, `New New Joiner Application: ${applicantName}`, 'info', AppView.ADMIN_PORTAL_SUBMISSION_REVIEW);
          } else {
            notifyRole(level1.roleId, `New New Joiner Application: ${applicantName}`, 'info', AppView.ADMIN_PORTAL_SUBMISSION_REVIEW, site?.id);
          }
        } else {
          notifyRole(level1.roleId, `New New Joiner Application: ${applicantName}`, 'info', AppView.ADMIN_PORTAL_SUBMISSION_REVIEW, site?.id);
        }
      }
      if (activeDraft?.id) {
        setActiveDraft(null);
      }

      if (isSuperAdmin) {
        refreshGlobalStats();
      }

      return { success: true, id: firebaseId };
    } catch (e: any) {
      console.error("Failed to submit to Firebase", e);
      return { success: false, error: e.message || "Failed to sync to cloud. Please check if your files are too large." };
    }
  }, [workflowConfigs, notifyRole, sites, staffUsers, sendNotification, logSystemAction, activeDraft, setActiveDraft, refreshGlobalStats]);

  // Initialize balance helper - Updated to use LeavePolicy
  const initializeLeaveBalance = (employeeId: string) => {
    const balances: any = {};

    // Default balances from policy
    leavePolicy.leaveTypes.forEach(type => {
      balances[type.typeId] = {
        total: type.defaultQuota,
        used: 0
      };
    });

    const newBalance: LeaveBalance = {
      employeeId,
      year: new Date().getFullYear(),
      balances: balances
    };
    setLeaveBalances(prev => [...prev, newBalance]);
  };

  const handleSubmitLeaveRequest = useCallback(async (requestData: any) => {
    if (checkWritesBlock()) return;
    if (!authUser) return;

    const processedData = { ...requestData };
    const userUniqueId = authUser.portalId || authUser.id;

    const newRequest: LeaveRequest = {
      ...processedData,
      id: uuidv4(),
      employeeId: userUniqueId,
      employeeName: authUser.name || 'Unknown',
      status: RequestStatus.PENDING,
      currentLevel: 1,
      approvalHistory: [],
      submissionDate: new Date().toISOString(),
      siteId: processedData.siteId || employeeData?.currentSiteId || '',
    };
    await submitLeaveRequest(newRequest);
    logSystemAction('SUBMIT', 'LEAVES', `Leave request submitted: ${newRequest.leaveType} (${newRequest.startDate} - ${newRequest.endDate})`);

    const config = workflowConfigs.find(c => c.moduleId === 'LEAVES');
    const level1 = config?.levels.find(l => l.level === 1);
    if (level1) notifyApprovers(userUniqueId, level1.roleId, `New Leave Request from ${authUser.name}`, AppView.ADMIN_PORTAL_LEAVE_MANAGEMENT, newRequest.siteId);
    refreshGlobalStats();
  }, [authUser, employeeData, workflowConfigs, notifyApprovers, logSystemAction, refreshGlobalStats, checkWritesBlock]);

  const handleSubmitResignationRequest = useCallback(async (requestData: any) => {
    if (checkWritesBlock()) return;
    if (!authUser) return;

    const processedData = { ...requestData };
    const userUniqueId = authUser.portalId || authUser.id;

    const reqSiteId = processedData.siteId || employeeData?.currentSiteId || '';
    const matchingSite = sites.find(s => s.id === reqSiteId);
    const siteName = matchingSite ? matchingSite.name : (processedData.unit || employeeData?.siteName || '');

    const newRequest: ResignationRequest = {
      ...processedData,
      id: uuidv4(),
      employeeId: userUniqueId,
      employeeName: authUser.name || 'Unknown',
      status: RequestStatus.PENDING,
      currentLevel: 1,
      approvalHistory: [],
      submissionDate: new Date().toISOString(),
      siteId: reqSiteId,
      unit: siteName,
    };
    await submitResignationRequest(newRequest);
    logSystemAction('SUBMIT', 'EMPLOYEES', `Resignation request submitted.`);
    const config = workflowConfigs.find(c => c.moduleId === 'RESIGNATIONS');
    const level1 = config?.levels.find(l => l.level === 1);
    if (level1) notifyApprovers(userUniqueId, level1.roleId, `New Resignation Request from ${authUser.name}`, AppView.ADMIN_PORTAL_RESIGNATION_MANAGEMENT, newRequest.siteId);
    refreshGlobalStats();
  }, [authUser, employeeData, sites, workflowConfigs, notifyApprovers, logSystemAction, refreshGlobalStats, checkWritesBlock]);

  const handleAdminLeaveAction = useCallback(async (requestId: string, newStatus: RequestStatus, adminComments?: string, isBypass?: boolean) => {
    if (!authUser) return;
    const r = leaveRequests.find(req => req.id === requestId);
    if (!r) return;

    try {
      const { processRequestReview } = await import('./src/services/requestService');
      await processRequestReview({
        requestType: 'LEAVES',
        requestId,
        action: newStatus === RequestStatus.APPROVED ? 'APPROVE' : 'REJECT',
        comment: adminComments,
        isBypass
      });
    } catch (serverErr: any) {
      console.error('[handleAdminLeaveAction] Cloud Function review failed:', serverErr);
      const msg = serverErr?.message || 'Failed to process leave action.';
      toast.error(msg);
      throw serverErr;
    }
    refreshGlobalStats();
  }, [leaveRequests, authUser, workflowConfigs, roles, logSystemAction, sendNotification, notifyApprovers, refreshGlobalStats, sites, staffUsers]);

  const handleAddDisciplinaryAction = useCallback(async (actionData: any) => {
    if (!authUser) return;

    const newAction: DisciplinaryAction = {
      ...actionData,
      id: uuidv4(),
      filedBy: authUser.name || 'Admin',
      filedByRoleId: authUser.roleId || 'super-admin'
    };
    await addDisciplinaryAction(newAction);
    logSystemAction('CREATE', 'EMPLOYEES', `Issued ${actionData.actionType} to ${actionData.employeeName}.`);
    sendNotification(actionData.employeeId, `You have received a new disciplinary record: ${actionData.actionType}.`, 'error', AppView.EMPLOYEE_DISCIPLINARY);
  }, [authUser, logSystemAction, sendNotification]);

  const handleAdminResignationAction = useCallback(async (requestId: string, newStatus: RequestStatus, adminComments?: string, updatedRelievingDate?: string, isBypass?: boolean) => {
    if (!authUser) return;
    const r = resignationRequests.find(req => req.id === requestId);
    if (!r) return;

    try {
      const { processRequestReview } = await import('./src/services/requestService');
      await processRequestReview({
        requestType: 'RESIGNATIONS',
        requestId,
        action: newStatus === RequestStatus.APPROVED ? 'APPROVE' : 'REJECT',
        comment: adminComments,
        updatedRelievingDate,
        isBypass
      });
    } catch (serverErr: any) {
      console.error('[handleAdminResignationAction] Cloud Function review failed:', serverErr);
      const msg = serverErr?.message || 'Failed to process resignation action.';
      toast.error(msg);
      throw serverErr;
    }
    refreshGlobalStats();
  }, [resignationRequests, authUser, workflowConfigs, roles, logSystemAction, sendNotification, notifyApprovers, refreshGlobalStats, sites, staffUsers]);

  // Automatically relieve employees whose approved notice period has concluded
  useEffect(() => {
    if (!authUser || (authUser as any).type !== 'Admin') return;
    if (resignationRequests && resignationRequests.length > 0) {
      processDueResignations(resignationRequests).catch(err => {
        console.warn('[AutoRelieve] Failed to process due resignations:', err);
      });
    }
  }, [resignationRequests, authUser]);

  const handleSubmitAccountUpdateRequest = useCallback(async (requestData: any) => {
    if (checkWritesBlock()) return;
    if (!authUser) return;

    const processedData = { ...requestData };
    const userUniqueId = authUser.portalId || authUser.id;

    const reqSiteId = employeeData?.currentSiteId || (authUser as any).currentSiteId || '';

    const newRequest: AccountUpdateRequest = {
      ...processedData,
      id: uuidv4(),
      employeeId: userUniqueId,
      employeeName: authUser.name || 'Unknown',
      status: RequestStatus.PENDING,
      currentLevel: 1,
      approvalHistory: [],
      submissionDate: new Date().toISOString(),
      siteId: reqSiteId,
    };
    await submitAccountUpdateRequest(newRequest);
    const config = workflowConfigs.find(c => c.moduleId === 'ACCOUNT_UPDATES');
    const level1 = config?.levels.find(l => l.level === 1);
    if (level1) notifyApprovers(userUniqueId, level1.roleId, `New Account Update Request`, AppView.ADMIN_PORTAL_ACCOUNT_UPDATE_MANAGEMENT, newRequest.siteId);
    refreshGlobalStats();
  }, [authUser, employeeData, workflowConfigs, notifyApprovers, logSystemAction, refreshGlobalStats, checkWritesBlock]);

  const handleAdminAccountUpdateAction = useCallback(async (requestId: string, newStatus: RequestStatus, adminComments?: string, isBypass?: boolean) => {
    if (!authUser) return;
    const req = accountUpdateRequests.find(r => r.id === requestId);
    if (!req) return;

    try {
      const { processRequestReview } = await import('./src/services/requestService');
      await processRequestReview({
        requestType: 'ACCOUNT_UPDATES',
        requestId,
        action: newStatus === RequestStatus.APPROVED ? 'APPROVE' : 'REJECT',
        comment: adminComments,
        isBypass
      });
    } catch (serverErr: any) {
      console.error('[handleAdminAccountUpdateAction] Cloud Function review failed:', serverErr);
      const msg = serverErr?.message || 'Failed to process account update action.';
      toast.error(msg);
      throw serverErr;
    }
    refreshGlobalStats();
  }, [accountUpdateRequests, authUser, workflowConfigs, roles, logSystemAction, sendNotification, notifyApprovers, refreshGlobalStats, sites, staffUsers]);

  const handleAdminApproveSubmission = useCallback(async (
    submissionId: string,
    employeeId: string,
    comments?: string,
    isRejection?: boolean,
    isBypass?: boolean,
    profileCompletionData?: {
      profileCompletionStatus: 'COMPLETE' | 'INCOMPLETE';
      pendingProfileFields?: string[];
      pendingProfileNote?: string;
    },
    customJoiningDate?: string,
    customRecruiter?: { id: string | null; name: string | null }
  ) => {
    if (!authUser) return;

    // FIND SUBMISSION
    const submission = submittedForms.find(s => s.id === submissionId);
    if (!submission) return;

    const config = workflowConfigs.find(c => c.moduleId === 'SUBMISSIONS');
    const maxLevels = config?.levels.length || 1;
    const actorName = authUser.name || 'Admin';
    const actorRole = roles.find(r => r.id === authUser.roleId)?.name || 'Admin';

    try {
      if (isRejection) {
        await updateSubmissionStatus(submissionId, 'Rejected', comments, actorName, '', undefined, actorRole);
        logSystemAction('REJECTION', 'EMPLOYEES', `Rejected application (ID: ${submissionId}).`);
      } else {
        // Retrieve submission site
        const siteName = String(submission.data?.['52ae217b-2602-4337-a1cd-a1f9bd36a4b0'] || '');
        const site = sites.find(s => s.name === siteName || s.id === siteName);
        const effectiveLevel = getEffectiveApprovalLevel(submission.currentLevel, site, config, staffUsers, roles);
        const nextRawLevel = effectiveLevel + 1;

        // Final if no more levels remain, or explicitly bypassing
        const isFinal = nextRawLevel > maxLevels || isBypass || (isSuperAdmin && isBypass);

        if (isFinal) {
          const dup = submission.duplicateCheck;
          if (dup?.isDuplicate) {
            const curForm = { ...(submission.formData || {}), ...(submission.data || {}) };
            const checkMatchStillActive = (m: any): boolean => {
              const { matchedField, matchedValue, matchType, submissionId: targetSubId } = m;
              if (!matchedField || !matchedValue) return true;

              // 1. Current submission check
              let curVal: string | null | undefined = null;
              if (matchedField === 'PAN Card') {
                curVal = submission.panNumber || curForm['da8edb18-4bed-41ca-8233-2280b97dac8d'];
                if (curVal && String(curVal).trim().toUpperCase() !== String(matchedValue).trim().toUpperCase()) return false;
              } else if (matchedField === 'Aadhaar Number') {
                curVal = submission.aadhaarNumber;
                if (curVal && String(curVal).trim() !== String(matchedValue).trim()) return false;
              } else if (matchedField === 'Phone Number') {
                curVal = submission.phoneNumber;
                if (curVal && String(curVal).trim() !== String(matchedValue).trim()) return false;
              } else if (matchedField === 'UAN Number') {
                curVal = submission.uanNumber;
                if (curVal && String(curVal).trim() !== String(matchedValue).trim()) return false;
              }

              // 2. Matched target submission check
              if (matchType === 'DUPLICATE_SUBMISSION' && targetSubId) {
                const otherSub = submittedForms.find(s => s.id === targetSubId);
                if (otherSub) {
                  if (otherSub.status === SubmissionStatus.REJECTED || (otherSub as any).isDeleted) return false;
                  const oForm = { ...(otherSub.formData || {}), ...(otherSub.data || {}) };
                  let oVal: string | null | undefined = null;
                  if (matchedField === 'PAN Card') {
                    oVal = otherSub.panNumber || oForm['da8edb18-4bed-41ca-8233-2280b97dac8d'];
                    if (oVal && String(oVal).trim().toUpperCase() !== String(matchedValue).trim().toUpperCase()) return false;
                  } else if (matchedField === 'Aadhaar Number') {
                    oVal = otherSub.aadhaarNumber;
                    if (oVal && String(oVal).trim() !== String(matchedValue).trim()) return false;
                  } else if (matchedField === 'Phone Number') {
                    oVal = otherSub.phoneNumber;
                    if (oVal && String(oVal).trim() !== String(matchedValue).trim()) return false;
                  } else if (matchedField === 'UAN Number') {
                    oVal = otherSub.uanNumber;
                    if (oVal && String(oVal).trim() !== String(matchedValue).trim()) return false;
                  }
                }
              }

              return true;
            };

            const rawMatches = dup.matches && dup.matches.length > 0
              ? dup.matches
              : [{
                  matchType: dup.matchType || 'DUPLICATE_SUBMISSION',
                  matchedField: dup.matchedField || 'PAN Card',
                  matchedValue: dup.matchedValue || '',
                  matchedId: dup.matchedId,
                  matchedName: dup.matchedName,
                  submissionId: dup.submissionId,
                  submissionStatus: dup.submissionStatus
                }];

            const activeMatches = rawMatches.filter(m => checkMatchStillActive(m));

            if (activeMatches.length > 0) {
              const activeEmpMatch = activeMatches.find(m => m.matchType === 'EXISTING_ACTIVE_EMPLOYEE');
              if (activeEmpMatch) {
                alert(`❌ ACTION BLOCKED: ACTIVE EMPLOYEE MATCH!\n\nActive employee "${activeEmpMatch.matchedName}" (${activeEmpMatch.matchedId}) already exists with this ${activeEmpMatch.matchedField}.\nFinal approval cannot proceed.`);
                return;
              }

              const dupSubMatch = activeMatches.find(m => m.matchType === 'DUPLICATE_SUBMISSION');
              if (dupSubMatch) {
                const list = activeMatches.map(m => `• ${m.matchedField} (${m.matchedValue}) matches ${m.matchedName || m.submissionId}`).join('\n');
                alert(`❌ ACTION BLOCKED: DUPLICATE SUBMISSION DETECTED (${activeMatches.length} CONFLICTS)!\n\n${list}\n\nFinal approval and Employee ID assignment are strictly blocked until all duplicate records are resolved.`);
                return;
              }
            }
          }
        }

        if (!isFinal) {
          // Progress to next level
          const nextEffective = getEffectiveApprovalLevel(nextRawLevel, site, config, staffUsers, roles);
          await updateSubmissionStatus(submissionId, 'Pending Review', comments, actorName, employeeId, nextEffective, actorRole);
          logSystemAction('APPROVAL', 'EMPLOYEES', `Approved application level ${effectiveLevel} (Pending Level ${nextEffective}) (ID: ${submissionId}).`);

          // Notify next level approvers
          const nextLevelConfig = config?.levels.find(l => l.level === nextEffective);
          if (nextLevelConfig) {
            notifyApprovers(submissionId, nextLevelConfig.roleId, `New Application Review: Level ${nextEffective}`, AppView.ADMIN_PORTAL_SUBMISSION_REVIEW);
          }
        } else {
          // Final Approval
          await updateSubmissionStatus(submissionId, 'Approved', comments, actorName, employeeId, undefined, actorRole, profileCompletionData, customJoiningDate, customRecruiter);
          logSystemAction('APPROVAL', 'EMPLOYEES', `Final Approval for application (ID: ${submissionId}). Assigned ID: ${employeeId || 'Auto'}. Profile: ${profileCompletionData?.profileCompletionStatus || 'COMPLETE'}. Joining Date: ${customJoiningDate || 'Today'}${customRecruiter ? `. Recruiter: ${customRecruiter.name || 'Direct Apply'}` : ''}`);
        }
      }
      refreshGlobalStats();
    } catch (error: any) {
      console.error("Error updating submission status:", error);
      alert(`Action Failed: ${error.message}`);
    }
  }, [authUser, logSystemAction, submittedForms, workflowConfigs, isSuperAdmin, notifyApprovers, roles, refreshGlobalStats, sites, staffUsers]);

  // NEW: ADVANCED MANAGEMENT HANDLERS
  const handleUpdateSubmissionId = useCallback(async (submissionId: string, oldId: string, newId: string) => {
    try {
      await updateSubmissionEmployeeId(submissionId, oldId, newId);
      logSystemAction('UPDATE', 'SUBMISSION', `Corrected Employee ID from ${oldId} to ${newId} (Sub: ${submissionId})`);
      sendNotification(authUser?.id || 'admin', `Employee ID updated to ${newId}.`, 'success');
    } catch (err: any) {
      alert(`Update Failed: ${err.message}`);
    }
  }, [authUser, logSystemAction, sendNotification]);

  const handleRevertSubmission = useCallback(async (submissionId: string, level: number, comments?: string) => {
    if (!authUser) return;
    const actorName = authUser.name || 'Admin';
    const actorRole = roles.find(r => r.id === authUser.roleId)?.name || 'Admin';

    try {
      await revertSubmissionWorkflow(submissionId, level, comments, actorName, actorRole);
      setSubmittedForms(prev => prev.map(s => s.id === submissionId ? { 
        ...s, 
        currentLevel: level, 
        status: SubmissionStatus.PENDING_REVIEW, 
        employeeId: '',
        approvalHistory: [
          ...(s.approvalHistory || []),
          {
            level: s.currentLevel,
            actionBy: actorName,
            actionByRole: actorRole,
            status: 'Reverted',
            comments: comments && comments.trim() ? `[Reverted to Level ${level}]: ${comments.trim()}` : `Reverted to Level ${level}`,
            timestamp: new Date().toISOString()
          }
        ]
      } : s));
      logSystemAction('UPDATE', 'SUBMISSION', `Reverted submission ${submissionId} to Level ${level}${comments ? `: ${comments}` : ''}`);
      sendNotification(authUser?.id || 'admin', `Submission reverted to Level ${level}.`, 'success');
    } catch (err: any) {
      alert(`Revert Failed: ${err.message}`);
    }
  }, [authUser, roles, logSystemAction, sendNotification]);

  const handleSoftDeleteSubmission = useCallback(async (id: string) => {
    try {
      // SMART CHECK: Is this an Employee or Submission?
      // 1. If it is a Portal ID, it's definitely a submission
      // 2. Otherwise, check if it exists in employees collection
      let isEmployee = false;
      if (!isPortalId(id)) {
        isEmployee = await checkEmployeeIdExists(id);
      }

      if (isEmployee) {
        await softDeleteEmployee(id);
      } else {
        await softDeleteSubmission(id);
      }

      setSubmittedForms(prev => prev.map(s => (s.id === id || s.employeeId === id) ? { ...s, status: SubmissionStatus.REJECTED, deletedAt: new Date().toISOString() } : s));
      logSystemAction('DELETE', 'SUBMISSION', `Soft deleted record ${id}`);
      refreshGlobalStats();
    } catch (error: any) {
      alert(error.message);
    }
  }, [logSystemAction, refreshGlobalStats]);

  const handleSoftDeleteEmployee = useCallback(async (employeeId: string) => {
    try {
      const emp = employees.find(e => e.id === employeeId || e.employeeId === employeeId);
      await softDeleteEmployee(employeeId);
      setSubmittedForms(prev => prev.map(s => (s.id === employeeId || s.employeeId === employeeId) ? { ...s, deletedAt: new Date().toISOString(), status: 'Deleted' as any } : s));
      logSystemAction('DELETE', 'EMPLOYEES', `Soft deleted employee ${employeeId}`);
    } catch (error: any) {
      alert(error.message);
    }
  }, [logSystemAction, employees]);



  const handleSyncDrive = useCallback(async (employeeId: string) => {
    try {
      sendNotification(authUser?.id || 'admin', `Syncing Drive for ${employeeId}...`, 'info');
      await syncDriveFolder(employeeId);
      sendNotification(authUser?.id || 'admin', `Drive folder synced successfully.`, 'success');
    } catch (error: any) {
      sendNotification(authUser?.id || 'admin', `Sync Failed: ${error.message}`, 'error');
      alert(`Sync Failed: ${error.message}`);
    }
  }, [authUser, sendNotification]);





  const handleDeleteSubmission = useCallback(async (id: string) => {
    setScanLoading({ isScanning: true, targetId: id, name: 'Employee' });
    try {
      // 1. Resolve full employee identity across employee records, submissions, auth UIDs, and emails
      const context = await resolveEmployeeFullContext(id);

      // 2. Fallback name if context didn't resolve one
      let name = context.applicantName;
      if (!name || name === 'Unknown') {
        const sub = submittedForms.find(s => s.employeeId === id || s.id === id);
        if (sub) {
          name = getApplicantName(sub.data, sub.originalFormSections) || id;
        } else {
          name = id;
        }
      }
      setScanLoading({ isScanning: true, targetId: id, name });

      // 3. Comprehensive scan across all 15 operational and relational areas (optimized parallel execution)
      const counts = await getEmployeeRecordCounts(context);

      setScanLoading(null);
      setDeletionSummary({
        id: context.employeeId || id,
        name,
        counts,
        context
      });
    } catch (error: any) {
      setScanLoading(null);
      log.error('[handleDeleteSubmission] Error scanning employee context:', error);
      alert(`Scan Failed: ${error.message}`);
    }
  }, [submittedForms]);

  const handleConfirmDeletion = async (deep: boolean) => {
    if (!deletionSummary) return;

    if (deep) {
      // Dual Authentication: Require Google Re-Authentication for permanent Deep Purge
      setIsAuthenticating(true);
      try {
        const { auth } = await import('./src/firebase/config');
        const { GoogleAuthProvider, signInWithPopup } = await import('firebase/auth');

        if (!auth.currentUser) {
          throw new Error("You must be signed in with your administrator account to authorize Deep Purge.");
        }

        const provider = new GoogleAuthProvider();
        provider.setCustomParameters({ prompt: 'select_account' });

        const result = await signInWithPopup(auth, provider);
        const signedInEmail = (result.user.email || '').toLowerCase().trim();
        const activeEmail = (auth.currentUser.email || authUser?.email || '').toLowerCase().trim();

        if (signedInEmail && activeEmail && signedInEmail !== activeEmail) {
          throw new Error(`Account mismatch: Re-authentication used "${signedInEmail}", but current admin session is logged in as "${activeEmail}".`);
        }
      } catch (authErr: any) {
        setIsAuthenticating(false);
        if (authErr.code === 'auth/popup-closed-by-user' || authErr.code === 'auth/cancelled-popup-request') {
          return; // User voluntarily cancelled Google re-auth
        }
        alert(`Google Re-Authentication Failed: ${authErr.message || 'Authorization is required for Deep Purge.'}`);
        return;
      } finally {
        setIsAuthenticating(false);
      }
    }

    setIsDeleting(true);
    try {
      const { id, name, context } = deletionSummary;
      const targetId = context?.employeeId || context?.docId || id;

      await permanentDeleteEmployee(targetId, name, deep);

      const idsToRemove = new Set(context?.allIds || [id]);
      if (context?.submissionId) idsToRemove.add(context.submissionId);
      if (context?.docId) idsToRemove.add(context.docId);
      if (context?.employeeId) idsToRemove.add(context.employeeId);
      if (id) idsToRemove.add(id);

      setSubmittedForms(prev => prev.filter(s => !idsToRemove.has(s.id) && !(s.employeeId && idsToRemove.has(s.employeeId))));
      setEmployees(prev => prev.filter(e => !idsToRemove.has(e.id) && !(e.employeeId && idsToRemove.has(e.employeeId))));

      // Immediately notify all active table views (e.g. Master Employee List) to purge rows from local state
      window.dispatchEvent(new CustomEvent('udf:record-deleted', { detail: { id: targetId, allIds: Array.from(idsToRemove) } }));

      logSystemAction('DELETE', 'EMPLOYEES', `${deep ? 'Deep purge (Google Authenticated)' : 'Standard deletion'} of ${name} (${targetId})`);
      sendNotification(authUser?.id || 'admin', `${name} has been ${deep ? 'fully purged' : 'deleted'}.`, 'success');
      setDeletionSummary(null);
      refreshGlobalStats();
    } catch (error: any) {
      alert(`Deletion Failed: ${error.message}`);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleBulkSoftDeleteSubmissions = useCallback(async (ids: string[]) => {
    try {
      // SMART HANDLING: Detect ID types accurately
      const subIds: string[] = [];
      const empIds: string[] = [];

      for (const id of ids) {
        if (isPortalId(id)) {
          subIds.push(id);
        } else {
          const isEmployee = await checkEmployeeIdExists(id);
          if (isEmployee) empIds.push(id);
          else subIds.push(id); // Treat as legacy submission ID
        }
      }

      let totalSuccess = 0;

      if (subIds.length > 0) {
        const res = await bulkSoftDeleteSubmissions(subIds);
        totalSuccess += res.success;
      }

      if (empIds.length > 0) {
        // Find existing submissions for these employees to keep them in sync
        const subIdPromises = empIds.map(id => findSubmissionIdByEmployeeId(id));
        const resolvedSubIds = (await Promise.all(subIdPromises)).filter(Boolean) as string[];

        if (resolvedSubIds.length > 0) {
          const res = await bulkSoftDeleteSubmissions(resolvedSubIds);
          totalSuccess += res.success;
        } else {
          // If no submissions found, just soft delete employee records
          for (const id of empIds) {
            await softDeleteEmployee(id);
            totalSuccess++;
          }
        }
      }

      setSubmittedForms(prev => prev.map(s => ids.includes(s.id) || (s.employeeId && ids.includes(s.employeeId)) ? { ...s, status: SubmissionStatus.REJECTED, deletedAt: new Date().toISOString() } : s));
      logSystemAction('DELETE', 'EMPLOYEES', `Bulk soft deleted ${totalSuccess} records.`);
      sendNotification(authUser?.id || 'admin', `Bulk move to Recycle Bin successful (${totalSuccess} items).`, 'success');
      refreshGlobalStats();
    } catch (error: any) {
      alert(error.message);
    }
  }, [logSystemAction, authUser, sendNotification, refreshGlobalStats]);

  const handleBulkDeleteSubmissions = useCallback(async (ids: string[]) => {
    try {
      let totalSuccess = 0;
      const idsToRemove = new Set<string>(ids);

      for (const id of ids) {
        try {
          const ctx = await resolveEmployeeFullContext(id);
          const targetId = ctx.employeeId || ctx.docId || id;
          await permanentDeleteEmployee(targetId, ctx.applicantName, true);
          ctx.allIds.forEach(i => idsToRemove.add(i));
          totalSuccess++;
        } catch (e) {
          log.warn(`[BulkDelete] Error deleting ${id}:`, e);
        }
      }

      setSubmittedForms(prev => prev.filter(s => !idsToRemove.has(s.id) && !(s.employeeId && idsToRemove.has(s.employeeId))));
      setEmployees(prev => prev.filter(e => !idsToRemove.has(e.id) && !(e.employeeId && idsToRemove.has(e.employeeId))));
      logSystemAction('DELETE', 'EMPLOYEES', `Bulk permanently deleted ${totalSuccess} records.`);
      sendNotification(authUser?.id || 'admin', `Bulk permanent deletion successful (${totalSuccess} items).`, 'success');
      refreshGlobalStats();
    } catch (error: any) {
      alert(error.message);
    }
  }, [logSystemAction, authUser, sendNotification, refreshGlobalStats, setSubmittedForms, setEmployees]);

  const handleRevertWorkflowRequest = useCallback(async (moduleId: 'LEAVES' | 'ACCOUNT_UPDATES' | 'RESIGNATIONS', requestId: string, level: number) => {
    try {
      const collMap = {
        'LEAVES': 'leave_requests',
        'ACCOUNT_UPDATES': 'account_updates',
        'RESIGNATIONS': 'resignations'
      } as const;

      // processRequestReviewServer (called inside revertWorkflowRequest) atomically
      // refunds leave balances and records the audit log entry when reverting an Approved leave.
      await revertWorkflowRequest(collMap[moduleId], requestId, level);
      logSystemAction('UPDATE', moduleId as any, `Reverted request ${requestId} to Level ${level}`);
      sendNotification(authUser?.id || 'admin', `${moduleId.replace('_', ' ')} request reverted to Level ${level}.`, 'success');
      refreshGlobalStats();
    } catch (err: any) {
      alert(`Revert Failed: ${err.message}`);
    }
  }, [authUser, logSystemAction, sendNotification, refreshGlobalStats, leaveRequests]);


  const handleDeleteWorkflowRequest = useCallback(async (moduleId: 'LEAVES' | 'ACCOUNT_UPDATES' | 'RESIGNATIONS', requestId: string) => {
    try {
      if (window.confirm(`PERMANENT DELETE: Are you sure you want to delete this ${moduleId.toLowerCase().replace('_', ' ')} request?`)) {
        const collMap = {
          'LEAVES': 'leave_requests',
          'ACCOUNT_UPDATES': 'account_updates',
          'RESIGNATIONS': 'resignations'
        } as const;

        // Item 5: If permanently deleting an approved leave, refund the balance back
        if (moduleId === 'LEAVES') {
          const req = leaveRequests.find(r => r.id === requestId);
          if (req && req.status === RequestStatus.APPROVED) {
            const [sY, sM, sD] = req.startDate.split('-').map(Number);
            const [eY, eM, eD] = req.endDate.split('-').map(Number);
            const daysTaken = Math.round((Date.UTC(eY, eM - 1, eD) - Date.UTC(sY, sM - 1, sD)) / (1000 * 3600 * 24)) + 1;
            const { updateEmployeeLeaveBalance } = await import('./src/services/employeeService');
            await updateEmployeeLeaveBalance(req.employeeId, req.leaveType, -daysTaken);
          }
        }

        await deleteWorkflowRequest(collMap[moduleId], requestId);

        switch (moduleId) {
          case 'LEAVES': setLeaveRequests(prev => prev.filter(r => r.id !== requestId)); break;
          case 'ACCOUNT_UPDATES': setAccountUpdateRequests(prev => prev.filter(r => r.id !== requestId)); break;
          case 'RESIGNATIONS': setResignationRequests(prev => prev.filter(r => r.id !== requestId)); break;
        }

        logSystemAction('DELETE', moduleId as any, `Permanently deleted ${moduleId} request ${requestId}`);
        sendNotification(authUser?.id || 'admin', `${moduleId.replace('_', ' ')} request deleted successfully.`, 'success');
        refreshGlobalStats();
      }
    } catch (err: any) {
      alert(`Delete Failed: ${err.message}`);
    }
  }, [authUser, logSystemAction, sendNotification, refreshGlobalStats, leaveRequests, setLeaveRequests, setAccountUpdateRequests, setResignationRequests]);

  const handleDeleteDisciplinaryAction = useCallback(async (actionId: string) => {
    try {
      if (window.confirm("PERMANENT DELETE: Delete this disciplinary record?")) {
        await deleteDisciplinaryAction(actionId);
        setDisciplinaryActions(prev => prev.filter(a => a.id !== actionId));
        logSystemAction('DELETE', 'EMPLOYEES', `Deleted disciplinary action ${actionId}`);
        sendNotification(authUser?.id || 'admin', `Disciplinary record deleted.`, 'success');
        refreshGlobalStats();
      }
    } catch (err: any) {
      alert(`Delete Failed: ${err.message}`);
    }
  }, [authUser, logSystemAction, sendNotification, refreshGlobalStats]);


  const handleSaveDraft = useCallback(async (data: any, sectionIndex: number, existingDraftId?: string) => {
    if (checkWritesBlock()) throw new Error("Database is in Read-Only Mode.");
    try {
      const targetId = existingDraftId || activeDraft?.id;
      const invId = (data as any)?.__referralInviteId || activeDraft?.inviteId || (typeof window !== 'undefined' ? (sessionStorage.getItem('referralInviteId') || localStorage.getItem('referralInviteId') || null) : null);
      if (invId && data && !data.__referralInviteId) {
        data.__referralInviteId = invId;
      }
      const draftId = await saveFormDraft(data, sectionIndex, targetId);
      // Do not call setActiveDraft here — echoing the saved snapshot back down triggers
      // an initialDraft update in EmployeeFormPage that can overwrite live user input or jump tabs.
      return draftId;
    } catch (err: any) {
      if (err?.message?.includes('APPLICATION_ALREADY_SUBMITTED')) {
        // Handled smoothly by EmployeeFormPage by switching to the submitted confirmation view
        throw err;
      }
      alert(`Save Draft Failed: ${err.message}`);
      throw err;
    }
  }, [activeDraft]);

  const handleRetrieveDraft = useCallback(async (draftId: string, silent: boolean = true) => {
    try {
      const draft = await getFormDraft(draftId);
      if (draft) {
        const invId = draft.inviteId || (draft.data as any)?.__referralInviteId || null;
        if (invId && typeof window !== 'undefined') {
          sessionStorage.setItem('referralInviteId', invId);
          localStorage.setItem('referralInviteId', invId);
        }
        if (typeof window !== 'undefined') {
          sessionStorage.setItem('onboarding_savedDraftId', JSON.stringify(draft.id));
          localStorage.setItem('onboarding_savedDraftId', JSON.stringify(draft.id));
        }
        setActiveDraft({ id: draft.id, data: draft.data, sectionIndex: draft.sectionIndex, inviteId: invId });
        navigateTo(AppView.EMPLOYEE_JOINING_FORM);
        return true;
      } else {
        if (!silent) {
          alert("Draft could not be found. Please check your recovery code.");
        }
        return false;
      }
    } catch (err: any) {
      console.error("Retrieve Draft Failed:", err);
      if (!silent) {
        alert(`Retrieve Failed: ${err.message}`);
      }
      return false;
    }
  }, [navigateTo]);

  const handleDiscardDraft = useCallback(async (draftId: string) => {
    try {
      await discardFormDraft(draftId);
      setActiveDraft(null);
      return true;
    } catch (err: any) {
      alert(`Discard Draft Failed: ${err.message}`);
      return false;
    }
  }, []);

  const handleRestoreEmployee = useCallback(async (id: string) => {
    try {
      sendNotification(authUser?.id || 'admin', `Restoring record...`, 'info');

      if (isPortalId(id)) {
        // Special case for restoring just the submission
        await restoreEmployee(id); // service handles SUB- prefix now
      } else {
        await restoreEmployee(id);
      }

      // Update local state to reflect restoration
      setSubmittedForms(prev => prev.map(s => (s.id === id || s.employeeId === id) ? { ...s, deletedAt: null, status: s.status === 'Deleted' ? 'Approved' : s.status } : s));

      logSystemAction('STATUS_CHANGE', 'EMPLOYEES', `Restored record ${id}`);
      sendNotification(authUser?.id || 'admin', `Record restored successfully.`, 'success');
    } catch (err: any) {
      alert(`Restore Failed: ${err.message}`);
    }
  }, [authUser, logSystemAction, sendNotification]);

  const handleRelieveEmployee = useCallback(async (
    employeeId: string,
    relievingDate: string,
    reason: 'Resignation' | 'Termination' | 'Absconding' | 'ContractEnded' | 'Other'
  ) => {
    try {
      sendNotification(authUser?.id || 'admin', `Relieving employee...`, 'info');
      await relieveEmployee(employeeId, relievingDate, reason);
      logSystemAction('STATUS_CHANGE', 'EMPLOYEES', `Relieved employee ${employeeId}. Reason: ${reason}`);
      sendNotification(authUser?.id || 'admin', `Employee relieved successfully.`, 'success');
    } catch (err: any) {
      alert(`Relieve Failed: ${err.message}`);
    }
  }, [authUser, logSystemAction, sendNotification]);

  const handleRejoinEmployee = useCallback(async (
    employeeId: string,
    rejoinDate: string,
    siteId: string,
    subUnitId: string | undefined,
    designation: string,
    newEmployeeId?: string,
    foldersToCopy?: string[]
  ) => {
    try {
      sendNotification(authUser?.id || 'admin', `Rejoining employee...`, 'info');

      // Look up names for service
      const site = sites.find(s => s.id === siteId);
      const siteName = site?.name || 'Unknown Site';
      let subUnitName: string | undefined = undefined;

      if (subUnitId && site?.subUnits) {
        const subUnit = site.subUnits.find(su => su.id === subUnitId);
        subUnitName = subUnit?.name;
      }

      await rejoinEmployee(
        employeeId,
        rejoinDate,
        siteId,
        siteName,
        subUnitId,
        subUnitName,
        designation,
        newEmployeeId,
        foldersToCopy
      );

      logSystemAction('STATUS_CHANGE', 'EMPLOYEES', `Rejoined employee ${employeeId} to ${siteName} as ${designation}${newEmployeeId ? ` (New ID: ${newEmployeeId})` : ''}`);
      sendNotification(authUser?.id || 'admin', `Employee rejoined successfully.`, 'success');
    } catch (err: any) {
      alert(`Rejoin Failed: ${err.message}`);
    }
  }, [authUser, logSystemAction, sendNotification, sites]);

  // findSubmissionIdByEmployeeId is now used directly from employeeService import

  const handleApproveProfileCompletion = useCallback(async (employeeId: string) => {
    try {
      const { db } = await import('./src/firebase/config');
      const { doc, updateDoc, getDoc, writeBatch } = await import('firebase/firestore');
      const { resolveEmployeeDoc } = await import('./src/services/employeeService');

      const resolved = await resolveEmployeeDoc(employeeId);
      const empRef = resolved ? resolved.ref : doc(db, 'employees', employeeId);

      const subId = await findSubmissionIdByEmployeeId(employeeId);
      if (subId) {
        const subRef = doc(db, 'onboarding_submissions', subId);
        const subSnap = await getDoc(subRef);

        const updateData: any = {
          needsProfileCompletion: false,
          profileStatus: 'approved',
          lastUpdated: new Date().toISOString()
        };

        let sourceUid = subId;
        if (subSnap.exists()) {
          const subData = subSnap.data();
          if (subData.authProvider) updateData.authProvider = subData.authProvider;
          if (subData.linkedGoogleEmail) updateData.linkedGoogleEmail = subData.linkedGoogleEmail;
          if (subData.linkedUid) {
            updateData.uid = subData.linkedUid;
            sourceUid = subData.linkedUid;
          }
        }

        // Migrate files in storage
        const { moveStorageFiles } = await import('./src/services/storageService');
        await moveStorageFiles(`onboarding/${sourceUid}`, `employees/${employeeId}`);

        // Read active employee record to update dynamic storage paths
        const empSnap = await getDoc(empRef);
        if (empSnap.exists()) {
          const empData = empSnap.data() as any;
          const rewriteStoragePaths = (obj: any, oldPrefix: string, newPrefix: string): any => {
            if (!obj) return obj;
            if (typeof obj !== 'object') return obj;
            if (Array.isArray(obj)) {
              return obj.map(item => rewriteStoragePaths(item, oldPrefix, newPrefix));
            }
            const newObj: any = {};
            for (const key of Object.keys(obj)) {
              const val = obj[key];
              if (val && typeof val === 'object' && val.storagePath && typeof val.storagePath === 'string') {
                newObj[key] = {
                  ...val,
                  storagePath: val.storagePath.replace(oldPrefix, newPrefix)
                };
              } else {
                newObj[key] = rewriteStoragePaths(val, oldPrefix, newPrefix);
              }
            }
            return newObj;
          };

          const oldPrefix = `onboarding/${sourceUid}`;
          const newPrefix = `employees/${employeeId}`;
          if (empData.profileData) {
            updateData.profileData = rewriteStoragePaths(empData.profileData, oldPrefix, newPrefix);
          }
          if (empData.data) {
            updateData.data = rewriteStoragePaths(empData.data, oldPrefix, newPrefix);
          }
        }

        const batch = writeBatch(db);
        batch.update(empRef, updateData);
        batch.update(subRef, {
          needsProfileCompletion: false,
          profileStatus: 'approved',
          lastUpdated: new Date().toISOString()
        });
        await batch.commit();
      } else {
        await updateDoc(empRef, {
          needsProfileCompletion: false,
          profileStatus: 'approved',
          lastUpdated: new Date().toISOString()
        });
      }

      logSystemAction('APPROVAL', 'EMPLOYEES', `Approved profile completion for ${employeeId}`);
      sendNotification(authUser?.id || 'admin', `Profile for ${employeeId} approved and activated.`, 'success');
    } catch (err: any) {
      alert(`Approval Failed: ${err.message}`);
    }
  }, [authUser, logSystemAction, sendNotification]);

  const handleUpdateSubmissionComment = useCallback(async (submissionId: string, historyIndex: number, newComment: string) => {
    try {
      const { db } = await import('./src/firebase/config');
      const { doc, getDoc, updateDoc } = await import('firebase/firestore');
      const subRef = doc(db, 'onboarding_submissions', submissionId);
      const subSnap = await getDoc(subRef);
      if (subSnap.exists()) {
        const data = subSnap.data();
        const history = [...(data.approvalHistory || [])];
        if (history[historyIndex]) {
          const oldComment = history[historyIndex].comments;
          history[historyIndex].comments = newComment;
          await updateDoc(subRef, { approvalHistory: history });

          // Also update the employee record if approved
          if (data.employeeId) {
            const { resolveEmployeeDoc } = await import('./src/services/employeeService');
            const resolved = await resolveEmployeeDoc(data.employeeId);
            if (resolved) {
              await updateDoc(resolved.ref, { approvalHistory: history });
            }
          }
          logSystemAction('UPDATE', 'SUBMISSION', `Updated review comment at step ${historyIndex} from "${oldComment || ''}" to "${newComment}"`);
          sendNotification(authUser?.id || 'admin', `Review comment updated successfully.`, 'success');
        }
      }
    } catch (err: any) {
      alert(`Failed to update comment: ${err.message}`);
    }
  }, [authUser, sendNotification]);

  const adminProps = {
    currentAdminView: currentView,
    navigateTo: navigateTo,
    onLogout: handleLogout,
    authUser: authUser,
    isSuperAdmin: isSuperAdmin,
    allowedSiteIds: allowedSiteIds,
    userRole: (() => {
      const baseRole = roles.find(r => r.id === authUser?.roleId);
      if (!baseRole) return undefined;

      const overrides = (authUser as any)?.permissionOverrides || {};
      const mergedPermissions = [...(baseRole.permissions || [])];

      // Apply overrides: true adds, false filters out
      Object.entries(overrides).forEach(([p, val]) => {
        if (val === true) {
          if (!mergedPermissions.includes(p)) {
            mergedPermissions.push(p);
          }
        } else if (val === false) {
          const index = mergedPermissions.indexOf(p);
          if (index > -1) {
            mergedPermissions.splice(index, 1);
          }
        }
      });

      return {
        ...baseRole,
        permissions: mergedPermissions
      };
    })(),
    onUpdateComment: handleUpdateSubmissionComment,
    sections: syncedSections,
    addSection: formBuilder.addSection,
    updateSectionName: formBuilder.updateSectionName,
    deleteSection: formBuilder.deleteSection,
    reorderSections: formBuilder.reorderSections,
    addField: formBuilder.addField,
    updateField: formBuilder.updateField,
    deleteField: formBuilder.deleteField,
    reorderFields: formBuilder.reorderFields,
    setSections: formBuilder.setSections,
    submittedForms: submittedForms,
    onApproveSubmission: handleAdminApproveSubmission,
    onBulkAddEmployees: (newEmp: any) => setSubmittedForms(prev => [...prev, ...newEmp]),
    leaveRequests: leaveRequests,
    onLeaveAction: handleAdminLeaveAction,
    accountUpdateRequests: accountUpdateRequests,
    onAccountUpdateAction: handleAdminAccountUpdateAction,
    resignationRequests: resignationRequests,
    onResignationAction: handleAdminResignationAction,
    roles: roles,
    setRoles: handleUpdateRoles,
    staffUsers: staffUsers,
    setStaffUsers: handleUpdateStaffUsers,
    workflowConfigs: workflowConfigs,
    setWorkflowConfigs: handleUpdateWorkflows,
    sites: sites,
    setSites: handleUpdateSites,
    toggleSectionStatus: formBuilder.toggleSectionStatus,
    toggleFieldStatus: formBuilder.toggleFieldStatus,
    editableFieldIds: editableFieldIds,
    setEditableFieldIds: handleUpdateEditableFields,
    leaveBalances: leaveBalances,
    disciplinaryActions: disciplinaryActions,
    employees: employees,
    drafts: drafts,
    onAddDiscipline: handleAddDisciplinaryAction,
    leavePolicy: leavePolicy,
    onUpdateLeavePolicy: handleUpdateLeavePolicy,
    portalConfig: portalConfig,
    setPortalConfig: handleUpdatePortalConfig,
    logAction: logSystemAction,
    notifications: notifications,
    onRevertSubmission: handleRevertSubmission,
    onDeleteSubmission: handleDeleteSubmission,
    onSoftDeleteSubmission: handleSoftDeleteSubmission,
    onSoftDeleteEmployee: handleSoftDeleteEmployee,
    onRestoreEmployee: handleRestoreEmployee,

    onRelieveEmployee: handleRelieveEmployee,
    onRejoinEmployee: handleRejoinEmployee,
    onSyncDrive: handleSyncDrive,
    onUpdateId: handleUpdateSubmissionId,
    onRevertWorkflowRequest: handleRevertWorkflowRequest,
    onDeleteRequest: handleDeleteWorkflowRequest,
    onDeleteDiscipline: handleDeleteDisciplinaryAction,
    onBulkDelete: handleBulkDeleteSubmissions,
    onBulkSoftDelete: handleBulkSoftDeleteSubmissions,
    onApproveProfile: handleApproveProfileCompletion,

    markNotificationAsRead: markNotificationAsRead,
    markAllNotificationsAsRead: markAllNotificationsAsRead,

    timelineEmployeeId: timelineEmployeeId,
    onViewTimeline: (empId: string) => {
      setTimelineEmployeeId(empId);
      try {
        sessionStorage.setItem('activeTimelineEmployeeId', empId);
      } catch {}
      setCurrentView(AppView.ADMIN_PORTAL_EMPLOYEE_TIMELINE);
    },
  };



  const handleDocumentUpload = useCallback(async (fieldId: string, file: File): Promise<string> => {
    if (!authUser || !employeeData) throw new Error("Not logged in");

    try {
      const name = employeeData.applicantName || authUser.name || 'Unknown';
      const submissionId = await findSubmissionIdByEmployeeId(authUser.id);

      // PRIMARY: Upload to Firebase Storage
      const url = await uploadSubmissionDocument(
        fieldId,
        file
      );

      // BACKUP: Fire-and-forget Drive copy
      uploadToDrive(file, name, "Profile Completion", submissionId || authUser.id)
        .then(() => console.log(`[DRIVE_BACKUP] ✅ ${file.name} backed up`))
        .catch(err => console.warn(`[DRIVE_BACKUP] ⚠️ ${file.name} backup failed:`, err));

      return url;
    } catch (err: any) {
      console.error("Single doc upload error:", err);
      throw err;
    }
  }, [authUser, employeeData]);

  const handleCompleteProfile = useCallback(async (updatedData?: Record<string, any>) => {
    if (!authUser || !employeeData) throw new Error("Not logged in");

    try {
      const { db } = await import('./src/firebase/config');
      const { doc, updateDoc } = await import('firebase/firestore');

      const userUniqueId = authUser.portalId || authUser.id || authUser.employeeId;
      const { resolveEmployeeDoc } = await import('./src/services/employeeService');
      const resolved = await resolveEmployeeDoc(userUniqueId);
      const empRef = resolved ? resolved.ref : doc(db, 'employees', userUniqueId);
      const requiresAdminApproval = (employeeData as any).importedVia === 'pending_profile_import';

      const employeePayload: any = {
        lastUpdated: new Date().toISOString()
      };

      if (requiresAdminApproval) {
        employeePayload.profileStatus = 'waiting_for_admin';
      } else {
        employeePayload.needsProfileCompletion = false;
        employeePayload.profileStatus = 'approved';
      }

      if (updatedData) {
        // Merge updated profile data fields directly
        employeePayload.profileData = { ...employeeData.profileData, ...updatedData };
        employeePayload.data = { ...employeeData.data, ...updatedData };
      }

      await updateDoc(empRef, employeePayload);

      const subId = await findSubmissionIdByEmployeeId(userUniqueId);
      if (subId) {
        const subRef = doc(db, 'onboarding_submissions', subId);

        const submissionPayload: any = {
          lastUpdated: new Date().toISOString()
        };

        if (requiresAdminApproval) {
          submissionPayload.profileStatus = 'waiting_for_admin';
        } else {
          submissionPayload.needsProfileCompletion = false;
          submissionPayload.profileStatus = 'approved';
        }

        if (updatedData) {
          submissionPayload.formData = { ...employeeData.formData, ...updatedData };
          submissionPayload.data = { ...employeeData.data, ...updatedData };
        }

        await updateDoc(subRef, submissionPayload);
      }

      if (requiresAdminApproval) {
        sendNotification(userUniqueId, "Profile submitted for admin approval! You will be notified once activated.", "info");
      } else {
        setAuthUser(prev => prev ? { ...prev, needsProfileCompletion: false } : null);
        sendNotification(userUniqueId, "Profile completed successfully! Welcome aboard.", "success");
      }
      navigateTo(AppView.EMPLOYEE_DASHBOARD);
    } catch (err: any) {
      console.error("Finalize profile error:", err);
      throw err;
    }
  }, [authUser, employeeData, navigateTo, sendNotification]);

  const employeeProps = {
    currentEmployeeView: currentView,
    navigateTo: navigateTo,
    onLogout: handleLogout,
    onLoginSuccess: async (emp: any) => {
      const name = emp.applicantName || emp.name || getApplicantName(emp.data, emp.originalFormSections) || emp.employeeId;
      const employeeUser = {
        type: UserType.EMPLOYEE,
        id: emp.id!,
        employeeId: emp.employeeId,
        portalId: emp.portalId || emp.submissionId || emp.id,
        isDefaultPassword: emp.isDefaultPassword || false,
        authProvider: emp.authProvider || 'manual',
        linkedGoogleEmail: emp.linkedGoogleEmail,
        name
      };
      setAuthUser(employeeUser);
      await logSystemAction('LOGIN', 'AUTH', `Employee logged in: ${name} (${emp.employeeId})`, employeeUser);
      const balance = leaveBalances.find(b => b.employeeId === emp.employeeId || b.employeeId === employeeUser.portalId);
      const redirectParam = new URLSearchParams(window.location.search).get('redirect');
      // Strictly prevent Open Redirect: must start with single '/', never '//', no protocol/scheme
      const safeRedirect = (redirectParam && redirectParam.startsWith('/') && !redirectParam.startsWith('//') && !redirectParam.startsWith('/\\') && !redirectParam.includes('://'))
        ? redirectParam
        : '/dashboard';
      navigate(safeRedirect);
    },
    authUser: authUser,
    employeeData: employeeData,
    leaveRequests: leaveRequests.filter(lr => lr.employeeId === authUser?.id || (authUser?.employeeId && lr.employeeId === authUser.employeeId) || (authUser?.portalId && lr.employeeId === authUser.portalId)),
    accountUpdateRequests: accountUpdateRequests.filter(aur => aur.employeeId === authUser?.id || (authUser?.employeeId && aur.employeeId === authUser.employeeId) || (authUser?.portalId && aur.employeeId === authUser.portalId)),
    resignationRequests: resignationRequests.filter(r => r.employeeId === authUser?.id || (authUser?.employeeId && r.employeeId === authUser.employeeId) || (authUser?.portalId && r.employeeId === authUser.portalId)),
    onSubmitLeaveRequest: handleSubmitLeaveRequest,
    onSubmitAccountUpdateRequest: handleSubmitAccountUpdateRequest,
    onSubmitResignationRequest: handleSubmitResignationRequest,
    onDocumentUpload: handleDocumentUpload,
    onCompleteProfile: handleCompleteProfile,
    formSections: syncedSections,
    editableFieldIds: editableFieldIds,
    roles: roles,
    workflowConfigs: workflowConfigs,
    leaveBalances: leaveBalances.filter(b => b.employeeId === authUser?.id || (authUser?.employeeId && b.employeeId === authUser.employeeId) || (authUser?.portalId && b.employeeId === authUser.portalId)),
    disciplinaryActions: disciplinaryActions.filter(d => d.employeeId === authUser?.id || (authUser?.employeeId && d.employeeId === authUser.employeeId) || (authUser?.portalId && d.employeeId === authUser.portalId)),
    leavePolicy: leavePolicy,
    portalConfig: portalConfig,
    sites: sites, // Added this
    notifications: notifications.filter(n => n.targetUserId === authUser?.id || (authUser?.employeeId && n.targetUserId === authUser.employeeId) || (authUser?.portalId && n.targetUserId === authUser.portalId)),
    markNotificationAsRead: markNotificationAsRead,
    markAllNotificationsAsRead: () => markAllNotificationsAsRead(authUser?.id || ''),
  };

  if (isLoading || authLoading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-gray-50 bg-opacity-75 z-50">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }
  // SAFETY CIRCUIT BREAKER: Block non-super-admins if database is locked/capped
  const isEmergencyLocked = portalConfig?.manualEmergencyLock === true || portalConfig?.blockReadsOnLimit === true;
  if (isEmergencyLocked && !isSuperAdmin) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-gray-950 text-white p-6 text-center select-none font-sans">
        <div className="bg-gray-900 p-8 rounded-2xl shadow-2xl max-w-md border border-red-500/20">
          <div className="text-red-500 text-6xl mb-4 animate-pulse">🛑</div>
          <h1 className="text-2xl font-bold mb-4 text-red-400">Portal Maintenance</h1>
          <p className="text-gray-400 mb-6 text-sm leading-relaxed">
            The Unique Delta Force HR Portal is currently undergoing temporary database maintenance to optimize performance and control resource usage.
          </p>
          <div className="bg-red-950/30 text-red-300 p-3 rounded-lg text-xs mb-6 border border-red-900/40">
            Normal system access will automatically resume tomorrow at midnight UTC.
          </div>
          <p className="text-gray-600 text-xs">
            For urgent security compliance or active deployments, contact system administration.
          </p>
        </div>
      </div>
    );
  }

  const isDbReadOnly = portalConfig?.manualReadOnly === true || portalConfig?.blockWritesOnLimit === true;

  return (
    <div className="app-container min-h-screen flex flex-col">
      {isDbReadOnly && (
        <div className="bg-amber-600 text-white text-center py-2 px-4 text-xs font-semibold select-none flex items-center justify-center gap-2 shadow-inner z-50">
          <span>⚠️</span>
          <span>Database is currently in READ-ONLY mode. Form submissions, leaves, and profile updates are temporarily disabled.</span>
        </div>
      )}
      <AppRoutes
        isLoading={isLoading}
        authUser={authUser}
        handleLogout={handleLogout}
        handleRetrieveDraft={handleRetrieveDraft}
        handleDiscardDraft={handleDiscardDraft}
        setActiveDraft={setActiveDraft}
        handleAdminLoginSubmit={handleAdminLoginSubmit}
        handleGoogleLogin={handleGoogleLogin}
        adminUsername={adminUsername}
        setAdminUsername={setAdminUsername}
        adminPassword={adminPassword}
        setAdminPassword={setAdminPassword}
        adminLoginError={adminLoginError}
        syncedSections={syncedSections}
        handleEmployeeFormSubmit={handleEmployeeFormSubmit}
        handleSaveDraft={handleSaveDraft}
        activeDraft={activeDraft}
        adminProps={adminProps}
        employeeProps={employeeProps}
      />
      <CookieConsent />

      {/* Universal Session Expired Modal Overlay */}
      {sessionExpiredInfo?.isOpen && (
        <div className="fixed inset-0 z-[9999999] flex items-center justify-center bg-slate-900/80 backdrop-blur-md p-4 animate-in fade-in duration-200">
          <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full p-6 text-center border border-gray-100 transform animate-in zoom-in-95 duration-200">
            <div className="mx-auto w-16 h-16 bg-amber-50 border border-amber-200 rounded-full flex items-center justify-center text-amber-600 mb-4 shadow-sm">
              <Clock className="w-8 h-8 stroke-[2.2]" />
            </div>
            <h3 className="text-xl font-bold text-gray-900 mb-2">Session Expired</h3>
            <p className="text-sm text-gray-600 mb-6 leading-relaxed">
              Your session has ended due to <span className="font-semibold text-gray-900">{sessionExpiredInfo.minutes} minutes</span> of inactivity. For your security, you have been automatically signed out.
            </p>
            <button
              onClick={() => {
                setSessionExpiredInfo(null);
                const appTarget = (import.meta as any).env?.VITE_APP_TARGET;
                const loginPath = appTarget === 'admin' ? '/admin/login' : '/login';
                window.location.href = window.location.origin + loginPath;
              }}
              className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl shadow-md hover:shadow-lg transition-all duration-150 transform active:scale-95 flex items-center justify-center gap-2"
            >
              <Lock className="w-4 h-4" />
              <span>Sign In Again</span>
            </button>
          </div>
        </div>
      )}
      {deletionSummary && (
        <Modal
          isOpen={!!deletionSummary}
          onClose={() => setDeletionSummary(null)}
          title="Confirm Permanent Deletion"
          size="md"
        >
          <div className="space-y-4">
            <div className="bg-amber-50 border border-amber-200 p-4 rounded-lg">
              <h4 className="text-amber-800 font-bold flex items-center mb-1">
                <ShieldAlert className="mr-2" size={18} /> Review Impact for {deletionSummary.name}
              </h4>
              <p className="text-amber-800/80 text-xs font-mono">
                Identifier: <span className="font-bold">{deletionSummary.context?.employeeId || deletionSummary.id}</span>
                {deletionSummary.context?.submissionId && ` • Submission: ${deletionSummary.context.submissionId}`}
              </p>
              <p className="text-amber-700 text-xs mt-1">
                Scanned across 15 operational systems. Please choose your deletion scope below.
              </p>
            </div>

            <div className="bg-white border rounded-lg overflow-hidden">
              <div className="bg-gray-50 px-4 py-2 border-b text-[10px] font-black uppercase text-gray-400 tracking-widest flex justify-between items-center">
                <span>Associated Record Counts (15 Areas)</span>
                <span className="font-bold text-blue-600">
                  {Object.values(deletionSummary.counts).reduce((acc: number, c: any) => acc + (typeof c === 'number' && c > 0 ? c : 0), 0)} Linked Items
                </span>
              </div>
              <div className="divide-y divide-gray-100 max-h-64 overflow-y-auto">
                {Object.entries(deletionSummary.counts).map(([label, count]) => (
                  <div key={label} className={`flex justify-between items-center px-4 py-2.5 ${(count as number) > 0 ? 'bg-blue-50/40' : ''}`}>
                    <span className={`text-sm font-medium ${(count as number) > 0 ? 'text-gray-900 font-semibold' : 'text-gray-600'}`}>{label}</span>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-bold ${(count as number) > 0 ? 'bg-blue-100 text-blue-700 font-mono' : 'text-gray-400'}`}>
                      {count as number}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-3 pt-4 border-t">
              <button
                disabled={isDeleting}
                onClick={() => handleConfirmDeletion(false)}
                className="w-full flex items-center justify-between p-4 rounded-xl border border-gray-200 hover:border-blue-400 group transition-all"
              >
                <div className="text-left">
                  <p className="font-bold text-gray-800 group-hover:text-blue-600">Standard Delete</p>
                  <p className="text-xs text-gray-500">Deletes the profile record only. Other data remains for history.</p>
                </div>
                <ChevronRight className="text-gray-400 group-hover:text-blue-600" size={20} />
              </button>

              <button
                disabled={isDeleting || isAuthenticating}
                onClick={() => handleConfirmDeletion(true)}
                className="w-full flex items-center justify-between p-4 rounded-xl border border-red-200 bg-red-50 hover:bg-red-100 transition-all group relative overflow-hidden"
              >
                <div className="text-left">
                  <div className="flex items-center gap-2">
                    <p className="font-bold text-red-800">Deep Purge (Wipe All Traces)</p>
                    <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider bg-red-100 text-red-700 px-2 py-0.5 rounded-full border border-red-200">
                      <Lock size={10} /> Google Re-Auth
                    </span>
                  </div>
                  <p className="text-xs text-red-600 mt-0.5">Deletes everything above AND Drive folder, Submissions, etc.</p>
                </div>
                {isAuthenticating ? (
                  <div className="flex items-center gap-1.5 text-xs font-bold text-red-700 animate-pulse">
                    <RotateCcw className="animate-spin text-red-600" size={18} />
                    <span>Authorizing...</span>
                  </div>
                ) : isDeleting ? (
                  <div className="flex items-center gap-1.5 text-xs font-bold text-red-700">
                    <RotateCcw className="animate-spin text-red-600" size={18} />
                    <span>Purging...</span>
                  </div>
                ) : (
                  <Trash2 className="text-red-400 group-hover:text-red-600 transition-colors" size={20} />
                )}
              </button>
            </div>

            <div className="flex justify-center pt-2">
              <button onClick={() => setDeletionSummary(null)} disabled={isDeleting || isAuthenticating} className="text-xs font-bold text-gray-400 hover:text-gray-600 uppercase tracking-widest disabled:opacity-50">Cancel Action</button>
            </div>
          </div>
        </Modal>
      )}

      {/* Screen-Locking Scan Loader (Prevents tab hopping while auditing 15 systems) */}
      {scanLoading?.isScanning && (
        <div className="fixed inset-0 bg-slate-900/70 backdrop-blur-sm z-[99999] flex items-center justify-center p-4 animate-in fade-in duration-150">
          <div className="bg-white rounded-2xl shadow-2xl p-6 max-w-sm w-full text-center space-y-4 border border-slate-100 animate-in zoom-in-95 duration-150">
            <div className="w-16 h-16 rounded-2xl bg-blue-50 text-blue-600 flex items-center justify-center mx-auto shadow-inner">
              <ShieldAlert size={32} className="animate-pulse" />
            </div>
            <div>
              <h3 className="text-base font-black text-slate-800">Auditing Linked Records</h3>
              <p className="text-xs font-bold text-blue-600 mt-1 truncate px-2">{scanLoading.name}</p>
              <p className="text-[11px] text-slate-500 mt-2 leading-relaxed">
                Scanning across 15 operational systems (Leaves, Attendance, Drive files, Statutory records)...
              </p>
            </div>
            <div className="flex items-center justify-center gap-2 text-xs font-bold text-slate-600 bg-slate-50 py-2.5 px-3 rounded-xl border border-slate-100">
              <Loader2 className="animate-spin text-blue-600" size={16} />
              <span>Analyzing links, please wait...</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default App;


