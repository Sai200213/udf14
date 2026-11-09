import log from '../src/utils/logger';

import React, { useState, useMemo } from 'react';
import { Site, SubUnit, SubmittedFormData, SubmissionStatus, StaffUser, Role, Permission, PortalConfig } from '../types';
import Button from './common/Button';
import Input from './common/Input';
import Modal from './common/Modal';
import Select from './common/Select';
import { MapPin, Plus, Trash2, Edit3, Users, Building, MapPinOff, UserCircle, ShieldCheck, AlertTriangle, Info, Power, Loader2, X, Briefcase, ShieldHalf } from 'lucide-react';
import { v4 as uuidv4 } from 'uuid';

interface AdminSiteManagementPageProps {
  sites: Site[];
  setSites: React.Dispatch<React.SetStateAction<Site[]>>;
  submittedForms: SubmittedFormData[];
  staffUsers: StaffUser[];
  roles: Role[];
  onNotify: (msg: string, type?: 'success' | 'error' | 'info' | 'warning') => void;
  userRole?: Role;
  isSuperAdmin: boolean;
  portalConfig: PortalConfig;
  setPortalConfig: React.Dispatch<React.SetStateAction<PortalConfig>>;
  // Audit Log Prop - Optional for backward compatibility if not passed immediately, but app logic will pass it
  logAction?: (actionType: 'CREATE' | 'UPDATE' | 'DELETE' | 'STATUS_CHANGE' | 'APPROVAL' | 'REJECTION', targetModule: 'SITES' | 'STAFF' | 'ROLES' | 'LEAVES' | 'EMPLOYEES' | 'SYSTEM', details: string) => void;
}

import { getSiteHeadcounts, getPaginatedEmployees } from '../src/services/employeeService';
import { saveAllSites } from '../src/services/siteService';
import { useData } from '../src/contexts/DataContext';
import { defaultFormSections } from '../src/constants/defaults';
import { moveToRecycleBin, restoreFromRecycleBin } from '../src/services/recycleBinService';
import { showUndoToast } from '../src/utils/undoToast';

const AdminSiteManagementPage: React.FC<AdminSiteManagementPageProps> = ({ sites, setSites, submittedForms, staffUsers, roles, onNotify, userRole, isSuperAdmin, portalConfig, setPortalConfig, logAction }) => {
  const { sections } = useData();
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [isDeleteConfirmOpen, setIsDeleteConfirmOpen] = useState(false);

  const [isManageDesignationsOpen, setIsManageDesignationsOpen] = useState(false);
  const [newDesignationName, setNewDesignationName] = useState('');
  const [isSavingDesignations, setIsSavingDesignations] = useState(false);
  const [designationToDelete, setDesignationToDelete] = useState<string | null>(null);
  const [isDeleteDesignationConfirmOpen, setIsDeleteDesignationConfirmOpen] = useState(false);
  const [isDeletingDesignation, setIsDeletingDesignation] = useState(false);

  const [editingSite, setEditingSite] = useState<Site | null>(null);
  const [viewingSite, setViewingSite] = useState<Site | null>(null);
  const [siteToDelete, setSiteToDelete] = useState<Site | null>(null);
  const [isDeletingSite, setIsDeletingSite] = useState(false);

  const [siteName, setSiteName] = useState('');
  const [location, setLocation] = useState('');
  const [supervisorId, setSupervisorId] = useState('');
  const [requiredClientIdIds, setRequiredClientIdIds] = useState<string[]>([]);
  const [allowedDesignations, setAllowedDesignations] = useState<string[]>([]);
  const [requiresBgv, setRequiresBgv] = useState(false);

  // Headcount State
  const [headcounts, setHeadcounts] = useState<Record<string, number>>({});
  const [siteEmployees, setSiteEmployees] = useState<any[]>([]);
  const [isEmployeesLoading, setIsEmployeesLoading] = useState(false);

  const [viewType, setViewType] = useState<'cards' | 'hierarchy'>('cards');
  const [showSubUnitsForSite, setShowSubUnitsForSite] = useState<string | null>(null);

  // Strictly Super Admin only can create and manage sites; all other roles have view-only access
  const hasManagePerm = Boolean(isSuperAdmin);

  // Fetch headcounts on load
  React.useEffect(() => {
    const fetchHeadcounts = async () => {
      try {
        const { defaultFormSections } = await import('../src/constants/defaults');
        // We pass sites and defaultFormSections (as we don't have formSections prop here, 
        // but normally we should pass it from parent. However, for headcounts we just need the field ID)
        const counts = await getSiteHeadcounts(sites, defaultFormSections);
        setHeadcounts(counts);
      } catch (err) {
        console.error("Error fetching headcounts:", err);
      }
    };
    if (sites.length > 0) fetchHeadcounts();
  }, [sites]);

  // Fetch employees for a specific site when viewing
  React.useEffect(() => {
    const fetchEmployeesMap = async () => {
      if (!viewingSite || !isViewModalOpen) return;
      setIsEmployeesLoading(true);
      try {
        const { defaultFormSections } = await import('../src/constants/defaults');
        const unitField = defaultFormSections
          .flatMap(s => s.fields || [])
          .find(f => f && f.label && (f.label.toLowerCase().includes('unit') || f.label.toLowerCase().includes('facility')));

        const result = await getPaginatedEmployees(
          'ACTIVE',
          50, // Fetch up to 50 for the quick view
          undefined,
          unitField?.id,
          viewingSite.name
        );
        setSiteEmployees(result.employees);
      } catch (err) {
        console.error("Error fetching site employees:", err);
      } finally {
        setIsEmployeesLoading(false);
      }
    };
    fetchEmployeesMap();
  }, [viewingSite, isViewModalOpen]);

  // Self-healing / reconciliation: If any site has a stale supervisor ID, auto-reconcile it to the active staff user
  React.useEffect(() => {
    if (!sites || sites.length === 0 || !staffUsers || staffUsers.length === 0) return;

    let needsUpdate = false;
    const reconciled = sites.map(site => {
      const isSupervisorStale = Boolean(site.supervisorId && !staffUsers.some(st => st.id === site.supervisorId));
      const staleInList = Boolean(Array.isArray(site.supervisorIds) && site.supervisorIds.some(id => !staffUsers.some(st => st.id === id)));

      if (isSupervisorStale || staleInList) {
        // Find if any active staff member manages this site
        const activeManager = staffUsers.find(st => st.sitesManaged?.includes(site.id)) ||
          staffUsers.find(st => Array.isArray(site.supervisorIds) && site.supervisorIds.includes(st.id));

        const cleanSupervisorIds = (site.supervisorIds || [])
          .filter(id => staffUsers.some(st => st.id === id));
        if (activeManager && !cleanSupervisorIds.includes(activeManager.id)) {
          cleanSupervisorIds.push(activeManager.id);
        }

        const newSupId = activeManager ? activeManager.id : (cleanSupervisorIds[0] || '');
        if (newSupId !== site.supervisorId || cleanSupervisorIds.length !== (site.supervisorIds?.length || 0)) {
          needsUpdate = true;
          return {
            ...site,
            supervisorId: newSupId,
            supervisorIds: cleanSupervisorIds
          };
        }
      }
      return site;
    });

    if (needsUpdate) {
      log.log("[Reconcile] Auto-healed stale supervisor assignments in sites.");
      setSites(reconciled);
      saveAllSites(reconciled).catch(console.error);
    }
  }, [sites, staffUsers]);

  const handleAddDesignation = async () => {
    if (!newDesignationName.trim()) return;
    const name = newDesignationName.trim();
    const current = portalConfig.designations || [];
    if (current.includes(name)) {
      onNotify("Designation already exists in library", "warning");
      return;
    }

    setIsSavingDesignations(true);
    try {
      const updatedList = [...current, name];
      await setPortalConfig(prev => ({ ...prev, designations: updatedList }));
      setNewDesignationName('');
      onNotify(`Added "${name}" to Designations Library.`, "success");
    } catch (err: any) {
      onNotify(`Failed to add designation: ${err.message}`, "error");
    } finally {
      setIsSavingDesignations(false);
    }
  };

  const handleDeleteDesignation = async (name: string) => {
    setIsDeletingDesignation(true);
    try {
      const { collection, query, where, getDocs } = await import('firebase/firestore');
      const { db } = await import('../src/firebase/config');

      // 1. Check if any employee is using this designation
      const empQ = query(collection(db, 'employees'), where('designation', '==', name));
      const empSnap = await getDocs(empQ);
      if (!empSnap.empty) {
        onNotify(`Cannot delete designation "${name}" because it is actively assigned to ${empSnap.size} employee(s) in the system.`, "error");
        setIsDeleteDesignationConfirmOpen(false);
        setDesignationToDelete(null);
        return;
      }

      // 2. Check if any pending onboarding submission is using this designation (either at top-level or inside formData)
      const subQ1 = query(collection(db, 'onboarding_submissions'), where('designation', '==', name));
      const subSnap1 = await getDocs(subQ1);
      const subQ2 = query(collection(db, 'onboarding_submissions'), where('formData.db307195-cf54-4a6e-9056-f3974b050c4d', '==', name));
      const subSnap2 = await getDocs(subQ2);

      if (!subSnap1.empty || !subSnap2.empty) {
        const total = subSnap1.size + subSnap2.size;
        onNotify(`Cannot delete designation "${name}" because it is actively used in ${total} pending onboarding application(s).`, "error");
        setIsDeleteDesignationConfirmOpen(false);
        setDesignationToDelete(null);
        return;
      }

      // 3. Clean up Form Builder designation mapping if present in optionsMap
      const sourceSections = sections.length > 0 ? sections : defaultFormSections;
      const jobSection = sourceSections.find(s => s.name === "Job Details");
      const designationField = jobSection?.fields.find(f =>
        f.label.trim().toLowerCase() === "post of apply" ||
        f.label.trim().toLowerCase() === "designation"
      );

      if (designationField?.optionsMap) {
        try {
          const { updateFormSections } = await import('../src/services/adminService');
          let hasChanges = false;
          const newOptionsMap = { ...designationField.optionsMap };

          Object.keys(newOptionsMap).forEach(siteName => {
            if (newOptionsMap[siteName]?.includes(name)) {
              newOptionsMap[siteName] = newOptionsMap[siteName].filter((x: string) => x !== name);
              hasChanges = true;
            }
          });

          if (hasChanges) {
            const updatedSections = sourceSections.map(s => {
              if (s.id === jobSection.id) {
                return {
                  ...s,
                  fields: s.fields.map(f => {
                    if (f.id === designationField.id) {
                      return {
                        ...f,
                        optionsMap: newOptionsMap
                      };
                    }
                    return f;
                  })
                };
              }
              return s;
            });
            await updateFormSections(updatedSections);
            log.log(`[Delete Designation] Successfully cleaned up designation "${name}" from Form Builder optionsMap mapping.`);
          }
        } catch (fbErr) {
          console.error("Failed to clean up Form Builder optionsMap mapping:", fbErr);
        }
      }

      const affectedSiteIds = sites.filter(s => s.allowedDesignations?.includes(name)).map(s => s.id);

      // 4. Move Designation to Universal Recycle Bin
      const binId = await moveToRecycleBin({
        itemType: 'DESIGNATION',
        name: name,
        originalId: name,
        originalCollection: 'settings/portal_config',
        data: {
          name,
          allowedSiteIds: affectedSiteIds
        },
        deletedByUid: isSuperAdmin ? 'super-admin' : 'staff',
        deletedByName: isSuperAdmin ? 'Super Admin' : 'Staff Admin',
        metadata: {
          allowedSiteIds: affectedSiteIds,
          siteCount: affectedSiteIds.length
        }
      });

      const current = portalConfig.designations || [];
      const updatedList = current.filter(x => x !== name);

      // Save global config
      await setPortalConfig(prev => ({ ...prev, designations: updatedList }));

      // Clean up from all sites
      const updatedSites = sites.map(s => {
        if (s.allowedDesignations?.includes(name)) {
          return {
            ...s,
            allowedDesignations: s.allowedDesignations.filter(x => x !== name)
          };
        }
        return s;
      });
      setSites(updatedSites);
      await saveAllSites(updatedSites);

      if (logAction) {
        logAction('DELETE', 'SYSTEM', `Moved designation "${name}" to Recycle Bin (${affectedSiteIds.length} site authorizations archived)`);
      }

      showUndoToast({
        message: `Designation "${name}" moved to Recycle Bin`,
        recycleBinId: binId,
        onUndo: async () => {
          try {
            await restoreFromRecycleBin(binId);
            setPortalConfig(prev => ({
              ...prev,
              designations: [...(prev.designations || []).filter(x => x !== name), name]
            }));
            if (affectedSiteIds.length > 0) {
              const restoredSites = sites.map(s => {
                if (affectedSiteIds.includes(s.id)) {
                  const cur = s.allowedDesignations || [];
                  if (!cur.includes(name)) {
                    return { ...s, allowedDesignations: [...cur, name] };
                  }
                }
                return s;
              });
              setSites(restoredSites);
              await saveAllSites(restoredSites);
            }
            onNotify(`Restored "${name}" to Designations Library.`, "success");
          } catch (restoreErr: any) {
            onNotify(`Failed to undo designation delete: ${restoreErr.message}`, "error");
          }
        }
      });

      setIsDeleteDesignationConfirmOpen(false);
      setDesignationToDelete(null);
    } catch (err: any) {
      onNotify(`Failed to delete designation: ${err.message}`, "error");
    } finally {
      setIsDeletingDesignation(false);
    }
  };

  const getSiteHeadcount = (siteName: string) => {
    return headcounts[siteName] || 0;
  };

  const getSupervisorDetails = (id?: string, site?: Site) => {
    // 1. Direct match by supervisorId
    if (id) {
      const staff = staffUsers.find(s => s.id === id);
      if (staff) {
        const role = roles.find(r => r.id === staff.roleId);
        return { name: staff.name, role: role?.name || 'Staff' };
      }
    }
    // 2. Check site.supervisorIds array
    if (site?.supervisorIds && Array.isArray(site.supervisorIds)) {
      for (const supId of site.supervisorIds) {
        const staff = staffUsers.find(s => s.id === supId);
        if (staff) {
          const role = roles.find(r => r.id === staff.roleId);
          return { name: staff.name, role: role?.name || 'Staff' };
        }
      }
    }
    // 3. Bidirectional match: check if any staff user has this site in sitesManaged
    if (site?.id) {
      const staffManaging = staffUsers.find(s => s.sitesManaged?.includes(site.id));
      if (staffManaging) {
        const role = roles.find(r => r.id === staffManaging.roleId);
        return { name: staffManaging.name, role: role?.name || 'Staff' };
      }
    }
    return null;
  };

  const handleAddSite = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hasManagePerm) return;
    if (!siteName.trim() || !location.trim()) {
      onNotify("Site Name and Location are required", "error");
      return;
    }

    const newSite: Site = {
      id: uuidv4(),
      name: siteName.trim(),
      location: location.trim(),
      ...(supervisorId ? { supervisorId } : {}),
      requiredClientIdIds: requiredClientIdIds,
      allowedDesignations: allowedDesignations,
      requiresBgv: requiresBgv,
      status: 'Active',
      createdAt: new Date().toISOString(),
    };

    const updatedSites = [...sites, newSite];
    setSites(updatedSites);
    saveAllSites(updatedSites).catch(err => console.error("Failed to save sites:", err));

    if (logAction) logAction('CREATE', 'SITES', `Created new site: ${newSite.name}`);
    onNotify(`Site "${newSite.name}" added successfully.`);
    resetForm();
    setIsAddModalOpen(false);
  };

  const resetForm = () => {
    setSiteName('');
    setLocation('');
    setSupervisorId('');
    setRequiredClientIdIds([]);
    setAllowedDesignations([]);
    setRequiresBgv(false);
  };

  const handleSaveEdit = () => {
    if (editingSite && hasManagePerm) {
      const siteToSave: Site = {
        ...editingSite,
        supervisorIds: editingSite.supervisorId ? [editingSite.supervisorId] : []
      };
      const updatedSites = sites.map(s => s.id === editingSite.id ? siteToSave : s);
      setSites(updatedSites);
      saveAllSites(updatedSites).catch(err => console.error("Failed to save sites:", err));

      if (logAction) logAction('UPDATE', 'SITES', `Updated details for site: ${editingSite.name}`);
      onNotify("Site details updated.");
      setIsEditModalOpen(false);
      setEditingSite(null);
    }
  };

  const handleDeleteSite = async () => {
    if (!siteToDelete || !hasManagePerm) return;
    setIsDeletingSite(true);

    try {
      const { httpsCallable } = await import('firebase/functions');
      const { functions } = await import('../src/firebase/config');
      const deleteSiteFn = httpsCallable<{ siteId: string; siteName?: string }, { success: boolean; message: string }>(
        functions,
        'deleteSiteServer'
      );
      const res = await deleteSiteFn({ siteId: siteToDelete.id, siteName: siteToDelete.name });

      // Clean up Form Builder designation mapping for this site if present in optionsMap
      const sourceSections = sections.length > 0 ? sections : defaultFormSections;
      const jobSection = sourceSections.find(s => s.name === "Job Details");
      const designationField = jobSection?.fields.find(f =>
        f.label.trim().toLowerCase() === "post of apply" ||
        f.label.trim().toLowerCase() === "designation"
      );

      if (designationField?.optionsMap && designationField.optionsMap[siteToDelete.name]) {
        try {
          const { updateFormSections } = await import('../src/services/adminService');
          const updatedSections = sourceSections.map(s => {
            if (s.id === jobSection.id) {
              return {
                ...s,
                fields: s.fields.map(f => {
                  if (f.id === designationField.id) {
                    const newOptionsMap = { ...f.optionsMap };
                    delete newOptionsMap[siteToDelete.name];
                    return {
                      ...f,
                      optionsMap: newOptionsMap
                    };
                  }
                  return f;
                })
              };
            }
            return s;
          });
          await updateFormSections(updatedSections).catch(() => { });
        } catch (fbErr: any) {
          console.error("Failed to clean up Form Builder optionsMap mapping:", fbErr);
        }
      }

      // Update active sites list in local state
      const updatedSites = sites.filter(s => s.id !== siteToDelete.id);
      setSites(updatedSites);

      onNotify(res.data?.message || `Site "${siteToDelete.name}" successfully moved to Recycle Bin.`, 'success');
      setIsDeleteConfirmOpen(false);
      setSiteToDelete(null);
    } catch (err: any) {
      console.error("Failed to delete site via server:", err);
      const msg = err.message || err.details || 'Failed to delete site.';
      onNotify(msg.replace(/^Error:\s*/i, ''), 'error');
    } finally {
      setIsDeletingSite(false);
    }
  };

  const toggleSiteStatus = (id: string) => {
  if (!hasManagePerm) return;
  const updatedSites = sites.map(s => {
    if (s.id === id) {
      const newStatus = s.status === 'Active' ? 'Inactive' : 'Active';

      // CASCADING DEACTIVATION: If parent goes inactive, all sub-units go inactive
      let updatedSubUnits = s.subUnits;
      if (newStatus === 'Inactive' && s.subUnits) {
        updatedSubUnits = s.subUnits.map(u => ({ ...u, status: 'Inactive' as const }));
      }

      onNotify(`Site "${s.name}" is now ${newStatus}${newStatus === 'Inactive' ? ' (all sub-units also deactivated)' : ''}.`, 'info');
      if (logAction) logAction('STATUS_CHANGE', 'SITES', `Changed status of ${s.name} to ${newStatus}`);
      return { ...s, status: newStatus, subUnits: updatedSubUnits };
    }
    return s;
  });

  setSites(updatedSites);
  saveAllSites(updatedSites).catch(err => console.error("Failed to save sites:", err));
};
const uStatusClass = (status?: string) => {
  if (status === 'Inactive') return 'bg-gray-100 text-gray-400 border-gray-200';
  return 'bg-blue-50 text-blue-600 border-blue-100 shadow-sm';
};

return (
  <div className="space-y-6">
    <div className="flex justify-between items-center bg-white p-6 rounded-lg shadow-sm border border-gray-200">
      <div>
        <h2 className="text-xl font-bold text-gray-800 flex items-center">
          <Building className="mr-2 text-blue-600" /> Manage Deployment Sites
        </h2>
        <p className="text-sm text-gray-500 mt-1">Check headcount and monitor deployment units.</p>
      </div>
      <div className="flex items-center space-x-4">
        <div className="flex items-center bg-gray-100 rounded-lg p-1">
          <button
            onClick={() => setViewType('cards')}
            className={`flex items-center px-3 py-1.5 text-xs font-bold rounded-md transition-all ${viewType === 'cards' ? 'bg-white text-blue-600 shadow-sm' : 'text-gray-500 hover:text-gray-700'}`}
          >
            <Users size={14} className="mr-1.5" /> Site Cards
          </button>
          <button
            onClick={() => setViewType('hierarchy')}
            className={`flex items-center px-3 py-1.5 text-xs font-bold rounded-md transition-all ${viewType === 'hierarchy' ? 'bg-white text-blue-600 shadow-sm' : 'text-gray-500 hover:text-gray-700'}`}
          >
            <Building size={14} className="mr-1.5" /> Hierarchy List
          </button>
        </div>
        {hasManagePerm ? (
          <div className="flex items-center space-x-2">
            <Button onClick={() => setIsManageDesignationsOpen(true)} variant="secondary">
              <Briefcase size={16} className="mr-1.5 text-slate-500" /> Manage Designations
            </Button>
            <Button onClick={() => setIsAddModalOpen(true)} variant="primary">
              <Plus size={18} className="mr-2" /> Add New Site
            </Button>
          </div>
        ) : (
          <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-2 rounded-md text-sm font-bold flex items-center">
            <Info size={16} className="mr-2" /> READ-ONLY
          </div>
        )}
      </div>
    </div>

    {viewType === 'cards' ? (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {sites.length === 0 ? (
          <div className="col-span-full py-12 bg-white rounded-lg border-2 border-dashed border-gray-200 flex flex-col items-center justify-center text-gray-400">
            <MapPinOff size={48} className="mb-2" />
            <p>No deployment sites configured.</p>
          </div>
        ) : (
          sites
            // VISIBILITY FILTER: Only Super Admin sees 'Inactive' sites
            .filter(site => isSuperAdmin || site.status === 'Active')
            .map(site => {
              const count = getSiteHeadcount(site.name);
              const supervisor = getSupervisorDetails(site.supervisorId, site);
              const isShowingInfo = showSubUnitsForSite === site.id;

              // Filter sub-units for display
              const visibleSubUnits = isSuperAdmin ? site.subUnits : site.subUnits?.filter(u => u.status === 'Active');

              return (
                <div
                  key={site.id}
                  className={`bg-white rounded-xl shadow-sm border p-5 flex flex-col transition-all hover:shadow-md ${site.status === 'Inactive' ? 'grayscale opacity-75' : 'hover:border-blue-200'}`}
                >
                  <div className="flex justify-between items-start mb-4">
                    <div className={`p-2 rounded-lg ${site.status === 'Active' ? 'bg-blue-50 text-blue-600' : 'bg-gray-100 text-gray-400'}`}>
                      <Building size={24} />
                    </div>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => setShowSubUnitsForSite(isShowingInfo ? null : site.id)}
                        className={`p-1 rounded-lg transition-colors ${isShowingInfo ? 'bg-blue-600 text-white' : 'bg-gray-50 text-gray-400 hover:bg-blue-50 hover:text-blue-600'}`}
                        title="Show Site Hierarchy"
                      >
                        <Info size={14} />
                      </button>
                      <span className={`text-[10px] font-bold uppercase px-2.5 py-1 rounded-full ${site.status === 'Active' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                        {site.status}
                      </span>
                      {site.requiresBgv && (
                        <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full bg-purple-100 text-purple-700 flex items-center gap-1" title="3rd-Party BGV Clearance Mandated">
                          <ShieldCheck size={12} /> BGV
                        </span>
                      )}
                    </div>
                  </div>

                  <h3 className="text-lg font-bold text-gray-800 mb-1">{site.name}</h3>
                  <div className="flex items-center text-sm text-gray-500 mb-4">
                    <MapPin size={14} className="mr-1" /> {site.location}
                  </div>

                  {/* Contextual Hierarchy View (Popover Style) */}
                  {isShowingInfo && (
                    <div className="mb-4 p-3 bg-blue-50/50 rounded-xl border border-blue-100 animate-in slide-in-from-top-2 duration-200">
                      <div className="flex justify-between items-center mb-2">
                        <p className="text-[10px] font-black text-blue-600 uppercase tracking-widest">Site Hierarchy</p>
                        <button onClick={() => setShowSubUnitsForSite(null)} className="text-gray-400 hover:text-gray-600"><X size={12} /></button>
                      </div>
                      <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1 custom-scrollbar">
                        {(!site.subUnits || site.subUnits.length === 0) ? (
                          <p className="text-[10px] text-gray-400 italic">No sub-units defined.</p>
                        ) : (
                          site.subUnits.map(unit => (
                            <div key={unit.id} className="flex items-center justify-between bg-white px-2 py-1.5 rounded-md border border-blue-50 shadow-sm">
                              <span className={`text-xs font-bold ${unit.status === 'Inactive' ? 'text-gray-400 line-through' : 'text-slate-700'}`}>{unit.name}</span>
                              {unit.code && <span className="text-[10px] bg-slate-100 text-slate-500 px-1.5 py-0.5 rounded font-mono uppercase">{unit.code}</span>}
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  )}

                  <div className="mt-auto grid grid-cols-2 gap-4 pt-4 border-t border-gray-100">
                    <div onClick={() => { setViewingSite(site); setIsViewModalOpen(true); }} className="cursor-pointer group">
                      <p className="text-xs text-gray-400 uppercase font-bold tracking-wider">Deployment</p>
                      <p className="text-xl font-bold text-blue-600 flex items-center group-hover:underline">
                        <Users size={18} className="mr-1.5" /> {count} Guards
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-400 uppercase font-bold tracking-wider">In-Charge</p>
                      <p className="text-sm font-bold text-gray-700 truncate">{supervisor?.name || 'Unassigned'}</p>
                      {supervisor && <p className="text-[10px] text-blue-500 font-medium">{supervisor.role}</p>}
                    </div>
                  </div>

                  <div className="mt-4 flex flex-col gap-2">
                    <Button
                      variant="secondary"
                      size="sm"
                      className="w-full bg-blue-50 hover:bg-blue-100 text-blue-700 border-blue-200"
                      onClick={() => { setViewingSite(site); setIsViewModalOpen(true); }}
                    >
                      <Users size={16} className="mr-2" /> View Personnel
                    </Button>
                    {hasManagePerm && (
                      <div className="flex gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="flex-1 hover:bg-gray-50 border border-gray-100"
                          onClick={() => {
                            setEditingSite({ ...site });
                            setIsEditModalOpen(true);
                          }}
                        >
                          <Edit3 size={14} className="mr-1.5" /> Edit
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className={`p-2 border border-gray-100 ${site.status === 'Active' ? 'text-gray-400 hover:text-red-500' : 'text-green-500 hover:bg-green-50'}`}
                          onClick={() => toggleSiteStatus(site.id)}
                          title={site.status === 'Active' ? "Deactivate Site" : "Activate Site"}
                        >
                          <Power size={14} />
                        </Button>
                        {isSuperAdmin && count === 0 && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="p-2 text-red-500 hover:bg-red-50 border border-gray-100"
                            onClick={() => {
                              setSiteToDelete(site);
                              setIsDeleteConfirmOpen(true);
                            }}
                          >
                            <Trash2 size={14} />
                          </Button>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })
        )}
      </div>
    ) : (
      /* Hierarchy List View */
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead className="bg-slate-50 border-b border-gray-200">
              <tr>
                <th className="px-6 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest w-1/4">Parent Site / Location</th>
                <th className="px-6 py-4 text-left text-[10px] font-black text-slate-500 uppercase tracking-widest w-1/3">Sub-Units / Facilities</th>
                <th className="px-6 py-4 text-center text-[10px] font-black text-slate-500 uppercase tracking-widest">Headcount</th>
                <th className="px-6 py-4 text-center text-[10px] font-black text-slate-500 uppercase tracking-widest">Status / In-Charge</th>
                <th className="px-6 py-4 text-right text-[10px] font-black text-slate-500 uppercase tracking-widest">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sites
                .filter(site => isSuperAdmin || site.status === 'Active') // Filter inactive from table
                .map(site => {
                  const count = getSiteHeadcount(site.name);
                  const supervisor = getSupervisorDetails(site.supervisorId, site);
                  const visibleSubUnits = isSuperAdmin ? site.subUnits : site.subUnits?.filter(u => u.status === 'Active'); // Filter sub-units in table
                  return (
                    <tr key={site.id} className={`hover:bg-slate-50/50 transition-colors ${site.status === 'Inactive' ? 'bg-gray-50/50 opacity-75' : ''}`}>
                      <td className="px-6 py-4">
                        <div className="flex items-start gap-3">
                          <div className={`p-1.5 rounded-lg ${site.status === 'Active' ? 'bg-blue-50 text-blue-600' : 'bg-gray-200 text-gray-500'}`}>
                            <Building size={16} />
                          </div>
                          <div>
                            <p className="font-bold text-slate-800 leading-tight flex items-center gap-1.5">
                              {site.name}
                              {site.requiresBgv && (
                                <span className="inline-flex items-center gap-0.5 text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-purple-100 text-purple-700">
                                  <ShieldCheck size={10} /> BGV
                                </span>
                              )}
                            </p>
                            <p className="text-[10px] text-slate-400 flex items-center mt-0.5"><MapPin size={10} className="mr-1" /> {site.location}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex flex-wrap gap-1.5">
                          {(!site.subUnits || site.subUnits.length === 0) ? (
                            <span className="text-xs text-gray-300 italic">No sub-units defined</span>
                          ) : (
                            site.subUnits.map(unit => (
                              <span
                                key={unit.id}
                                className={`inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold border ${uStatusClass(unit.status)}`}
                              >
                                {unit.name}
                                {unit.code && <span className="ml-1 opacity-50">[{unit.code}]</span>}
                              </span>
                            ))
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-center">
                        <span className="text-sm font-black text-blue-600 bg-blue-50 px-2 py-1 rounded-lg border border-blue-100">{count}</span>
                      </td>
                      <td className="px-6 py-4 text-center">
                        <div className="flex flex-col items-center">
                          <span className={`text-[9px] font-black uppercase px-2 py-0.5 rounded-full mb-1 ${site.status === 'Active' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}>
                            {site.status}
                          </span>
                          <p className="text-[10px] font-bold text-slate-600">{supervisor?.name || 'Unassigned'}</p>
                        </div>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex items-center justify-end space-x-1">
                          <button onClick={() => { setEditingSite({ ...site }); setIsEditModalOpen(true); }} className="p-1.5 text-slate-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors" title="Edit Site">
                            <Edit3 size={16} />
                          </button>
                          <button onClick={() => toggleSiteStatus(site.id)} className={`p-1.5 rounded-lg transition-colors ${site.status === 'Active' ? 'text-slate-400 hover:text-red-500 hover:bg-red-50' : 'text-green-600 hover:bg-green-50'}`} title="Toggle Status">
                            <Power size={16} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </div>
    )}
    {/* Add Modal */}
    {isAddModalOpen && (
      <Modal isOpen={isAddModalOpen} onClose={() => setIsAddModalOpen(false)} title="Register New Deployment Site">
        <form onSubmit={handleAddSite} className="space-y-4">
          <Input label="Site Name" value={siteName} onChange={e => setSiteName(e.target.value)} placeholder="e.g. City Central Mall" required />
          <Input label="Location / Address" value={location} onChange={e => setLocation(e.target.value)} placeholder="Full address or area" required />

          <Select
            label="Assigned Supervisor / Staff In-Charge"
            value={supervisorId}
            onChange={e => setSupervisorId(e.target.value)}
          >
            <option value="">Select a staff member...</option>
            {staffUsers.map(staff => (
              <option key={staff.id} value={staff.id}>
                {staff.name} ({roles.find(r => r.id === staff.roleId)?.name || 'Staff'})
              </option>
            ))}
          </Select>

          <div className="pt-2">
            <label className="text-xs font-black text-slate-500 uppercase tracking-widest flex items-center mb-3">
              <ShieldHalf size={14} className="mr-1.5 text-blue-600" /> Required Global Client IDs
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {portalConfig.clientIdDefinitions?.filter(def => !def.isDisabled || requiredClientIdIds.includes(def.id)).map(def => (
                <label key={def.id} className={`flex items-center space-x-2 p-2 rounded border cursor-pointer transition-colors ${requiredClientIdIds.includes(def.id) ? 'bg-blue-50 border-blue-200' : 'bg-gray-50 border-gray-100 hover:border-gray-200'} ${def.isDisabled ? 'opacity-60 grayscale' : ''}`}>
                  <input
                    type="checkbox"
                    checked={requiredClientIdIds.includes(def.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setRequiredClientIdIds([...requiredClientIdIds, def.id]);
                      } else {
                        setRequiredClientIdIds(requiredClientIdIds.filter(id => id !== def.id));
                      }
                    }}
                    className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                  />
                  <div className="flex flex-col">
                    <span className="text-sm font-medium text-gray-700">{def.name}</span>
                    {def.description && <span className="text-[10px] text-gray-400 leading-tight">{def.description}</span>}
                  </div>
                </label>
              ))}
            </div>
            {(!portalConfig.clientIdDefinitions || portalConfig.clientIdDefinitions.length === 0) && (
              <div className="p-4 rounded-lg bg-amber-50 border border-amber-100 flex items-start space-x-3 mt-2">
                <AlertTriangle className="text-amber-500 shrink-0" size={16} />
                <p className="text-xs text-amber-700">No IDs defined in the <strong>Client ID Library</strong>. Setup definitions first to enable validation.</p>
              </div>
            )}
            <p className="text-xs text-gray-400 mt-2">Selecting these ensures employees at this site provide validated IDs.</p>
          </div>


          {/* Allowed Designations Section */}
          <div className="pt-4 border-t border-gray-100">
            <label className="text-xs font-black text-slate-500 uppercase tracking-widest flex items-center mb-3">
              <Briefcase size={14} className="mr-1.5 text-blue-600" /> Authorized Designations
            </label>
            <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto p-2 border rounded bg-gray-50">
              {(() => {
                const sourceSections = sections.length > 0 ? sections : defaultFormSections;
                const jobSection = sourceSections.find(s => s.name === "Job Details");
                const designationField = jobSection?.fields.find(f =>
                  f.label.trim().toLowerCase() === "post of apply" ||
                  f.label.trim().toLowerCase() === "designation"
                );
                const options = portalConfig.designations || designationField?.options || [];

                if (options.length === 0) return <p className="text-xs text-gray-400 italic">No designations found in Library or Form Builder.</p>;

                return options.map(opt => {
                  const isSelected = allowedDesignations.includes(opt);
                  return (
                    <label key={opt} className="flex items-center space-x-2 text-xs cursor-pointer hover:bg-white p-1 rounded">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setAllowedDesignations([...allowedDesignations, opt]);
                          } else {
                            setAllowedDesignations(allowedDesignations.filter(x => x !== opt));
                          }
                        }}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span>{opt}</span>
                    </label>
                  );
                });
              })()}
            </div>
          </div>

          {/* 3rd-Party BGV Mandate */}
          <div className="pt-3 border-t border-gray-100">
            <label className="flex items-center justify-between p-3 rounded-xl border border-purple-200 bg-purple-50/50 cursor-pointer hover:bg-purple-50 transition-colors">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-lg bg-purple-100 text-purple-700">
                  <ShieldCheck size={18} />
                </div>
                <div>
                  <div className="text-sm font-bold text-gray-900 flex items-center gap-1.5">
                    Mandate 3rd-Party BGV Clearance
                    <span className="text-[10px] uppercase font-black px-1.5 py-0.5 rounded bg-purple-200 text-purple-800">Client Mandate</span>
                  </div>
                  <p className="text-xs text-gray-500">
                    Employees deployed to this site (e.g. Wipro, Capgemini) will automatically require 3rd-party background verification.
                  </p>
                </div>
              </div>
              <input
                type="checkbox"
                checked={requiresBgv}
                onChange={(e) => setRequiresBgv(e.target.checked)}
                className="w-5 h-5 text-purple-600 rounded border-gray-300 focus:ring-purple-500 cursor-pointer"
              />
            </label>
          </div>

          <div className="pt-4 flex justify-end space-x-2">
            <Button variant="secondary" onClick={() => setIsAddModalOpen(false)}>Cancel</Button>
            <Button type="submit" variant="primary">Create Site</Button>
          </div>
        </form>
      </Modal>
    )}

    {/* Edit Modal */}
    {isEditModalOpen && editingSite && (
      <Modal isOpen={isEditModalOpen} onClose={() => setIsEditModalOpen(false)} title="Update Site Details">
        <div className="space-y-4">
          <Input label="Site Name" value={editingSite.name} onChange={e => setEditingSite({ ...editingSite, name: e.target.value })} />
          <Input label="Location" value={editingSite.location} onChange={e => setEditingSite({ ...editingSite, location: e.target.value })} />

          <Select
            label="Assigned Supervisor / Staff In-Charge"
            value={(() => {
              if (editingSite.supervisorId && staffUsers.some(s => s.id === editingSite.supervisorId)) {
                return editingSite.supervisorId;
              }
              const fromList = editingSite.supervisorIds?.find(id => staffUsers.some(s => s.id === id));
              if (fromList) return fromList;
              const fromStaff = staffUsers.find(s => s.sitesManaged?.includes(editingSite.id));
              if (fromStaff) return fromStaff.id;
              return '';
            })()}
            onChange={e => {
              const newId = e.target.value;
              setEditingSite({
                ...editingSite,
                supervisorId: newId,
                supervisorIds: newId ? [newId] : []
              });
            }}
          >
            <option value="">Unassigned</option>
            {staffUsers.map(staff => (
              <option key={staff.id} value={staff.id}>
                {staff.name} ({roles.find(r => r.id === staff.roleId)?.name || 'Staff'})
              </option>
            ))}
          </Select>

          <div className="pt-2 border-t border-gray-100 mt-2">
            <label className="text-xs font-black text-slate-500 uppercase tracking-widest flex items-center mb-3 mt-4">
              <ShieldHalf size={14} className="mr-1.5 text-blue-600" /> Required Global Client IDs
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {portalConfig.clientIdDefinitions?.filter(def => !def.isDisabled || (editingSite.requiredClientIdIds || []).includes(def.id)).map(def => (
                <label key={def.id} className={`flex items-center space-x-2 p-2 rounded border cursor-pointer transition-colors ${(editingSite.requiredClientIdIds || []).includes(def.id) ? 'bg-blue-50 border-blue-200' : 'bg-gray-50 border-gray-100 hover:border-gray-200'} ${def.isDisabled ? 'opacity-60 grayscale' : ''}`}>
                  <input
                    type="checkbox"
                    checked={(editingSite.requiredClientIdIds || []).includes(def.id)}
                    onChange={(e) => {
                      const current = editingSite.requiredClientIdIds || [];
                      const next = e.target.checked
                        ? [...current, def.id]
                        : current.filter(id => id !== def.id);
                      setEditingSite({ ...editingSite, requiredClientIdIds: next });
                    }}
                    className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                  />
                  <div className="flex flex-col">
                    <span className="text-sm font-medium text-gray-700">{def.name}</span>
                    {def.description && <span className="text-[10px] text-gray-400 leading-tight">{def.description}</span>}
                  </div>
                </label>
              ))}
            </div>
            <p className="text-xs text-gray-400 mt-2">Pick from the <span className="text-blue-600 font-medium">Client ID Library</span> to enable real-time validation.</p>
          </div>


          {/* Allowed Designations Section */}
          <div className="pt-4 border-t border-gray-100">
            <div className="flex items-center justify-between mb-3">
              <label className="text-xs font-black text-slate-500 uppercase tracking-widest flex items-center">
                <Briefcase size={14} className="mr-1.5 text-blue-600" /> Authorized Designations
              </label>
              <button
                type="button"
                onClick={() => {
                  const sourceSections = sections.length > 0 ? sections : defaultFormSections;
                  const jobSection = sourceSections.find(s => s.name === "Job Details");
                  const designationField = jobSection?.fields.find(f =>
                    f.label.trim().toLowerCase() === "post of apply" ||
                    f.label.trim().toLowerCase() === "designation"
                  );
                  if (designationField?.optionsMap && designationField.optionsMap[editingSite.name]) {
                    const newDesignations = designationField.optionsMap[editingSite.name];
                    log.log(`[Sync] Found Form Builder mapping for ${editingSite.name}:`, newDesignations);
                    setEditingSite({
                      ...editingSite,
                      allowedDesignations: newDesignations
                    });
                    onNotify(`Synced ${newDesignations.length} designations from Form Builder configuration.`, "success");
                  } else {
                    log.log(`[Sync] No mapping found for site "${editingSite.name}" in optionsMap:`, designationField?.optionsMap);
                    onNotify("No specific mapping found in Form Builder for this site.", "info");
                  }
                }}
                className="text-[10px] text-blue-600 hover:underline font-bold uppercase cursor-pointer bg-blue-50 px-2 py-1 rounded"
              >
                Sync from Form Builder
              </button>
            </div>

            <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto p-2 border rounded bg-gray-50">
              {(() => {
                const sourceSections = sections.length > 0 ? sections : defaultFormSections;
                const jobSection = sourceSections.find(s => s.name === "Job Details");
                const designationField = jobSection?.fields.find(f =>
                  f.label.trim().toLowerCase() === "post of apply" ||
                  f.label.trim().toLowerCase() === "designation"
                );
                const options = portalConfig.designations || designationField?.options || [];

                if (options.length === 0) return <p className="text-xs text-gray-400 italic">No designations found in Library or Form Builder.</p>;

                return options.map(opt => {
                  const isSelected = editingSite.allowedDesignations?.includes(opt) || false;
                  return (
                    <label key={opt} className="flex items-center space-x-2 text-xs cursor-pointer hover:bg-white p-1 rounded">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={(e) => {
                          const current = editingSite.allowedDesignations || [];
                          let newAllowed;
                          if (e.target.checked) {
                            newAllowed = [...current, opt];
                          } else {
                            newAllowed = current.filter(x => x !== opt);
                          }
                          setEditingSite({ ...editingSite, allowedDesignations: newAllowed });
                        }}
                        className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      />
                      <span>{opt}</span>
                    </label>
                  );
                });
              })()}
            </div>
          </div>

          {/* 3rd-Party BGV Mandate */}
          <div className="pt-3 border-t border-gray-100">
            <label className="flex items-center justify-between p-3 rounded-xl border border-purple-200 bg-purple-50/50 cursor-pointer hover:bg-purple-50 transition-colors">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-lg bg-purple-100 text-purple-700">
                  <ShieldCheck size={18} />
                </div>
                <div>
                  <div className="text-sm font-bold text-gray-900 flex items-center gap-1.5">
                    Mandate 3rd-Party BGV Clearance
                    <span className="text-[10px] uppercase font-black px-1.5 py-0.5 rounded bg-purple-200 text-purple-800">Client Mandate</span>
                  </div>
                  <p className="text-xs text-gray-500">
                    Employees deployed to this site (e.g. Wipro, Capgemini) will automatically require 3rd-party background verification.
                  </p>
                </div>
              </div>
              <input
                type="checkbox"
                checked={Boolean(editingSite.requiresBgv)}
                onChange={(e) => setEditingSite({ ...editingSite, requiresBgv: e.target.checked })}
                className="w-5 h-5 text-purple-600 rounded border-gray-300 focus:ring-purple-500 cursor-pointer"
              />
            </label>
          </div>

          {/* Sub-unit Management Section */}
          <div className="pt-4 border-t border-gray-100">
            <label className="text-xs font-black text-slate-500 uppercase tracking-widest mb-3 block flex items-center">
              <Building size={14} className="mr-1.5 text-blue-600" /> Site Sub-units / Specific Locations
            </label>

            <div className="space-y-2 mb-3 max-h-40 overflow-y-auto pr-1 custom-scrollbar">
              {(!editingSite.subUnits || editingSite.subUnits.length === 0) ? (
                <p className="text-xs text-gray-400 italic py-2">No sub-units defined for this site.</p>
              ) : (
                editingSite.subUnits.map(unit => (
                  <div key={unit.id} className={`flex items-center gap-2 p-2 rounded-lg border transition-colors group ${unit.status === 'Inactive' ? 'bg-gray-100 border-gray-200 opacity-75' : 'bg-slate-50 border-slate-100'}`}>
                    <div className="flex-1">
                      <Input
                        value={unit.name}
                        onChange={e => {
                          const newUnits = editingSite.subUnits?.map(u => u.id === unit.id ? { ...u, name: e.target.value } : u);
                          setEditingSite({ ...editingSite, subUnits: newUnits });
                        }}
                        className={`h-8 text-xs font-bold ${unit.status === 'Inactive' ? 'text-gray-400' : ''}`}
                        placeholder="Unit Name (e.g. T4)"
                        disabled={unit.status === 'Inactive'}
                      />
                    </div>
                    <div className="w-28">
                      <Input
                        value={unit.code || ''}
                        onChange={e => {
                          const newUnits = editingSite.subUnits?.map(u => u.id === unit.id ? { ...u, code: e.target.value } : u);
                          setEditingSite({ ...editingSite, subUnits: newUnits });
                        }}
                        className="h-8 text-xs"
                        placeholder="Unit Code"
                        disabled={unit.status === 'Inactive'}
                      />
                    </div>
                    <div className="flex items-center space-x-1">
                      <button
                        title={unit.status === 'Inactive' ? 'Activate Sub-unit' : 'Deactivate Sub-unit'}
                        onClick={() => {
                          const newStatus = unit.status === 'Inactive' ? 'Active' : 'Inactive';
                          const newUnits = editingSite.subUnits?.map(u => u.id === unit.id ? { ...u, status: newStatus as any } : u);
                          setEditingSite({ ...editingSite, subUnits: newUnits });
                        }}
                        className={`p-1.5 rounded-md transition-colors ${unit.status === 'Inactive'
                          ? 'text-gray-400 hover:text-green-600 hover:bg-green-50'
                          : 'text-blue-600 hover:text-red-600 hover:bg-red-50'
                          }`}
                      >
                        <Power size={14} />
                      </button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-red-400 hover:text-red-600 p-1 opacity-0 group-hover:opacity-100 transition-opacity"
                        onClick={() => {
                          const newUnits = editingSite.subUnits?.filter(u => u.id !== unit.id);
                          setEditingSite({ ...editingSite, subUnits: newUnits });
                        }}
                      >
                        <Trash2 size={14} />
                      </Button>
                    </div>
                  </div>
                ))
              )}
            </div>

            <Button
              variant="secondary"
              size="sm"
              className="w-full bg-blue-50 text-blue-600 border-dashed border-blue-200 hover:bg-blue-100"
              onClick={() => {
                const newUnit: SubUnit = { id: uuidv4(), name: '', status: 'Active' };
                setEditingSite({
                  ...editingSite,
                  subUnits: [...(editingSite.subUnits || []), newUnit]
                });
              }}
            >
              <Plus size={14} className="mr-1" /> Add Sub-unit
            </Button>
          </div>

          <div className="pt-4 flex justify-end space-x-2">
            <Button variant="secondary" onClick={() => setIsEditModalOpen(false)}>Cancel</Button>
            <Button variant="primary" onClick={handleSaveEdit}>Save Changes</Button>
          </div>
        </div>
      </Modal>
    )}

    {/* Delete Confirmation Modal */}
    {isDeleteConfirmOpen && siteToDelete && (
      <Modal isOpen={isDeleteConfirmOpen} onClose={() => setIsDeleteConfirmOpen(false)} title="Delete Site Configuration">
        <div className="space-y-4">
          <div className="flex items-center space-x-3 p-4 bg-red-50 text-red-700 rounded-lg">
            <AlertTriangle className="flex-shrink-0" />
            <p className="text-sm font-medium">Are you sure you want to permanently delete <strong>{siteToDelete.name}</strong>? This action cannot be undone.</p>
          </div>

          {/* Designations and Form Builder mapping delink notice */}
          {(() => {
            const sourceSections = sections.length > 0 ? sections : defaultFormSections;
            const jobSection = sourceSections.find(s => s.name === "Job Details");
            const designationField = jobSection?.fields.find(f =>
              f.label.trim().toLowerCase() === "post of apply" ||
              f.label.trim().toLowerCase() === "designation"
            );

            const localDesignations = siteToDelete.allowedDesignations || [];
            const formBuilderDesignations = designationField?.optionsMap?.[siteToDelete.name] || [];
            const uniqueDesignations = Array.from(new Set([...localDesignations, ...formBuilderDesignations]));

            if (uniqueDesignations.length === 0) return null;

            return (
              <div className="p-4 bg-amber-50 border border-amber-200 text-amber-800 rounded-lg space-y-2">
                <p className="text-xs font-bold uppercase tracking-wider text-amber-900">Delink Designations Notice:</p>
                <p className="text-xs">
                  This site is linked to the following authorized designations:
                </p>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {uniqueDesignations.map(d => (
                    <span key={d} className="bg-amber-100 border border-amber-200 text-amber-800 px-2 py-0.5 rounded text-[10px] font-semibold">
                      {d}
                    </span>
                  ))}
                </div>
                <p className="text-[11px] text-amber-700 font-medium">
                  Deleting the site will permanently delink these designations and automatically clean up the configuration inside the Form Builder Designation field.
                </p>
              </div>
            );
          })()}

          <p className="text-sm text-gray-500">Note: You can only delete sites with zero active headcount. Consider "Disabling" the site if historical data exists.</p>
          <div className="pt-4 flex justify-end space-x-2">
            <Button variant="secondary" onClick={() => setIsDeleteConfirmOpen(false)} disabled={isDeletingSite}>Cancel</Button>
            <Button variant="danger" onClick={handleDeleteSite} disabled={isDeletingSite}>
              {isDeletingSite ? <Loader2 size={16} className="animate-spin mr-1.5" /> : null}
              Delete Site
            </Button>
          </div>
        </div>
      </Modal>
    )}

    {/* View Headcount Modal */}
    {isViewModalOpen && viewingSite && (
      <Modal isOpen={isViewModalOpen} onClose={() => setIsViewModalOpen(false)} title={`Active Deployment: ${viewingSite.name}`} size="lg">
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-blue-50 p-4 rounded-lg flex items-center justify-between border border-blue-100">
              <div>
                <h4 className="text-sm font-bold text-blue-800 uppercase tracking-widest">Total On-Site Guards</h4>
                <p className="text-3xl font-black text-blue-900">{getSiteHeadcount(viewingSite.name)}</p>
              </div>
              <Users size={40} className="text-blue-200" />
            </div>
            <div className="bg-indigo-50 p-4 rounded-lg flex items-center justify-between border border-indigo-100">
              <div>
                <h4 className="text-sm font-bold text-indigo-800 uppercase tracking-widest">Staff In-Charge</h4>
                <p className="text-lg font-black text-indigo-900">{getSupervisorDetails(viewingSite.supervisorId, viewingSite)?.name || 'Unassigned'}</p>
                <p className="text-xs text-indigo-600 font-bold uppercase tracking-tight">{getSupervisorDetails(viewingSite.supervisorId, viewingSite)?.role || 'Contact HR'}</p>
              </div>
              <ShieldCheck size={40} className="text-indigo-200" />
            </div>
          </div>

          <h5 className="text-sm font-bold text-gray-500 uppercase flex items-center mb-2 mt-4">
            <UserCircle size={16} className="mr-1" /> Assigned Personnel List
          </h5>

          <div className="max-h-[350px] overflow-y-auto space-y-2 border rounded-lg p-2 bg-gray-50">
            {isEmployeesLoading ? (
              <div className="py-12 flex flex-col items-center justify-center text-gray-400">
                <Loader2 size={32} className="animate-spin mb-2" />
                <p className="text-sm">Loading personnel list...</p>
              </div>
            ) : siteEmployees.length === 0 ? (
              <div className="py-8 text-center text-gray-400 italic text-sm">No active employees recorded at this site yet.</div>
            ) : (
              siteEmployees.map(emp => (
                <div key={emp.id} className="bg-white p-3 rounded-md shadow-sm border border-gray-100 flex items-center justify-between">
                  <div className="flex items-center">
                    <div className="w-8 h-8 bg-green-100 text-green-700 rounded-full flex items-center justify-center font-bold text-xs mr-3 text-center leading-8">
                      {(emp.applicantName || 'E').charAt(0)}
                    </div>
                    <div>
                      <p className="text-sm font-bold text-gray-800">{emp.applicantName || 'Anonymous'}</p>
                      <p className="text-[10px] font-mono text-gray-400 uppercase tracking-tighter">ID: {emp.employeeId || 'NO-ID'}</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-xs text-gray-500">{emp.data['eb3617dc-9f1d-475d-a2db-005b6bc2500c'] || 'No Phone'}</p>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="pt-4 flex justify-end">
            <Button variant="secondary" onClick={() => setIsViewModalOpen(false)}>Close</Button>
          </div>
        </div>
      </Modal>
    )}
    {/* Manage Designations Library Modal */}
    {isManageDesignationsOpen && (
      <Modal
        isOpen={isManageDesignationsOpen}
        onClose={() => setIsManageDesignationsOpen(false)}
        title="Manage Designations Library"
        size="md"
      >
        <div className="space-y-4">
          <p className="text-xs text-gray-500">
            Manage the global list of employee designations. Changes made here will automatically propagate as choices across site authorizations, form builder definitions, and referral invites.
          </p>

          <div className="flex space-x-2">
            <Input
              placeholder="e.g. Senior Guard"
              value={newDesignationName}
              onChange={e => setNewDesignationName(e.target.value)}
              onKeyPress={e => e.key === 'Enter' && handleAddDesignation()}
              className="flex-1 animate-in fade-in"
              disabled={isSavingDesignations}
            />
            <Button
              onClick={handleAddDesignation}
              variant="primary"
              disabled={!newDesignationName.trim() || isSavingDesignations}
            >
              {isSavingDesignations ? <Loader2 size={16} className="animate-spin" /> : <Plus size={16} />} Add
            </Button>
          </div>

          <div className="border rounded-lg bg-gray-50 max-h-60 overflow-y-auto divide-y divide-gray-200">
            {(() => {
              const list = portalConfig.designations || [];
              if (list.length === 0) {
                return <p className="p-4 text-center text-xs text-gray-400 italic">No designations defined in the library yet.</p>;
              }
              return list.map(name => (
                <div key={name} className="flex items-center justify-between p-3 bg-white hover:bg-gray-50 transition-colors">
                  <span className="text-sm font-semibold text-gray-700">{name}</span>
                  <button
                    onClick={() => {
                      setDesignationToDelete(name);
                      setIsDeleteDesignationConfirmOpen(true);
                    }}
                    disabled={isSavingDesignations || isDeletingDesignation}
                    className="p-1.5 text-red-500 hover:bg-red-50 rounded-lg transition-colors disabled:opacity-50"
                    title="Delete Designation"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              ));
            })()}
          </div>

          <div className="pt-4 border-t flex justify-end">
            <Button variant="secondary" onClick={() => setIsManageDesignationsOpen(false)}>Close</Button>
          </div>
        </div>
      </Modal>
    )}

    {/* Delete Designation Confirmation Modal */}
    {isDeleteDesignationConfirmOpen && designationToDelete && (
      <Modal
        isOpen={isDeleteDesignationConfirmOpen}
        onClose={() => {
          if (!isDeletingDesignation) {
            setIsDeleteDesignationConfirmOpen(false);
            setDesignationToDelete(null);
          }
        }}
        title="Delete Designation"
        size="md"
      >
        <div className="space-y-4">
          <div className="flex items-center space-x-3 p-4 bg-amber-50 text-amber-800 rounded-lg border border-amber-200">
            <AlertTriangle className="flex-shrink-0 text-amber-600" />
            <p className="text-sm font-medium">
              Are you sure you want to remove <strong>{designationToDelete}</strong> from the library? This designation will be moved to the <strong>Recycle Bin</strong> (30-day retention) and can be restored at any time.
            </p>
          </div>

          {(() => {
            const linkedSites = sites.filter(s => s.allowedDesignations?.includes(designationToDelete));
            if (linkedSites.length === 0) return null;
            return (
              <div className="p-4 bg-gray-50 border border-gray-200 text-gray-800 rounded-lg space-y-2">
                <p className="text-xs font-bold uppercase tracking-wider text-gray-700">Delink sites notice:</p>
                <p className="text-xs">
                  This designation is currently authorized at the following site(s):
                </p>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {linkedSites.map(s => (
                    <span key={s.id} className="bg-white border border-gray-200 text-gray-800 px-2 py-0.5 rounded text-[10px] font-semibold">
                      {s.name}
                    </span>
                  ))}
                </div>
                <p className="text-[11px] text-gray-600 font-medium">
                  Moving to Recycle Bin will delink this designation from these sites. If restored later, authorizations will be reinstated automatically.
                </p>
              </div>
            );
          })()}

          <p className="text-xs text-gray-500">
            Note: The system will verify that this designation is not assigned to any active employee or used in pending onboarding applications before proceeding.
          </p>

          <div className="pt-4 flex justify-end space-x-2">
            <Button
              variant="secondary"
              onClick={() => {
                setIsDeleteDesignationConfirmOpen(false);
                setDesignationToDelete(null);
              }}
              disabled={isDeletingDesignation}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => handleDeleteDesignation(designationToDelete)}
              disabled={isDeletingDesignation}
            >
              {isDeletingDesignation ? <Loader2 size={16} className="animate-spin mr-1.5" /> : null}
              Move to Recycle Bin
            </Button>
          </div>
        </div>
      </Modal>
    )}
  </div>
);
};

export default AdminSiteManagementPage;


