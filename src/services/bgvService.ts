import { db, storage, functions } from '../firebase/config';
import { httpsCallable } from 'firebase/functions';
import { 
  collection, 
  doc, 
  getDoc, 
  setDoc, 
  updateDoc, 
  query, 
  where,
  getDocs,
  onSnapshot
} from 'firebase/firestore';
import { ref, uploadBytes, getDownloadURL } from 'firebase/storage';
import { BgvRecord, BgvStatus, FirestoreEmployee, Site, FormSection } from '../../types';
import { autoCompressFile, uploadFile } from './storageService';
import { logSystemAction } from './auditService';
import log from '../utils/logger';

const BGV_COLLECTION = 'bgv_records';

/**
 * Subscribe in real time to all BGV records.
 */
export const subscribeToBgvRecords = (callback: (records: BgvRecord[]) => void) => {
  const q = query(collection(db, BGV_COLLECTION));
  return onSnapshot(q, (snapshot) => {
    const records: BgvRecord[] = [];
    snapshot.forEach(docSnap => {
      records.push({
        id: docSnap.id,
        ...docSnap.data()
      } as BgvRecord);
    });
    callback(records);
  }, (err) => {
    log.error('Failed to subscribe to BGV records:', err);
  });
};

/**
 * Helper to extract configured fields from employee data based on SuperAdmin config.
 */
export const extractCustomFieldsFromEmployee = (
  emp: any,
  extractedFieldIds: string[] | undefined,
  formSections: FormSection[] | undefined
): Record<string, { label: string; value: any; isFile?: boolean }> => {
  if (!extractedFieldIds || extractedFieldIds.length === 0 || !formSections) {
    return {};
  }

  const fieldsMap = new Map<string, any>();
  formSections.forEach(s => s.fields?.forEach(f => fieldsMap.set(f.id, f)));

  const allData = {
    ...(emp.formData || {}),
    ...(emp.profileData || {}),
    ...(emp.profileData?.personalDetails || {}),
    ...(emp.profileData?.bankDetails || {}),
    ...(emp.profileData?.documents || {})
  };

  const customFields: Record<string, { label: string; value: any; isFile?: boolean }> = {};

  extractedFieldIds.forEach(fieldId => {
    const fieldDef = fieldsMap.get(fieldId);
    if (!fieldDef) return;

    let rawVal = allData[fieldId] ?? (emp as any)[fieldId] ?? (emp.formData && emp.formData[fieldId]);

    // Check by field label lowercase match if UUID key not present in flattened data
    if (rawVal === undefined || rawVal === null || rawVal === '') {
      const labelLower = fieldDef.label.toLowerCase();
      for (const [key, val] of Object.entries(allData)) {
        if (key.toLowerCase().includes(labelLower) || labelLower.includes(key.toLowerCase())) {
          rawVal = val;
          break;
        }
      }
    }

    if (rawVal !== undefined && rawVal !== null && rawVal !== '') {
      const isFile =
        fieldDef.type === 'File Upload' ||
        fieldDef.type === 'file' ||
        fieldDef.type === 'FILE_UPLOAD' ||
        (typeof rawVal === 'string' && (
          rawVal.includes('firebasestorage') ||
          rawVal.endsWith('.pdf') ||
          rawVal.endsWith('.jpg') ||
          rawVal.endsWith('.png') ||
          rawVal.startsWith('http') ||
          rawVal.startsWith('data:')
        )) ||
        (typeof rawVal === 'object' && rawVal !== null && (
          'storagePath' in rawVal ||
          'path' in rawVal ||
          'url' in rawVal ||
          'downloadUrl' in rawVal ||
          'name' in rawVal
        ));

      customFields[fieldId] = {
        label: fieldDef.label,
        value: rawVal,
        isFile: Boolean(isFile)
      };
    }
  });

  return customFields;
};

/**
 * Automatically syncs active employees assigned to BGV-mandated sites into the BGV pipeline.
 * Extracts details configured by SuperAdmin.
 * Returns the count of newly enrolled candidates.
 */
export const syncBgvCandidates = async (
  sites: Site[],
  existingRecords: BgvRecord[],
  passedEmployees?: FirestoreEmployee[],
  extractedFieldIds?: string[],
  formSections?: FormSection[]
): Promise<number> => {
  const bgvSites = sites.filter(s => s && s.requiresBgv === true);
  if (bgvSites.length === 0) return 0;

  const bgvSiteIds = new Set(bgvSites.map(s => s.id));
  const bgvSiteNames = new Set(bgvSites.map(s => s.name.trim().toLowerCase()));

  const existingMap = new Map<string, BgvRecord>();
  existingRecords.forEach(r => {
    existingMap.set(r.employeeDocId, r);
    if (r.employeeId) existingMap.set(r.employeeId, r);
  });

  let employeesList: any[] = passedEmployees || [];
  if (employeesList.length === 0) {
    try {
      const q = query(collection(db, 'employees'), where('isActive', '==', true));
      const snap = await getDocs(q);
      employeesList = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    } catch (err) {
      log.error('Failed to fetch active employees for BGV sync:', err);
      try {
        const snap = await getDocs(collection(db, 'employees'));
        employeesList = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      } catch (fallbackErr) {
        log.error('Fallback employee fetch also failed:', fallbackErr);
      }
    }
  }

  const activeEmployees = employeesList.filter(e => {
    if (e.isActive === false || (e as any).isRelieved === true) return false;

    // Check if employee is assigned to a BGV site
    const currentSiteId = (e as any).currentSiteId || (e as any).siteId;
    if (currentSiteId && bgvSiteIds.has(currentSiteId)) return true;

    const unitName = (e as any).unit || (e as any).siteName || (e as any).currentSiteName || '';
    if (unitName && bgvSiteNames.has(unitName.trim().toLowerCase())) return true;

    const assignedIds: string[] = (e as any).assignedSiteIds || [];
    if (assignedIds.some(id => bgvSiteIds.has(id))) return true;

    return false;
  });

  let addedCount = 0;

  for (const emp of activeEmployees) {
    const docId = emp.id;
    const badgeId = (emp as any).employeeId || docId;

    // Extract dynamic custom fields configured by SuperAdmin
    const customFields = extractCustomFieldsFromEmployee(emp, extractedFieldIds, formSections);

    // Extract details from profileData / formData
    const profile = (emp as any).profileData || (emp as any).formData || {};
    const personal = profile.personalDetails || {};

    const fullName = (emp as any).name || (emp as any).applicantName || personal.fullName || 'Employee';
    const phone = (emp as any).phone || (emp as any).phoneNumber || personal.phoneNumber || personal.mobileNumber || '';
    const aadhaar = (emp as any).aadhaarNumber || personal.aadhaarNumber || personal.aadhar || '';
    let dob = (emp as any).dateOfBirth || (emp as any).dob || personal.dob || personal.dateOfBirth || '';
    let fatherName = personal.fatherName || (emp as any).fatherName || '';
    const address = personal.permanentAddress || (emp as any).address || '';

    // Photos and Aadhaar files
    let photo = (emp as any).profilePhotoURL || (emp as any).photoUrl || personal.profilePhotoURL || '';
    let aadhaarDoc = (emp as any).aadhaarDocPath || (emp as any).aadhaarUrl || personal.aadhaarDoc || '';

    // Scan dynamic formData if still missing
    if (!photo || !aadhaarDoc) {
      const dataEntries = Object.entries(emp.formData || emp.profileData || {});
      for (const [key, val] of dataEntries) {
        if (typeof val === 'string' && val.length > 5) {
          const valLower = val.toLowerCase();
          const keyLower = key.toLowerCase();
          if (!photo && (keyLower.includes('photo') || valLower.includes('/photo') || valLower.includes('profilephoto'))) {
            photo = val;
          }
          if (!aadhaarDoc && (keyLower.includes('aadhaar') || keyLower.includes('aadhar') || valLower.includes('aadhaar') || valLower.includes('aadhar'))) {
            aadhaarDoc = val;
          }
        } else if (val && typeof val === 'object' && val !== null) {
          const rawPath = (val as any).storagePath || (val as any).path || (val as any).url || (val as any).downloadUrl || '';
          const keyLower = key.toLowerCase();
          const nameLower = String((val as any).name || '').toLowerCase();
          if (!photo && (keyLower.includes('photo') || nameLower.includes('photo'))) photo = rawPath;
          if (!aadhaarDoc && (keyLower.includes('aadhaar') || keyLower.includes('aadhar') || nameLower.includes('aadhaar') || nameLower.includes('aadhar'))) aadhaarDoc = rawPath;
        }
      }
    }

    // Fallback from customFields if primary fields were empty
    if (!dob) {
      for (const item of Object.values(customFields)) {
        if (item.label.toLowerCase().includes('birth') || item.label.toLowerCase().includes('dob')) {
          dob = String(item.value);
          break;
        }
      }
    }
    if (!fatherName) {
      for (const item of Object.values(customFields)) {
        if (item.label.toLowerCase().includes('father')) {
          fatherName = String(item.value);
          break;
        }
      }
    }
    if (!aadhaarDoc) {
      for (const item of Object.values(customFields)) {
        if (item.label.toLowerCase().includes('aadhar') || item.label.toLowerCase().includes('aadhaar')) {
          const val = item.value;
          if (typeof val === 'object' && val !== null) {
            aadhaarDoc = (val as any).storagePath || (val as any).path || (val as any).url || (val as any).downloadUrl || '';
          } else if (typeof val === 'string' && val.length > 5) {
            aadhaarDoc = val;
          }
          if (aadhaarDoc) break;
        }
      }
    }

    if (!existingMap.has(docId) && !existingMap.has(badgeId)) {
      // Find matching site
      const matchedSite = bgvSites.find(s => 
        s.id === (emp as any).currentSiteId ||
        s.id === (emp as any).siteId ||
        s.name.trim().toLowerCase() === String((emp as any).unit || (emp as any).siteName || (emp as any).currentSiteName || '').trim().toLowerCase() ||
        ((emp as any).assignedSiteIds || []).includes(s.id)
      ) || bgvSites[0];

      const recordId = `BGV-${badgeId || docId}`;
      const newRecord: BgvRecord = {
        id: recordId,
        employeeId: badgeId,
        employeeDocId: docId,
        employeeName: fullName,
        siteId: matchedSite.id,
        siteName: matchedSite.name,
        designation: (emp as any).designation || 'Security Guard',
        phoneNumber: phone,
        aadhaarNumber: aadhaar,
        dob: dob,
        fatherName: fatherName,
        permanentAddress: address,
        photoUrl: photo,
        aadhaarDocPath: aadhaarDoc,
        customFields: customFields,
        status: BgvStatus.PENDING,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      try {
        await setDoc(doc(db, BGV_COLLECTION, recordId), newRecord);
        existingMap.set(docId, newRecord);
        existingMap.set(badgeId, newRecord);
        addedCount++;
        log.log(`[BGV] Enrolled candidate ${fullName} (${badgeId}) for BGV at site ${matchedSite.name}`);
      } catch (err) {
        log.error(`[BGV] Failed to enroll candidate ${docId}:`, err);
      }
    } else {
      // Existing record: refresh customFields and populate any missing essentials
      const existing = existingMap.get(docId) || existingMap.get(badgeId);
      if (existing) {
        try {
          const updates: any = {
            customFields: customFields,
            updatedAt: new Date().toISOString()
          };
          if (!existing.dob && dob) updates.dob = dob;
          if (!existing.fatherName && fatherName) updates.fatherName = fatherName;
          if (!existing.aadhaarDocPath && aadhaarDoc) updates.aadhaarDocPath = aadhaarDoc;
          if (!existing.photoUrl && photo) updates.photoUrl = photo;
          
          await updateDoc(doc(db, BGV_COLLECTION, existing.id), updates);
        } catch (updateErr) {
          log.error(`[BGV] Failed to refresh customFields for ${existing.id}:`, updateErr);
        }
      }
    }
  }

  return addedCount;
};

/**
 * Mark a BGV record as sent to the 3rd-party vendor (Under Process).
 */
export const markBgvUnderProcess = async (
  recordId: string, 
  vendorName: string, 
  vendorCaseId?: string, 
  notes?: string
) => {
  const refDoc = doc(db, BGV_COLLECTION, recordId);
  const updates: Partial<BgvRecord> = {
    status: BgvStatus.UNDER_PROCESS,
    vendorName: vendorName.trim(),
    vendorCaseId: (vendorCaseId || '').trim(),
    sentToVendorDate: new Date().toISOString(),
    notes: (notes || '').trim(),
    updatedAt: new Date().toISOString()
  };
  await updateDoc(refDoc, updates);
  await logSystemAction('STATUS_CHANGE', 'BGV', `Dispatched BGV for candidate ${recordId} to vendor "${vendorName.trim()}" (Case: ${vendorCaseId || 'N/A'})`);
};

/**
 * 3rd-Party Vendor submits the BGV completion certificate report.
 * Moves status to VENDOR_SUBMITTED (Pending Staff Review).
 */
export const vendorSubmitBgvReport = async (
  recordId: string,
  employeeId: string,
  file: File,
  vendorNotes?: string
) => {
  const cleanName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
  const storagePath = await uploadFile(file, `employees/${employeeId}/bgv`, `${Date.now()}_${cleanName}`);

  const refDoc = doc(db, BGV_COLLECTION, recordId);
  const updates: Partial<BgvRecord> = {
    status: BgvStatus.VENDOR_SUBMITTED,
    bgvDocumentUrl: storagePath,
    bgvDocumentPath: storagePath,
    bgvDocumentName: file.name,
    vendorSubmittedDate: new Date().toISOString(),
    notes: (vendorNotes || '').trim(),
    updatedAt: new Date().toISOString()
  };
  await updateDoc(refDoc, updates);
  await logSystemAction('SUBMIT', 'BGV', `Vendor submitted BGV report certificate for candidate ${employeeId} (${recordId})`);
};

/**
 * Staff accepts and approves the vendor-submitted BGV certificate.
 * Marks the employee as officially COMPLETED.
 */
export const staffApproveBgv = async (
  recordId: string, 
  staffName: string, 
  approvalNotes?: string,
  employeeId?: string
) => {
  // 1. Server-enforced approval and atomic employee sync
  try {
    const completeFn = httpsCallable<{
      recordId: string;
      employeeId?: string;
      action: 'APPROVE' | 'REJECT';
      notes?: string;
    }, { success: boolean }>(functions, 'completeBgvReviewServer');
    const res = await completeFn({
      recordId,
      employeeId,
      action: 'APPROVE',
      notes: (approvalNotes || '').trim()
    });
    if (res.data?.success) {
      log.log(`[BGV] Server approved BGV for ${recordId}`);
      return;
    }
  } catch (serverErr) {
    log.warn('[BGV] Server completeBgvReviewServer failed, checking direct fallback:', serverErr);
  }

  // 2. Fallback to direct Firestore update
  const refDoc = doc(db, BGV_COLLECTION, recordId);
  const updates: Partial<BgvRecord> = {
    status: BgvStatus.COMPLETED,
    approvedBy: staffName,
    approvedDate: new Date().toISOString(),
    notes: (approvalNotes || '').trim(),
    updatedAt: new Date().toISOString()
  };
  await updateDoc(refDoc, updates);
  await logSystemAction('APPROVAL', 'BGV', `Staff ${staffName} approved BGV verification for ${recordId}`);
};

/**
 * Staff directly completes the BGV (Mode A: Staff received BGV report via email and uploads it).
 */
export const staffDirectCompleteBgv = async (
  recordId: string,
  employeeId: string,
  file: File,
  staffName: string,
  vendorName?: string,
  vendorCaseId?: string,
  notes?: string
) => {
  const cleanName = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
  const storagePath = await uploadFile(file, `employees/${employeeId}/bgv`, `${Date.now()}_${cleanName}`);

  // 1. Server-enforced approval and atomic employee sync
  try {
    const completeFn = httpsCallable<{
      recordId: string;
      employeeId?: string;
      action: 'APPROVE' | 'REJECT';
      notes?: string;
      bgvDocumentUrl?: string;
      bgvDocumentPath?: string;
      bgvDocumentName?: string;
      vendorName?: string;
      vendorCaseId?: string;
    }, { success: boolean }>(functions, 'completeBgvReviewServer');
    const res = await completeFn({
      recordId,
      employeeId,
      action: 'APPROVE',
      notes: (notes || '').trim(),
      bgvDocumentUrl: storagePath,
      bgvDocumentPath: storagePath,
      bgvDocumentName: file.name,
      vendorName: vendorName ? vendorName.trim() : undefined,
      vendorCaseId: vendorCaseId ? vendorCaseId.trim() : undefined
    });
    if (res.data?.success) {
      log.log(`[BGV] Server direct-completed BGV for ${employeeId} (${recordId})`);
      return;
    }
  } catch (serverErr) {
    log.warn('[BGV] Server completeBgvReviewServer failed for direct upload, falling back to direct write:', serverErr);
  }

  // 2. Fallback to direct Firestore update
  const refDoc = doc(db, BGV_COLLECTION, recordId);
  const updates: Partial<BgvRecord> = {
    status: BgvStatus.COMPLETED,
    bgvDocumentUrl: storagePath,
    bgvDocumentPath: storagePath,
    bgvDocumentName: file.name,
    vendorName: vendorName ? vendorName.trim() : undefined,
    vendorCaseId: vendorCaseId ? vendorCaseId.trim() : undefined,
    approvedBy: staffName,
    approvedDate: new Date().toISOString(),
    sentToVendorDate: new Date().toISOString(),
    notes: (notes || '').trim(),
    updatedAt: new Date().toISOString()
  };
  await updateDoc(refDoc, updates);
  await logSystemAction('APPROVAL', 'BGV', `Staff ${staffName} uploaded report and verified BGV for ${employeeId} (${recordId})`);
};

/**
 * Staff rejects or flags adverse findings on a BGV.
 */
export const staffRejectBgv = async (
  recordId: string,
  staffName: string,
  rejectionReason: string,
  employeeId?: string
) => {
  // 1. Server-enforced rejection and atomic employee sync
  try {
    const completeFn = httpsCallable<{
      recordId: string;
      employeeId?: string;
      action: 'APPROVE' | 'REJECT';
      notes?: string;
      rejectionReason?: string;
    }, { success: boolean }>(functions, 'completeBgvReviewServer');
    const res = await completeFn({
      recordId,
      employeeId,
      action: 'REJECT',
      notes: rejectionReason.trim(),
      rejectionReason: rejectionReason.trim()
    });
    if (res.data?.success) {
      log.log(`[BGV] Server rejected/flagged BGV for ${recordId}`);
      return;
    }
  } catch (serverErr) {
    log.warn('[BGV] Server completeBgvReviewServer failed for rejection, falling back to direct write:', serverErr);
  }

  // 2. Fallback to direct Firestore update
  const refDoc = doc(db, BGV_COLLECTION, recordId);
  const updates: Partial<BgvRecord> = {
    status: BgvStatus.FAILED,
    rejectionReason: rejectionReason.trim(),
    notes: `Adverse / Rejected by ${staffName}: ${rejectionReason.trim()}`,
    updatedAt: new Date().toISOString()
  };
  await updateDoc(refDoc, updates);
  await logSystemAction('REJECTION', 'BGV', `Staff ${staffName} flagged adverse findings/rejected BGV ${recordId}: ${rejectionReason.trim()}`);
};
