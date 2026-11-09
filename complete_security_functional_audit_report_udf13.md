# Exhaustive Security, Authorization, AST & Functional Code Audit (`udf13` / `91fb875`)

**Target Application:** Unique Delta Force HR & Workforce Management Portal (`udfonline.in`, `admin.udfonline.in`, `employee.udfonline.in`)  
**Audited Repository Archive:** `udf13-91fb875af046aaa23fbe8c57916990bcfe3ec55e`  
**Audit Scope:** Full repository diff against `udf11` (`029f088`), AST/declaration verification, security rules cross-check (`firestore.rules` [599 lines], `storage.rules` [47 lines]), serverless backend inspection (`functions/index.js` [7,978 lines, 59 exported functions]), `GOOGLE_APPS_SCRIPT_v7.2.js`, `App.tsx`, `src/services/*`, `src/contexts/*`, and `components/*`.

---

## 1. Status of Previous Audit Findings (`udf11` -> `udf13`)

7 out of the 8 issues from the `udf11` audit (`UDF11-01` through `UDF11-08`) were resolved in `udf13` (`91fb875`):

| Earlier Issue ID | Summary of Previous Issue | Status in `udf13` (`91fb875`) |
| :--- | :--- | :--- |
| **`UDF11-01`** | Hardcoded `"server_admin"` bypass in `GOOGLE_APPS_SCRIPT_v7.2.js:46–47` and `functions/index.js:5904, 6022, 6384`. | **FIXED** — Removed `"server_admin"` fallback in both files and enforced `scriptSecret && scriptSecret.length >= 32`. |
| **`UDF11-02`** | Missing `isDisabled`/`isActive` checks in `moveStorageFolder`, `deleteStoragePath`, `getStorageFolderSizeServer`, and `getSystemMetrics`. | **FIXED** — Token `isDisabled` checks and active-staff checks added (`L2163, 2288, 2444, 2995, 3013`). |
| **`UDF11-03`** | Missing `isDisabled`/`isActive` checks in Firestore fallback blocks of 5 admin callables (`processRequestReviewServer`, `approveOnboardingServer`, `relieveEmployeeServer`, `syncEmployeeToGoogleDriveServer`, `syncSubmissionToSheetsServer`). | **FIXED** — Added `isDisabled === true \|\| isActive === false` checks (`L4652, 5066, 5401, 6496, 6540`). |
| **`UDF11-04`** | `firestore.rules` locks `/recycle_bin/{id}` to `isSuperAdmin()` only, blocking `EMPLOYEES_TAB_RECYCLE_BIN`. | **NOT FIXED (Tracked as `UDF13-08`)** — `firestore.rules:578` still restricts `read, update, delete` to `isSuperAdmin()`. |
| **`UDF11-05`** | Google-linked employee self-update fails on `/employees/{userId}`. | **FIXED** — `firestore.rules:204` now uses `isSelfEmployee(userId, resource.data)`. |
| **`UDF11-06`** | Portal ID vs. Auth UID mismatch on `leave_balances` & `gamification_logs`. | **FIXED** — `isOwnerOfPortalId(...)` added to `firestore.rules:421–422` and `593`. |
| **`UDF11-07`** | `refreshAdminClaims` lacked active-staff caller verification. | **FIXED** — `functions/index.js:3870–3883` now verifies the caller is an active staff member and restricts cross-user refreshes to SuperAdmin. |
| **`UDF11-08`** | `verifyViaApi` in `GOOGLE_APPS_SCRIPT_v7.2.js:80` lacked `isDisabled`/`isActive` check. | **FIXED** — Added at `GOOGLE_APPS_SCRIPT_v7.2.js:83–89`. |

---

## 2. Executive Summary of All 14 Findings in `udf13` (`91fb875`)

In `udf13`, 9 new `CLOUD-8` enterprise callables were added to `functions/index.js` (`lines 6674–7978`: `permanentDeleteEmployeeServer`, `restoreRecycleBinServer`, `deleteSiteServer`, `promoteEmployeeServer`, `bulkImportEmployeesServer`, `recordDailyStreakServer`, `redeemRewardServer`, `sendNotificationServer`, `completeBgvReviewServer`). Auditing these new functions and their cross-file interactions uncovered **14 total findings**:

| ID | Severity | Category | Target File(s) | Exact Lines | Summary of Finding |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`UDF13-01`** | **CRITICAL** | **Privilege Escalation / IDOR** | `functions/index.js` | `L6861–7034` | **`restoreRecycleBinServer` Has Zero Admin/Role Check for Non-Staff/Role Items:** Any authenticated user (including an anonymous candidate or regular guard) can restore deleted `SITE`, `EMPLOYEE`, `SUBMISSION`, `VACANCY`, or `DESIGNATION` items. Also omits `case 'INVITE':` (throwing `Unknown itemType: "INVITE"`) and fails to re-enable Firebase Auth on `STAFF` restore. |
| **`UDF13-02`** | **HIGH** | **Business Logic / Point Exploit** | `functions/index.js` | `L7656–7752` | **`redeemRewardServer` Trusts Client-Supplied `pointsSpent` & `rewardTitle`:** Never checks `settings/gamification_rules.rewards` on the server. A user can pass `{ rewardTitle: "Premium Warm Winter Jacket", pointsSpent: 1 }` to mint a valid `UDF-RWD-*` voucher for 1 point instead of 1,200 points. |
| **`UDF13-03`** | **HIGH** | **Broken UI / Runtime Crash** | `functions/index.js`<br>`components/AdminRecycleBinPage.tsx` | `L7152–7166`<br>`L115, 337, 344` | **`deleteSiteServer` Writes Wrong Schema to `recycle_bin`, Crashing Recycle Bin Search:** Writes `title`, `deletedBy`, `autoPurgeAt` instead of `name`, `deletedByName`, `expiresAt`. Opening Recycle Bin shows blank item titles and typing in the search box crashes React with `TypeError: Cannot read properties of undefined (reading 'toLowerCase')`. |
| **`UDF13-04`** | **MEDIUM** | **Broken Feature / Points Desync** | `functions/index.js` | `L5940–5945`<br>`L7628–7632`<br>`L7717–7721` | **Gamification `user_engagement` & `gamification_logs` Dual-ID Desync:** `completeTrainingQuizServer` writes `userId: uid` to `gamification_logs` and syncs points to both `targetDocId` and `uid`, whereas `recordDailyStreakServer` and `redeemRewardServer` write `userId: targetDocId` and only update `targetDocId`. |
| **`UDF13-05`** | **MEDIUM** | **Multi-Tenant Bypass & Data Loss** | `functions/index.js` | `L7338–7497` | **`bulkImportEmployeesServer` Overwrites Existing Employees When `overwriteMode === 'skip'` & Lacks `sitesManaged` Check:** `batch.set(empRef, employeeRecord, { merge: false })` overwrites existing docs instead of skipping them; also lacks `sitesManaged` scope enforcement and Firestore permission fallback. |
| **`UDF13-06`** | **MEDIUM** | **Broken Feature / Missing Fallback** | `functions/index.js` | `L7055–7066`<br>`L7214–7224`<br>`L7858–7866` | **`deleteSiteServer`, `promoteEmployeeServer`, and `completeBgvReviewServer` Lack Firestore Permission Fallback:** Rely solely on `request.auth.token.permissions` without falling back to `staff_accounts`/`roles` when custom claims are stale (and `completeBgvReviewServer` lacks `sitesManaged` verification). |
| **`UDF13-07`** | **LOW** | **Notification Delivery Mismatch** | `functions/index.js` | `L7302–7311` | **`promoteEmployeeServer` Sends Notification to `empData.uid \|\| empSnap.id` Instead of `employeeId`:** Employees whose active session subscribes to `employeeId` miss promotion notifications, and `id`/`timestamp` fields are omitted. |
| **`UDF13-08`** | **LOW** | **Broken Permission (`UDF11-04`)** | `firestore.rules` | `L577–581` | **`/recycle_bin/{id}` Still Locked to `isSuperAdmin()` Only:** Delegated HR admins with `EMPLOYEES_TAB_RECYCLE_BIN` still cannot read or restore items from `/recycle_bin`. |
| **`UDF13-09`** | **HIGH** | **Workflow Notification Blackout** | `App.tsx`<br>`functions/index.js`<br>`firestore.rules` | `L471–513`<br>`L7783–7797`<br>`L395` | **Employee & Candidate Submissions Fail to Notify Level 1 Approvers Across 3 Layers:**<br>1. `staffUsers` is empty (`[]`) for non-admin sessions, so `notifyRole`/`notifyApprovers` finds 0 recipients.<br>2. `sendNotificationServer` blocks non-admins from sending to `ROLE:*` or individual supervisor/staff UIDs.<br>3. `firestore.rules:395` (`allow create: if isAdmin()`) blocks the client fallback. |
| **`UDF13-10`** | **MEDIUM** | **Missing Role Subscription** | `src/contexts/NotificationContext.tsx` | `L31–44, 88` | **`NotificationContext.tsx` Never Subscribes to `ROLE:${user.roleId}`:** Level 2+ workflow escalation notifications created by `processRequestReviewServer` (`targetUserId: "ROLE:..."`) are never received by admin notification bells. |
| **`UDF13-11`** | **LOW** | **UI State Bug** | `src/contexts/NotificationContext.tsx` | `L107–108` | **`sendNotification` Injects Outgoing Notifications into Sender's Bell:** Unconditionally calls `setNotifications(prev => [newNotif, ...])` even when `targetUserId` belongs to another user. |
| **`UDF13-12`** | **MEDIUM** | **Incomplete Purge / Wrong Action** | `functions/index.js`<br>`GOOGLE_APPS_SCRIPT_v7.2.js` | `L6713–6802`<br>`L120, 143` | **`permanentDeleteEmployeeServer` Sends Invalid `'delete_folder'` Action to Apps Script & Skips 6 Collections:** Sends `action: 'delete_folder'` instead of `'permanent_delete_employee'`, skips `resolveSubmissionDocAdmin` when `empSnap` exists, and omits `complaints`, `reward_redemptions`, `bgv_records`, `correction_requests`, and `draft_submissions`. |
| **`UDF13-13`** | **LOW** | **Broken Cron Cleanup** | `functions/index.js` | `L2655–2678` | **`autoDeleteRecycleBin` Cron Job Never Purges `/recycle_bin`:** Deletes soft-deleted docs in `employees` and `onboarding_submissions`, but never purges expired documents in `/recycle_bin`. |
| **`UDF13-14`** | **LOW** | **ID Format Inconsistency** | `functions/index.js`<br>`src/services/employeeService.ts` | `L7418–7421`<br>`L545–567` | **`bulkImportEmployeesServer` Uses 6-Char `UDF-*` Suffix Without Checksum:** `employeeService.ts` uses a 7-char weighted checksum suffix (`UDF-YYYYMM-XXXXXXX`), while `bulkImportEmployeesServer` generates a 6-char suffix (`UDF-YYYYMM-XXXXXX`). |

---

## 3. Detailed Breakdown of All 14 Findings

### `UDF13-01` (CRITICAL — Privilege Escalation / IDOR): `restoreRecycleBinServer` Missing Admin Authorization & Missing `case 'INVITE'`
* **Location:** `functions/index.js` (`lines 6861–7034`)
* **Root Cause:**
  1. `permissions` is declared at line 6877 (`const permissions = Array.isArray(token.permissions) ? token.permissions : [];`) and **never checked**. Only `STAFF` and `ROLE` items check `if (!isSuperAdmin)` at line 6888. Any authenticated user (including an anonymous candidate or regular guard) can restore deleted `SITE`, `EMPLOYEE`, `SUBMISSION`, `VACANCY`, or `DESIGNATION` items.
  2. In the `switch (String(itemType || '').toUpperCase())` block, `case 'INVITE':` is completely missing, throwing `Unknown itemType: "INVITE"` when restoring referral links.
  3. Restoring a `STAFF` account updates Firestore and claims, but never re-enables the disabled Firebase Auth user via `admin.auth().updateUser(originalId, { disabled: false })`.
* **Remediation Diff:**
  ```javascript
  // In functions/index.js -> restoreRecycleBinServer
  const hasRestorePerm = isSuperAdmin || 
      permissions.includes('EMPLOYEES_TAB_RECYCLE_BIN') || 
      permissions.includes('DELETE_EMPLOYEE');
  if (!hasRestorePerm) {
      throw new functions.https.HttpsError('permission-denied', 'Missing permission to restore items from Recycle Bin.');
  }
  ```

---

### `UDF13-02` (HIGH — Business Logic / Point Exploit): `redeemRewardServer` Trusts Client-Supplied `pointsSpent` & `rewardTitle`
* **Location:** `functions/index.js` (`lines 7656–7752`)
* **Root Cause:**
  The server takes `rewardTitle` and `pointsSpent` directly from `request.data`:
  ```javascript
  const { rewardTitle, pointsSpent } = request.data || {};
  const cost = Number(pointsSpent);
  ```
  It verifies `currentPoints >= cost`, but **never validates `cost` against the canonical rewards list in `settings/gamification_rules`**. A user with 1 point can pass `{ rewardTitle: "Company Winter Jacket (1,200 pts)", pointsSpent: 1 }` and receive a valid `UDF-RWD-*` voucher.
* **Remediation Diff:**
  Query `settings/gamification_rules` on the server and resolve the actual `pointsCost` by matching `rewardId` or `rewardTitle`.

---

### `UDF13-03` (HIGH — Broken UI / Runtime Crash): `deleteSiteServer` Schema Mismatch in `recycle_bin`
* **Location:** `functions/index.js` (`lines 7152–7166`), `components/AdminRecycleBinPage.tsx` (`lines 115, 337, 344`)
* **Root Cause:**
  `deleteSiteServer` writes:
  ```javascript
  batch.set(binRef, {
      itemType: 'SITE',
      originalId: siteId,
      title: resolvedSiteName, // <-- Field mismatch
      deletedBy: request.auth.uid, // <-- Field mismatch
      autoPurgeAt: new Date(...).toISOString() // <-- Field mismatch
  });
  ```
  `AdminRecycleBinPage.tsx` expects `name`, `deletedByName`, and `expiresAt`. Line 115 executes:
  ```typescript
  const matchesName = item.name.toLowerCase().includes(q);
  ```
  When `item.name` is undefined, typing in the Recycle Bin search box crashes React with `TypeError: Cannot read properties of undefined (reading 'toLowerCase')`.
* **Remediation Diff:**
  Set `name: resolvedSiteName`, `title: resolvedSiteName`, `deletedByName: token.name || 'Admin'`, `expiresAt: autoPurgeAt` in `deleteSiteServer`.

---

### `UDF13-04` (MEDIUM — Points Desync): Gamification `user_engagement` & `gamification_logs` Dual-ID Desync
* **Location:** `functions/index.js` (`lines 5940–5945`, `7628–7632`, `7717–7721`)
* **Root Cause:**
  * In `completeTrainingQuizServer`, points are credited to `targetDocId` AND `uid`, while `gamification_logs` is recorded under `userId: uid`.
  * In `recordDailyStreakServer` and `redeemRewardServer`, points and logs are recorded strictly under `targetDocId`.
  * When employees view engagement history by `uid` or `portalId`, quiz logs and streak logs end up split across different identifiers.
* **Remediation Diff:**
  Unify `gamification_logs` to always write both `userId: targetDocId` and `userUid: uid`, and update both `targetDocId` and `uid` in `recordDailyStreakServer` and `redeemRewardServer`.

---

### `UDF13-05` (MEDIUM — Multi-Tenant Bypass & Data Loss): `bulkImportEmployeesServer` Overwrite Bug & Missing Scope Check
* **Location:** `functions/index.js` (`lines 7338–7497`)
* **Root Cause:**
  1. `batch.set(empRef, employeeRecord, { merge: overwriteMode === 'overwrite' })`: when `overwriteMode === 'skip'`, `merge: false` completely **replaces** the document instead of skipping it.
  2. Lacks multi-tenant `sitesManaged` checks. Non-superadmins with `EMPLOYEES_IMPORT` can import employees into sites they do not manage.
* **Remediation Diff:**
  When `overwriteMode === 'skip'`, check `if (empSnap.exists) continue;`. Enforce `sitesManaged.includes(siteId)` for non-superadmins.

---

### `UDF13-06` (MEDIUM — Missing Fallback): Missing Firestore Fallbacks in New Callables
* **Location:** `functions/index.js` (`deleteSiteServer: L7055–7066`, `promoteEmployeeServer: L7214–7224`, `completeBgvReviewServer: L7858–7866`)
* **Root Cause:**
  Unlike older functions (`approveOnboardingServer`, `processRequestReviewServer`), these three functions only inspect `request.auth.token.permissions`. If an admin's custom claims are expired or not yet refreshed after role assignment, the functions throw `permission-denied` instead of falling back to read `staff_accounts/{uid}`.
* **Remediation Diff:**
  Add standard Firestore fallback block reading `staff_accounts` and `roles` when `!isSuperAdmin && !hasPerm`.

---

### `UDF13-07` (LOW — Notification Delivery Mismatch): `promoteEmployeeServer` Notification Target
* **Location:** `functions/index.js` (`lines 7302–7311`)
* **Root Cause:**
  `promoteEmployeeServer` creates a notification targeting `empData.uid || empSnap.id`, but omits `id`, `timestamp`, and fails to target `empData.employeeId` (where employee mobile app listeners subscribe).
* **Remediation Diff:**
  Target `empData.employeeId || empData.uid || empSnap.id` and add `id: notifRef.id` and `timestamp: nowIso`.

---

### `UDF13-08` (LOW — Broken Permission): `/recycle_bin/{id}` Still Locked to `isSuperAdmin()`
* **Location:** `firestore.rules` (`lines 577–581`)
* **Root Cause:**
  `firestore.rules` specifies:
  ```javascript
  match /recycle_bin/{id} {
    allow read, update, delete: if isSuperAdmin();
    allow create: if isSuperAdmin() || (isAdmin() && !request.resource.data.get('itemType', '').matches('(?i)(STAFF|ROLE)'));
  }
  ```
  Delegated HR staff who hold `EMPLOYEES_TAB_RECYCLE_BIN` get `PERMISSION_DENIED` when loading the Recycle Bin page.
* **Remediation Diff:**
  Change `allow read:` to `if isSuperAdmin() || hasPermission('EMPLOYEES_TAB_RECYCLE_BIN');`.

---

### `UDF13-09` (HIGH — Workflow Notification Blackout): Submissions Fail to Notify Level 1 Approvers
* **Location:** `App.tsx` (`lines 471–513`), `functions/index.js` (`lines 7783–7797`), `firestore.rules` (`line 395`)
* **Root Cause:**
  1. For regular employees or candidate sessions, `staffUsers` in `App.tsx` is initialized to `[]` (security isolation). Calling `notifyApprovers(...)` finds 0 target users.
  2. In `sendNotificationServer`, non-admins are blocked from sending notifications to `ROLE:*` or supervisor UIDs.
  3. In `firestore.rules`, line 395 now sets `allow create: if isAdmin();`, completely blocking client fallback writes from non-admins.
  As a result, when an employee submits a Leave, Account Update, or Resignation, Level 1 approvers are never notified.
* **Remediation Diff:**
  In `sendNotificationServer`, allow authenticated non-admins to create workflow-triggered notifications where `metadata.module` is in `['LEAVES', 'ACCOUNT_UPDATES', 'RESIGNATIONS', 'ONBOARDING']`.

---

### `UDF13-10` (MEDIUM — Missing Role Subscription): `NotificationContext.tsx` Role Listener
* **Location:** `src/contexts/NotificationContext.tsx` (`lines 31–44, 88`)
* **Root Cause:**
  When `processRequestReviewServer` escalates requests to Level 2+, it notifies `targetUserId: 'ROLE:' + nextLevelConfig.roleId`.
  However, `NotificationContext.tsx` only queries `[user.id, 'all_admins', 'admin', user.employeeId, user.portalId]`. It **never adds `'ROLE:' + user.roleId`** to the subscription array. Approvers never receive bell notifications for escalated approvals.
* **Remediation Diff:**
  In `NotificationContext.tsx`, add:
  ```typescript
  if ((user as any).roleId) {
      targetIds.push(`ROLE:${(user as any).roleId}`);
  }
  ```

---

### `UDF13-11` (LOW — UI State Bug): Outgoing Notifications Injected into Sender's Bell
* **Location:** `src/contexts/NotificationContext.tsx` (`lines 107–108`)
* **Root Cause:**
  `sendNotification` executes:
  ```typescript
  setNotifications(prev => [newNotif, ...prev.filter(n => n.id !== notifId)]);
  ```
  regardless of whether `targetUserId` matches the logged-in user. Sending a notification to an employee injects the employee's notification into the admin's own bell icon until the page is refreshed.
* **Remediation Diff:**
  Only call `setNotifications` if `targetUserId === user.id || targetIds.includes(targetUserId)`.

---

### `UDF13-12` (MEDIUM — Incomplete Purge): `permanentDeleteEmployeeServer` Apps Script Action & Skipped Collections
* **Location:** `functions/index.js` (`lines 6713–6802`), `GOOGLE_APPS_SCRIPT_v7.2.js` (`lines 120, 143`)
* **Root Cause:**
  1. `permanentDeleteEmployeeServer` sends `action: 'delete_folder'` to Google Apps Script. In `GOOGLE_APPS_SCRIPT_v7.2.js`, valid deletion actions are `'permanent_delete_employee'` and `'delete_employee'`. `'delete_folder'` does not exist, so the Apps Script call silently fails to purge the Google Drive folder.
  2. `collectionsToClean` omits `complaints`, `reward_redemptions`, `bgv_records`, `correction_requests`, and `draft_submissions`.
* **Remediation Diff:**
  Send `action: 'permanent_delete_employee'` and include all 5 omitted collections in `collectionsToClean`.

---

### `UDF13-13` (LOW — Broken Cron Cleanup): `autoDeleteRecycleBin` Does Not Purge `/recycle_bin`
* **Location:** `functions/index.js` (`lines 2655–2678`)
* **Root Cause:**
  The `autoDeleteRecycleBin` scheduled cron job (running daily at midnight) purges soft-deleted docs in `employees` and `onboarding_submissions` where `deletedAt <= 30 days ago`. However, it **never queries or deletes documents in `/recycle_bin`**. Expired Recycle Bin documents remain stored indefinitely.
* **Remediation Diff:**
  Add a query on `db.collection('recycle_bin').where('autoPurgeAt', '<=', nowIso).get()` and delete matching docs.

---

### `UDF13-14` (LOW — ID Format Inconsistency): `bulkImportEmployeesServer` Checksum Mismatch
* **Location:** `functions/index.js` (`lines 7418–7421`), `src/services/employeeService.ts` (`lines 545–567`)
* **Root Cause:**
  `employeeService.ts` generates submission IDs with a 7-character checksum suffix (`UDF-YYYYMM-XXXXXXX`), whereas `bulkImportEmployeesServer` generates a 6-character suffix (`UDF-YYYYMM-XXXXXX`) without the polynomial checksum.
* **Remediation Diff:**
  Align `bulkImportEmployeesServer` with the ISO polynomial check suffix algorithm.

---

## 4. Implementation Priority Matrix

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             REMEDIATION ROADMAP                                  │
├──────────────┬──────────────────┬────────────────────────────────────────────────┤
│ Phase        │ Target Issues    │ Key Objectives                                 │
├──────────────┼──────────────────┼────────────────────────────────────────────────┤
│ **Wave 1**   │ `UDF13-01`       │ Close unauthenticated restore privilege bug;   │
│ (Critical &  │ `UDF13-02`       │ enforce server-side reward point validation;   │
│  High UI)    │ `UDF13-03`       │ fix Recycle Bin search crash schema mismatch;  │
│              │ `UDF13-09`       │ unblock level 1 workflow approval notifications│
├──────────────┼──────────────────┼────────────────────────────────────────────────┤
│ **Wave 2**   │ `UDF13-04`       │ Align dual-ID gamification points & logs;      │
│ (Medium      │ `UDF13-05`       │ fix bulk import overwrite & site multi-tenancy;│
│  Workflows)  │ `UDF13-06`       │ add Firestore fallback blocks to new callables;│
│              │ `UDF13-10`       │ subscribe NotificationContext to ROLE:* IDs;   │
│              │ `UDF13-12`       │ fix Apps Script action & purge all collections │
├──────────────┼──────────────────┼────────────────────────────────────────────────┤
│ **Wave 3**   │ `UDF13-07`       │ Fix promotion notification employeeId target;  │
│ (Low /       │ `UDF13-08`       │ allow delegated HR to read /recycle_bin;       │
│  Hygiene)    │ `UDF13-11`       │ prevent self-injection in notification bell;   │
│              │ `UDF13-13`       │ purge /recycle_bin in daily cron cleanup;      │
│              │ `UDF13-14`       │ align bulk import CSPRNG checksum format       │
└──────────────┴──────────────────┴────────────────────────────────────────────────┘
```
