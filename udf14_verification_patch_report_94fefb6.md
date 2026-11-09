# UDF14 (`94fefb6`) Verification & Patch Report

## Executive Summary

A diff and code audit of `udf14` (`94fefb6`) against `udf13` (`91fb875`) confirms that out of the **14 findings** from the `udf13` audit report:

* **9 findings** are completely resolved.

* **1 finding (`UDF13-06`)** introduced a JavaScript Temporal Dead Zone (`ReferenceError: Cannot access 'db' before initialization`) crash in `completeBgvReviewServer`.

* **4 findings (`UDF13-02`, `UDF13-04`, `UDF13-08`, `UDF13-09`, `UDF13-13`)** were partially applied or used mismatched field names.

## 1. Status Matrix of All 14 `UDF13` Findings in `udf14` (`94fefb6`)

| ID | Summary | Status in `udf14` (`94fefb6`) | 
| ----- | ----- | ----- | 
| **`UDF13-01`** | `restoreRecycleBinServer` admin auth check, `case 'INVITE':`, and Auth re-enable | **FIXED** (`functions/index.js:6898–6918, 6976, 7027–7037`) | 
| **`UDF13-02`** | `redeemRewardServer` server-side reward price verification | **BROKEN IN `udf14` (Field Name Mismatch)** — `functions/index.js:7840–7843` checks `r.title` and `matchedReward.pointsCost`, but `gamification_rules.rewards` stores `{ id, name, cost }` (`AdminWebsiteManager.tsx:167`, `BlogDashboardPage.tsx:58`), and if a user passes an unknown `rewardTitle`, `verifiedCost` falls back to client-supplied `cost` (`L7832`). | 
| **`UDF13-03`** | `deleteSiteServer` `recycle_bin` schema & `AdminRecycleBinPage.tsx` search crash | **FIXED** (`functions/index.js:7220–7236` & `components/AdminRecycleBinPage.tsx:115, 338, 345`) | 
| **`UDF13-04`** | Gamification dual-ID (`targetDocId` & `uid`) sync in streak & reward redemption | **PARTIALLY FIXED** — Added to `recordDailyStreakServer` (`L7761`) and `redeemRewardServer` (`L7879`), but `completeTrainingQuizServer` (`L5952`) still writes `userId: uid` instead of `userId: targetDocId`. | 
| **`UDF13-05`** | `bulkImportEmployeesServer` `overwriteMode: 'skip'` check, `sitesManaged` check, and role fallback | **FIXED** (`functions/index.js:7445–7461, 7559–7582`) | 
| **`UDF13-06`** | `deleteSiteServer`, `promoteEmployeeServer`, and `completeBgvReviewServer` Firestore fallback & site check | **CRASH BUG INTRODUCED IN `completeBgvReviewServer` (`ReferenceError`)** — At `functions/index.js:8041`, the fallback block calls `db.collection('staff_accounts')`, **before** `const db = admin.firestore();` is declared on line `8057`! In JavaScript, accessing `const db` before its declaration throws `ReferenceError: Cannot access 'db' before initialization`. | 
| **`UDF13-07`** | `promoteEmployeeServer` notification `targetUserId`, `id`, and `timestamp` | **FIXED** (`functions/index.js:7386–7396`) | 
| **`UDF13-08`** | `/recycle_bin/{id}` rules for `EMPLOYEES_TAB_RECYCLE_BIN` | **PARTIALLY FIXED** — `firestore.rules:578` added `hasPermission('EMPLOYEES_TAB_RECYCLE_BIN')` to `allow read`, but left `allow update, delete: if isSuperAdmin();` (`L579`), so the client fallback in `recycleBinService.ts:273` (`deleteDoc(binDocRef)`) still fails for non-SuperAdmins. | 
| **`UDF13-09`** | Employee & candidate workflow notifications to Level 1 approvers | **STILL BROKEN IN `udf14`** — `functions/index.js:7953–7971` requires `metadata.isWorkflow` or `metadata.module` to allow non-admins to notify `ROLE:*` or a supervisor, **but `NotificationContext.tsx:119–125` never passes `metadata` to `sendNotificationServer`**! Plus, any employee can pass `{ metadata: { isWorkflow: true } }` to spoof role broadcasts to `ROLE:employee`. | 
| **`UDF13-10`** | `NotificationContext.tsx` subscription to `ROLE:${user.roleId}` | **FIXED** (`src/contexts/NotificationContext.tsx:35–40, 94`) | 
| **`UDF13-11`** | `NotificationContext.tsx` local state pollution on outgoing notifications | **FIXED** (`src/contexts/NotificationContext.tsx:113–122`) | 
| **`UDF13-12`** | `permanentDeleteEmployeeServer` Apps Script `'permanent_delete_employee'` action & 6 missing collections | **FIXED** (`functions/index.js:6730–6733, 6785, 6814–6820`) | 
| **`UDF13-13`** | `autoDeleteRecycleBin` cron cleanup of `/recycle_bin` | **QUERY BUG IN `udf14`** — `functions/index.js:2681` queries `.where('autoPurgeAt', '<=', thirtyDaysAgoIso)`. First, `moveToRecycleBin` (`src/services/recycleBinService.ts:57`) writes `expiresAt` (not `autoPurgeAt`). Second, `autoPurgeAt`/`expiresAt` is set to `now + 30 days`, so comparing it against `thirtyDaysAgoIso` (`now - 30 days`) wouldn't purge items until **60 days** after deletion! Querying `.where('deletedAt', '<=', thirtyDaysAgoIso)` fixes both because every item in `recycle_bin` has `deletedAt`. | 
| **`UDF13-14`** | `UDF-*` 7-character weighted checksum suffix in `bulkImportEmployeesServer` | **FIXED** (`functions/index.js:7518–7526`) | 

## 2. Exact Patch Diffs for Remaining Issues in `udf14` (`94fefb6`)

### Fix 1: `UDF13-06` — `ReferenceError: Cannot access 'db' before initialization` in `completeBgvReviewServer` (`functions/index.js:8037–8058`)

**Root Cause:**
In `completeBgvReviewServer`, `const db = admin.firestore();` is declared on line `8057`, *after* `db.collection('staff_accounts')` is called on line `8041`. Whenever a staff user whose permissions are not embedded in custom claims (or a newly assigned BGV reviewer) calls `completeBgvReviewServer`, Node.js throws `ReferenceError: Cannot access 'db' before initialization`.

**Patch (`functions/index.js`):**

```
--- a/functions/index.js
+++ b/functions/index.js
@@ -8037,6 +8037,7 @@
         permissions.includes('BGV_APPROVE_REJECT') ||
         permissions.includes('BGV_MANAGE');
 
+    const db = admin.firestore();
     if (!hasBgvPerm) {
         const saSnap = await db.collection('staff_accounts').doc(request.auth.uid).get();
         const saData = saSnap.exists ? saSnap.data() : null;
@@ -8054,7 +8055,6 @@
         }
     }
 
-    const db = admin.firestore();
     const bgvRef = db.collection('bgv_records').doc(recordId);

```

### Fix 2: `UDF13-02` — `redeemRewardServer` Checks Wrong Property Names (`r.title` / `pointsCost` Instead of `r.name` / `cost`) and Allows Unknown Rewards (`functions/index.js:7829–7850`)

**Root Cause:**

1. In `components/AdminWebsiteManager.tsx:167` and `components/BlogDashboardPage.tsx:58`, rewards stored in `settings/gamification_rules` use the schema `{ id: 'cap', name: 'UDF Branded Security Cap', cost: 300 }`.

2. `functions/index.js:7840–7843` checks `r.title` and `matchedReward.pointsCost`, which are `undefined`.

3. Furthermore, if `settings/gamification_rules` does not exist yet (using default rewards) or if a client passes a custom `rewardTitle`, `matchedReward` is `undefined` and `verifiedCost` falls back to the unverified client-supplied `cost` (`let verifiedCost = cost;` at line `7832`).

**Patch (`functions/index.js`):**

```
--- a/functions/index.js
+++ b/functions/index.js
@@ -7829,22 +7829,28 @@
     }
 
     // Server-side reward cost verification against gamification_rules (UDF13-02)
-    let verifiedCost = cost;
-    try {
-        const rulesSnap = await db.collection('settings').doc('gamification_rules').get();
-        if (rulesSnap.exists) {
-            const rulesData = rulesSnap.data() || {};
-            const rewardsList = Array.isArray(rulesData.rewards) ? rulesData.rewards : [];
-            const matchedReward = rewardsList.find(r => r && (
-                (r.id && r.id === request.data.rewardId) ||
-                (r.title && r.title.trim().toLowerCase() === rewardTitle.trim().toLowerCase())
-            ));
-            if (matchedReward && matchedReward.pointsCost !== undefined) {
-                verifiedCost = Number(matchedReward.pointsCost);
-            }
-        }
-    } catch (rulesErr) {
-        console.warn('[redeemRewardServer] Could not verify reward price against gamification_rules:', rulesErr);
+    const defaultRewards = [
+        { id: 'cap', name: 'UDF Branded Security Cap', cost: 300 },
+        { id: 'bottle', name: 'Stainless Steel Water Bottle', cost: 500 },
+        { id: 'jacket', name: 'Premium Warm Winter Jacket', cost: 1200 }
+    ];
+    const rulesSnap = await db.collection('settings').doc('gamification_rules').get();
+    const rulesData = rulesSnap.exists ? (rulesSnap.data() || {}) : {};
+    const rewardsList = (Array.isArray(rulesData.rewards) && rulesData.rewards.length > 0)
+        ? rulesData.rewards
+        : defaultRewards;
+    const matchedReward = rewardsList.find(r => r && (
+        (r.id && r.id === request.data.rewardId) ||
+        ((r.name || r.title || '').trim().toLowerCase() === rewardTitle.trim().toLowerCase())
+    ));
+    if (!matchedReward) {
+        throw new functions.https.HttpsError('not-found', `Reward "${rewardTitle.trim()}" is not in the active rewards catalog.`);
+    }
+    const verifiedCost = Number(matchedReward.cost ?? matchedReward.pointsCost);
+    if (!Number.isInteger(verifiedCost) || verifiedCost <= 0) {
+        throw new functions.https.HttpsError('failed-precondition', 'Invalid reward cost configuration.');
     }

```

### Fix 3: `UDF13-09` — `sendNotificationServer` Blocks Employee/Candidate Workflow Notifications Because `NotificationContext.tsx` Doesn't Send `metadata` (`functions/index.js:7946–7976`)

**Root Cause:**

1. In `src/contexts/NotificationContext.tsx:119–125`, `sendFn` is invoked with `{ id, targetUserId, message, type, link }` and does not accept or pass a `metadata` object.

2. In `functions/index.js:7953–7971`, `isWorkflowNotification` is always `undefined` for calls coming from `addNotification(...)`, causing all employee/candidate Level-1 notifications (`ROLE:${roleId}` or `supervisor.id`) to still fail with `permission-denied`.

3. Additionally, trusting a client-supplied `metadata.isWorkflow === true` allows any authenticated user to broadcast to `ROLE:employee`. Instead, `sendNotificationServer` should allow non-admins to notify administrative roles (blocking only employee broadcast targets like `ROLE:employee` and `ROLE:role-security-guard`) and verified staff/admin UIDs (`staff_accounts/{target}` or `users/{target}`).

**Patch (`functions/index.js`):**

```
--- a/functions/index.js
+++ b/functions/index.js
@@ -7946,29 +7946,27 @@
 
     const trimmedTarget = targetUserId.trim();
+    const db = admin.firestore();
 
     // 1. Check broadcast permissions
     const isBroadcast = trimmedTarget.startsWith('ROLE:') || trimmedTarget === 'all_admins' || trimmedTarget === 'admin';
 
-    // Allow non-admins to send notifications if it is an official workflow notification (UDF13-09)
-    const isWorkflowNotification = metadata && (
-        metadata.module === 'LEAVES' ||
-        metadata.module === 'ACCOUNT_UPDATES' ||
-        metadata.module === 'RESIGNATIONS' ||
-        metadata.module === 'ONBOARDING' ||
-        metadata.module === 'SUBMISSIONS' ||
-        metadata.isWorkflow === true
-    );
-
     if (isBroadcast) {
-        if (trimmedTarget.startsWith('ROLE:') && !isAdmin && !isWorkflowNotification) {
+        const isEmployeeBroadcast = trimmedTarget === 'ROLE:employee' || trimmedTarget === 'ROLE:role-security-guard';
+        if (isEmployeeBroadcast && !isAdmin) {
             throw new functions.https.HttpsError('permission-denied', 'Only administrators can broadcast role-based notifications.');
         }
         // Non-admins can message 'all_admins', 'admin', or workflow roles
     } else {
         // Individual recipient check: Non-admins can send notifications addressed to themselves, an admin, or workflow approver
         const isSelf = (trimmedTarget === uid || trimmedTarget === token.employeeId || trimmedTarget === token.portalId);
-        if (!isSelf && !isAdmin && !isWorkflowNotification) {
-            throw new functions.https.HttpsError('permission-denied', 'Non-administrative users cannot send notifications to other users.');
+        if (!isSelf && !isAdmin) {
+            const [staffSnap, userSnap] = await Promise.all([
+                db.collection('staff_accounts').doc(trimmedTarget).get(),
+                db.collection('users').doc(trimmedTarget).get()
+            ]);
+            if (!staffSnap.exists && !userSnap.exists) {
+                throw new functions.https.HttpsError('permission-denied', 'Non-administrative users cannot send notifications to other employees.');
+            }
         }
     }
 
-    const db = admin.firestore();
     const notifId = (typeof clientProvidedId === 'string' && clientProvidedId.trim()) ? clientProvidedId.trim() : db.collection('notifications').doc().id;

```

### Fix 4: `UDF13-13` & `UDF13-04` — `autoDeleteRecycleBin` Query Field (`deletedAt` vs `autoPurgeAt`) & Quiz Log `userId` (`functions/index.js:2681, 5952`)

**Root Cause:**

1. **`UDF13-13` (`functions/index.js:2681`):** `autoDeleteRecycleBin` queries `db.collection('recycle_bin').where('autoPurgeAt', '<=', thirtyDaysAgoIso)`. However:

   * `moveToRecycleBin` in `src/services/recycleBinService.ts:54–57` writes `deletedAt` and `expiresAt` (not `autoPurgeAt`).

   * Even for server-created entries that have `autoPurgeAt`, `autoPurgeAt` is set to `deletedAt + 30 days`. Comparing `autoPurgeAt <= now - 30 days` means items wouldn't be purged until **60 days** after deletion.

   * Every document in `recycle_bin` (both client and server) has `deletedAt` as an ISO timestamp, so querying `.where('deletedAt', '<=', thirtyDaysAgoIso)` accurately purges all items older than 30 days.

2. **`UDF13-04` (`functions/index.js:5952`):** `completeTrainingQuizServer` writes `userId: uid` instead of `userId: targetDocId, userUid: uid` like `recordDailyStreakServer` and `redeemRewardServer`.

**Patch (`functions/index.js`):**

```
--- a/functions/index.js
+++ b/functions/index.js
@@ -2678,7 +2678,7 @@
 
         // Query expired items in /recycle_bin (UDF13-13)
         if (deletedCount < maxAllowedDeletes) {
-            const expiredBinSnap = await db.collection('recycle_bin').where('autoPurgeAt', '<=', thirtyDaysAgoIso).get();
+            const expiredBinSnap = await db.collection('recycle_bin').where('deletedAt', '<=', thirtyDaysAgoIso).get();
             for (const binDoc of expiredBinSnap.docs) {
                 if (deletedCount >= maxAllowedDeletes) break;
                 await binDoc.ref.delete().catch(() => {});
@@ -5950,7 +5950,8 @@
     }
 
     batch.set(logRef, {
-        userId: uid,
+        userId: targetDocId,
+        userUid: uid,
         type: 'QUIZ',
         questionId: questionId || 'daily_safety_quiz',

```

### Fix 5: `UDF13-08` — Allow `EMPLOYEES_TAB_RECYCLE_BIN` to Delete/Update Non-Staff/Role Items in `firestore.rules` (`L579`)

**Root Cause:**
`firestore.rules:578` granted `read` permission to `hasPermission('EMPLOYEES_TAB_RECYCLE_BIN')`, but kept `allow update, delete: if isSuperAdmin();` on line `579`. If a delegated HR admin triggers the client-side restore fallback (`src/services/recycleBinService.ts:273`) or deletes a non-staff item from the recycle bin, Firestore denies the `deleteDoc` operation.

**Patch (`firestore.rules`):**

```
--- a/firestore.rules
+++ b/firestore.rules
@@ -576,6 +576,7 @@
     // ─── Central Recycle Bin (Soft Delete & Universal Undo Vault - Super Admin / Delegated HR) ───────────
     match /recycle_bin/{id} {
       allow read: if isSuperAdmin() || hasPermission('EMPLOYEES_TAB_RECYCLE_BIN');
-      allow update, delete: if isSuperAdmin();
+      allow update, delete: if isSuperAdmin() ||
+        (hasPermission('EMPLOYEES_TAB_RECYCLE_BIN') && !resource.data.get('itemType', '').matches('(?i)(STAFF|ROLE)'));
       // SEC-07: Non-superadmins cannot archive STAFF or ROLE documents to prevent Trojan privilege escalation
       allow create: if isSuperAdmin() || (isAdmin() && !request.resource.data.get('itemType', '').matches('(?i)(STAFF|ROLE)'));
     }

```