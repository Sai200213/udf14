const functions = require('firebase-functions'); // firebase-functions v7 = gen2 API
const admin = require('firebase-admin');
const bcrypt = require('bcryptjs');
const { onDocumentWritten, onDocumentCreated } = require('firebase-functions/v2/firestore');

admin.initializeApp();

// SECURITY: Use bcrypt (cost 12) for all password operations — NOT SHA-256.
// bcrypt is intentionally slow, making brute-force attacks far more expensive.
const BCRYPT_ROUNDS = 12;

const hashPassword = async (password) => {
    return await bcrypt.hash(password, BCRYPT_ROUNDS);
};

const verifyPassword = async (plainText, hash) => {
    // Handle legacy SHA-256 hashes during migration period
    if (hash && hash.length === 64 && !hash.startsWith('$2')) {
        // It's a legacy SHA-256 hex hash — compare and upgrade on next login
        const crypto = require('crypto');
        const legacySalt = process.env.LEGACY_SHA256_SALT || 'UDF_PORTAL_SALT_2026_!!';
        const sha256 = crypto.createHash('sha256').update(plainText + legacySalt).digest('hex');
        return sha256 === hash;
    }
    // Modern bcrypt hash
    return await bcrypt.compare(plainText, hash);
};

// STRICT CORS ORIGIN WHITELIST
// Prevents cross-origin malicious execution from unauthorized domains.
const ALLOWED_CORS_ORIGINS = [
    'https://udfonline.in',
    'https://www.udfonline.in',
    'https://admin.udfonline.in',
    'https://employee.udfonline.in',
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost',
    'capacitor://localhost'
];

/**
 * Secure wrapper around functions.https.onCall enforcing the strict CORS origin whitelist.
 */
const secureOnCall = (optsOrHandler, maybeHandler) => {
    const opts = typeof optsOrHandler === 'function' ? {} : (optsOrHandler || {});
    const handler = typeof optsOrHandler === 'function' ? optsOrHandler : maybeHandler;
    return functions.https.onCall({
        cors: ALLOWED_CORS_ORIGINS,
        ...opts
    }, handler);
};

// Secure server-side password hashing using bcrypt (cost 12)
exports.hashCandidatePasswordServer = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');
    }
    const { password } = request.data || {};
    if (!password || typeof password !== 'string' || password.length < 6) {
        throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 6 characters');
    }
    const hashed = await hashPassword(password);
    return { passwordHash: hashed };
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH & IDENTITY INTEGRITY
// ─────────────────────────────────────────────────────────────────────────────

// Check global uniqueness across all identity collections
exports.checkGlobalUniqueness = secureOnCall(async (request) => {
    // Only authenticated users can check uniqueness (prevents public scraping)
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Verification rejected.');
    }

    const { email, uid, options = {} } = request.data;
    const { excludeAdmin = false } = options;

    if (!email && !uid) {
        throw new functions.https.HttpsError('invalid-argument', 'Email or UID is required.');
    }

    const db = admin.firestore();

    try {
        const checks = [];

        if (email) {
            const normalizedEmail = email.toLowerCase().trim();
            checks.push(
                { type: 'staff', query: db.collection('staff').where('email', '==', normalizedEmail).get() },
                { type: 'staff_accounts', query: db.collection('staff_accounts').where('email', '==', normalizedEmail).get() },
                { type: 'employees', query: db.collection('employees').where('profileData.personalDetails.email', '==', normalizedEmail).get() },
                { type: 'employees', query: db.collection('employees').where('linkedGoogleEmail', '==', normalizedEmail).get() },
                { type: 'onboarding_submissions', query: db.collection('onboarding_submissions').where('email', '==', normalizedEmail).get() },
                { type: 'onboarding_submissions', query: db.collection('onboarding_submissions').where('linkedGoogleEmail', '==', normalizedEmail).get() }
            );

            if (!excludeAdmin) {
                checks.unshift({ type: 'users', query: db.collection('users').where('email', '==', normalizedEmail).get() });
            }
        }

        if (uid) {
            checks.push(
                { type: 'staff_accounts_doc', query: db.collection('staff_accounts').doc(uid).get() },
                { type: 'staff_doc', query: db.collection('staff').doc(uid).get() },
                { type: 'employees', query: db.collection('employees').where('uid', '==', uid).get() },
                { type: 'employees', query: db.collection('employees').where('linkedUid', '==', uid).get() },
                { type: 'onboarding_submissions', query: db.collection('onboarding_submissions').where('uid', '==', uid).get() },
                { type: 'onboarding_submissions', query: db.collection('onboarding_submissions').where('linkedUid', '==', uid).get() }
            );

            if (!excludeAdmin) {
                checks.unshift({ type: 'users_doc', query: db.collection('users').doc(uid).get() });
            }
        }

        const results = await Promise.all(checks.map(c => c.query));
        
        let conflict = false;
        for (let i = 0; i < checks.length; i++) {
            const { type } = checks[i];
            const snap = results[i];
            
            if (type.endsWith('_doc')) {
                if (snap.exists) {
                    conflict = true;
                    break;
                }
                continue;
            }

            if (snap.empty) continue;
            
            if (type === 'users' || type === 'staff' || type === 'staff_accounts') {
                conflict = true;
                break;
            } else if (type === 'employees') {
                const active = snap.docs.some(doc => !doc.data().deletedAt);
                if (active) {
                    conflict = true;
                    break;
                }
            } else if (type === 'onboarding_submissions') {
                const active = snap.docs.some(doc => {
                    const data = doc.data();
                    return !data.deletedAt && data.status !== 'Rejected' && data.status !== 'Deleted';
                });
                if (active) {
                    conflict = true;
                    break;
                }
            }
        }

        return {
            unique: !conflict,
            conflict: conflict ? 'Account or email already exists in system' : null
        };
    } catch (error) {
        console.error('Error checking uniqueness:', error);
        throw new functions.https.HttpsError('internal', 'Search failed.');
    }
});

// Create a staff user
exports.createStaffUser = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');
    }

    // SECURITY: Only SuperAdmins can create Staff users. Check staff_accounts first, fallback to users.
    let callerDoc = await admin.firestore().collection('staff_accounts').doc(request.auth.uid).get();
    if (!callerDoc.exists) {
        callerDoc = await admin.firestore().collection('users').doc(request.auth.uid).get();
    }
    if (!callerDoc.exists || callerDoc.data().roleId !== 'role-super-admin' || callerDoc.data().isDisabled === true || callerDoc.data().isActive === false) {
        throw new functions.https.HttpsError('permission-denied', 'Only active SuperAdmins can create Staff accounts.');
    }

    const { email, password, name, username, roleId } = request.data;

    if (!email || !password || !name || !username || !roleId) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields');
    }

    const normalizedEmail = email.toLowerCase().trim();

    try {
        // SYSTEMIC FIX: Check all collections for collision BEFORE creating auth user
        const db = admin.firestore();
        const [userSnap, staffSnapCurrent, empSnap] = await Promise.all([
            db.collection('users').where('email', '==', normalizedEmail).get(),
            db.collection('staff_accounts').where('email', '==', normalizedEmail).get(),
            db.collection('employees').where('email', '==', normalizedEmail).get()
        ]);

        if (!userSnap.empty || !staffSnapCurrent.empty || !empSnap.empty) {
            throw new functions.https.HttpsError('already-exists', 'Email is already registered as Admin, Staff, or Employee.');
        }

        const userRecord = await admin.auth().createUser({
            email: normalizedEmail,
            password: password,
            displayName: name,
        });

        const staffData = {
            id: userRecord.uid,
            username: username,
            usernameLower: (username || '').toLowerCase().trim(),
            email: normalizedEmail,
            name: name,
            roleId: roleId,
            isDisabled: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        await db.collection('staff_accounts').doc(userRecord.uid).set(staffData);

        return {
            success: true,
            uid: userRecord.uid,
            email: normalizedEmail,
            message: `User ${name} created successfully`
        };
    } catch (error) {
        console.error('Error creating user:', error);
        if (error.code === 'already-exists') throw error; // Re-throw our collision error
        if (error.code === 'auth/email-already-exists') {
            throw new functions.https.HttpsError('already-exists', 'Email already exists in Authentication system');
        }
        throw new functions.https.HttpsError('internal', error.message || 'Internal server error');
    }
});

// Delete a staff user
exports.deleteStaffUser = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');
    }

    // SECURITY: Only SuperAdmins can delete Staff users. Check staff_accounts first, fallback to users.
    let callerDoc = await admin.firestore().collection('staff_accounts').doc(request.auth.uid).get();
    if (!callerDoc.exists) {
        callerDoc = await admin.firestore().collection('users').doc(request.auth.uid).get();
    }
    if (!callerDoc.exists || callerDoc.data().roleId !== 'role-super-admin' || callerDoc.data().isDisabled === true || callerDoc.data().isActive === false) {
        throw new functions.https.HttpsError('permission-denied', 'Only active SuperAdmins can delete Staff accounts.');
    }

    const { uid } = request.data;
    
    if (!uid) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required uid field');
    }

    if (uid === request.auth.uid) {
        throw new functions.https.HttpsError('permission-denied', 'Cannot delete your own account.');
    }

    try {
        let targetDoc = await admin.firestore().collection('staff_accounts').doc(uid).get();
        if (!targetDoc.exists) {
            targetDoc = await admin.firestore().collection('users').doc(uid).get();
        }
        if (targetDoc.exists && targetDoc.data().roleId === 'role-super-admin') {
            throw new functions.https.HttpsError('permission-denied', 'Cannot delete other SuperAdmin accounts.');
        }

        try {
            await admin.auth().deleteUser(uid);
        } catch (authErr) {
            // Non-fatal if user is not in Auth (e.g. already deleted or created with custom ID)
            if (authErr.code !== 'auth/user-not-found') {
                console.warn(`[deleteStaffUser] Warning deleting auth user ${uid}:`, authErr.message);
            }
        }

        await admin.firestore().collection('staff_accounts').doc(uid).delete().catch(() => {});
        await admin.firestore().collection('users').doc(uid).delete().catch(() => {});
        return { success: true, message: 'User deleted successfully' };
    } catch (error) {
        console.error('Error deleting user:', error);
        throw new functions.https.HttpsError('internal', error.message || 'Internal server error');
    }
});

// Toggle staff user status (isDisabled status synced to Firebase Auth)
exports.setStaffUserStatus = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');
    }

    // SECURITY: Only SuperAdmins can manage staff status. Check staff_accounts first, fallback to users.
    let callerDoc = await admin.firestore().collection('staff_accounts').doc(request.auth.uid).get();
    if (!callerDoc.exists) {
        callerDoc = await admin.firestore().collection('users').doc(request.auth.uid).get();
    }
    if (!callerDoc.exists || callerDoc.data().roleId !== 'role-super-admin' || callerDoc.data().isDisabled === true || callerDoc.data().isActive === false) {
        throw new functions.https.HttpsError('permission-denied', 'Only SuperAdmins can manage staff status.');
    }

    const { uid, isDisabled } = request.data;
    if (!uid || isDisabled === undefined) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields: uid or isDisabled');
    }

    try {
        const db = admin.firestore();
        
        // 1. Update Firebase Auth status
        await admin.auth().updateUser(uid, { disabled: isDisabled });

        // 2. Update Firestore record in staff_accounts and users if exists
        await db.collection('staff_accounts').doc(uid).set({ isDisabled }, { merge: true });
        const legacyDoc = await db.collection('users').doc(uid).get();
        if (legacyDoc.exists) {
            await db.collection('users').doc(uid).update({ isDisabled });
        }

        return { success: true, message: `User status set to ${isDisabled ? 'Disabled' : 'Enabled'} successfully` };
    } catch (error) {
        console.error('Error toggling staff user status:', error);
        throw new functions.https.HttpsError('internal', error.message || 'Internal server error');
    }
});

// Reset staff user password directly
exports.resetStaffUserPassword = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');
    }

    // SECURITY: Only SuperAdmins can reset staff passwords. Check staff_accounts first, fallback to users.
    let callerDoc = await admin.firestore().collection('staff_accounts').doc(request.auth.uid).get();
    if (!callerDoc.exists) {
        callerDoc = await admin.firestore().collection('users').doc(request.auth.uid).get();
    }
    if (!callerDoc.exists || callerDoc.data().roleId !== 'role-super-admin' || callerDoc.data().isDisabled === true || callerDoc.data().isActive === false) {
        throw new functions.https.HttpsError('permission-denied', 'Only SuperAdmins can reset staff passwords.');
    }

    const { uid, password } = request.data;
    if (!uid || !password) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields: uid or password');
    }

    try {
        // Update Firebase Auth password
        await admin.auth().updateUser(uid, { password });

        return { success: true, message: 'Password updated successfully' };
    } catch (error) {
        console.error('Error resetting staff user password:', error);
        throw new functions.https.HttpsError('internal', error.message || 'Internal server error');
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// EMPLOYEE AUTH FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

// Helper: get and increment failed attempt counter. Returns true if locked.
async function checkAndIncrementFailedAttempts(db, employeeId) {
    const attemptsRef = db.collection('_auth_attempts').doc(employeeId);
    const attemptsDoc = await attemptsRef.get();
    
    const now = Date.now();
    const LOCK_DURATION_MS = 60 * 60 * 1000; // 1 hour
    const MAX_ATTEMPTS = 3;

    if (attemptsDoc.exists) {
        const data = attemptsDoc.data();
        if (data.lockedUntil && data.lockedUntil > now) {
            return true; // Still locked
        }
        const newCount = (data.count || 0) + 1;
        if (newCount >= MAX_ATTEMPTS) {
            await attemptsRef.set({ count: newCount, lockedUntil: now + LOCK_DURATION_MS });
        } else {
            await attemptsRef.set({ count: newCount, lockedUntil: null });
        }
    } else {
        await attemptsRef.set({ count: 1, lockedUntil: null });
    }
    return false;
}

async function clearFailedAttempts(db, employeeId) {
    await db.collection('_auth_attempts').doc(employeeId).delete();
}

// Daily rate limiter for Claim Profile (max 3 attempts per 24 hours per employee ID)
async function checkClaimDailyAttempts(db, employeeId) {
    const attemptsRef = db.collection('_auth_attempts').doc(`claim_${employeeId}`);
    const snap = await attemptsRef.get();
    const now = Date.now();
    const ONE_DAY_MS = 24 * 60 * 60 * 1000;
    const MAX_DAILY_ATTEMPTS = 3;

    if (snap.exists) {
        const data = snap.data();
        if (data.firstAttemptAt && (now - data.firstAttemptAt > ONE_DAY_MS)) {
            await attemptsRef.set({ count: 1, firstAttemptAt: now, lockedUntil: null });
            return false;
        }
        if (data.lockedUntil && data.lockedUntil > now) {
            return true;
        }
        const newCount = (data.count || 0) + 1;
        if (newCount >= MAX_DAILY_ATTEMPTS) {
            await attemptsRef.set({ count: newCount, firstAttemptAt: data.firstAttemptAt || now, lockedUntil: (data.firstAttemptAt || now) + ONE_DAY_MS });
            return true;
        } else {
            await attemptsRef.set({ count: newCount, firstAttemptAt: data.firstAttemptAt || now, lockedUntil: null });
            return false;
        }
    } else {
        await attemptsRef.set({ count: 1, firstAttemptAt: now, lockedUntil: null });
        return false;
    }
}

async function clearClaimDailyAttempts(db, employeeId) {
    try {
        await db.collection('_auth_attempts').doc(`claim_${employeeId}`).delete();
    } catch (e) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// EMPLOYEE GOOGLE LOGIN — SSO to Custom Token Exchange
// Exchanges a valid Google ID Token for an Employee Custom Token.
// Protects strict Firestore rules by standardizing request.auth.uid to Employee ID.
// ─────────────────────────────────────────────────────────────────────────────

exports.employeeGoogleLogin = secureOnCall(async (request) => {
    const { idToken } = request.data;
    if (!idToken) throw new functions.https.HttpsError('invalid-argument', 'Missing Google idToken');

    const db = admin.firestore();

    try {
        // Verify Google identity securely on backend
        const ticket = await admin.auth().verifyIdToken(idToken);
        const googleUid = ticket.uid;
        const email = ticket.email;

        if (!email) {
             throw new functions.https.HttpsError('invalid-argument', 'Google token missing email');
        }

        if (ticket.email_verified === false) {
             throw new functions.https.HttpsError('unauthenticated', 'Google email is not verified.');
        }

        const normalizedEmail = email.toLowerCase().trim();

        console.log(`[GOOGLE LOGIN] Attempt for: ${normalizedEmail}`);

        let employeeDoc = null;
        let submissionDoc = null;

        // 1. Try finding by Google UID in employees (BUG-A56-03: Active employees are primary)
        let empSnap = await db.collection('employees')
            .where('linkedUid', '==', googleUid)
            .limit(1).get();
        if (empSnap.empty) {
            empSnap = await db.collection('employees')
                .where('googleUid', '==', googleUid)
                .limit(1).get();
        }
        if (empSnap.empty) {
            empSnap = await db.collection('employees')
                .where('uid', '==', googleUid)
                .limit(1).get();
        }
        if (empSnap.empty) {
            empSnap = await db.collection('employees')
                .where('linkedGoogleEmail', '==', normalizedEmail)
                .limit(1).get();
        }
        if (!empSnap.empty) {
            employeeDoc = empSnap.docs[0];
        }

        // 2. Fallback: Try finding by Google UID in onboarding_submissions
        let subSnap = await db.collection('onboarding_submissions')
            .where('linkedUid', '==', googleUid)
            .limit(1).get();
        if (subSnap.empty) {
            subSnap = await db.collection('onboarding_submissions')
                .where('googleUid', '==', googleUid)
                .limit(1).get();
        }
        if (subSnap.empty) {
            subSnap = await db.collection('onboarding_submissions')
                .where('uid', '==', googleUid)
                .limit(1).get();
        }
        if (subSnap.empty) {
            subSnap = await db.collection('onboarding_submissions')
                .where('linkedGoogleEmail', '==', normalizedEmail)
                .limit(1).get();
        }
        if (!subSnap.empty) {
            submissionDoc = subSnap.docs[0];
        }

        // Cross-reference documents if one is missing
        if (submissionDoc && !employeeDoc) {
            const empId = submissionDoc.data().employeeId;
            const portalId = submissionDoc.id;
            if (empId) {
                let crossEmp = await db.collection('employees').doc(portalId).get();
                if (!crossEmp.exists) {
                    const crossSnap = await db.collection('employees').where('employeeId', '==', empId).limit(1).get();
                    if (!crossSnap.empty) {
                        crossEmp = crossSnap.docs[0];
                    }
                }
                if (crossEmp.exists) {
                    employeeDoc = crossEmp;
                }
            }
        } else if (employeeDoc && !submissionDoc) {
            const empId = employeeDoc.data().employeeId;
            const portalId = employeeDoc.data().portalId || employeeDoc.id;
            let crossSub = await db.collection('onboarding_submissions').doc(portalId).get();
            if (!crossSub.exists && empId) {
                const crossSnap = await db.collection('onboarding_submissions').where('employeeId', '==', empId).limit(1).get();
                if (!crossSnap.empty) {
                    crossSub = crossSnap.docs[0];
                }
            }
            if (crossSub.exists) {
                submissionDoc = crossSub;
            }
        }

        if (!employeeDoc && !submissionDoc) {
            console.warn(`[GOOGLE LOGIN] Employee not found for Google UID: ${googleUid} Email: ${email}`);
            throw new functions.https.HttpsError('not-found', 'No employee record linked to this Google account.');
        }

        // SECURITY: Block inactive, relieved, or blocked employees from Google SSO login
        const empData = employeeDoc ? employeeDoc.data() : null;
        const subData = submissionDoc ? submissionDoc.data() : null;

        const isInactive = (empData && (empData.isActive === false || empData.isRelieved === true || empData.isBlocked === true || !!empData.deletedAt)) ||
                           (subData && (subData.isActive === false || subData.isRelieved === true || subData.isBlocked === true || !!subData.deletedAt));

        if (isInactive) {
            console.warn(`[GOOGLE LOGIN] Blocked login for inactive/relieved employee (UID: ${googleUid}, Email: ${email})`);
            throw new functions.https.HttpsError('permission-denied', 'This account is inactive. Relieved employees cannot log in.');
        }

        const portalId = (submissionDoc ? submissionDoc.id : null) || (employeeDoc ? (employeeDoc.data().portalId || employeeDoc.id) : null);
        if (!portalId) {
            throw new functions.https.HttpsError('internal', 'Could not resolve Portal ID for the employee.');
        }

        // Auto-link both documents without overwriting the core employee auth UID
        if (submissionDoc) {
            const data = submissionDoc.data();
            const updates = {};
            if (data.linkedUid !== googleUid) updates.linkedUid = googleUid;
            if (data.googleUid !== googleUid) updates.googleUid = googleUid;
            if (data.linkedGoogleEmail !== normalizedEmail) updates.linkedGoogleEmail = normalizedEmail;
            // Preserve portalId as uid so it matches customToken auth.currentUser.uid
            if (!data.uid || data.uid === 'none') updates.uid = portalId;

            if (Object.keys(updates).length > 0) {
                await submissionDoc.ref.update(updates);
                console.log(`[GOOGLE LOGIN] Linked Google UID ${googleUid} to onboarding_submissions/${submissionDoc.id}`);
            }
        }
        if (employeeDoc) {
            const data = employeeDoc.data();
            const updates = {};
            if (data.linkedUid !== googleUid) updates.linkedUid = googleUid;
            if (data.googleUid !== googleUid) updates.googleUid = googleUid;
            if (data.linkedGoogleEmail !== normalizedEmail) updates.linkedGoogleEmail = normalizedEmail;
            // Preserve portalId as uid so it matches customToken auth.currentUser.uid
            if (!data.uid || data.uid === 'none') updates.uid = portalId;

            if (Object.keys(updates).length > 0) {
                await employeeDoc.ref.update(updates);
                console.log(`[GOOGLE LOGIN] Linked Google UID ${googleUid} to employees/${employeeDoc.id}`);
            }
        }

        // Generate Custom Token using the *exact* Portal ID (global ID)
        const customToken = await admin.auth().createCustomToken(portalId, { portal: 'employee', portalType: 'employee', authProvider: 'google' });
        
        // Clear fails
        await clearFailedAttempts(db, `login_${portalId}`);

        return { success: true, token: customToken };
    } catch (error) {
        console.error('Error in employeeGoogleLogin:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('unauthenticated', 'Invalid Google token');
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// EMPLOYEE LOGIN — Custom Token Authentication
// Replaces anonymous auth with a stable, persistent Firebase session.
// ─────────────────────────────────────────────────────────────────────────────

exports.employeeLogin = secureOnCall(async (request) => {
    let { employeeId, password } = request.data;
    
    // Normalize Employee ID to uppercase for case-insensitive lookup
    if (employeeId) {
        employeeId = employeeId.trim().toUpperCase();
    }

    if (!employeeId || !password) {
        throw new functions.https.HttpsError('invalid-argument', 'Employee ID and password are required.');
    }

    const db = admin.firestore();
    console.log(`[LOGIN] Attempt for ID: "${employeeId}" (Normalized: "${employeeId.trim().toUpperCase()}")`);

    // SECURITY: Rate-limit login attempts
    const isLocked = await checkAndIncrementFailedAttempts(db, `login_${employeeId}`);
    if (isLocked) {
        throw new functions.https.HttpsError('resource-exhausted', 'Too many failed attempts. Try again in 1 hour.');
    }

    let matchedDoc = null;
    let matchedData = null;
    let matchedCollection = null;

    // 1. Check employees collection (BUG-A56-03: Active Master Employee Directory is primary)
    const empSnap = await db.collection('employees')
        .where('employeeId', '==', employeeId)
        .limit(1)
        .get();

    if (!empSnap.empty) {
        const emp = empSnap.docs[0];
        const empData = emp.data();
        let isMatch = false;

        if (empData.passwordHash) {
            isMatch = await verifyPassword(password, empData.passwordHash);
        } else if (empData.mockPassword) {
            isMatch = empData.mockPassword === password;
        }

        if (isMatch) {
            if (empData.isActive === false || empData.isDisabled === true || empData.isRelieved === true || empData.isBlocked === true || empData.status === 'relieved' || empData.status === 'terminated' || !!empData.deletedAt) {
                console.warn(`[LOGIN] Blocked login for disabled/inactive/relieved employee ${employeeId}`);
                throw new functions.https.HttpsError('permission-denied', 'This account is disabled or inactive. Disabled employees cannot log in.');
            }
            matchedDoc = emp;
            matchedData = empData;
            matchedCollection = 'employees';
            console.log(`[LOGIN] Match found in employees collection for ${employeeId}`);
        } else {
            console.log(`[LOGIN] User found in employees collection for ${employeeId} but password mismatch`);
        }
    }

    // 2. Fallback: Check onboarding_submissions (self-onboarded joiners pending sync)
    if (!matchedDoc) {
        const subSnap = await db.collection('onboarding_submissions')
            .where('employeeId', '==', employeeId)
            .where('status', '==', 'Approved')
            .limit(1)
            .get();

        if (!subSnap.empty) {
            const sub = subSnap.docs[0];
            const subData = sub.data();
            let isMatch = false;

            if (subData.passwordHash) {
                isMatch = await verifyPassword(password, subData.passwordHash);
            } else if (subData.mockPassword) {
                isMatch = subData.mockPassword === password;
            }

            if (isMatch) {
                // SECURITY: Verify the employee is active, not disabled, not relieved, not terminated, and not blocked
                let isInactive = subData.isActive === false || subData.isDisabled === true || subData.isRelieved === true || subData.isBlocked === true || subData.status === 'relieved' || subData.status === 'terminated' || subData.status === 'rejected' || !!subData.deletedAt;
                if (!isInactive) {
                    // Cross-check employees collection by portalId (sub.id) or employeeId
                    let empCheck = await db.collection('employees').doc(sub.id).get();
                    if (!empCheck.exists) {
                        const empSnapCheck = await db.collection('employees').where('employeeId', '==', employeeId).limit(1).get();
                        if (!empSnapCheck.empty) empCheck = empSnapCheck.docs[0];
                    }
                    if (empCheck.exists) {
                        const checkData = empCheck.data();
                        if (checkData.isActive === false || checkData.isDisabled === true || checkData.isRelieved === true || checkData.isBlocked === true || checkData.status === 'relieved' || checkData.status === 'terminated' || !!checkData.deletedAt) {
                            isInactive = true;
                        }
                    }
                }

                if (isInactive) {
                    console.warn(`[LOGIN] Blocked login for disabled/inactive/relieved employee ${employeeId}`);
                    throw new functions.https.HttpsError('permission-denied', 'This account is disabled or inactive. Disabled employees cannot log in.');
                }

                matchedDoc = sub;
                matchedData = subData;
                matchedCollection = 'onboarding_submissions';
                console.log(`[LOGIN] Match found in onboarding_submissions for ${employeeId}`);
            } else {
                console.log(`[LOGIN] User found in onboarding_submissions for ${employeeId} but password mismatch`);
            }
        }
    }

    if (!matchedDoc) {
        console.warn(`[LOGIN] No match for ${employeeId} in any collection or wrong password`);
        throw new functions.https.HttpsError('not-found', 'Invalid Employee ID or Password.');
    }

    // SUCCESS: Clear rate-limit counter
    await clearFailedAttempts(db, `login_${employeeId}`);

    // 4. Generate Custom Token
    let customToken;
    const customTokenUid = matchedDoc.id; // SECURITY: Must use the Firestore Document ID as UID to preserve history/references!

    try {
        // Generate a stable UID matching the Firestore Document ID
        customToken = await admin.auth().createCustomToken(customTokenUid, {
            portal: 'employee',
            portalType: 'employee',
            employeeId: employeeId,
            role: 'employee'
        });

        // Link the stable UID to the employee record
        await matchedDoc.ref.update({ uid: customTokenUid });

        // Upgrade legacy password to bcrypt if needed
        const isSha256 = matchedData.passwordHash && matchedData.passwordHash.length === 64 && !matchedData.passwordHash.startsWith('$2');
        if ((matchedData.mockPassword && !matchedData.passwordHash) || isSha256) {
            const hashed = await hashPassword(password);
            const updatePayload = {
                passwordHash: hashed,
                isDefaultPassword: matchedData.isDefaultPassword || false
            };
            if (matchedData.mockPassword) {
                updatePayload.mockPassword = admin.firestore.FieldValue.delete();
            }
            await matchedDoc.ref.update(updatePayload);
        }

        // Return token + employee data for the client
        return {
            success: true,
            token: customToken,
            employee: {
                id: matchedDoc.id,
                employeeId: matchedData.employeeId,
                applicantName: matchedData.applicantName || matchedData.name || '',
                isDefaultPassword: matchedData.isDefaultPassword || false,
                authProvider: matchedData.authProvider || 'manual',
                linkedGoogleEmail: matchedData.linkedGoogleEmail || null,
                status: matchedData.status || 'Approved',
                collection: matchedCollection
            }
        };
    } catch (error) {
        console.error('Error creating custom token full error:', JSON.stringify(error, null, 2));
        
        // Detect IAM permission errors (signBlob)
        if (error.code === 'auth/insufficient-permission' || 
            (error.message && error.message.includes('signBlob'))) {
            throw new functions.https.HttpsError(
                'permission-denied',
                `SERVER_SETUP_REQUIRED: The Cloud Function service account lacks the "Service Account Token Creator" role. Technical detail: ${error.message}`
            );
        }
        
        throw new functions.https.HttpsError('internal', 'Authentication failed. Please try again.');
    }
});

// 1. Verify and Reset Password (Forgot Password flow)
exports.verifyAndResetEmployeePassword = secureOnCall(async (request) => {
    let { employeeId, verificationDetails, newPassword } = request.data;
    
    // Normalize Employee ID to uppercase for case-insensitive lookup
    if (employeeId) {
        employeeId = employeeId.trim().toUpperCase();
    }

    if (!employeeId || !verificationDetails || !newPassword) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields');
    }

    const { name, mobile, aadhar, dob } = verificationDetails;
    if (!name || !mobile || !aadhar || !dob) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing verification details');
    }

    try {
        const db = admin.firestore();
        console.log(`[RESET] Attempt for ID: "${employeeId}"`);

        // SECURITY: Rate-limit verification attempts
        const isLocked = await checkAndIncrementFailedAttempts(db, `reset_${employeeId}`);
        if (isLocked) {
            throw new functions.https.HttpsError('resource-exhausted', 'Too many failed attempts. Try again in 1 hour.');
        }

        let empSnapshot = await db.collection('employees').where('employeeId', '==', employeeId).limit(1).get();
        let empDoc = !empSnapshot.empty ? empSnapshot.docs[0] : null;

        if (!empDoc) {
            // Check onboarding_submissions as well
            empSnapshot = await db.collection('onboarding_submissions').where('employeeId', '==', employeeId).limit(1).get();
            empDoc = !empSnapshot.empty ? empSnapshot.docs[0] : null;
        }

        if (!empDoc) {
            console.warn(`[RESET] No record found for ${employeeId}`);
            throw new functions.https.HttpsError('permission-denied', 'Verification failed: invalid credentials or ID');
        }

        const empRef = empDoc.ref;
        const empData = empDoc.data();
        const profileData = empData.profileData || {};
        const storedData = empData.data || {};

        const NAME_FIELD = '7debf274-baee-4bac-a137-4b4b46719874';
        const MOBILE_FIELD = 'eb3617dc-9f1d-475d-a2db-005b6bc2500c';
        const DOB_FIELD = '6e570a01-14e0-4e18-b112-97ddc51d0778';
        const AADHAR_FIELD = '18855ee9-0d66-41d6-988b-128b776a8c5b';

        // Normalization helpers
        const normStr = (s) => String(s || '').trim().toLowerCase().replace(/\s+/g, ' ');
        const normDigits = (s) => String(s || '').replace(/\D/g, '');
        const normDate = (s) => {
            if (!s) return '';
            const clean = String(s).trim().replace(/[\/\.]/g, '-');
            const parts = clean.split('-');
            if (parts.length === 3) {
                if (parts[0].length === 4) {
                    return `${parts[0]}-${parts[1].padStart(2, '0')}-${parts[2].padStart(2, '0')}`;
                } else if (parts[2].length === 4) {
                    return `${parts[2]}-${parts[1].padStart(2, '0')}-${parts[0].padStart(2, '0')}`;
                }
            }
            return clean;
        };

        const inputName = normStr(name);
        const inputMobile = normDigits(mobile).slice(-10);
        const inputAadhar = normDigits(aadhar);
        const inputDob = normDate(dob);

        // Candidate collections
        const candidateNames = [
            empData.applicantName, empData.name, empData.fullName,
            profileData[NAME_FIELD], storedData[NAME_FIELD],
            profileData['name'], profileData['applicantName'], profileData['fullName'],
            storedData['name'], storedData['applicantName'], storedData['fullName']
        ];

        const candidateMobiles = [
            empData.mobile, empData.phoneNumber, empData.phone,
            profileData[MOBILE_FIELD], storedData[MOBILE_FIELD],
            profileData['mobile'], profileData['phoneNumber'], profileData['phone'],
            storedData['mobile'], storedData['phoneNumber'], storedData['phone']
        ];

        const candidateAadhars = [
            empData.aadhar, empData.aadhaar, empData.aadharNumber, empData.aadhaarNumber,
            profileData[AADHAR_FIELD], storedData[AADHAR_FIELD],
            profileData['aadhar'], profileData['aadhaar'], profileData['aadharNumber'], profileData['aadhaarNumber'],
            storedData['aadhar'], storedData['aadhaar'], storedData['aadharNumber'], storedData['aadhaarNumber']
        ];

        const candidateDobs = [
            empData.dob, empData.dateOfBirth,
            profileData[DOB_FIELD], storedData[DOB_FIELD],
            profileData['dob'], profileData['dateOfBirth'],
            storedData['dob'], storedData['dateOfBirth']
        ];

        const matchName = candidateNames.some(c => c && normStr(c) === inputName);
        const matchMobile = candidateMobiles.some(c => c && normDigits(c).slice(-10) === inputMobile) ||
            (inputMobile.length >= 10 && (
                Object.values(profileData).some(val => typeof val === 'string' && normDigits(val).slice(-10) === inputMobile) ||
                Object.values(storedData).some(val => typeof val === 'string' && normDigits(val).slice(-10) === inputMobile)
            ));
        const matchAadhar = candidateAadhars.some(c => c && normDigits(c) === inputAadhar) ||
            (inputAadhar.length >= 12 && (
                Object.values(profileData).some(val => typeof val === 'string' && normDigits(val) === inputAadhar) ||
                Object.values(storedData).some(val => typeof val === 'string' && normDigits(val) === inputAadhar)
            ));
        const matchDob = candidateDobs.some(c => c && normDate(c) === inputDob) ||
            (inputDob.length >= 8 && (
                Object.values(profileData).some(val => typeof val === 'string' && normDate(val) === inputDob) ||
                Object.values(storedData).some(val => typeof val === 'string' && normDate(val) === inputDob)
            ));

        if (!matchName || !matchMobile || !matchDob || !matchAadhar) {
            console.warn(`[RESET] Verification mismatch for ${employeeId}. Name: ${matchName}, Mobile: ${matchMobile}, DOB: ${matchDob}, Aadhar: ${matchAadhar}`);
            throw new functions.https.HttpsError('permission-denied', 'Verification failed: invalid credentials or ID');
        }

        // SUCCESS: Clear rate limit counter and hash password with bcrypt
        await clearFailedAttempts(db, `reset_${employeeId}`);
        const passwordHash = await hashPassword(newPassword);
        const updatePayload = {
            passwordHash: passwordHash,
            mockPassword: admin.firestore.FieldValue.delete(), // Remove plain-text password
            isDefaultPassword: false
        };

        const batch = db.batch();
        batch.update(empRef, updatePayload);

        // Update all related onboarding_submissions documents to prevent dual-collection desynchronization
        const subSnaps = await db.collection('onboarding_submissions')
            .where('employeeId', '==', employeeId).get();
        subSnaps.docs.forEach(d => batch.update(d.ref, updatePayload));

        if (empRef.id) {
            const subDirectSnap = await db.collection('onboarding_submissions').doc(empRef.id).get();
            if (subDirectSnap.exists) {
                batch.update(subDirectSnap.ref, updatePayload);
            }
        }
        await batch.commit();

        return { success: true, message: 'Password reset successfully' };

    } catch (error) {
        console.error('Error resetting password:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('internal', 'Internal server error');
    }
});

// 2. Change Password (Authenticated flow)
exports.changeEmployeePassword = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');
    }

    let { employeeId, currentPassword, newPassword } = request.data;
    
    // Normalize Employee ID to uppercase for case-insensitive lookup
    if (employeeId) {
        employeeId = employeeId.trim().toUpperCase();
    }

    if (!employeeId || !currentPassword || !newPassword) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields');
    }

    try {
        const db = admin.firestore();

        // Check both collections
        let docRef = null;
        let empData = null;

        // BUG-A56-03: Check master employees collection first
        const empSnap = await db.collection('employees')
            .where('employeeId', '==', employeeId).limit(1).get();
        if (!empSnap.empty) {
            docRef = empSnap.docs[0].ref;
            empData = empSnap.docs[0].data();
        } else {
            const subSnap = await db.collection('onboarding_submissions')
                .where('employeeId', '==', employeeId).limit(1).get();
            if (!subSnap.empty) {
                docRef = subSnap.docs[0].ref;
                empData = subSnap.docs[0].data();
            }
        }

        if (!empData) {
            throw new functions.https.HttpsError('not-found', 'Employee not found');
        }

        // SECURITY: Verify caller owns this employee profile
        const callerUid = request.auth.uid;
        if (empData.uid !== callerUid && empData.linkedUid !== callerUid) {
            throw new functions.https.HttpsError('permission-denied', 'You do not have permission to change this password.');
        }

        // SECURITY: Use bcrypt verify. Also handle legacy SHA-256 hashes.
        let isVerified = false;
        if (empData.passwordHash) {
            isVerified = await verifyPassword(currentPassword, empData.passwordHash);
        }
        // NOTE: mockPassword plain-text fallback has been removed for security.
        // All employees must use their hashed password or go through reset flow.

        if (!isVerified) {
            throw new functions.https.HttpsError('permission-denied', 'Incorrect current password');
        }

        // Hash new password with bcrypt and remove legacy plain-text password
        const newHash = await hashPassword(newPassword);
        const updatePayload = {
            passwordHash: newHash,
            mockPassword: admin.firestore.FieldValue.delete(),
            isDefaultPassword: false
        };

        const batch = db.batch();
        batch.update(docRef, updatePayload);

        // Update all matching documents across both collections to prevent desync
        const [allSubs, allEmps] = await Promise.all([
            db.collection('onboarding_submissions').where('employeeId', '==', employeeId).get(),
            db.collection('employees').where('employeeId', '==', employeeId).get()
        ]);
        allSubs.docs.forEach(d => batch.update(d.ref, updatePayload));
        allEmps.docs.forEach(d => batch.update(d.ref, updatePayload));
        await batch.commit();

        return { success: true };
    } catch (error) {
        console.error('Error changing password:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('internal', 'Internal server error');
    }
});

// 3. Link Google Account
exports.linkEmployeeGoogleAccount = secureOnCall(async (request) => {
    let { employeeId, currentPassword, googleUid, email, idToken } = request.data || {};
    
    // Normalize Employee ID to uppercase for case-insensitive lookup
    if (employeeId) {
        employeeId = employeeId.trim().toUpperCase();
    }

    // Verify Google ID Token if passed, or verify request.auth context
    if (idToken) {
        try {
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            googleUid = decodedToken.uid;
            email = decodedToken.email || email;
        } catch (tokErr) {
            console.error('Failed to verify Google ID token:', tokErr);
            throw new functions.https.HttpsError('unauthenticated', 'Invalid Google authentication token');
        }
    } else if (!googleUid && request.auth && request.auth.uid) {
        googleUid = request.auth.uid;
        if (request.auth.token && request.auth.token.email) {
            email = request.auth.token.email;
        }
    }

    console.log('linkEmployeeGoogleAccount called with:', { employeeId, googleUid, email, hasPassword: !!currentPassword });

    if (!employeeId || !currentPassword || !googleUid || !email) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields');
    }

    try {
        const db = admin.firestore();

        // 1. Enforce Global Uniqueness for the Google Account
        const normalizedGoogleEmail = email.toLowerCase().trim();
        
        // Check if this Google account belongs to Staff or Admin
        const staffDocs = await Promise.all([
            db.collection('users').doc(googleUid).get(),
            db.collection('staff').doc(googleUid).get(),
            db.collection('staff_accounts').doc(googleUid).get(),
            db.collection('users').where('email', '==', normalizedGoogleEmail).get(),
            db.collection('staff').where('email', '==', normalizedGoogleEmail).get(),
            db.collection('staff_accounts').where('email', '==', normalizedGoogleEmail).get()
        ]);

        const isStaffConflict = staffDocs.some(docOrSnap => {
            if (docOrSnap.docs) return !docOrSnap.empty; // QuerySnapshot
            return docOrSnap.exists;     // DocumentSnapshot
        });

        if (isStaffConflict) {
            throw new functions.https.HttpsError('already-exists', 'This Google account is already registered in our system. Please contact your administrator.');
        }

        // Check if it belongs to another Employee
        const empChecks = await Promise.all([
            db.collection('employees').where('uid', '==', googleUid).get(),
            db.collection('employees').where('linkedGoogleEmail', '==', normalizedGoogleEmail).get(),
            db.collection('onboarding_submissions').where('uid', '==', googleUid).get(),
            db.collection('onboarding_submissions').where('linkedUid', '==', googleUid).get(),
            db.collection('onboarding_submissions').where('linkedGoogleEmail', '==', normalizedGoogleEmail).get()
        ]);

        for (const snap of empChecks) {
            if (!snap.empty) {
                const isOnlySelf = snap.docs.every(doc => doc.data().employeeId === employeeId);
                if (!isOnlySelf) {
                    throw new functions.https.HttpsError('already-exists', 'This Google account is already registered in our system. Please contact your administrator.');
                }
            }
        }

        let isVerified = false;
        let collectionName = null;
        let docId = null;

        // BUG-A56-03: Check master employees collection first
        const empSnap = await db.collection('employees')
            .where('employeeId', '==', employeeId).limit(1).get();
        if (!empSnap.empty) {
            const empData = empSnap.docs[0].data();
            collectionName = 'employees';
            docId = empSnap.docs[0].id;
            if (empData.passwordHash) {
                isVerified = await verifyPassword(currentPassword, empData.passwordHash);
            }
        }

        // Fallback: check onboarding_submissions
        if (!isVerified) {
            const subSnap = await db.collection('onboarding_submissions')
                .where('employeeId', '==', employeeId)
                .limit(1)
                .get();

            if (!subSnap.empty) {
                const subData = subSnap.docs[0].data();
                collectionName = 'onboarding_submissions';
                docId = subSnap.docs[0].id;
                if (subData.passwordHash) {
                    isVerified = await verifyPassword(currentPassword, subData.passwordHash);
                }
            }
        }

        if (!collectionName) {
            throw new functions.https.HttpsError('not-found', 'Employee not found');
        }

        if (!isVerified) {
            throw new functions.https.HttpsError('permission-denied', 'Incorrect password');
        }

        // Link Google UID across both collections
        const linkPayload = {
            uid: googleUid,
            linkedUid: googleUid,
            authProvider: 'google',
            linkedGoogleEmail: email
        };

        const batch = db.batch();
        batch.update(db.collection(collectionName).doc(docId), linkPayload);

        const cleanId = employeeId.trim().toUpperCase();
        const [allSubs, allEmps] = await Promise.all([
            db.collection('onboarding_submissions').where('employeeId', '==', cleanId).get(),
            db.collection('employees').where('employeeId', '==', cleanId).get()
        ]);
        allSubs.docs.forEach(d => batch.update(d.ref, linkPayload));
        allEmps.docs.forEach(d => batch.update(d.ref, linkPayload));
        await batch.commit();

        return { success: true, message: 'Google account linked successfully' };

    } catch (error) {
        console.error('Error linking Google account:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('internal', 'Internal server error');
    }
});

// 4. Verify Password (e.g. before showing Google popup)
exports.verifyEmployeePassword = secureOnCall(async (request) => {
    let { employeeId, password } = request.data;
    
    // Normalize Employee ID to uppercase for case-insensitive lookup
    if (employeeId) {
        employeeId = employeeId.trim().toUpperCase();
    }

    if (!employeeId || !password) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields');
    }

    try {
        const db = admin.firestore();

        // Rate-limit password verification attempts
        const isLocked = await checkAndIncrementFailedAttempts(db, `verify_${employeeId}`);
        if (isLocked) {
            throw new functions.https.HttpsError('resource-exhausted', 'Too many failed attempts. Try again in 1 hour.');
        }

        // Check both collections
        let empData = null;

        // BUG-A56-03: Check master employees collection first
        const empSnap = await db.collection('employees')
            .where('employeeId', '==', employeeId).limit(1).get();
        if (!empSnap.empty) {
            empData = empSnap.docs[0].data();
        } else {
            const subSnap = await db.collection('onboarding_submissions')
                .where('employeeId', '==', employeeId).limit(1).get();
            if (!subSnap.empty) {
                empData = subSnap.docs[0].data();
            }
        }

        if (!empData) {
            throw new functions.https.HttpsError('not-found', 'Employee not found');
        }

        let isVerified = false;
        if (empData.passwordHash) {
            isVerified = await verifyPassword(password, empData.passwordHash);
        }

        if (!isVerified) {
            throw new functions.https.HttpsError('permission-denied', 'Incorrect password');
        }

        // Clear failed attempts counter on successful verification
        await clearFailedAttempts(db, `verify_${employeeId}`);

        return { success: true };
    } catch (error) {
        console.error('Error verifying password:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('internal', 'Internal server error');
    }
});

// 5. Unlink Google Account
exports.unlinkEmployeeGoogleAccount = secureOnCall(async (request) => {
    // 1. Security Gate: Must be an authenticated session
    if (!request.auth || !request.auth.uid) {
        throw new functions.https.HttpsError('unauthenticated', 'You must be logged into your account to unlink Google.');
    }

    let { employeeId, currentPassword } = request.data;
    
    if (employeeId) employeeId = employeeId.trim().toUpperCase();

    if (!employeeId || !currentPassword) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields');
    }

    try {
        const db = admin.firestore();

        // Rate-limit password verification attempts to prevent brute-forcing
        const isLocked = await checkAndIncrementFailedAttempts(db, `unlink_${employeeId}`);
        if (isLocked) {
            throw new functions.https.HttpsError('resource-exhausted', 'Too many failed attempts. Try again in 1 hour.');
        }

        let isVerified = false;
        let docRefs = [];

        // BUG-A56-03: Check master employees collection first
        const empSnap = await db.collection('employees')
            .where('employeeId', '==', employeeId).limit(1).get();
        if (!empSnap.empty) {
            docRefs.push(empSnap.docs[0].ref);
            const empData = empSnap.docs[0].data();
            if (empData.passwordHash) {
                isVerified = await verifyPassword(currentPassword, empData.passwordHash);
            }
        }

        const subSnap = await db.collection('onboarding_submissions')
            .where('employeeId', '==', employeeId).limit(1).get();
        if (!subSnap.empty) {
            docRefs.push(subSnap.docs[0].ref);
            if (!isVerified) {
                const subData = subSnap.docs[0].data();
                if (subData.passwordHash) {
                    isVerified = await verifyPassword(currentPassword, subData.passwordHash);
                }
            }
        }

        if (docRefs.length === 0) throw new functions.https.HttpsError('not-found', 'Employee not found');
        if (!isVerified) throw new functions.https.HttpsError('permission-denied', 'Incorrect password');

        // Clear failed attempts counter on successful verification
        await clearFailedAttempts(db, `unlink_${employeeId}`);

        const updates = {
            linkedUid: 'none',
            authProvider: 'manual',
            linkedGoogleEmail: admin.firestore.FieldValue.delete()
        };

        await Promise.all(docRefs.map(ref => ref.update(updates)));

        return { success: true, message: 'Google account unlinked safely' };
    } catch (error) {
        console.error('Error unlinking Google account:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('internal', 'Internal server error');
    }
});

// 5b. Setup Initial Password (replaces client-side SHA-256 hashing)
// Called when employee sets their first password during account setup
exports.setupEmployeePassword = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');
    }

    const { employeeId, newPassword } = request.data;
    if (!employeeId || !newPassword) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields');
    }
    if (newPassword.length < 6) {
        throw new functions.https.HttpsError('invalid-argument', 'Password must be at least 6 characters');
    }

    try {
        const db = admin.firestore();
        const callerUid = request.auth.uid;

        // Find the employee record and verify ownership
        let docRef = null;
        let collectionName = null;

        const empSnap = await db.collection('employees').doc(callerUid).get();
        if (empSnap.exists) {
            docRef = empSnap.ref;
            collectionName = 'employees';
        }

        if (!docRef) {
            const subSnap = await db.collection('onboarding_submissions').doc(callerUid).get();
            if (subSnap.exists) {
                docRef = subSnap.ref;
                collectionName = 'onboarding_submissions';
            }
        }

        // Also check by employeeId field
        if (!docRef) {
            const empQuery = await db.collection('employees')
                .where('employeeId', '==', employeeId.trim().toUpperCase())
                .where('uid', '==', callerUid)
                .limit(1).get();
            if (!empQuery.empty) {
                docRef = empQuery.docs[0].ref;
                collectionName = 'employees';
            }
        }

        if (!docRef) {
            const subQuery = await db.collection('onboarding_submissions')
                .where('employeeId', '==', employeeId.trim().toUpperCase())
                .where('uid', '==', callerUid)
                .limit(1).get();
            if (!subQuery.empty) {
                docRef = subQuery.docs[0].ref;
                collectionName = 'onboarding_submissions';
            }
        }

        if (!docRef) {
            throw new functions.https.HttpsError('permission-denied', 'You can only set password for your own account');
        }

        // Hash with bcrypt (secure, salted, slow)
        const passwordHash = await hashPassword(newPassword);
        const updatePayload = {
            passwordHash: passwordHash,
            mockPassword: admin.firestore.FieldValue.delete(),
            isDefaultPassword: false,
            authProvider: 'manual'
        };

        const batch = db.batch();
        batch.update(docRef, updatePayload);

        const cleanId = employeeId.trim().toUpperCase();
        const [allSubs, allEmps] = await Promise.all([
            db.collection('onboarding_submissions').where('employeeId', '==', cleanId).get(),
            db.collection('employees').where('employeeId', '==', cleanId).get()
        ]);
        allSubs.docs.forEach(d => batch.update(d.ref, updatePayload));
        allEmps.docs.forEach(d => batch.update(d.ref, updatePayload));
        await batch.commit();

        console.log(`[SETUP_PASSWORD] Password set for ${employeeId} in ${collectionName}`);
        return { success: true };
    } catch (error) {
        console.error('Error setting up password:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('internal', 'Internal server error');
    }
});

exports.selfLinkGoogleAccount = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');
    }

    let targetGoogleUid = request.data.googleUid;
    let targetEmail = request.data.email;

    // Cryptographic verification if idToken is supplied
    if (request.data.googleIdToken) {
        try {
            const decodedToken = await admin.auth().verifyIdToken(request.data.googleIdToken);
            targetGoogleUid = decodedToken.uid;
            targetEmail = decodedToken.email;
        } catch (tokenErr) {
            console.error('[selfLinkGoogleAccount] Token verification failed:', tokenErr);
            throw new functions.https.HttpsError('unauthenticated', 'Invalid Google token signature.');
        }
    }

    const { employeeId } = request.data;
    const googleUid = targetGoogleUid;
    const email = targetEmail;
    if (!employeeId || !googleUid || !email) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields');
    }

    try {
        const db = admin.firestore();
        const callerUid = request.auth.uid; // This is the Portal ID (their document key)

        // Find the employee record and verify ownership
        let docRef = null;
        let collectionName = null;

        // Try by document ID (callerUid)
        const empSnap = await db.collection('employees').doc(callerUid).get();
        if (empSnap.exists) {
            docRef = empSnap.ref;
            collectionName = 'employees';
        }

        if (!docRef) {
            const subSnap = await db.collection('onboarding_submissions').doc(callerUid).get();
            if (subSnap.exists) {
                docRef = subSnap.ref;
                collectionName = 'onboarding_submissions';
            }
        }

        // Also check by employeeId field matching callerUid
        if (!docRef) {
            const empQuery = await db.collection('employees')
                .where('employeeId', '==', employeeId.trim().toUpperCase())
                .where('uid', '==', callerUid)
                .limit(1).get();
            if (!empQuery.empty) {
                docRef = empQuery.docs[0].ref;
                collectionName = 'employees';
            }
        }

        if (!docRef) {
            const subQuery = await db.collection('onboarding_submissions')
                .where('employeeId', '==', employeeId.trim().toUpperCase())
                .where('uid', '==', callerUid)
                .limit(1).get();
            if (!subQuery.empty) {
                docRef = subQuery.docs[0].ref;
                collectionName = 'onboarding_submissions';
            }
        }

        if (!docRef) {
            throw new functions.https.HttpsError('permission-denied', 'You can only link Google account for your own account');
        }

        // Check Google account conflict (make sure this Google account isn't used by another user)
        const normalizedGoogleEmail = email.toLowerCase().trim();

        // 🛡️ SECURITY: Check if this email belongs to an Admin/Staff user via Firebase Auth API
        try {
            const authUserRecord = await admin.auth().getUserByEmail(normalizedGoogleEmail);
            if (authUserRecord) {
                const [empSnapByUid, subSnapByUid] = await Promise.all([
                    db.collection('employees').where('uid', '==', authUserRecord.uid).limit(1).get(),
                    db.collection('onboarding_submissions').where('linkedUid', '==', authUserRecord.uid).limit(1).get()
                ]);
                if (empSnapByUid.empty && subSnapByUid.empty) {
                    throw new functions.https.HttpsError('already-exists', 'This Google account is already registered in our system. Please contact your administrator.');
                }
            }
        } catch (authError) {
            if (authError.code !== 'auth/user-not-found' && !(authError instanceof functions.https.HttpsError)) {
                throw authError;
            }
            if (authError instanceof functions.https.HttpsError) throw authError;
        }

        const empChecks = await Promise.all([
            db.collection('employees').where('uid', '==', googleUid).get(),
            db.collection('employees').where('linkedGoogleEmail', '==', normalizedGoogleEmail).get(),
            db.collection('onboarding_submissions').where('uid', '==', googleUid).get(),
            db.collection('onboarding_submissions').where('linkedGoogleEmail', '==', normalizedGoogleEmail).get()
        ]);

        for (const snap of empChecks) {
            if (!snap.empty) {
                const isOnlySelf = snap.docs.every(doc => doc.id === callerUid || doc.data().employeeId === employeeId);
                if (!isOnlySelf) {
                    throw new functions.https.HttpsError('already-exists', 'This Google account is already registered in our system. Please contact your administrator.');
                }
            }
        }

        // Link Google Account
        const linkPayload = {
            uid: googleUid,
            linkedUid: googleUid,
            authProvider: 'google',
            linkedGoogleEmail: normalizedGoogleEmail,
            isDefaultPassword: false,
            passwordHash: '', // Clear manual password hash if linking Google
            mockPassword: admin.firestore.FieldValue.delete() // Clear plain text password
        };

        const batch = db.batch();
        batch.update(docRef, linkPayload);

        const cleanId = employeeId.trim().toUpperCase();
        const [allSubs, allEmps] = await Promise.all([
            db.collection('onboarding_submissions').where('employeeId', '==', cleanId).get(),
            db.collection('employees').where('employeeId', '==', cleanId).get()
        ]);
        allSubs.docs.forEach(d => batch.update(d.ref, linkPayload));
        allEmps.docs.forEach(d => batch.update(d.ref, linkPayload));
        await batch.commit();

        console.log(`[SELF_LINK_GOOGLE] Google account linked for ${employeeId} in ${collectionName}`);
        return { success: true };
    } catch (error) {
        console.error('Error linking Google account:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('internal', 'Internal server error');
    }
});

// 6. Admin Control Employee Auth
exports.adminControlEmployeeAuth = secureOnCall(async (request) => {
    if (!request.auth) throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');

    const db = admin.firestore();
    const [userSnap, staffSnap, staffAccSnap] = await Promise.all([
        db.collection('users').doc(request.auth.uid).get(),
        db.collection('staff').doc(request.auth.uid).get(),
        db.collection('staff_accounts').doc(request.auth.uid).get()
    ]);

    // SECURITY: Ensure caller staff account is active and not disabled
    const staffDoc = staffAccSnap.exists ? staffAccSnap.data() : (staffSnap.exists ? staffSnap.data() : (userSnap.exists ? userSnap.data() : null));
    if (staffDoc && (staffDoc.isDisabled === true || staffDoc.isActive === false)) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled. Access denied.');
    }

    // SECURITY: Only SuperAdmin can reset employee passwords or mutate auth providers
    const isSuperAdmin = (userSnap.exists && userSnap.data().roleId === 'role-super-admin') ||
                         (staffAccSnap.exists && staffAccSnap.data().roleId === 'role-super-admin') ||
                         (staffSnap.exists && staffSnap.data().roleId === 'role-super-admin');

    if (!isSuperAdmin) {
        throw new functions.https.HttpsError('permission-denied', 'Only Super Administrators can perform employee credential resets or auth provider changes.');
    }

    let { employeeId, action, payload } = request.data;
    if (employeeId) employeeId = employeeId.trim().toUpperCase();
    if (!employeeId || !action) throw new functions.https.HttpsError('invalid-argument', 'Missing employeeId or action');

    try {
        let docRefs = [];
        const empSnap = await db.collection('employees').where('employeeId', '==', employeeId).limit(1).get();
        if (!empSnap.empty) docRefs.push(empSnap.docs[0].ref);

        const subSnap = await db.collection('onboarding_submissions').where('employeeId', '==', employeeId).limit(1).get();
        if (!subSnap.empty) docRefs.push(subSnap.docs[0].ref);

        if (docRefs.length === 0) throw new functions.https.HttpsError('not-found', 'Employee not found');

        if (action === 'reset_password') {
            const { newPassword } = payload || {};
            if (!newPassword || newPassword.length < 6) throw new functions.https.HttpsError('invalid-argument', 'Invalid new password');
            const hashed = await hashPassword(newPassword);
            const updates = {
                passwordHash: hashed,
                mockPassword: admin.firestore.FieldValue.delete(), // Plaintext password permanently removed
                isDefaultPassword: true, // Forces employee to change password on next login
                authProvider: 'manual'
            };
            await Promise.all(docRefs.map(ref => ref.update(updates)));
            return { success: true };
        } 
        else if (action === 'unlink_google') {
            const updates = {
                uid: admin.firestore.FieldValue.delete(),
                linkedUid: 'none',
                authProvider: 'manual',
                linkedGoogleEmail: admin.firestore.FieldValue.delete()
            };
            await Promise.all(docRefs.map(ref => ref.update(updates)));
            return { success: true };
        }
        else if (action === 'link_google_email') {
            const { googleEmail } = payload || {};
            if (!googleEmail) throw new functions.https.HttpsError('invalid-argument', 'Google email is required');
            const updates = {
                linkedGoogleEmail: googleEmail.toLowerCase().trim(),
                linkedUid: 'none',
                authProvider: 'google'
            };
            await Promise.all(docRefs.map(ref => ref.update(updates)));
            return { success: true };
        }
        else if (action === 'set_auth_provider') {
            const { provider } = payload || {};
            if (provider !== 'manual' && provider !== 'google') throw new functions.https.HttpsError('invalid-argument', 'Invalid provider');
            await Promise.all(docRefs.map(ref => ref.update({ authProvider: provider })));
            return { success: true };
        }
        else if (action === 'update_email') {
            const { email } = payload || {};
            if (!email) throw new functions.https.HttpsError('invalid-argument', 'Email is required');
            const updates = { 
                email: email.toLowerCase().trim(),
                linkedGoogleEmail: email.toLowerCase().trim() 
            };
            await Promise.all(docRefs.map(ref => ref.update(updates)));
            return { success: true };
        }
        else if (action === 'reset_to_default') {
            // Read the employee data to generate default password or use admin custom password
            const empData = empSnap.empty ? null : empSnap.docs[0].data();
            const subData = subSnap.empty ? null : subSnap.docs[0].data();
            const sourceData = empData || subData;
            
            if (!sourceData) throw new functions.https.HttpsError('not-found', 'Cannot read employee data');
            
            let tempPassword = (payload && payload.newPassword) ? payload.newPassword : '';
            if (!tempPassword) {
                // Get name: applicantName or from formData
                const fullName = sourceData.applicantName || sourceData.name || 'user';
                const firstName = fullName.split(' ')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
                
                // Get DOB year: search in data object for any date-of-birth field
                let year = '123';
                const dataObj = sourceData.data || sourceData.formData || {};
                for (const [key, val] of Object.entries(dataObj)) {
                    if (typeof val === 'string' && val.match(/^\d{4}-\d{2}-\d{2}$/)) {
                        const keyLower = key.toLowerCase();
                        if (keyLower.includes('birth') || keyLower.includes('dob')) {
                            year = val.split('-')[0];
                            break;
                        }
                    }
                }
                if (year === '123') {
                    for (const [key, val] of Object.entries(dataObj)) {
                        if (typeof val === 'string' && val.match(/^\d{4}-\d{2}-\d{2}$/)) {
                            const y = parseInt(val.split('-')[0]);
                            if (y > 1950 && y < 2010) {
                                year = val.split('-')[0];
                                break;
                            }
                        }
                    }
                }
                const phoneOrAadhaar = sourceData.phoneNumber || sourceData.aadhaarNumber || '';
                const cleanSuffix = (phoneOrAadhaar || '').replace(/\D/g, '').slice(-4);
                tempPassword = `${firstName}${year}${cleanSuffix ? '@' + cleanSuffix : ''}`;
            }
            
            const hashed = await hashPassword(tempPassword);
            const updates = {
                passwordHash: hashed,
                mockPassword: admin.firestore.FieldValue.delete(), // Plaintext password is NEVER saved in database
                isDefaultPassword: true, // Forces employee to change password on next login
                authProvider: 'manual'
            };
            await Promise.all(docRefs.map(ref => ref.update(updates)));
            return { success: true, generatedPassword: tempPassword };
        }
        else {
            throw new functions.https.HttpsError('invalid-argument', 'Invalid action');
        }
    } catch (error) {
        console.error('Error in adminControlEmployeeAuth:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('internal', 'Internal server error');
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// SECURE FILE STORAGE & RETRIEVAL
// ─────────────────────────────────────────────────────────────────────────────

// Generate a 15-minute temporary signed URL for a given Firebase Storage path
exports.getSecureDocumentURL = secureOnCall(async (request) => {
    // SECURITY: Must be authenticated
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'You must be logged in to access secure documents.');
    }

    const { storagePath } = request.data;
    if (!storagePath) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing storagePath parameter.');
    }

    try {
        const db = admin.firestore();
        const uid = request.auth.uid;
        
        // 1. Check if caller is Admin or Staff
        let isAdminOrStaff = false;
        const [userSnap, staffSnap, staffAccSnap] = await Promise.all([
            db.collection('users').doc(uid).get(),
            db.collection('staff').doc(uid).get(),
            db.collection('staff_accounts').doc(uid).get()
        ]);
        
        const staffDoc = (staffAccSnap.exists ? staffAccSnap.data() : (staffSnap.exists ? staffSnap.data() : (userSnap.exists ? userSnap.data() : null)));
        if (staffDoc) {
            if (staffDoc.isDisabled === true || staffDoc.isActive === false || staffDoc.status === 'relieved' || staffDoc.status === 'terminated') {
                throw new functions.https.HttpsError('permission-denied', 'This staff account is disabled. Access denied.');
            }
            isAdminOrStaff = true;
        } else if (request.auth.token && request.auth.token.email && request.auth.token.email_verified) {
            // Fallback: Check if user exists in staff collections by email (for legacy staff matched by email)
            const email = request.auth.token.email;
            const [usersByEmail, staffByEmail, staffAccByEmail] = await Promise.all([
                db.collection('users').where('email', '==', email).limit(1).get(),
                db.collection('staff').where('email', '==', email).limit(1).get(),
                db.collection('staff_accounts').where('email', '==', email).limit(1).get()
            ]);
            const matchedDoc = (!staffAccByEmail.empty ? staffAccByEmail.docs[0] : (!staffByEmail.empty ? staffByEmail.docs[0] : (!usersByEmail.empty ? usersByEmail.docs[0] : null)));
            if (matchedDoc) {
                const sData = matchedDoc.data();
                if (sData.isDisabled === true || sData.isActive === false || sData.status === 'relieved' || sData.status === 'terminated') {
                    throw new functions.https.HttpsError('permission-denied', 'This staff account is disabled. Access denied.');
                }
                isAdminOrStaff = true;
            }
        }

        // 2. Perform Authorization Checks based on path
        let isAuthorized = false;

        // SEC-08: Enforce site scoping for staff; only SuperAdmin has global document view access
        const isSuperAdminCaller = (request.auth.token && request.auth.token.isSuperAdmin) || 
                                   (staffDoc && (staffDoc.roleId === 'role-super-admin' || staffDoc.type === 'Admin')) ||
                                   (request.auth.token && request.auth.token.permissions && request.auth.token.permissions.includes('EMPLOYEES_VIEW_SCOPE_ALL'));

        if (isAdminOrStaff && isSuperAdminCaller) {
            isAuthorized = true;
        } else if (isAdminOrStaff) {
            // Staff with restricted sites: verify target employee/document belongs to sitesManaged
            const cleanStoragePath = storagePath.replace(/^\/+/, '');
            const parts = cleanStoragePath.split('/');
            const targetDocId = parts[1];
            if (targetDocId) {
                const [targetEmp, targetSub] = await Promise.all([
                    db.collection('employees').doc(targetDocId).get(),
                    db.collection('onboarding_submissions').doc(targetDocId).get()
                ]);
                const docData = (targetEmp.exists ? targetEmp.data() : (targetSub.exists ? targetSub.data() : null)) || {};
                const docSite = docData.siteId || docData.currentSiteId || '';
                const staffSites = (staffDoc && Array.isArray(staffDoc.sitesManaged)) ? staffDoc.sitesManaged : (request.auth.token?.sitesManaged || []);
                if (docSite && staffSites.includes(docSite)) {
                    isAuthorized = true;
                } else if (!docSite) {
                    isAuthorized = true; // Non-site-bound document
                } else {
                    console.warn(`[SECURITY] SEC-08 Blocked cross-site document access: Staff ${uid} attempted accessing site "${docSite}"`);
                    throw new functions.https.HttpsError('permission-denied', 'You do not have permission to view documents from this site.');
                }
            } else {
                isAuthorized = true;
            }
        } else if (storagePath.startsWith('public/')) {
            isAuthorized = true; // Anyone authenticated can view public assets
        } else if (storagePath.startsWith(`employees/`)) {
            const pathParts = storagePath.split('/');
            const employeeIdInPath = pathParts[1];
            
            if (employeeIdInPath) {
                if (employeeIdInPath === uid) {
                    isAuthorized = true;
                } else {
                    // 1. Direct document ID lookup
                    let empDoc = await db.collection('employees').doc(employeeIdInPath).get();
                    let empData = empDoc.exists ? empDoc.data() : null;

                    // 2. Fallback: Search by employeeId field (e.g. HY140001)
                    if (!empData) {
                        const snap = await db.collection('employees')
                            .where('employeeId', '==', employeeIdInPath)
                            .limit(1)
                            .get();
                        if (!snap.empty) {
                            empDoc = snap.docs[0];
                            empData = empDoc.data();
                        }
                    }

                    // 3. Fallback: Check onboarding_submissions
                    if (!empData) {
                        const subDoc = await db.collection('onboarding_submissions').doc(employeeIdInPath).get();
                        if (subDoc.exists) {
                            empDoc = subDoc;
                            empData = subDoc.data();
                        } else {
                            const subSnap = await db.collection('onboarding_submissions')
                                .where('employeeId', '==', employeeIdInPath)
                                .limit(1)
                                .get();
                            if (!subSnap.empty) {
                                empDoc = subSnap.docs[0];
                                empData = empDoc.data();
                            }
                        }
                    }

                    if (empData) {
                        if (
                            empData.linkedUid === uid ||
                            empData.uid === uid ||
                            empData.employeeId === uid ||
                            empData.portalId === uid ||
                            (empDoc && empDoc.id === uid)
                        ) {
                            isAuthorized = true;
                        }
                    }
                }
            }
        } else if (storagePath.startsWith(`onboarding/`)) {
            const pathParts = storagePath.split('/');
            const folderUid = pathParts[1];
            
            if (folderUid === uid) {
                isAuthorized = true; 
            } else {
                // Check if onboarding submission has matching Portal ID or linked Google account
                const subDoc = await db.collection('onboarding_submissions').doc(folderUid).get();
                if (subDoc.exists && (subDoc.data().linkedUid === uid || subDoc.data().uid === uid || subDoc.data().employeeId === uid)) {
                    isAuthorized = true;
                } else {
                    const subSnap = await db.collection('onboarding_submissions')
                        .where('linkedUid', '==', folderUid)
                        .limit(1)
                        .get();
                    if (!subSnap.empty) {
                        const subData = subSnap.docs[0].data();
                        if (subData.linkedUid === uid || subData.uid === uid || subData.employeeId === uid || subSnap.docs[0].id === uid) {
                            isAuthorized = true;
                        }
                    } else {
                        const subSnap2 = await db.collection('onboarding_submissions')
                            .where('uid', '==', folderUid)
                            .limit(1)
                            .get();
                        if (!subSnap2.empty) {
                            const subData = subSnap2.docs[0].data();
                            if (subData.linkedUid === uid || subData.uid === uid || subData.employeeId === uid || subSnap2.docs[0].id === uid) {
                                isAuthorized = true;
                            }
                        }
                    }
                }
            }

            // Check 4: Draft submissions — draft_submissions/{folderUid}
            if (!isAuthorized) {
                const draftDoc = await db.collection('draft_submissions').doc(folderUid).get();
                if (draftDoc.exists) {
                    const d = draftDoc.data();
                    if (
                        d.ownerUid === uid ||
                        d.activeSessionUid === uid ||
                        d.uid === uid ||
                        d.linkedUid === uid ||
                        (request.auth.token && request.auth.token.email && d.ownerEmail === request.auth.token.email)
                    ) {
                        isAuthorized = true;
                    }
                }
            }
        } else if (storagePath.startsWith(`users/`)) {
            const pathParts = storagePath.split('/');
            const portalUserId = pathParts[1];
            
            if (portalUserId) {
                if (portalUserId === uid) {
                    isAuthorized = true;
                } else {
                    // Check employees collection
                    const empDoc = await db.collection('employees').doc(portalUserId).get();
                    if (empDoc.exists && empDoc.data().linkedUid === uid) {
                        isAuthorized = true;
                    } else {
                        // Check onboarding_submissions
                        const subDoc = await db.collection('onboarding_submissions').doc(portalUserId).get();
                        if (subDoc.exists && (subDoc.data().linkedUid === uid || subDoc.data().uid === uid || subDoc.data().employeeId === uid)) {
                            isAuthorized = true;
                        } else {
                            // Check draft_submissions
                            const draftDoc = await db.collection('draft_submissions').doc(portalUserId).get();
                            if (draftDoc.exists && draftDoc.data().ownerUid === uid) {
                                isAuthorized = true;
                            }
                        }
                    }
                }
            }
        } else {
            console.warn(`[SECURITY] Unauthorized access attempt by ${uid} for path: ${storagePath}`);
            throw new functions.https.HttpsError('permission-denied', 'You do not have permission to view this document.');
        }

        if (!isAuthorized) {
            throw new functions.https.HttpsError('permission-denied', 'Access denied.');
        }

        // 3. Generate Signed URL
        const bucket = admin.storage().bucket();
        const file = bucket.file(storagePath);
        
        const [exists] = await file.exists();
        if (!exists) {
            console.warn(`[STORAGE] File not found: ${storagePath}`);
            throw new functions.https.HttpsError('not-found', 'The requested file does not exist.');
        }

        const [url] = await file.getSignedUrl({
            action: 'read',
            expires: Date.now() + 15 * 60 * 1000 // 15 minutes
        });

        return { success: true, url };
    } catch (error) {
        console.error('Error generating secure URL:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        
        // Handle IAM permission errors for getSignedUrl gracefully
        if (error.message && error.message.includes('signBlob')) {
             throw new functions.https.HttpsError(
                 'internal', 
                 'Server configuration error: Service Account Token Creator role missing.'
             );
        }
        throw new functions.https.HttpsError('internal', 'Failed to generate secure document URL.');
    }
});

/**
 * getBatchSignedViewUrls (CLOUD-8)
 * Generates signed URLs for up to 30 storage paths in a single round-trip.
 * Validates ownership once per prefix / target ID instead of 10-15 parallel calls.
 */
exports.getBatchSignedViewUrls = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'You must be logged in to access secure documents.');
    }

    const { storagePaths } = request.data || {};
    if (!Array.isArray(storagePaths) || storagePaths.length === 0) {
        return { success: true, urls: {} };
    }

    // Limit batch size to 30 paths to prevent abuse
    const pathsToProcess = storagePaths.slice(0, 30);
    const db = admin.firestore();
    const uid = request.auth.uid;

    try {
        // 1. Check if caller is Admin or Staff
        let isAdminOrStaff = false;
        let staffDoc = null;
        if (request.auth.token && (request.auth.token.isAdmin === true || request.auth.token.isSuperAdmin === true)) {
            isAdminOrStaff = true;
        } else {
            const [userSnap, staffSnap, staffAccSnap] = await Promise.all([
                db.collection('users').doc(uid).get(),
                db.collection('staff').doc(uid).get(),
                db.collection('staff_accounts').doc(uid).get()
            ]);
            staffDoc = (staffAccSnap.exists ? staffAccSnap.data() : (staffSnap.exists ? staffSnap.data() : (userSnap.exists ? userSnap.data() : null)));
            if (staffDoc && staffDoc.isDisabled !== true && staffDoc.isActive !== false && staffDoc.status !== 'relieved' && staffDoc.status !== 'terminated') {
                isAdminOrStaff = true;
            } else if (request.auth.token && request.auth.token.email && request.auth.token.email_verified) {
                const email = request.auth.token.email;
                const [usersByEmail, staffByEmail, staffAccByEmail] = await Promise.all([
                    db.collection('users').where('email', '==', email).limit(1).get(),
                    db.collection('staff').where('email', '==', email).limit(1).get(),
                    db.collection('staff_accounts').where('email', '==', email).limit(1).get()
                ]);
                const matchedDoc = (!staffAccByEmail.empty ? staffAccByEmail.docs[0] : (!staffByEmail.empty ? staffByEmail.docs[0] : (!usersByEmail.empty ? usersByEmail.docs[0] : null)));
                if (matchedDoc) {
                    const sData = matchedDoc.data();
                    if (sData.isDisabled !== true && sData.isActive !== false && sData.status !== 'relieved' && sData.status !== 'terminated') {
                        isAdminOrStaff = true;
                        staffDoc = sData;
                    }
                }
            }
        }

        const isSuperAdminCaller = (request.auth.token && request.auth.token.isSuperAdmin) || 
                                   (staffDoc && (staffDoc.roleId === 'role-super-admin' || staffDoc.type === 'Admin')) ||
                                   (request.auth.token && request.auth.token.permissions && request.auth.token.permissions.includes('EMPLOYEES_VIEW_SCOPE_ALL'));
        const staffSites = (staffDoc && Array.isArray(staffDoc.sitesManaged)) ? staffDoc.sitesManaged : (request.auth.token?.sitesManaged || []);

        // Cache authorization decisions per target ID / folder to avoid repeated Firestore lookups
        const authCache = new Map();

        const checkPathAuthorization = async (p) => {
            if (isAdminOrStaff && isSuperAdminCaller) return true;
            if (typeof p !== 'string') return false;
            const cleanPath = p.trim().replace(/^\/+/, '');
            if (cleanPath.startsWith('public/')) return true;

            const parts = cleanPath.split('/');
            const root = parts[0];
            const targetId = parts[1];

            if (isAdminOrStaff) {
                if (!targetId) return true;
                const cacheKey = `staff_site:${targetId}`;
                if (authCache.has(cacheKey)) return authCache.get(cacheKey);
                const [targetEmp, targetSub] = await Promise.all([
                    db.collection('employees').doc(targetId).get(),
                    db.collection('onboarding_submissions').doc(targetId).get()
                ]);
                const docData = (targetEmp.exists ? targetEmp.data() : (targetSub.exists ? targetSub.data() : null)) || {};
                const docSite = docData.siteId || docData.currentSiteId || '';
                const allowed = (!docSite || staffSites.includes(docSite));
                authCache.set(cacheKey, allowed);
                return allowed;
            }

            if (!root || !targetId) return false;
            const cacheKey = `${root}:${targetId}`;
            if (authCache.has(cacheKey)) return authCache.get(cacheKey);

            let authorized = false;
            if (root === 'employees') {
                if (targetId === uid) {
                    authorized = true;
                } else {
                    let empDoc = await db.collection('employees').doc(targetId).get();
                    let empData = empDoc.exists ? empDoc.data() : null;
                    if (!empData) {
                        const snap = await db.collection('employees').where('employeeId', '==', targetId).limit(1).get();
                        if (!snap.empty) empData = snap.docs[0].data();
                    }
                    if (!empData) {
                        const subDoc = await db.collection('onboarding_submissions').doc(targetId).get();
                        if (subDoc.exists) empData = subDoc.data();
                        else {
                            const subSnap = await db.collection('onboarding_submissions').where('employeeId', '==', targetId).limit(1).get();
                            if (!subSnap.empty) empData = subSnap.docs[0].data();
                        }
                    }
                    if (empData) {
                        if (
                            empData.linkedUid === uid ||
                            empData.uid === uid ||
                            empData.employeeId === uid ||
                            empData.portalId === uid
                        ) {
                            authorized = true;
                        }
                    }
                }
            } else if (root === 'onboarding') {
                if (targetId === uid) {
                    authorized = true;
                } else {
                    const subDoc = await db.collection('onboarding_submissions').doc(targetId).get();
                    if (subDoc.exists && (subDoc.data().linkedUid === uid || subDoc.data().uid === uid || subDoc.data().employeeId === uid)) {
                        authorized = true;
                    } else {
                        const draftDoc = await db.collection('draft_submissions').doc(targetId).get();
                        if (draftDoc.exists) {
                            const d = draftDoc.data();
                            if (d.ownerUid === uid || d.activeSessionUid === uid || d.uid === uid || d.linkedUid === uid || (request.auth.token && request.auth.token.email && d.ownerEmail === request.auth.token.email)) {
                                authorized = true;
                            }
                        }
                    }
                }
            } else if (root === 'users') {
                if (targetId === uid) authorized = true;
            }

            authCache.set(cacheKey, authorized);
            return authorized;
        };

        const bucket = admin.storage().bucket();
        const urls = {};
        const expiresAt = Date.now() + 30 * 60 * 1000; // 30 minutes

        await Promise.all(pathsToProcess.map(async (p) => {
            if (!p || typeof p !== 'string') return;
            const cleanPath = p.trim().replace(/^\/+/, '');
            // Prevent path traversal
            if (cleanPath.includes('..')) return;

            const isAuth = await checkPathAuthorization(cleanPath);
            if (!isAuth) return;

            try {
                const file = bucket.file(cleanPath);
                const [exists] = await file.exists();
                if (!exists) return;

                const [signedUrl] = await file.getSignedUrl({
                    action: 'read',
                    expires: expiresAt
                });
                urls[p] = signedUrl;
            } catch (fileErr) {
                console.warn(`[getBatchSignedViewUrls] Could not sign path ${cleanPath}:`, fileErr.message);
            }
        }));

        return { success: true, urls };
    } catch (error) {
        console.error('[getBatchSignedViewUrls] Error:', error);
        if (error instanceof functions.https.HttpsError) throw error;
        throw new functions.https.HttpsError('internal', 'Failed to generate batch signed URLs.');
    }
});

/**
 * Moves a folder and its contents in Firebase Storage.
 * Used during onboarding approval to move files from temporary to permanent location.
 */
exports.moveStorageFolder = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'The function must be called while authenticated.');
    }
    if (request.auth.token && request.auth.token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const { sourcePath, destinationPath } = request.data;
    if (!sourcePath || !destinationPath) {
        throw new functions.https.HttpsError('invalid-argument', 'sourcePath and destinationPath are required.');
    }

    try {
        const db = admin.firestore();
        const uid = request.auth.uid;

        // 1. Check if caller is Admin or Staff
        let isAdminOrStaff = false;
        const [userSnap, staffSnap, staffAccSnap] = await Promise.all([
            db.collection('users').doc(uid).get(),
            db.collection('staff').doc(uid).get(),
            db.collection('staff_accounts').doc(uid).get()
        ]);
        
        if (userSnap.exists || staffSnap.exists || staffAccSnap.exists) {
            const staffDoc = (staffAccSnap.exists ? staffAccSnap.data() : (staffSnap.exists ? staffSnap.data() : userSnap.data())) || {};
            if (staffDoc.isDisabled === true || staffDoc.isActive === false || staffDoc.status === 'relieved' || staffDoc.status === 'terminated') {
                throw new functions.https.HttpsError('permission-denied', 'This staff account is disabled. Access denied.');
            }
            isAdminOrStaff = true;
        }

        // Check custom claims if not already confirmed staff
        if (!isAdminOrStaff && request.auth.token && (request.auth.token.isAdmin || request.auth.token.isSuperAdmin)) {
            isAdminOrStaff = true;
        }

        // If caller is NOT Admin or Staff, enforce strict ownership of BOTH source and destination (SEC-01 IDOR fix)
        if (!isAdminOrStaff) {
            if (sourcePath.includes('..') || destinationPath.includes('..')) {
                throw new functions.https.HttpsError('invalid-argument', 'Path traversal is not permitted.');
            }

            const cleanSource = sourcePath.replace(/^\/+/, '');
            const cleanDest = destinationPath.replace(/^\/+/, '');

            // Collect all identifiers that legitimately belong to this caller
            const allowedIds = new Set([uid]);
            const [byUidSnap, byLinkedSnap, directDoc] = await Promise.all([
                db.collection('employees').where('uid', '==', uid).limit(1).get(),
                db.collection('employees').where('linkedUid', '==', uid).limit(1).get(),
                db.collection('employees').doc(uid).get()
            ]);

            if (!byUidSnap.empty) {
                const ed = byUidSnap.docs[0].data();
                if (ed.employeeId) allowedIds.add(ed.employeeId);
                allowedIds.add(byUidSnap.docs[0].id);
            }
            if (!byLinkedSnap.empty) {
                const ed = byLinkedSnap.docs[0].data();
                if (ed.employeeId) allowedIds.add(ed.employeeId);
                allowedIds.add(byLinkedSnap.docs[0].id);
            }
            if (directDoc.exists) {
                const ed = directDoc.data();
                if (ed.employeeId) allowedIds.add(ed.employeeId);
            }

            const sourceParts = cleanSource.split('/');
            const sourceId = sourceParts[1];
            const destParts = cleanDest.split('/');
            const destId = destParts[1];

            const ownsSource = (sourceId && allowedIds.has(sourceId)) || cleanSource.includes(uid);
            const ownsDest = (destId && allowedIds.has(destId)) || cleanDest.includes(uid);

            if (!ownsSource || !ownsDest) {
                console.warn(`[SECURITY] IDOR file move blocked: User ${uid} attempted moving "${sourcePath}" to "${destinationPath}"`);
                throw new functions.https.HttpsError('permission-denied', 'Access denied. You can only move files within your own employee profile.');
            }
        }

        const bucket = admin.storage().bucket();
        const [files] = await bucket.getFiles({ prefix: sourcePath });
        
        // Handle exact single file move if getFiles prefix didn't match nested keys
        if (files.length === 0) {
            const singleFile = bucket.file(sourcePath);
            const [exists] = await singleFile.exists();
            if (exists) {
                await singleFile.move(destinationPath);
                return { success: true };
            }
        }

        const movePromises = files.map(file => {
            if (file.name === sourcePath) {
                // Exact single-file move
                return file.move(destinationPath);
            }
            const relativeName = file.name.slice(sourcePath.length);
            if (relativeName) {
                const newFilePath = destinationPath.endsWith('/')
                    ? destinationPath + (relativeName.startsWith('/') ? relativeName.slice(1) : relativeName)
                    : (relativeName.startsWith('/') ? destinationPath + relativeName : destinationPath + '/' + relativeName);
                return file.move(newFilePath);
            }
            return Promise.resolve();
        });

        await Promise.all(movePromises);
        return { success: true };
    } catch (error) {
        console.error('Error moving storage folder:', error);
        throw new functions.https.HttpsError('internal', 'Failed to move storage folder.');
    }
});

/**
 * deleteStoragePath
 * Securely deletes a file or folder in Firebase Storage on the backend.
 * Bypasses client-side storage.rules deny-all while verifying caller permissions.
 */
exports.deleteStoragePath = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be logged in.');
    }
    if (request.auth.token && request.auth.token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const { storagePath, isFolder } = request.data || {};
    if (!storagePath || typeof storagePath !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'Valid storagePath is required.');
    }

    const cleanPath = storagePath.replace(/^\/+/, '').trim();
    if (!cleanPath) {
        throw new functions.https.HttpsError('invalid-argument', 'storagePath cannot be root.');
    }

    if (cleanPath.includes('..')) {
        throw new functions.https.HttpsError('invalid-argument', 'Path traversal is not permitted.');
    }

    // SEC-02: Protect against company-wide storage wipeout
    const pathSegments = cleanPath.split('/').filter(Boolean);
    const forbiddenRoots = [
        'employees', 'onboarding', 'draft_submissions', 'users', 'staff',
        'staff_accounts', 'site_assets', 'blog_assets', 'public', 'temp', 
        'corrections', 'portal_assets', 'documents', 'submissions', 'bgv', 'leaves'
    ];

    const normalizedRoot = pathSegments[0]?.toLowerCase();
    if (pathSegments.length < 2 || forbiddenRoots.includes(cleanPath.toLowerCase()) || forbiddenRoots.includes(cleanPath.replace(/\/+$/, '').toLowerCase())) {
        console.warn(`[SECURITY] Blocked attempt to delete root or top-level directory: "${cleanPath}" by uid=${request.auth.uid}`);
        throw new functions.https.HttpsError('permission-denied', `Deletion of root directory "${cleanPath}" is strictly forbidden.`);
    }

    const uid = request.auth.uid;
    const db = admin.firestore();

    // 1. Check if caller is Admin or Staff
    let isAuthorized = false;
    if (request.auth.token && (request.auth.token.isAdmin || request.auth.token.isSuperAdmin)) {
        isAuthorized = true;
    } else {
        const [userSnap, staffSnap, staffAccSnap] = await Promise.all([
            db.collection('users').doc(uid).get(),
            db.collection('staff').doc(uid).get(),
            db.collection('staff_accounts').doc(uid).get()
        ]);
        if (userSnap.exists || staffSnap.exists || staffAccSnap.exists) {
            const staffDoc = (staffAccSnap.exists ? staffAccSnap.data() : (staffSnap.exists ? staffSnap.data() : userSnap.data())) || {};
            if (staffDoc.isDisabled !== true && staffDoc.isActive !== false && staffDoc.status !== 'relieved' && staffDoc.status !== 'terminated') {
                const isSuperAdmin = staffDoc.roleId === 'role-super-admin' || staffDoc.type === 'Admin';
                // If deleting an entire employee directory (e.g. employees/{empId}), require SuperAdmin
                if (isFolder && pathSegments[0] === 'employees' && pathSegments.length === 2 && !isSuperAdmin) {
                    throw new functions.https.HttpsError('permission-denied', 'Only SuperAdmin can delete an entire employee directory.');
                }
                isAuthorized = true;
            }
        }
    }

    // 2. Candidate / Employee self-deletion checks
    if (!isAuthorized) {
        // Allow deleting their own files:
        if (
            cleanPath.startsWith(`onboarding/${uid}/`) ||
            cleanPath.startsWith(`draft_submissions/${uid}/`) ||
            cleanPath.startsWith(`users/${uid}/`) ||
            cleanPath.startsWith(`employees/${uid}/`) ||
            cleanPath === `onboarding/${uid}` ||
            cleanPath === `draft_submissions/${uid}` ||
            cleanPath === `users/${uid}` ||
            cleanPath === `employees/${uid}`
        ) {
            isAuthorized = true;
        } else if (cleanPath.startsWith('onboarding/')) {
            const folderId = cleanPath.split('/')[1];
            if (folderId) {
                // Check draft_submissions or onboarding_submissions
                const [draftDoc, subDoc] = await Promise.all([
                    db.collection('draft_submissions').doc(folderId).get(),
                    db.collection('onboarding_submissions').doc(folderId).get()
                ]);
                if (draftDoc.exists) {
                    const dd = draftDoc.data();
                    if (dd.ownerUid === uid || dd.activeSessionUid === uid || dd.uid === uid || dd.linkedUid === uid) {
                        isAuthorized = true;
                    }
                }
                if (!isAuthorized && subDoc.exists) {
                    const sd = subDoc.data();
                    if (sd.linkedUid === uid || sd.uid === uid || sd.employeeId === uid) {
                        isAuthorized = true;
                    }
                }
            }
        } else if (cleanPath.startsWith('employees/')) {
            const empId = cleanPath.split('/')[1];
            if (empId) {
                let empDoc = await db.collection('employees').doc(empId).get();
                if (!empDoc.exists) {
                    const byEmpId = await db.collection('employees').where('employeeId', '==', empId).limit(1).get();
                    if (!byEmpId.empty) empDoc = byEmpId.docs[0];
                    else {
                        const byPortalId = await db.collection('employees').where('portalId', '==', empId).limit(1).get();
                        if (!byPortalId.empty) empDoc = byPortalId.docs[0];
                    }
                }
                if (empDoc && empDoc.exists) {
                    const ed = empDoc.data();
                    if (ed.linkedUid === uid || ed.uid === uid || ed.portalId === uid || ed.employeeId === uid || empDoc.id === uid) {
                        isAuthorized = true;
                    } else if (ed.activeCorrectionToken) {
                        const crDoc = await db.collection('correction_requests').doc(ed.activeCorrectionToken).get();
                        if (crDoc.exists && crDoc.data().status === 'pending') {
                            isAuthorized = true;
                        }
                    }
                }
            }
        }
    }

    if (!isAuthorized) {
        console.warn(`[SECURITY] Unauthorized delete attempt by ${uid} on path: ${cleanPath}`);
        throw new functions.https.HttpsError('permission-denied', 'Permission denied to delete storage path.');
    }

    try {
        const bucket = admin.storage().bucket();
        if (isFolder || cleanPath.endsWith('/')) {
            const prefix = cleanPath.endsWith('/') ? cleanPath : cleanPath + '/';
            await bucket.deleteFiles({ prefix, force: true });
        } else {
            // Delete exact file
            const file = bucket.file(cleanPath);
            const [exists] = await file.exists();
            if (exists) {
                await file.delete();
            } else {
                // If not found as exact file, try deleting files with prefix just in case it's a folder without trailing slash
                await bucket.deleteFiles({ prefix: cleanPath + '/', force: true });
            }
        }
        return { success: true };
    } catch (err) {
        console.error(`[deleteStoragePath] Error deleting ${cleanPath}:`, err);
        throw new functions.https.HttpsError('internal', 'Failed to delete storage path.');
    }
});

/**
 * getStorageFolderSizeServer
 * Computes folder storage consumption on backend using Admin SDK.
 */
exports.getStorageFolderSizeServer = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'User must be logged in.');
    }
    if (request.auth.token && request.auth.token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const { folderPath } = request.data || {};
    if (!folderPath || typeof folderPath !== 'string') {
        return { totalBytes: 0 };
    }

    const cleanPath = folderPath.replace(/^\/+/, '').trim();
    const uid = request.auth.uid;
    const db = admin.firestore();

    // Check authorization: caller can view their own folder or must be staff/admin
    let isAuthorized = cleanPath.startsWith(`onboarding/${uid}`) || cleanPath.startsWith(`draft_submissions/${uid}`) || cleanPath.startsWith(`employees/${uid}`);
    if (!isAuthorized) {
        if (request.auth.token && (request.auth.token.isAdmin || request.auth.token.isSuperAdmin)) {
            isAuthorized = true;
        } else {
            const staffSnap = await db.collection('staff_accounts').doc(uid).get();
            if (staffSnap.exists && staffSnap.data().isDisabled !== true && staffSnap.data().isActive !== false) isAuthorized = true;
        }
    }
    if (!isAuthorized && cleanPath.startsWith('onboarding/')) {
        const draftId = cleanPath.split('/')[1];
        if (draftId) {
            const [draftSnap, subSnap] = await Promise.all([
                db.collection('draft_submissions').doc(draftId).get(),
                db.collection('onboarding_submissions').doc(draftId).get()
            ]);
            if (draftSnap.exists) {
                const dd = draftSnap.data();
                if (!dd.ownerUid || dd.ownerUid === uid || dd.linkedUid === uid || dd.activeSessionUid === uid || !dd.isGoogleDraft) isAuthorized = true;
            }
            if (!isAuthorized && subSnap.exists) {
                const sd = subSnap.data();
                if (sd.uid === uid || sd.linkedUid === uid || sd.ownerUid === uid || sd.activeCorrectionToken) isAuthorized = true;
            }
        }
    } else if (!isAuthorized && cleanPath.startsWith('employees/')) {
        const empId = cleanPath.split('/')[1];
        if (empId) {
            let empDoc = await db.collection('employees').doc(empId).get();
            if (!empDoc.exists) {
                const byEmpId = await db.collection('employees').where('employeeId', '==', empId).limit(1).get();
                if (!byEmpId.empty) empDoc = byEmpId.docs[0];
                else {
                    const byPortalId = await db.collection('employees').where('portalId', '==', empId).limit(1).get();
                    if (!byPortalId.empty) empDoc = byPortalId.docs[0];
                }
            }
            if (empDoc && empDoc.exists) {
                const ed = empDoc.data();
                if (ed.linkedUid === uid || ed.uid === uid || ed.portalId === uid || ed.employeeId === uid || empDoc.id === uid) {
                    isAuthorized = true;
                }
            }
        }
    }

    if (!isAuthorized) {
        return { totalBytes: 0 };
    }

    try {
        const bucket = admin.storage().bucket();
        const prefix = cleanPath.endsWith('/') ? cleanPath : cleanPath + '/';
        const [files] = await bucket.getFiles({ prefix });
        let totalBytes = 0;
        for (const file of files) {
            const size = parseInt(file.metadata?.size || '0', 10);
            if (!isNaN(size)) totalBytes += size;
        }
        return { totalBytes };
    } catch (err) {
        console.warn(`[getStorageFolderSizeServer] Failed for ${cleanPath}:`, err);
        return { totalBytes: 0 };
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// RECYCLE BIN AUTOMATED CLEANUP
// ─────────────────────────────────────────────────────────────────────────────
const { onSchedule } = require("firebase-functions/v2/scheduler");

// Runs every night at midnight to permanently delete soft-deleted records older than 30 days
exports.autoDeleteRecycleBin = onSchedule({
    schedule: "0 0 * * *",
    timeZone: "Asia/Kolkata",
    timeoutSeconds: 300 // 5 minutes just in case there are a lot of records
}, async (event) => {
    console.log('[CRON] Starting 30-day Recycle Bin cleanup job...');
    const db = admin.firestore();
    const bucket = admin.storage().bucket();
    const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
    const now = Date.now();
    let deletedCount = 0;

    let maxAllowedDeletes = 10000; // Large default cap

    // Check remaining daily write quota using Google Monitoring API
    try {
        const { GoogleAuth } = require('google-auth-library');
        const auth = new GoogleAuth({
            scopes: ['https://www.googleapis.com/auth/monitoring.read']
        });
        const client = await auth.getClient();
        const projectId = await auth.getProjectId() || 'hr-portal-unique-delta';
        const tokenResponse = await client.getAccessToken();
        const accessToken = tokenResponse.token || '';

        if (accessToken) {
            const nowTime = new Date();
            const startOfToday = new Date(Date.UTC(nowTime.getUTCFullYear(), nowTime.getUTCMonth(), nowTime.getUTCDate(), 0, 0, 0));
            const startTime = startOfToday.toISOString();
            const endTime = nowTime.toISOString();
            
            const metricType = 'firestore.googleapis.com/document/write_count';
            const url = `https://monitoring.googleapis.com/v3/projects/${projectId}/timeSeries?filter=metric.type="${metricType}"&interval.startTime=${startTime}&interval.endTime=${endTime}`;
            
            const res = await fetch(url, { headers: { 'Authorization': `Bearer ${accessToken}` } });
            if (res.ok) {
                const data = await res.json();
                let todayWrites = 0;
                if (data.timeSeries) {
                    for (const ts of data.timeSeries) {
                        if (ts.points) {
                            for (const p of ts.points) {
                                if (p.value && p.value.int64Value !== undefined) {
                                    todayWrites += parseInt(p.value.int64Value, 10);
                                } else if (p.value && p.value.doubleValue !== undefined) {
                                    todayWrites += p.value.doubleValue;
                                }
                            }
                        }
                    }
                }
                
                // Firestore free tier has 20,000 writes/day. We leave a safety buffer of 2,000 writes.
                const remainingWrites = 20000 - todayWrites - 2000;
                
                if (remainingWrites > 0) {
                    maxAllowedDeletes = remainingWrites;
                    console.log(`[CRON] Today's writes so far: ${todayWrites}. Remaining free-tier write quota: ${remainingWrites}.`);
                } else {
                    maxAllowedDeletes = 0;
                    console.warn(`[CRON] Daily free-tier write limit nearly reached. Aborting cleanup to save quota.`);
                }
            }
        }
    } catch (metricErr) {
        console.warn(`[CRON] Failed to query GCP metrics, using fallback limit:`, metricErr.message);
        maxAllowedDeletes = 500; // Safe fallback limit
    }

    const performHardDelete = async (docSnap, collectionName, isAbandoned = false) => {
        try {
            const data = docSnap.data();
            if (!isAbandoned) {
                const deletedAtStr = data.deletedAt;
                if (!deletedAtStr) return; // Not soft deleted
                
                const deletedAtTime = new Date(deletedAtStr).getTime();
                if (now - deletedAtTime <= THIRTY_DAYS_MS) {
                    return;
                }
            }

            const uniqueId = docSnap.id;
            console.log(`[CRON] Hard deleting ${collectionName} ${uniqueId}${isAbandoned ? ' (Abandoned >30d)' : ` (deletedAt: ${data.deletedAt})`}`);

            // 1. Delete associated Firebase Storage folder
            if (collectionName === 'employees') {
                await bucket.deleteFiles({ prefix: `employees/${docSnap.id}/` });
                console.log(`[CRON] Wiped Firebase Storage folder for employees/${docSnap.id}`);
            } else if (collectionName === 'onboarding_submissions') {
                await bucket.deleteFiles({ prefix: `onboarding/${docSnap.id}/` });
                if (data.linkedUid) {
                    await bucket.deleteFiles({ prefix: `onboarding/${data.linkedUid}/` });
                }
                if (data.uid) {
                    await bucket.deleteFiles({ prefix: `onboarding/${data.uid}/` });
                }
                console.log(`[CRON] Wiped Firebase Storage folder for ${docSnap.id} and associated applicant folders`);
            }

            // 2. Cascade delete requests
            const deleteAssociated = async (id) => {
                const reqCollections = ['leave_requests', 'account_updates', 'resignations', 'disciplinary_actions', '_auth_attempts'];
                for (const reqCol of reqCollections) {
                    const q = db.collection(reqCol).where('employeeId', '==', id);
                    const snaps = await q.get();
                    const promises = snaps.docs.map(d => d.ref.delete());
                    await Promise.all(promises);
                }
            };
            
            await deleteAssociated(uniqueId);
            if (collectionName === 'onboarding_submissions' && docSnap.id.startsWith('SUB-')) {
                await deleteAssociated(docSnap.id);
            }

            // 3. Delete the main document
            await docSnap.ref.delete();
            deletedCount++;
        } catch (err) {
            console.error(`[CRON] Error hard deleting ${docSnap.id}:`, err);
        }
    };

    try {
        const thirtyDaysAgoIso = new Date(now - THIRTY_DAYS_MS).toISOString();

        // Query deleted employees directly by deletedAt age index
        const empSnap = await db.collection('employees').where('deletedAt', '<=', thirtyDaysAgoIso).get();
        for (const doc of empSnap.docs) {
            if (deletedCount >= maxAllowedDeletes) {
                console.log(`[CRON] Capped cleanup at ${deletedCount} deletes to protect free tier quota.`);
                break;
            }
            await performHardDelete(doc, 'employees');
        }

        // Query deleted submissions directly by deletedAt age index
        if (deletedCount < maxAllowedDeletes) {
            const subSnap = await db.collection('onboarding_submissions').where('deletedAt', '<=', thirtyDaysAgoIso).get();
            for (const doc of subSnap.docs) {
                if (deletedCount >= maxAllowedDeletes) {
                    console.log(`[CRON] Capped cleanup at ${deletedCount} deletes to protect free tier quota.`);
                    break;
                }
                await performHardDelete(doc, 'onboarding_submissions');
            }
        }

        // Check portal config setting: autoDeleteAbandonedSubmissions
        const configDoc = await db.collection('settings').doc('portal_config').get();
        const portalCfg = configDoc.exists ? configDoc.data() : {};
        const isAbandonedCleanupEnabled = portalCfg.autoDeleteAbandonedSubmissions === true;

        // Query abandoned pending onboarding submissions (>30 days inactive) if enabled in settings
        if (isAbandonedCleanupEnabled && deletedCount < maxAllowedDeletes) {
            const abandonedSnap1 = await db.collection('onboarding_submissions')
                .where('status', '==', 'Pending Review')
                .where('timestamp', '<=', thirtyDaysAgoIso)
                .get();
            for (const doc of abandonedSnap1.docs) {
                if (deletedCount >= maxAllowedDeletes) break;
                console.log(`[CRON] Cleaning up abandoned onboarding submission (Pending Review) ${doc.id}`);
                await performHardDelete(doc, 'onboarding_submissions', true);
            }

            if (deletedCount < maxAllowedDeletes) {
                const abandonedSnap2 = await db.collection('onboarding_submissions')
                    .where('status', '==', 'Pending')
                    .where('submittedAt', '<=', thirtyDaysAgoIso)
                    .get();
                for (const doc of abandonedSnap2.docs) {
                    if (deletedCount >= maxAllowedDeletes) break;
                    console.log(`[CRON] Cleaning up abandoned onboarding submission (Pending) ${doc.id}`);
                    await performHardDelete(doc, 'onboarding_submissions', true);
                }
            }
        } else if (!isAbandonedCleanupEnabled) {
            console.log('[CRON] Abandoned submissions cleanup is disabled in Portal Settings.');
        }

        console.log(`[CRON] Finished cleanup. Hard deleted ${deletedCount} records.`);
    } catch (globalErr) {
        console.error('[CRON] Global error during cleanup:', globalErr);
    }
    return null;
});

// Runs every night at 00:30 IST to automatically relieve employees whose notice period has concluded (IMP-9)
exports.processNoticePeriodExitsCron = onSchedule({
    schedule: "30 0 * * *",
    timeZone: "Asia/Kolkata",
    timeoutSeconds: 300
}, async (event) => {
    console.log('[CRON: processNoticePeriodExitsCron] Starting notice period exit check...');
    const db = admin.firestore();
    const todayStr = new Date().toISOString().split('T')[0];

    try {
        const snap = await db.collection('employees')
            .where('resignationStatus', '==', 'Notice Period')
            .get();

        if (snap.empty) {
            console.log('[CRON: processNoticePeriodExitsCron] No employees on Notice Period.');
            return null;
        }

        let processedCount = 0;
        for (const doc of snap.docs) {
            const data = doc.data();
            const relievingDate = data.pendingRelievingDate || data.relievingDate;
            if (!relievingDate) continue;

            const relDateStr = relievingDate.split('T')[0];
            if (relDateStr <= todayStr) {
                console.log(`[CRON: processNoticePeriodExitsCron] Notice period completed for ${data.applicantName || doc.id} (Relieving Date: ${relDateStr}). Relieving...`);

                const batch = db.batch();
                batch.update(doc.ref, {
                    isActive: false,
                    status: 'Relieved',
                    isRelieved: true,
                    resignationStatus: 'Relieved',
                    relievingDate: relDateStr,
                    relievingReason: data.relievingReason || 'Notice Period Completed',
                    relievingRemarks: 'Automated midnight exit upon notice period completion',
                    relievedAt: admin.firestore.FieldValue.serverTimestamp()
                });

                // Sync to onboarding_submissions
                const subSnap = await resolveSubmissionDocAdmin(db, data.employeeId, doc.id);
                if (subSnap && subSnap.exists) {
                    batch.update(subSnap.ref, {
                        isActive: false,
                        status: 'Relieved',
                        isRelieved: true,
                        relievingDate: relDateStr,
                        relievingReason: data.relievingReason || 'Notice Period Completed',
                        relievingRemarks: 'Automated midnight exit upon notice period completion'
                    });
                }

                // Disable Firebase Auth account
                const linkedUid = data.linkedUid || data.uid;
                if (linkedUid && linkedUid !== 'none' && linkedUid.length > 5) {
                    try {
                        await admin.auth().updateUser(linkedUid, { disabled: true });
                    } catch (authErr) {
                        console.warn(`[CRON: processNoticePeriodExitsCron] Could not disable auth for ${linkedUid}:`, authErr.message);
                    }
                }

                // Append audit log
                const auditRef = db.collection('audit_logs').doc();
                batch.set(auditRef, {
                    action: 'RESIGNATION_NOTICE_EXIT',
                    module: 'RESIGNATIONS',
                    targetId: doc.id,
                    actorId: 'system_cron',
                    actorName: 'System (processNoticePeriodExitsCron)',
                    details: `Notice period completed on ${relDateStr}. Auto-relieved employee ${data.applicantName || data.employeeId} (${doc.id}).`,
                    timestamp: admin.firestore.FieldValue.serverTimestamp()
                });

                await batch.commit();
                processedCount++;
            }
        }

        console.log(`[CRON: processNoticePeriodExitsCron] Successfully auto-relieved ${processedCount} employees.`);
    } catch (err) {
        console.error('[CRON: processNoticePeriodExitsCron] Error processing notice period exits:', err);
    }
    return null;
});

// ─────────────────────────────────────────────────────────────────────────────
// LEGACY PROFILE CLAIM (AUTOMATED)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * claimEmployeeProfile
 * Authenticated callable that verifies a legacy employee's identity
 * and links their current Google account (UID) to the legacy record.
 * 
 * Input: { employeeId: string, verificationData: object }
 * Returns: { success: true, submissionId?: string, employeeName: string, legacyData: object }
 */
exports.claimEmployeeProfile = secureOnCall(async (request) => {
    const { employeeId, verificationData } = request.data || {};
    const db = admin.firestore();

    const currentUid = request.auth ? request.auth.uid : null;
    const currentEmail = (request.auth && request.auth.token) ? (request.auth.token.email || '') : '';

    if (!employeeId || !verificationData) {
        throw new functions.https.HttpsError('invalid-argument', 'Employee ID and verification data are required.');
    }

    const trimmedId = String(employeeId).trim();

    try {
        // Rate limit: Max 3 attempts per 24 hours per employee ID
        const isLocked = await checkClaimDailyAttempts(db, trimmedId.toUpperCase());
        if (isLocked) {
            throw new functions.https.HttpsError('resource-exhausted', 'Maximum claim attempts (3) exceeded for this ID today. Please try again tomorrow or contact HR.');
        }

        // 2. SECURITY CHECK: Is this Google account already linked to ANY employee or submission?
        // This prevents one Google account from claiming multiple profiles.
        if (currentUid) {
            const [empSnap, subSnap] = await Promise.all([
                db.collection('employees').where('linkedUid', '==', currentUid).limit(1).get(),
                db.collection('onboarding_submissions').where('linkedUid', '==', currentUid).limit(1).get()
            ]);

            if (!empSnap.empty || !subSnap.empty) {
                // GENERIC MESSAGE: Prevent ID leaking as requested by user
                throw new functions.https.HttpsError('already-exists', 'This Google account is already associated with an employee profile. Please login to the Main Portal instead.');
            }
        }

        // 3. Load the admin's legacy claim configuration
        const configSnap = await db.collection('settings').doc('legacy_claim_config').get();
        if (!configSnap.exists || !configSnap.data().enabled) {
            throw new functions.https.HttpsError('failed-precondition', 'Profile claim feature is currently disabled. Please contact HR.');
        }
        const config = configSnap.data();
        let metrics = config.verificationMetrics;
        if (!Array.isArray(metrics) || metrics.length === 0) {
            metrics = ['aadhaar', 'dob', 'phone']; // Fallback safe metrics
        }

        const normalize = (s) => String(s || '').replace(/[\s\-\/\.]/g, '').toLowerCase();
        const parseDateToYMD = (dateStr) => {
            if (!dateStr) return null;
            const clean = String(dateStr).trim();
            if (/^\d{4}-\d{2}-\d{2}$/.test(clean)) return clean;
            const dmyMatch = clean.match(/^(\d{1,2})[-/\.](\d{1,2})[-/\.](\d{4})$/);
            if (dmyMatch) {
                const [_, d, m, y] = dmyMatch;
                return `${y}-${m.padStart(2, '0')}-${d.padStart(2, '0')}`;
            }
            const ymdMatch = clean.match(/^(\d{4})[-/\.](\d{1,2})[-/\.](\d{1,2})$/);
            if (ymdMatch) {
                const [_, y, m, d] = ymdMatch;
                return `${y}-${m.padStart(2, '0')}-${d.padStart(2, '0')}`;
            }
            return null;
        };

        // 4. Find the legacy import record (case-insensitive lookup: try uppercase first, then fallback to raw trimmed)
        const normalizedEmpId = trimmedId.toUpperCase();
        let legacySnap = await db.collection('legacy_employee_imports')
            .where('employeeId', '==', normalizedEmpId)
            .where('claimed', '==', false)
            .limit(1)
            .get();

        if (legacySnap.empty && normalizedEmpId !== trimmedId) {
            legacySnap = await db.collection('legacy_employee_imports')
                .where('employeeId', '==', trimmedId)
                .where('claimed', '==', false)
                .limit(1)
                .get();
        }

        if (legacySnap.empty) {
            throw new functions.https.HttpsError('not-found', 'No unclaimed profile found with this Employee ID. It may have already been claimed, or the ID is incorrect.');
        }

        const legacyDoc = legacySnap.docs[0];
        const legacyData = legacyDoc.data();

        // 5. Verify ALL enabled metrics
        for (const metric of metrics) {
            let storedValue = '';
            if (metric === 'phone') storedValue = legacyData.phoneNumber;
            else if (metric === 'aadhaar') storedValue = legacyData.aadhaarNumber;
            else if (metric === 'pan') storedValue = legacyData.panNumber;
            else if (metric === 'bankAccount') storedValue = legacyData.bankAccountNumber;
            else if (metric === 'fatherName') storedValue = legacyData.fatherName;
            else if (metric === 'dob') storedValue = legacyData.dateOfBirth;

            const providedValue = verificationData[metric];

            if (!storedValue) {
                console.warn(`[LEGACY] Missing metric ${metric} in stored record for ${trimmedId}. Failing closed for security (Finding 42).`);
                throw new functions.https.HttpsError(
                    'failed-precondition',
                    `Your legacy profile record is missing ${metric} verification data. For your security, please contact HR to claim your account.`
                );
            }

            if (metric === 'dob') {
                const sYMD = parseDateToYMD(storedValue);
                const pYMD = parseDateToYMD(providedValue);
                if (!sYMD || !pYMD || sYMD !== pYMD) {
                    throw new functions.https.HttpsError('permission-denied', `Verification failed. The ${metric} you entered does not match our records.`);
                }
            } else if (!providedValue || normalize(storedValue) !== normalize(providedValue)) {
                throw new functions.https.HttpsError('permission-denied', `Verification failed. The ${metric} you entered does not match our records.`);
            }
        }

        // Clear daily failed attempts counter upon successful verification
        await clearClaimDailyAttempts(db, trimmedId.toUpperCase());

        // 6. Link verified legacy record to current Google account
        await legacyDoc.ref.update({
            claimed: true,
            claimedAt: new Date().toISOString(),
            claimedByUid: currentUid || '',
            linkedEmail: currentEmail || ''
        });

        // 7. Check if there's an existing onboarding_submissions record for this legacy ID
        const existingSubSnap = await db.collection('onboarding_submissions')
            .where('employeeId', '==', trimmedId)
            .limit(1)
            .get();
        const submissionId = existingSubSnap.empty ? null : existingSubSnap.docs[0].id;

        console.log(`[LEGACY] Profile ${trimmedId} claimed and linked to UID ${currentUid}`);

        const tokenUid = submissionId || trimmedId;
        const customToken = await admin.auth().createCustomToken(tokenUid, { portal: 'employee', portalType: 'employee', authProvider: 'google' });

        return {
            success: true,
            id: legacyDoc.id,
            legacyImportId: legacyDoc.id,
            token: customToken,
            submissionId: submissionId,
            employeeName: legacyData.fullName || '',
            legacyData: {
                ...legacyData,
                // Ensure rawData or flat fields are returned for auto-fill
                fullName: legacyData.fullName,
                phoneNumber: legacyData.phoneNumber,
                aadhaarNumber: legacyData.aadhaarNumber,
                panNumber: legacyData.panNumber,
                dateOfBirth: legacyData.dateOfBirth,
                fatherName: legacyData.fatherName,
                designation: legacyData.designation,
                location: legacyData.location,
            }
        };
    } catch (err) {
        if (err.code) throw err; // Re-throw HttpsErrors
        console.error('[LEGACY] Claim error:', err);
        throw new functions.https.HttpsError('internal', 'Internal error during profile claim.');
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// SYSTEM USAGE & MONITORING API
// ─────────────────────────────────────────────────────────────────────────────

exports.getSystemMetrics = secureOnCall(async (request) => {
    // Only allow authenticated users
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Access denied.');
    }
    if (request.auth.token && request.auth.token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const db = admin.firestore();
    const callerUid = request.auth.uid;
    const token = request.auth.token || {};

    try {
        // Authenticate admin check
        let isAdmin = token.isAdmin === true || token.isSuperAdmin === true || token.roleId === 'role-super-admin';
        if (!isAdmin) {
            const [adminSnap, staffSnap] = await Promise.all([
                db.collection('users').doc(callerUid).get(),
                db.collection('staff_accounts').doc(callerUid).get()
            ]);
            const adminDoc = adminSnap.exists ? adminSnap.data() : null;
            const staffDoc = staffSnap.exists ? staffSnap.data() : null;
            const isSuperFromAdmin = adminDoc && adminDoc.isDisabled !== true && adminDoc.isActive !== false && (adminDoc.roleId === 'role-super-admin' || adminDoc.type === 'Admin');
            const isSuperFromStaff = staffDoc && staffDoc.isDisabled !== true && staffDoc.isActive !== false && staffDoc.roleId === 'role-super-admin';
            isAdmin = !!(isSuperFromAdmin || isSuperFromStaff);
        }
        
        if (!isAdmin) {
            throw new functions.https.HttpsError('permission-denied', 'Access denied. Administrator privileges required.');
        }

        // Obtain GCP Google Auth client for Stackdriver Monitoring
        const { GoogleAuth } = require('google-auth-library');
        const auth = new GoogleAuth({
            scopes: ['https://www.googleapis.com/auth/monitoring.read']
        });

        let client;
        let projectId = 'hr-portal-unique-delta';
        let accessToken = '';

        try {
            client = await auth.getClient();
            projectId = await auth.getProjectId() || projectId;
            const tokenResponse = await client.getAccessToken();
            accessToken = tokenResponse.token || '';
        } catch (authErr) {
            console.warn('[METRICS] Failed to obtain GCP credentials, returning mock/fallback data for development:', authErr.message);
            // Graceful fallback for local emulator development
            return {
                isMock: true,
                reads: 1845,
                writes: 232,
                deletes: 12,
                storageBytes: 154 * 1024 * 1024,
                storageUploads: 45,
                storageDownloads: 112,
                storageEgress: 24 * 1024 * 1024,
                invocations: 850,
                buildMinutes: 12.5,
                containerStorage: 310 * 1024 * 1024
            };
        }

        const now = new Date();
        const startOfToday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), 0, 0, 0));
        const startTime = startOfToday.toISOString();
        const endTime = now.toISOString();

        // Helper function for sum queries
        const getMetricCount = async (metricType) => {
            const url = `https://monitoring.googleapis.com/v3/projects/${projectId}/timeSeries?filter=metric.type="${metricType}"&interval.startTime=${startTime}&interval.endTime=${endTime}`;
            try {
                const res = await fetch(url, { headers: { 'Authorization': `Bearer ${accessToken}` } });
                if (!res.ok) return 0;
                const data = await res.json();
                let sum = 0;
                if (data.timeSeries) {
                    for (const ts of data.timeSeries) {
                        if (ts.points) {
                            for (const p of ts.points) {
                                if (p.value && p.value.int64Value !== undefined) {
                                    sum += parseInt(p.value.int64Value, 10);
                                } else if (p.value && p.value.doubleValue !== undefined) {
                                    sum += p.value.doubleValue;
                                }
                            }
                        }
                    }
                }
                return sum;
            } catch (e) {
                console.error(`Error querying metric ${metricType}:`, e);
                return 0;
            }
        };

        // Helper for latest value gauge queries (e.g. storage size)
        const getLatestMetricValue = async (metricType) => {
            const url = `https://monitoring.googleapis.com/v3/projects/${projectId}/timeSeries?filter=metric.type="${metricType}"&interval.startTime=${startTime}&interval.endTime=${endTime}`;
            try {
                const res = await fetch(url, { headers: { 'Authorization': `Bearer ${accessToken}` } });
                if (!res.ok) return 0;
                const data = await res.json();
                if (data.timeSeries && data.timeSeries[0] && data.timeSeries[0].points && data.timeSeries[0].points[0]) {
                    const val = data.timeSeries[0].points[0].value;
                    if (val.int64Value !== undefined) return parseInt(val.int64Value, 10);
                    if (val.doubleValue !== undefined) return val.doubleValue;
                }
                return 0;
            } catch (e) {
                console.error(`Error querying gauge ${metricType}:`, e);
                return 0;
            }
        };

        const [reads, writes, deletes, storageBytes, executions, egress] = await Promise.all([
            getMetricCount('firestore.googleapis.com/document/read_count'),
            getMetricCount('firestore.googleapis.com/document/write_count'),
            getMetricCount('firestore.googleapis.com/document/delete_count'),
            getLatestMetricValue('storage.googleapis.com/storage/total_bytes'),
            getMetricCount('cloudfunctions.googleapis.com/function/execution_count'),
            getMetricCount('storage.googleapis.com/storage/sent_bytes_count')
        ]);

        return {
            isMock: false,
            reads: reads || 0,
            writes: writes || 0,
            deletes: deletes || 0,
            storageBytes: storageBytes || 0,
            storageUploads: Math.round((writes || 0) * 0.1),
            storageDownloads: Math.round((reads || 0) * 0.15),
            storageEgress: egress || 0,
            invocations: executions || 0,
            buildMinutes: 5.2,
            containerStorage: 180 * 1024 * 1024
        };

    } catch (error) {
        console.error('getSystemMetrics failed:', error);
        throw new functions.https.HttpsError('internal', 'Failed to retrieve system metrics.');
    }
});

// Shared IP rate limiting for public unauthenticated lookup endpoints (max 10 requests per minute per IP)
const lookupRateLimits = new Map();

function checkLookupRateLimit(ip) {
    const now = Date.now();
    const windowMs = 60 * 1000; // 1 minute
    const maxAttempts = 10;

    let record = lookupRateLimits.get(ip);
    if (!record || now - record.startTime > windowMs) {
        record = { count: 1, startTime: now };
        lookupRateLimits.set(ip, record);
        return true;
    }

    if (record.count >= maxAttempts) {
        return false;
    }

    record.count++;
    return true;
}

// Secure check for employee status during Forgot Password flow with IP rate-limiting (Finding 3)
exports.checkForgotPasswordEmployeeStatus = secureOnCall(async (request) => {
    const rawReq = request.rawRequest;
    const clientIp = (rawReq && (rawReq.headers['x-forwarded-for'] || rawReq.ip || rawReq.connection?.remoteAddress)) || 'unknown-client';
    const cleanIp = typeof clientIp === 'string' ? clientIp.split(',')[0].trim() : 'unknown-client';

    if (!checkLookupRateLimit(cleanIp)) {
        console.warn(`[checkForgotPasswordEmployeeStatus] Rate limit exceeded for IP: ${cleanIp}`);
        throw new functions.https.HttpsError('resource-exhausted', 'Too many lookup requests. Please wait a minute before trying again.');
    }

    const { employeeId } = request.data || {};
    if (!employeeId) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing employeeId');
    }

    try {
        const db = admin.firestore();
        const trimmedId = employeeId.trim().toUpperCase();
        let empDoc = await db.collection('employees').doc(trimmedId).get();
        
        if (!empDoc.exists) {
            const querySnap = await db.collection('employees').where('employeeId', '==', trimmedId).limit(1).get();
            if (!querySnap.empty) {
                empDoc = querySnap.docs[0];
            }
        }

        if (!empDoc.exists) {
            return { exists: false };
        }

        const data = empDoc.data();
        // Return only safe flags to client
        return {
            exists: true,
            isActive: data.isActive !== false,
            needsProfileCompletion: data.needsProfileCompletion || false,
            hasSecurityQuestion: !!(data.securityQuestion || data.passwordResetQuestion),
            securityQuestion: data.securityQuestion || data.passwordResetQuestion || "What is your primary identification number (last 4 digits)?"
        };
    } catch (error) {
        console.error('checkForgotPasswordEmployeeStatus failed:', error);
        throw new functions.https.HttpsError('internal', 'Internal error occurred.');
    }
});



exports.resolveUsernameToEmail = secureOnCall(async (request) => {
    const rawReq = request.rawRequest;
    const clientIp = (rawReq && (rawReq.headers['x-forwarded-for'] || rawReq.ip || rawReq.connection?.remoteAddress)) || 'unknown-client';
    const cleanIp = typeof clientIp === 'string' ? clientIp.split(',')[0].trim() : 'unknown-client';

    if (!checkLookupRateLimit(cleanIp)) {
        console.warn(`[resolveUsernameToEmail] Rate limit exceeded for IP: ${cleanIp}`);
        throw new functions.https.HttpsError('resource-exhausted', 'Too many lookup requests. Please wait a minute before trying again.');
    }

    const { username, portalType } = request.data || {};
    if (!username || typeof username !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'Missing or invalid username');
    }

    const db = admin.firestore();
    const cleanUsername = username.trim();
    const lowerUsername = cleanUsername.toLowerCase();

    try {
        let foundEmail = null;

        if (portalType === 'management') {
            // 1. Check staff_accounts (usernameLower and username)
            let staffAccSnap = await db.collection('staff_accounts')
                .where('usernameLower', '==', lowerUsername)
                .limit(1).get();
            if (staffAccSnap.empty) {
                staffAccSnap = await db.collection('staff_accounts')
                    .where('username', 'in', [cleanUsername, lowerUsername])
                    .limit(1).get();
            }
            if (!staffAccSnap.empty) {
                const data = staffAccSnap.docs[0].data();
                if (data.isActive !== false) {
                    foundEmail = data.email;
                }
            }

            // 2. Check staff collection
            if (!foundEmail) {
                let staffSnap = await db.collection('staff')
                    .where('usernameLower', '==', lowerUsername)
                    .limit(1).get();
                if (staffSnap.empty) {
                    staffSnap = await db.collection('staff')
                        .where('username', 'in', [cleanUsername, lowerUsername])
                        .limit(1).get();
                }
                if (!staffSnap.empty) {
                    const data = staffSnap.docs[0].data();
                    if (data.isActive !== false) {
                        foundEmail = data.email;
                    }
                }
            }

            // 3. Check users collection
            if (!foundEmail) {
                let usersSnap = await db.collection('users')
                    .where('usernameLower', '==', lowerUsername)
                    .limit(1).get();
                if (usersSnap.empty) {
                    usersSnap = await db.collection('users')
                        .where('username', 'in', [cleanUsername, lowerUsername])
                        .limit(1).get();
                }
                if (!usersSnap.empty) {
                    const data = usersSnap.docs[0].data();
                    if (data.isActive !== false) {
                        foundEmail = data.email;
                    }
                }
            }

            // 4. Case-insensitive fallback scan for existing legacy staff accounts
            if (!foundEmail) {
                const [allStaffAccs, allStaff, allUsers] = await Promise.all([
                    db.collection('staff_accounts').limit(100).get(),
                    db.collection('staff').limit(100).get(),
                    db.collection('users').limit(100).get()
                ]);
                for (const docSnap of [...allStaffAccs.docs, ...allStaff.docs, ...allUsers.docs]) {
                    const data = docSnap.data();
                    if (data.isActive !== false && data.username && String(data.username).trim().toLowerCase() === lowerUsername) {
                        foundEmail = data.email;
                        break;
                    }
                }
            }
        } else if (portalType === 'employee') {
            let empSnap = await db.collection('employees')
                .where('usernameLower', '==', lowerUsername)
                .limit(1).get();
            if (empSnap.empty) {
                empSnap = await db.collection('employees')
                    .where('username', 'in', [cleanUsername, lowerUsername])
                    .limit(1).get();
            }
            if (!empSnap.empty) {
                const data = empSnap.docs[0].data();
                if (data.isActive !== false && data.isRelieved !== true) {
                    foundEmail = data.email;
                }
            }
        }

        return { email: foundEmail || null };
    } catch (error) {
        if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        console.error('Error in resolveUsernameToEmail:', error);
        throw new functions.https.HttpsError('internal', 'Internal error resolving username.');
    }
});


// Secure server-side referral counter increments with IP rate-limiting (Finding 2)
exports.recordReferralMetricServer = secureOnCall(async (request) => {
    const { refId, metric } = request.data || {};
    if (!refId || typeof refId !== 'string' || !metric || typeof metric !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'Missing refId or metric.');
    }

    const allowedMetrics = ['clicks', 'starts', 'joined'];
    if (!allowedMetrics.includes(metric)) {
        throw new functions.https.HttpsError('invalid-argument', 'Invalid referral metric.');
    }

    const rawReq = request.rawRequest;
    const clientIp = (rawReq && (rawReq.headers['x-forwarded-for'] || rawReq.ip || rawReq.connection?.remoteAddress)) || 'unknown-client';
    const cleanIp = typeof clientIp === 'string' ? clientIp.split(',')[0].trim() : 'unknown-client';

    if (!checkLookupRateLimit(cleanIp)) {
        throw new functions.https.HttpsError('resource-exhausted', 'Rate limit exceeded. Please wait a moment.');
    }

    try {
        const db = admin.firestore();
        const docRef = db.collection('referral_invites').doc(refId.trim());
        const docSnap = await docRef.get();
        if (!docSnap.exists) {
            throw new functions.https.HttpsError('not-found', 'Referral invite not found.');
        }

        let updateData = {};
        if (metric === 'clicks') {
            updateData.clicks = admin.firestore.FieldValue.increment(1);
        } else if (metric === 'starts') {
            updateData.starts = admin.firestore.FieldValue.increment(1);
            updateData.started = admin.firestore.FieldValue.increment(1);
        } else if (metric === 'joined') {
            updateData.joined = admin.firestore.FieldValue.increment(1);
        }

        await docRef.update(updateData);
        return { success: true };
    } catch (error) {
        if (error instanceof functions.https.HttpsError) throw error;
        console.error('[recordReferralMetricServer] Error:', error);
        throw new functions.https.HttpsError('internal', 'Failed to update referral metric.');
    }
});

// Sync staff Google Login UID to Firestore staff_accounts collection (Finding 10)
exports.syncStaffGoogleLogin = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated');
    }
    const uid = request.auth.uid;
    const email = (request.auth.token.email || '').toLowerCase().trim();
    if (!email) {
        throw new functions.https.HttpsError('invalid-argument', 'No email associated with auth token');
    }

    // SECURITY: Ensure email is verified by Google to prevent account takeover (Finding 33)
    if (!request.auth.token.email_verified) {
        throw new functions.https.HttpsError('failed-precondition', 'Google account email must be verified.');
    }

    try {
        const db = admin.firestore();
        const staffRef = db.collection('staff_accounts').doc(uid);
        const directSnap = await staffRef.get();
        if (directSnap.exists) {
            return { success: true, message: 'Already synced' };
        }

        // Look for staff account matching this email
        const staffQuery = await db.collection('staff_accounts').where('email', '==', email).limit(1).get();
        if (!staffQuery.empty) {
            const originalDoc = staffQuery.docs[0];
            const originalData = originalDoc.data();
            
            if (originalData.isDisabled === true || originalData.isActive === false) {
                throw new functions.https.HttpsError('permission-denied', 'Account is disabled');
            }

            await staffRef.set({
                ...originalData,
                id: uid,
                googleUid: uid,
                originalDocId: originalDoc.id,
                syncedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });

            return { success: true, syncedUid: uid };
        }

        // Also check users collection for SuperAdmins
        const userQuery = await db.collection('users').where('email', '==', email).limit(1).get();
        if (!userQuery.empty) {
            const originalUser = userQuery.docs[0];
            const userData = originalUser.data();
            if (userData.isDisabled === true || userData.isActive === false) {
                throw new functions.https.HttpsError('permission-denied', 'Account is disabled');
            }
            await db.collection('users').doc(uid).set({
                ...userData,
                googleUid: uid,
                originalDocId: originalUser.id,
                syncedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return { success: true, syncedUid: uid };
        }

        return { success: false, message: 'No matching staff account found by email' };
    } catch (err) {
        if (err instanceof functions.https.HttpsError) throw err;
        console.error('Error in syncStaffGoogleLogin:', err);
        throw new functions.https.HttpsError('internal', err.message || 'Error syncing staff Google account');
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// STORAGE — SIGNED UPLOAD URL (Replaces complex storage.rules ownership checks)
// Context-aware: checks only what is relevant to the caller's page/context.
// No 2-query limit — this runs in Node.js with full Firestore access.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * getUploadUrl
 * Called by the client BEFORE uploading a file. Validates ownership based on
 * context, then returns a short-lived (15 min) signed upload URL.
 *
 * Request data:
 *   context      — "onboarding" | "employee" | "admin" | "profile"
 *   storagePath  — full path where file will be stored e.g. "onboarding/UDF-202410-0042/aadhaar/1234_file.jpg"
 *   contentType  — MIME type e.g. "image/jpeg" or "application/pdf"
 *   fileSize     — size in bytes (must be <= 10MB)
 */
exports.getUploadUrl = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'You must be logged in to upload files.');
    }

    const { context, storagePath, contentType, fileSize } = request.data;
    const uid = request.auth.uid;

    // ── Input Validation ──────────────────────────────────────────────────────
    if (!context || !storagePath || !contentType) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields: context, storagePath, contentType.');
    }

    // 1. Enforce MIME Whitelist (strictly PDF and images, excluding SVG/HTML)
    let normalizedContentType = (contentType || '').toLowerCase().trim();
    if (normalizedContentType === 'image/jpg') normalizedContentType = 'image/jpeg';
    const ALLOWED_TYPES = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp'];
    if (!ALLOWED_TYPES.includes(normalizedContentType)) {
        throw new functions.https.HttpsError('invalid-argument', 'File type not allowed. Permitted types: PDF, JPEG, PNG, WEBP.');
    }

    // 2. Enforce File Size Ceiling (Max 10MB, Min 1 byte)
    const MAX_SIZE = 10 * 1024 * 1024;
    if (!fileSize || typeof fileSize !== 'number' || fileSize <= 0 || fileSize > MAX_SIZE) {
        throw new functions.https.HttpsError('invalid-argument', 'File size must be specified and must not exceed 10MB.');
    }

    // 3. Prevent Path Traversal and Relative Traversal Attacks
    const path = require('path');
    const normalizedPath = storagePath.replace(/\\/g, '/').trim();
    if (
        normalizedPath.includes('..') ||
        normalizedPath.includes('\0') ||
        normalizedPath.startsWith('/') ||
        path.normalize(normalizedPath).replace(/\\/g, '/') !== normalizedPath
    ) {
        throw new functions.https.HttpsError('invalid-argument', 'Invalid storage path: Path traversal is strictly prohibited.');
    }

    // 4. Enforce Context-Specific Root Folder Namespacing
    const firstSegment = normalizedPath.split('/')[0];
    if (context === 'onboarding' && firstSegment !== 'onboarding') {
        throw new functions.https.HttpsError('invalid-argument', 'Onboarding uploads must reside under onboarding/.');
    }
    if (context === 'employee' && firstSegment !== 'employees') {
        throw new functions.https.HttpsError('invalid-argument', 'Employee uploads must reside under employees/.');
    }
    if (context === 'profile' && firstSegment !== 'profile' && firstSegment !== 'employees') {
        throw new functions.https.HttpsError('invalid-argument', 'Profile uploads must reside under profile/ or employees/.');
    }

    const db = admin.firestore();
    let isAuthorized = false;

    try {
        // ── CONTEXT: onboarding ───────────────────────────────────────────────
        // Applicant uploading their own joining form documents
        if (context === 'onboarding') {
            const pathParts = storagePath.split('/');
            const folderName = pathParts[1]; // e.g. "UDF-202410-0042" or a UID

            if (!folderName) throw new functions.https.HttpsError('invalid-argument', 'Invalid onboarding path.');

            // Check 1: Folder name directly matches caller's UID
            if (folderName === uid) {
                isAuthorized = true;
            } else {
                // Check 2: Draft ownership — draft_submissions/{folderName}
                const draftDoc = await db.collection('draft_submissions').doc(folderName).get();
                if (draftDoc.exists) {
                    const d = draftDoc.data();
                    if (
                        d.ownerUid === uid ||
                        d.activeSessionUid === uid ||
                        d.uid === uid ||
                        d.linkedUid === uid ||
                        (request.auth.token.email && d.ownerEmail === request.auth.token.email)
                    ) {
                        isAuthorized = true;
                    }
                }

                // Check 3: Submitted onboarding ownership — onboarding_submissions/{folderName}
                if (!isAuthorized) {
                    const subDoc = await db.collection('onboarding_submissions').doc(folderName).get();
                    if (subDoc.exists) {
                        const s = subDoc.data();
                        if (
                            s.ownerUid === uid ||
                            s.linkedUid === uid ||
                            s.uid === uid ||
                            (request.auth.token.email && s.linkedGoogleEmail === request.auth.token.email)
                        ) {
                            isAuthorized = true;
                        }
                    }
                }

                // Check 4: Data Correction Token
                if (!isAuthorized) {
                    const crDoc = await db.collection('correction_requests').doc(folderName).get();
                    if (crDoc.exists && crDoc.data().status === 'pending') {
                        isAuthorized = true;
                    } else {
                        const [subSnap, empSnap] = await Promise.all([
                            db.collection('onboarding_submissions').doc(folderName).get(),
                            db.collection('employees').doc(folderName).get()
                        ]);
                        const activeToken = (subSnap.exists && subSnap.data().activeCorrectionToken) || (empSnap.exists && empSnap.data().activeCorrectionToken);
                        if (activeToken) {
                            const tokenDoc = await db.collection('correction_requests').doc(activeToken).get();
                            if (tokenDoc.exists && tokenDoc.data().status === 'pending') {
                                isAuthorized = true;
                            }
                        }
                    }
                }
            }
        }

        // ── CONTEXT: employee ─────────────────────────────────────────────────
        // Logged-in employee uploading their own documents (profile photo, requests)
        else if (context === 'employee') {
            const pathParts = storagePath.split('/');
            const employeeId = pathParts[1]; // e.g. employees/{employeeId}/...

            if (!employeeId) throw new functions.https.HttpsError('invalid-argument', 'Invalid employee path.');

            // Allow if caller is Admin or SuperAdmin
            if (request.auth.token && (request.auth.token.isAdmin || request.auth.token.isSuperAdmin)) {
                isAuthorized = true;
            } else if (employeeId === uid) {
                isAuthorized = true;
            } else {
                // Check employee record for linked UID by doc ID
                let empDoc = await db.collection('employees').doc(employeeId).get();
                if (!empDoc.exists) {
                    const snap = await db.collection('employees').where('employeeId', '==', employeeId).limit(1).get();
                    if (!snap.empty) {
                        empDoc = snap.docs[0];
                    } else {
                        const snap2 = await db.collection('employees').where('portalId', '==', employeeId).limit(1).get();
                        if (!snap2.empty) empDoc = snap2.docs[0];
                    }
                }
                if (empDoc.exists) {
                    const e = empDoc.data();
                    if (e.linkedUid === uid || e.uid === uid || e.ownerUid === uid || e.portalId === uid || e.employeeId === uid || empDoc.id === uid) {
                        isAuthorized = true;
                    } else if (e.activeCorrectionToken) {
                        const tokenDoc = await db.collection('correction_requests').doc(e.activeCorrectionToken).get();
                        if (tokenDoc.exists && tokenDoc.data().status === 'pending') {
                            isAuthorized = true;
                        }
                    }
                }
            }
        }

        // ── CONTEXT: profile ──────────────────────────────────────────────────
        // Employee uploading their profile photo
        else if (context === 'profile') {
            const pathParts = storagePath.split('/');
            const employeeId = pathParts[1];

            if (!employeeId) throw new functions.https.HttpsError('invalid-argument', 'Invalid profile path.');

            if (employeeId === uid) {
                isAuthorized = true;
            } else {
                let empDoc = await db.collection('employees').doc(employeeId).get();
                if (!empDoc.exists) {
                    const snap = await db.collection('employees').where('employeeId', '==', employeeId).limit(1).get();
                    if (!snap.empty) {
                        empDoc = snap.docs[0];
                    } else {
                        const snap2 = await db.collection('employees').where('portalId', '==', employeeId).limit(1).get();
                        if (!snap2.empty) empDoc = snap2.docs[0];
                    }
                }
                if (empDoc.exists) {
                    const e = empDoc.data();
                    if (e.linkedUid === uid || e.uid === uid || e.portalId === uid || e.employeeId === uid || empDoc.id === uid) {
                        isAuthorized = true;
                    }
                }
            }
        }

        // ── CONTEXT: admin ────────────────────────────────────────────────────
        // Admin uploading documents (BGV certs, employee docs, public assets)
        else if (context === 'admin') {
            // Check custom claims first (fastest)
            if (request.auth.token && (request.auth.token.isAdmin || request.auth.token.isSuperAdmin)) {
                isAuthorized = true;
            } else {
                // Check if caller is an active admin/staff in Firestore
                const [userSnap, staffAccSnap] = await Promise.all([
                    db.collection('users').doc(uid).get(),
                    db.collection('staff_accounts').doc(uid).get()
                ]);

                const adminDoc = staffAccSnap.exists ? staffAccSnap.data() : (userSnap.exists ? userSnap.data() : null);
                if (adminDoc && adminDoc.isDisabled !== true && adminDoc.isActive !== false) {
                    isAuthorized = true;
                }
            }
        }

        else {
            throw new functions.https.HttpsError('invalid-argument', `Unknown context: ${context}`);
        }

        if (!isAuthorized) {
            console.warn(`[SECURITY] Upload denied for uid=${uid}, context=${context}, path=${storagePath}`);
            throw new functions.https.HttpsError('permission-denied', 'You do not have permission to upload to this location.');
        }

        // ── Generate Signed Upload URL ────────────────────────────────────────
        const bucket = admin.storage().bucket();
        const file = bucket.file(storagePath);

        const [signedUrl] = await file.getSignedUrl({
            action: 'write',
            expires: Date.now() + 15 * 60 * 1000, // 15 minutes
            contentType: normalizedContentType,
        });

        console.log(`[STORAGE] Signed upload URL issued for uid=${uid}, context=${context}, path=${storagePath}`);
        return { success: true, uploadUrl: signedUrl, storagePath };

    } catch (error) {
        if (error instanceof functions.https.HttpsError) throw error;
        console.error('[getUploadUrl] Error:', error);
        throw new functions.https.HttpsError('internal', 'Failed to generate upload URL.');
    }
});


// ─────────────────────────────────────────────────────────────────────────────
// AUTH CLAIMS — SET ADMIN CUSTOM CLAIMS (Replaces Firestore lookups in rules)
// Stamps role, permissions, and admin status into the user's JWT token.
// After this, Firestore rules read from the token — zero Firestore lookups.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * computeAndApplyUserClaims (Shared helper for setAdminClaims, refreshAdminClaims & triggers)
 * Resolves permissions, roles, and site scopes, then stamps Firebase custom claims.
 */
const computeAndApplyUserClaims = async (uid, resolvedDocId = null, explicitDoc = null) => {
    const db = admin.firestore();
    let doc = explicitDoc;
    let userDoc = null;
    let finalDocId = resolvedDocId || uid;

    if (!doc) {
        const [staffAccSnap, userSnap, legacyStaffSnap] = await Promise.all([
            db.collection('staff_accounts').doc(uid).get(),
            db.collection('users').doc(uid).get(),
            db.collection('staff').doc(uid).get()
        ]);
        const staffDoc = staffAccSnap.exists ? staffAccSnap.data() : (legacyStaffSnap.exists ? legacyStaffSnap.data() : null);
        userDoc = userSnap.exists ? userSnap.data() : null;
        doc = staffDoc || userDoc;

        if (!doc) {
            const authUser = await admin.auth().getUser(uid).catch(() => null);
            const email = authUser && authUser.email ? authUser.email.trim() : '';
            if (email) {
                for (const colName of ['staff_accounts', 'users', 'staff']) {
                    const qSnap = await db.collection(colName).where('email', '==', email).limit(1).get();
                    if (!qSnap.empty) {
                        finalDocId = qSnap.docs[0].id;
                        doc = qSnap.docs[0].data();
                        if (colName === 'users') userDoc = doc;
                        break;
                    }
                }
            }
        }
    }

    if (!doc) {
        await admin.auth().setCustomUserClaims(uid, {});
        return { success: true, isAdmin: false };
    }

    if (doc.isDisabled === true || doc.isActive === false) {
        await admin.auth().setCustomUserClaims(uid, {});
        return { success: true, isAdmin: false, isDisabled: true };
    }

    const roleId = doc.roleId || 'none';
    const isSuperAdmin = roleId === 'role-super-admin' || !!userDoc || doc.type === 'Admin' || (doc.roles && doc.roles.includes('super-admin'));

    // Resolve all sites managed
    const sitesManagedSet = new Set(Array.isArray(doc.sitesManaged) ? doc.sitesManaged.filter(Boolean) : []);
    try {
        const sitesSnap = await db.collection('settings').doc('sites').get();
        if (sitesSnap.exists) {
            const data = sitesSnap.data() || {};
            const list = Array.isArray(data.sites) ? data.sites : (Array.isArray(data.sitesList) ? data.sitesList : []);
            const adminIdentifiers = new Set([uid, finalDocId, doc.id, doc.username, doc.employeeId].filter(Boolean));
            for (const s of list) {
                if (!s || !s.id) continue;
                const supIds = Array.isArray(s.supervisorIds) ? s.supervisorIds : [];
                if (adminIdentifiers.has(s.supervisorId) || supIds.some(id => adminIdentifiers.has(id))) {
                    sitesManagedSet.add(s.id);
                }
            }
        }
    } catch (sitesErr) {
        console.warn('[computeAndApplyUserClaims] Error reading settings/sites:', sitesErr);
    }
    const sitesManaged = Array.from(sitesManagedSet);

    // Fetch permissions from the roles collection
    let permissions = [];
    const permissionOverrides = doc.permissionOverrides || {};
    if (roleId && roleId !== 'none') {
        const roleSnap = await db.collection('roles').doc(roleId).get();
        if (roleSnap.exists && roleSnap.data().isDisabled !== true) {
            permissions = roleSnap.data().permissions || [];
        }
    }

    const finalPermissions = [...new Set([
        ...permissions.filter(p => permissionOverrides[p] !== false),
        ...Object.keys(permissionOverrides).filter(p => permissionOverrides[p] === true)
    ])];

    const claims = {
        isAdmin: true,
        isSuperAdmin,
        roleId,
        sitesManaged,
        permissions: finalPermissions
    };

    await admin.auth().setCustomUserClaims(uid, claims);
    console.log(`[AUTH CLAIMS] Stamped claims for uid=${uid}, role=${roleId}, isSuperAdmin=${isSuperAdmin}`);
    return { success: true, isAdmin: true, isSuperAdmin, roleId, sitesManaged, permissions: finalPermissions };
};

/**
 * setAdminClaims
 * Called after any staff/admin login. Fetches user permissions and stamps them as custom claims.
 */
exports.setAdminClaims = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated.');
    }
    const uid = request.auth.uid;
    const email = (request.auth.token && request.auth.token.email) ? request.auth.token.email.toLowerCase().trim() : '';
    const db = admin.firestore();

    // 1. Strict Server-Side Verification: Verify caller against staff_accounts or users
    const [staffDocSnap, userDocSnap, staffEmailSnap] = await Promise.all([
        db.collection('staff_accounts').doc(uid).get(),
        db.collection('users').doc(uid).get(),
        email ? db.collection('staff_accounts').where('email', '==', email).limit(1).get() : Promise.resolve(null)
    ]);

    const staffData = staffDocSnap.exists ? staffDocSnap.data() : (staffEmailSnap && !staffEmailSnap.empty ? staffEmailSnap.docs[0].data() : null);
    const userData = userDocSnap.exists ? userDocSnap.data() : null;
    const profile = staffData || userData;

    if (!profile) {
        await admin.auth().setCustomUserClaims(uid, {});
        throw new functions.https.HttpsError('permission-denied', 'Unauthorized: Caller is not a registered staff member.');
    }

    if (profile.isDisabled === true || profile.isActive === false) {
        await admin.auth().setCustomUserClaims(uid, {});
        throw new functions.https.HttpsError('permission-denied', 'Unauthorized: Account is inactive or disabled.');
    }

    try {
        const resolvedDocId = staffDocSnap.exists ? uid : (staffEmailSnap && !staffEmailSnap.empty ? staffEmailSnap.docs[0].id : uid);
        const res = await computeAndApplyUserClaims(uid, resolvedDocId, null);
        if (!res.isAdmin) {
            throw new functions.https.HttpsError('permission-denied', 'Unauthorized to receive admin claims.');
        }
        return res;
    } catch (error) {
        if (error instanceof functions.https.HttpsError) throw error;
        console.error('[setAdminClaims] Error:', error);
        throw new functions.https.HttpsError('internal', 'Failed to set admin claims.');
    }
});

/**
 * refreshAdminClaims
 * Called by SuperAdmin after changing another staff member's role or permissions.
 */
exports.refreshAdminClaims = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated.');
    }
    if (request.auth.token && request.auth.token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const callerUid = request.auth.uid;
    const { targetUid } = request.data || {};

    if (!targetUid) {
        throw new functions.https.HttpsError('invalid-argument', 'targetUid is required.');
    }

    const isSuperAdmin = request.auth.token && request.auth.token.isSuperAdmin === true;
    if (!isSuperAdmin && callerUid !== targetUid) {
        throw new functions.https.HttpsError('permission-denied', 'Only SuperAdmins can refresh another user\'s claims.');
    }

    const db = admin.firestore();
    const [callerStaff, callerUser] = await Promise.all([
        db.collection('staff_accounts').doc(callerUid).get(),
        db.collection('users').doc(callerUid).get()
    ]);
    const callerDoc = callerStaff.exists ? callerStaff.data() : (callerUser.exists ? callerUser.data() : null);
    if (!callerDoc || callerDoc.isDisabled === true || callerDoc.isActive === false) {
        throw new functions.https.HttpsError('permission-denied', 'Only active staff can refresh admin claims.');
    }

    try {
        const res = await computeAndApplyUserClaims(targetUid);
        return { success: true, ...res };
    } catch (error) {
        if (error instanceof functions.https.HttpsError) throw error;
        console.error('[refreshAdminClaims] Error:', error);
        throw new functions.https.HttpsError('internal', 'Failed to refresh claims.');
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// CLOUD-3: AUTOMATIC CUSTOM CLAIMS REAL-TIME SYNC TRIGGERS
// ─────────────────────────────────────────────────────────────────────────────

/**
 * onRoleWritten
 * Triggered whenever a role in /roles/{roleId} is created, updated, or deleted.
 * Automatically recalculates and stamps custom claims for all staff accounts with this role.
 */
exports.onRoleWritten = onDocumentWritten("roles/{roleId}", async (event) => {
    const roleId = event.params.roleId;
    const db = admin.firestore();
    console.log(`[TRIGGER: onRoleWritten] Role ${roleId} changed, recomputing claims for affected staff...`);

    try {
        const [staffAccSnap, legacyStaffSnap] = await Promise.all([
            db.collection('staff_accounts').where('roleId', '==', roleId).get(),
            db.collection('staff').where('roleId', '==', roleId).get()
        ]);

        const processedUids = new Set();
        const updates = [];

        const handleStaffDoc = async (docSnap) => {
            const data = docSnap.data();
            let authUid = data.uid || docSnap.id;
            let authUser = await admin.auth().getUser(authUid).catch(() => null);
            if (!authUser && data.email) {
                authUser = await admin.auth().getUserByEmail(data.email).catch(() => null);
                if (authUser) authUid = authUser.uid;
            }
            if (authUser && !processedUids.has(authUid)) {
                processedUids.add(authUid);
                await computeAndApplyUserClaims(authUid, docSnap.id, data);
                updates.push(docSnap.ref.update({
                    claimsUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
                }));
            }
        };

        for (const d of staffAccSnap.docs) await handleStaffDoc(d);
        for (const d of legacyStaffSnap.docs) await handleStaffDoc(d);

        await Promise.all(updates);
        console.log(`[TRIGGER: onRoleWritten] Successfully refreshed claims for ${processedUids.size} staff members.`);
    } catch (err) {
        console.error('[TRIGGER: onRoleWritten] Error:', err);
    }
});

/**
 * handleStaffOrUserWritten
 * Helper to recompute custom claims whenever staff_accounts, users, or staff document is updated.
 */
async function handleStaffOrUserWritten(event, collectionName) {
    const staffId = event.params.staffId;
    const afterData = event.data?.after?.data();
    const beforeData = event.data?.before?.data();

    // Prevent infinite loop if only claimsUpdatedAt was touched
    if (beforeData && afterData) {
        const bKeys = Object.keys(beforeData).filter(k => k !== 'claimsUpdatedAt');
        const aKeys = Object.keys(afterData).filter(k => k !== 'claimsUpdatedAt');
        if (bKeys.length === aKeys.length && bKeys.every(k => JSON.stringify(beforeData[k]) === JSON.stringify(afterData[k]))) {
            return;
        }
    }

    console.log(`[TRIGGER: handleStaffOrUserWritten] ${collectionName}/${staffId} updated, recomputing claims...`);
    try {
        let authUid = afterData?.uid || staffId;
        let authUser = await admin.auth().getUser(authUid).catch(() => null);
        if (!authUser && (afterData?.email || beforeData?.email)) {
            const email = afterData?.email || beforeData?.email;
            authUser = await admin.auth().getUserByEmail(email).catch(() => null);
            if (authUser) authUid = authUser.uid;
        }

        if (authUser) {
            if (!event.data?.after?.exists) {
                await admin.auth().setCustomUserClaims(authUid, {});
                console.log(`[TRIGGER: handleStaffOrUserWritten] Cleared claims for deleted doc ${collectionName}/${authUid}`);
            } else {
                await computeAndApplyUserClaims(authUid, staffId, afterData);
                await event.data.after.ref.update({
                    claimsUpdatedAt: admin.firestore.FieldValue.serverTimestamp()
                });
                console.log(`[TRIGGER: handleStaffOrUserWritten] Updated claims for ${authUid} via ${collectionName}`);
            }
        }
    } catch (err) {
        console.error(`[TRIGGER: handleStaffOrUserWritten] Error for ${collectionName}/${staffId}:`, err);
    }
}

exports.onStaffAccountWritten = onDocumentWritten("staff_accounts/{staffId}", async (event) => {
    return handleStaffOrUserWritten(event, "staff_accounts");
});

exports.onUserAccountWritten = onDocumentWritten("users/{staffId}", async (event) => {
    return handleStaffOrUserWritten(event, "users");
});

exports.onLegacyStaffWritten = onDocumentWritten("staff/{staffId}", async (event) => {
    return handleStaffOrUserWritten(event, "staff");
});

/**
 * onSettingsSitesWritten
 * Triggered whenever /settings/sites is updated.
 * Automatically recalculates custom claims for any supervisors whose site assignments changed.
 */
exports.onSettingsSitesWritten = onDocumentWritten("settings/sites", async (event) => {
    if (!event.data?.after?.exists) return;
    const afterSites = event.data.after.data()?.sites || event.data.after.data()?.sitesList || [];
    const beforeSites = event.data?.before?.exists ? (event.data.before.data()?.sites || event.data.before.data()?.sitesList || []) : [];

    const extractSupervisors = (sites) => {
        const sups = new Set();
        for (const s of sites) {
            if (s && s.supervisorId) sups.add(s.supervisorId);
            if (s && Array.isArray(s.supervisorIds)) s.supervisorIds.forEach(id => sups.add(id));
        }
        return sups;
    };

    const beforeSups = extractSupervisors(beforeSites);
    const afterSups = extractSupervisors(afterSites);

    const changedSups = new Set();
    for (const id of afterSups) {
        if (!beforeSups.has(id)) changedSups.add(id);
    }
    for (const id of beforeSups) {
        if (!afterSups.has(id)) changedSups.add(id);
    }

    if (changedSups.size === 0) return;

    console.log(`[TRIGGER: onSettingsSitesWritten] Supervisor changes detected for: ${Array.from(changedSups).join(', ')}`);
    const db = admin.firestore();

    for (const supId of changedSups) {
        try {
            let authUser = await admin.auth().getUser(supId).catch(() => null);
            if (!authUser) {
                const snap = await db.collection('staff_accounts').doc(supId).get();
                if (snap.exists && snap.data().email) {
                    authUser = await admin.auth().getUserByEmail(snap.data().email).catch(() => null);
                }
            }
            if (authUser) {
                await computeAndApplyUserClaims(authUser.uid);
                console.log(`[TRIGGER: onSettingsSitesWritten] Recomputed claims for supervisor ${authUser.uid}`);
            }
        } catch (supErr) {
            console.warn(`[TRIGGER: onSettingsSitesWritten] Error updating supervisor ${supId}:`, supErr);
        }
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// CLOUD-1: DATA CORRECTION SECURE PIPELINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * getCorrectionChallenge
 * Public callable: Returns safe, sanitized challenge metadata for a correction link
 * WITHOUT leaking plaintext verificationDob, verificationPhone, or requestedFieldValues.
 */
exports.getCorrectionChallenge = secureOnCall(async (request) => {
    const { token } = request.data || {};
    if (!token || typeof token !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'Correction token is required.');
    }

    const cleanToken = token.trim();
    const db = admin.firestore();
    const docSnap = await db.collection('correction_requests').doc(cleanToken).get();

    if (!docSnap.exists) {
        throw new functions.https.HttpsError('not-found', 'Invalid correction link. This link does not exist.');
    }

    const data = docSnap.data();
    const failedAttempts = data.failedAttempts || 0;
    const isLocked = data.status === 'locked' || failedAttempts >= 5;

    // Check expiry
    let isExpired = false;
    if (data.expiresAt) {
        const expiryDate = data.expiresAt.toDate ? data.expiresAt.toDate() : new Date(data.expiresAt);
        if (expiryDate < new Date()) {
            isExpired = true;
        }
    }

    // Mask phone helper
    const rawPhone = String(data.verificationPhone || '');
    const maskedPhone = rawPhone.length >= 4 ? `XXXXXX${rawPhone.slice(-4)}` : null;

    // Mask email helper
    let maskedEmail = null;
    const rawEmail = String(data.linkedGoogleEmail || '');
    if (rawEmail && rawEmail.includes('@')) {
        const [local, domain] = rawEmail.split('@');
        const first = local.slice(0, 2);
        const last = local.slice(-1);
        maskedEmail = `${first}****${last}@${domain}`;
    }

    return {
        success: true,
        applicantName: data.applicantName || 'Applicant',
        status: isLocked ? 'locked' : (isExpired ? 'expired' : data.status),
        authProvider: data.authProvider || 'manual',
        linkedGoogleEmail: maskedEmail,
        maskedPhone,
        requiresVerification: data.authProvider !== 'google',
        failedAttempts,
        maxAttempts: 5,
        targetType: data.targetType || 'submission',
        expiresAt: data.expiresAt ? (data.expiresAt.toDate ? data.expiresAt.toDate().toISOString() : data.expiresAt) : null
    };
});

/**
 * verifyCorrectionIdentity
 * Verifies candidate's DOB and Phone on the backend.
 * Enforces rate limiting (max 5 attempts).
 * On success, issues an HMAC-signed session token and releases requestedFieldDefinitions/Values.
 */
exports.verifyCorrectionIdentity = secureOnCall(async (request) => {
    const { token, dob, phone } = request.data || {};
    if (!token || typeof token !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'Correction token is required.');
    }

    const cleanToken = token.trim();
    const db = admin.firestore();
    const docRef = db.collection('correction_requests').doc(cleanToken);
    const docSnap = await docRef.get();

    if (!docSnap.exists) {
        throw new functions.https.HttpsError('not-found', 'Correction link does not exist.');
    }

    const data = docSnap.data();

    // Check status
    if (data.status === 'completed') {
        throw new functions.https.HttpsError('failed-precondition', 'This correction link has already been used.');
    }
    if (data.status === 'locked' || (data.failedAttempts || 0) >= 5) {
        throw new functions.https.HttpsError('permission-denied', 'This correction link is locked due to too many failed attempts.');
    }

    // Check if Google-linked and caller authenticated via Google
    let isGoogleVerified = false;
    if (data.authProvider === 'google' || data.linkedGoogleEmail) {
        if (request.auth && request.auth.token && request.auth.token.email) {
            const callerEmail = request.auth.token.email.toLowerCase().trim();
            const targetEmail = (data.linkedGoogleEmail || '').toLowerCase().trim();
            if (callerEmail === targetEmail) {
                isGoogleVerified = true;
            }
        }
    }

    if (!isGoogleVerified) {
        if (!dob || !phone) {
            throw new functions.https.HttpsError('invalid-argument', 'Date of birth and mobile number are required.');
        }

        // Normalize DOB (YYYY-MM-DD)
        const normalizeDob = (d) => {
            if (!d) return '';
            const clean = String(d).trim().replace(/[/\s]/g, '-');
            const parts = clean.split('-');
            if (parts.length === 3) {
                if (parts[0].length === 4) return `${parts[0]}-${parts[1].padStart(2, '0')}-${parts[2].padStart(2, '0')}`;
                if (parts[2].length === 4) return `${parts[2]}-${parts[1].padStart(2, '0')}-${parts[0].padStart(2, '0')}`;
            }
            return clean;
        };

        const inputDobNorm = normalizeDob(dob);
        const storedDobNorm = normalizeDob(data.verificationDob);

        // Normalize Phone (last 10 digits)
        const inputPhone10 = String(phone).replace(/\D/g, '').slice(-10);
        const storedPhone10 = String(data.verificationPhone || '').replace(/\D/g, '').slice(-10);

        const dobMatch = Boolean(inputDobNorm && storedDobNorm && inputDobNorm === storedDobNorm);
        const phoneMatch = Boolean(inputPhone10 && storedPhone10 && inputPhone10 === storedPhone10);

        if (!dobMatch || !phoneMatch) {
            const newAttempts = (data.failedAttempts || 0) + 1;
            const isNowLocked = newAttempts >= 5;
            await docRef.update({
                failedAttempts: newAttempts,
                ...(isNowLocked ? { status: 'locked' } : {})
            });

            if (isNowLocked) {
                throw new functions.https.HttpsError('permission-denied', 'Verification failed. Link is now locked due to 5 failed attempts.');
            }
            throw new functions.https.HttpsError('unauthenticated', `Verification details do not match. Attempts remaining: ${5 - newAttempts}`);
        }
    }

    // Success! Generate HMAC session token
    const crypto = require('crypto');
    const timestamp = Date.now();
    const sessionPayload = `${cleanToken}:${timestamp}:${data.targetId}`;
    const hmacSecret = process.env.CORRECTION_HMAC_SECRET;
    if (!hmacSecret) {
        console.error('[SECURITY FATAL] CORRECTION_HMAC_SECRET environment variable is missing.');
        throw new functions.https.HttpsError('internal', 'Server security configuration error.');
    }
    const sessionToken = crypto.createHmac('sha256', hmacSecret).update(sessionPayload).digest('hex') + `.${timestamp}`;

    // Store active session token on doc for validation
    await docRef.update({
        activeSessionToken: sessionToken,
        sessionCreatedAt: admin.firestore.FieldValue.serverTimestamp(),
        failedAttempts: 0
    });

    return {
        success: true,
        sessionToken,
        targetId: data.targetId,
        targetType: data.targetType || 'submission',
        requestedFields: data.requestedFields || [],
        requestedFieldValues: data.requestedFieldValues || {},
        requestedFieldDefinitions: data.requestedFieldDefinitions || [],
        originalFormSections: data.originalFormSections || [],
        instructions: data.instructions || '',
        applicantName: data.applicantName || ''
    };
});

/**
 * submitCorrectionServer
 * Submits the updated fields directly from the server.
 * Validates the HMAC session token, updates /employees or /onboarding_submissions,
 * recalculates identifiers and duplicate checks, marks correction request completed,
 * and clears activeCorrectionToken.
 */
exports.submitCorrectionServer = secureOnCall(async (request) => {
    const { token, sessionToken, updatedFields } = request.data || {};
    if (!token || !updatedFields || typeof updatedFields !== 'object') {
        throw new functions.https.HttpsError('invalid-argument', 'Token and updatedFields are required.');
    }

    const cleanToken = token.trim();
    const db = admin.firestore();
    const docRef = db.collection('correction_requests').doc(cleanToken);
    const docSnap = await docRef.get();

    if (!docSnap.exists) {
        throw new functions.https.HttpsError('not-found', 'Correction link does not exist.');
    }

    const reqData = docSnap.data();

    if (reqData.status !== 'pending') {
        throw new functions.https.HttpsError('failed-precondition', 'Correction request is no longer pending.');
    }

    // Resolve target record first
    const targetCollection = reqData.targetType === 'employee' ? 'employees' : 'onboarding_submissions';
    let targetRef = db.collection(targetCollection).doc(reqData.targetId);
    let targetSnap = await targetRef.get();

    if (!targetSnap.exists && reqData.targetType === 'employee') {
        const qSnap = await db.collection('employees').where('employeeId', '==', reqData.targetId).limit(1).get();
        if (!qSnap.empty) {
            targetRef = qSnap.docs[0].ref;
            targetSnap = qSnap.docs[0];
        }
    }

    if (!targetSnap.exists) {
        throw new functions.https.HttpsError('not-found', `Target ${reqData.targetType} record not found.`);
    }

    const targetData = targetSnap.data();

    // Authorization: Either valid sessionToken HMAC OR authenticated caller matching the record or admin
    let isAuthorized = false;
    if (sessionToken) {
        const crypto = require('crypto');
        const [tokenHash, tsStr] = String(sessionToken).split('.');
        const timestamp = parseInt(tsStr, 10);
        if (tokenHash && !isNaN(timestamp) && (Date.now() - timestamp <= 2 * 60 * 60 * 1000)) {
            const expectedPayload = `${cleanToken}:${timestamp}:${reqData.targetId}`;
            const hmacSecret = process.env.CORRECTION_HMAC_SECRET;
    if (!hmacSecret) {
        console.error('[SECURITY FATAL] CORRECTION_HMAC_SECRET environment variable is missing.');
        throw new functions.https.HttpsError('internal', 'Server security configuration error.');
    }
            const expectedHash = crypto.createHmac('sha256', hmacSecret).update(expectedPayload).digest('hex');
            if (tokenHash === expectedHash) {
                isAuthorized = true;
            }
        }
    }

    if (!isAuthorized && request.auth) {
        const callerUid = request.auth.uid;
        const callerEmail = (request.auth.token?.email || '').toLowerCase().trim();
        const targetEmail = (targetData.linkedGoogleEmail || targetData.email || reqData.linkedGoogleEmail || '').toLowerCase().trim();
        const isOwner = callerUid === targetData.uid || callerUid === targetData.linkedUid || (callerEmail && callerEmail === targetEmail);
        const isAdmin = request.auth.token?.isSuperAdmin === true || (Array.isArray(request.auth.token?.permissions) && request.auth.token.permissions.includes('SUBMISSIONS_CREATE_CORRECTION_LINK'));
        if (isOwner || isAdmin) {
            isAuthorized = true;
        }
    }

    if (!isAuthorized) {
        throw new functions.https.HttpsError('permission-denied', 'Correction session expired or invalid. Please verify again.');
    }

    const updates = {
        updatedAt: new Date().toISOString(),
        lastUpdated: new Date().toISOString(),
        activeCorrectionToken: admin.firestore.FieldValue.delete()
    };

    // Filter updated fields to only allow those requested in reqData.requestedFields (or all if empty)
    const allowedFields = Array.isArray(reqData.requestedFields) && reqData.requestedFields.length > 0 ? new Set(reqData.requestedFields) : null;
    const processedData = {};
    for (const [k, v] of Object.entries(updatedFields)) {
        if (!allowedFields || allowedFields.has(k)) {
            processedData[k] = v;
        }
    }

    if (reqData.targetType === 'employee') {
        for (const [key, value] of Object.entries(processedData)) {
            updates[`profileData.${key}`] = value;
            updates[`data.${key}`] = value;
        }
    } else {
        for (const [key, value] of Object.entries(processedData)) {
            updates[`formData.${key}`] = value;
            if (targetData.data) {
                updates[`data.${key}`] = value;
            }
        }
    }

    // Sync top-level identifiers if modified, enforcing strict server-side validation (Finding 4)
    for (const [fieldKey, fieldVal] of Object.entries(processedData)) {
        const strVal = typeof fieldVal === 'string' ? fieldVal.trim() : (fieldVal?.value || '');
        if (!strVal) continue;
        const keyLower = fieldKey.toLowerCase();
        if (/pan/i.test(keyLower) || fieldKey === 'da8edb18-4bed-41ca-8233-2280b97dac8d') {
            const cleanPan = strVal.toUpperCase();
            if (!/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(cleanPan)) {
                throw new functions.https.HttpsError('invalid-argument', 'Invalid PAN format. Must be 10 characters (e.g. ABCDE1234F).');
            }
            updates.panNumber = cleanPan;
        }
        if (/aadhaar|aadhar/i.test(keyLower) || fieldKey === '18855ee9-0d66-41d6-988b-128b776a8c5b') {
            const cleanAadhaar = strVal.replace(/\D/g, '');
            if (cleanAadhaar.length !== 12) {
                throw new functions.https.HttpsError('invalid-argument', 'Invalid Aadhaar format. Must be 12 digits.');
            }
            updates.aadhaarNumber = cleanAadhaar;
        }
        if (/uan/i.test(keyLower) || fieldKey === 'f6665f3e-98f4-4d92-8b53-adcaa1993bbe') {
            const cleanUan = strVal.replace(/\D/g, '');
            if (cleanUan.length !== 12) {
                throw new functions.https.HttpsError('invalid-argument', 'Invalid UAN format. Must be 12 digits.');
            }
            updates.uanNumber = cleanUan;
        }
        if (/phone|mobile|contact/i.test(keyLower) || fieldKey === 'eb3617dc-9f1d-475d-a2db-005b6bc2500c') {
            const cleanPhone = strVal.replace(/\D/g, '').slice(-10);
            if (cleanPhone.length !== 10) {
                throw new functions.https.HttpsError('invalid-argument', 'Invalid mobile phone number. Must be 10 digits.');
            }
            updates.phoneNumber = cleanPhone;
        }
        if (/name|applicant_?name/i.test(keyLower) && !/father|mother|spouse|reference|bank/i.test(keyLower)) {
            updates.applicantName = strVal;
        }
    }

    // Atomic batch commit for target document update, request completion, and audit trail
    const batch = db.batch();
    batch.update(targetRef, updates);
    batch.update(docRef, {
        status: 'completed',
        completedAt: new Date().toISOString(),
        submittedUpdates: processedData
    });

    const auditRef = db.collection('audit_logs').doc();
    batch.set(auditRef, {
        action: 'UPDATE',
        category: 'EMPLOYEES',
        description: `Data correction completed for ${reqData.targetType} ${reqData.targetId} via token ${cleanToken}`,
        targetId: reqData.targetId,
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        performedBy: 'DATA_CORRECTION_SESSION',
        metadata: {
            requestId: cleanToken,
            targetType: reqData.targetType,
            modifiedFields: Object.keys(processedData)
        }
    });

    await batch.commit();

    console.log(`[submitCorrectionServer] Successfully processed correction ${cleanToken} for ${reqData.targetId}`);
    return { success: true };
});

// ─────────────────────────────────────────────────────────────────────────────
// CLOUD-2: ONBOARDING SUBMISSION SERVER TRIGGER & PIPELINE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * onSubmissionCreated (CLOUD-2)
 * Triggered on Firestore when a new document is created in /onboarding_submissions/{submissionId}.
 * Executes guaranteed server-side duplicate detection, audit logging, and draft cleanup.
 */
exports.onSubmissionCreated = onDocumentCreated("onboarding_submissions/{submissionId}", async (event) => {
    const submissionId = event.params.submissionId;
    const snap = event.data;
    if (!snap) return;

    const data = snap.data() || {};
    const db = admin.firestore();
    console.log(`[TRIGGER: onSubmissionCreated] Processing new submission ${submissionId}...`);

    try {
        const formData = data.formData || data.data || {};

        // 1. Extract candidate identifiers
        const candidateAadhaar = String(
            data.aadhaar || data.aadhaarNumber || formData.aadhaar || formData.aadhaarNumber ||
            formData['18855ee9-0d66-41d6-988b-128b776a8c5b'] || ''
        ).replace(/\s+/g, '').trim();

        const candidatePan = String(
            data.pan || data.panNumber || formData.pan || formData.panNumber ||
            formData['da8edb18-4bed-41ca-8233-2280b97dac8d'] || ''
        ).toUpperCase().trim();

        const candidatePhone = String(
            data.phone || data.contactNumber || formData.phone || formData.contactNumber ||
            formData['eb3617dc-9f1d-475d-a2db-005b6bc2500c'] || ''
        ).replace(/[^\d]/g, '').slice(-10);

        let candidateEmail = String(
            data.linkedGoogleEmail || data.email || formData.email || formData.applicantEmail || ''
        ).toLowerCase().trim();

        const checks = [
            { field: 'Aadhaar Card', value: candidateAadhaar, queryFields: ['aadhaar', 'aadhaarNumber', 'data.18855ee9-0d66-41d6-988b-128b776a8c5b', 'profileData.18855ee9-0d66-41d6-988b-128b776a8c5b'] },
            { field: 'PAN Card', value: candidatePan, queryFields: ['pan', 'panNumber', 'data.da8edb18-4bed-41ca-8233-2280b97dac8d', 'profileData.da8edb18-4bed-41ca-8233-2280b97dac8d'] },
            { field: 'Contact Number', value: candidatePhone, queryFields: ['phone', 'contactNumber', 'data.eb3617dc-9f1d-475d-a2db-005b6bc2500c', 'profileData.eb3617dc-9f1d-475d-a2db-005b6bc2500c'] },
            { field: 'Email', value: candidateEmail, queryFields: ['email', 'linkedGoogleEmail', 'applicantEmail'] }
        ].filter(c => c.value && c.value.length >= 5);

        // 2. Server-side Duplicate Checks
        const duplicateMatches = [];
        for (const check of checks) {
            for (const qf of check.queryFields) {
                // Check employees
                const empSnap = await db.collection('employees').where(qf, '==', check.value).limit(1).get();
                if (!empSnap.empty) {
                    const emp = empSnap.docs[0].data();
                    if (!emp.deletedAt) {
                        const isRelieved = emp.isRelieved === true || emp.isActive === false;
                        const empId = emp.employeeId || emp.portalId || empSnap.docs[0].id;
                        const empName = emp.applicantName || 'Employee';
                        const siteName = emp.siteName || emp.currentSiteId || 'N/A';

                        if (!isRelieved) {
                            duplicateMatches.push({
                                matchType: 'EXISTING_ACTIVE_EMPLOYEE',
                                matchedField: check.field,
                                matchedValue: check.value,
                                matchedId: empId,
                                matchedName: empName,
                                matchedSite: siteName,
                                details: `Active employee (${empId} - ${empName}) already exists with this ${check.field}.`
                            });
                        } else {
                            duplicateMatches.push({
                                matchType: 'EX_EMPLOYEE_REHIRE',
                                matchedField: check.field,
                                matchedValue: check.value,
                                matchedId: empId,
                                matchedName: empName,
                                matchedSite: siteName,
                                relievingDate: emp.relievingDate || 'N/A',
                                details: `Ex-employee (${empId} - ${empName}) relieved on ${emp.relievingDate || 'N/A'}.`
                            });
                        }
                        break;
                    }
                }
            }
        }

        // 3. Stamp duplicate matches if found
        const updates = {};
        if (duplicateMatches.length > 0) {
            updates.duplicateMatches = duplicateMatches;
            console.log(`[TRIGGER: onSubmissionCreated] Stamped ${duplicateMatches.length} duplicate matches on ${submissionId}`);
        }

        // 4. Server-Side Draft Cleanup
        const draftsToDelete = new Set([submissionId]);
        if (candidateEmail) {
            const draftsSnap = await db.collection('draft_submissions').where('ownerEmail', '==', candidateEmail).limit(10).get();
            draftsSnap.docs.forEach(d => draftsToDelete.add(d.id));
        }
        if (data.ownerUid) {
            const draftsSnap2 = await db.collection('draft_submissions').where('ownerUid', '==', data.ownerUid).limit(10).get();
            draftsSnap2.docs.forEach(d => draftsToDelete.add(d.id));
        }

        for (const dId of draftsToDelete) {
            try {
                await db.collection('draft_submissions').doc(dId).delete();
                console.log(`[TRIGGER: onSubmissionCreated] Cleaned up draft ${dId}`);
            } catch (delErr) {
                // Non-fatal
            }
        }

        // 5. Append-only server audit log
        await db.collection('audit_logs').add({
            action: 'SUBMIT',
            module: 'ONBOARDING',
            targetId: submissionId,
            actorId: data.ownerUid || data.linkedUid || 'candidate',
            actorName: data.applicantName || 'Candidate',
            details: `New onboarding application submitted for ${data.applicantName || 'Candidate'} (${submissionId})`,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        if (Object.keys(updates).length > 0) {
            await snap.ref.update(updates);
        }

        // 6. Automated Server-Side Drive & Sheets Sync (CLOUD-7)
        try {
            console.log(`[TRIGGER: onSubmissionCreated] Initiating automated server-side Drive & Sheets sync for ${submissionId}...`);
            await syncRecordToDriveAndSheetsCore(submissionId, 'submission');
            console.log(`[TRIGGER: onSubmissionCreated] ✅ Automated Drive & Sheets sync completed for ${submissionId}`);
        } catch (syncErr) {
            console.warn(`[TRIGGER: onSubmissionCreated] Background Drive/Sheets sync encountered non-fatal error:`, syncErr.message);
        }

        console.log(`[TRIGGER: onSubmissionCreated] Successfully processed ${submissionId}`);
    } catch (err) {
        console.error(`[TRIGGER: onSubmissionCreated] Error processing ${submissionId}:`, err);
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// CLOUD-4: Multi-Level Approval Engine for Leave, Resignation & Account Updates
// ─────────────────────────────────────────────────────────────────────────────

async function resolveEmployeeDocAdmin(db, empId) {
    if (!empId) return null;
    let snap = await db.collection('employees').doc(empId).get();
    if (snap.exists) return snap;
    const byEmpId = await db.collection('employees').where('employeeId', '==', empId).limit(1).get();
    if (!byEmpId.empty) return byEmpId.docs[0];
    const byPortalId = await db.collection('employees').where('portalId', '==', empId).limit(1).get();
    if (!byPortalId.empty) return byPortalId.docs[0];
    return null;
}

async function resolveSubmissionDocAdmin(db, empId, subDocId) {
    if (subDocId) {
        const snap = await db.collection('onboarding_submissions').doc(subDocId).get();
        if (snap.exists) return snap;
    }
    if (!empId) return null;
    const byEmpId = await db.collection('onboarding_submissions').where('employeeId', '==', empId).limit(1).get();
    if (!byEmpId.empty) return byEmpId.docs[0];
    const byId = await db.collection('onboarding_submissions').doc(empId).get();
    if (byId.exists) return byId;
    return null;
}

exports.processRequestReviewServer = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'You must be logged in to review requests.');
    }

    const {
        requestType,
        requestId,
        action,
        comment,
        isBypass,
        updatedRelievingDate,
        targetLevel
    } = request.data || {};

    const typeMap = {
        'LEAVES': 'leave_requests',
        'leave_requests': 'leave_requests',
        'ACCOUNT_UPDATES': 'account_updates',
        'account_updates': 'account_updates',
        'RESIGNATIONS': 'resignations',
        'resignations': 'resignations'
    };
    const collectionName = typeMap[requestType];
    if (!collectionName) {
        throw new functions.https.HttpsError('invalid-argument', `Invalid requestType: "${requestType}". Expected LEAVES, ACCOUNT_UPDATES, or RESIGNATIONS.`);
    }

    if (!requestId || typeof requestId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'requestId is required.');
    }

    const normalizedAction = String(action || '').toUpperCase();
    if (!['APPROVE', 'REJECT', 'REVERT'].includes(normalizedAction)) {
        throw new functions.https.HttpsError('invalid-argument', `Invalid action: "${action}". Expected APPROVE, REJECT, or REVERT.`);
    }

    const db = admin.firestore();
    const uid = request.auth.uid;
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'super-admin';

    // 1. Resolve caller details, permissions, and sites
    let callerName = token.name || '';
    let callerRoleId = token.roleId || '';
    let callerRoleName = 'Admin';
    let permissions = Array.isArray(token.permissions) ? [...token.permissions] : [];
    let sitesManaged = Array.isArray(token.sitesManaged) ? [...token.sitesManaged] : [];

    if (!callerName || !callerRoleId || permissions.length === 0) {
        const [saSnap, uSnap, stSnap] = await Promise.all([
            db.collection('staff_accounts').doc(uid).get(),
            db.collection('users').doc(uid).get(),
            db.collection('staff').doc(uid).get()
        ]);
        const staffDoc = saSnap.exists ? saSnap.data() : (stSnap.exists ? stSnap.data() : (uSnap.exists ? uSnap.data() : null));
        if (staffDoc) {
            if (staffDoc.isDisabled === true || staffDoc.isActive === false) {
                throw new functions.https.HttpsError('permission-denied', 'Account is disabled or inactive.');
            }
            callerName = callerName || staffDoc.name || staffDoc.fullName || staffDoc.displayName || 'Admin';
            callerRoleId = callerRoleId || staffDoc.roleId || 'admin';
            if (Array.isArray(staffDoc.sitesManaged)) {
                sitesManaged = Array.from(new Set([...sitesManaged, ...staffDoc.sitesManaged]));
            }
        }
    }
    if (!callerName) callerName = 'Admin';
    if (callerRoleId) {
        const roleSnap = await db.collection('roles').doc(callerRoleId).get();
        if (roleSnap.exists) {
            const rData = roleSnap.data();
            callerRoleName = rData.name || callerRoleId;
            if (Array.isArray(rData.permissions)) {
                permissions = Array.from(new Set([...permissions, ...rData.permissions]));
            }
        }
    }

    // 2. Permission check
    const moduleMap = {
        'leave_requests': 'LEAVES',
        'account_updates': 'ACCOUNT_UPDATES',
        'resignations': 'RESIGNATIONS'
    };
    const modId = moduleMap[collectionName];

    let hasPerm = isSuperAdmin;
    if (!hasPerm) {
        if (normalizedAction === 'APPROVE') {
            hasPerm = permissions.includes(`${modId}_APPROVE`);
        } else if (normalizedAction === 'REJECT') {
            hasPerm = permissions.includes(`${modId}_REJECT`) || permissions.includes(`${modId}_APPROVE`);
        } else if (normalizedAction === 'REVERT') {
            hasPerm = permissions.includes(`${modId}_REVERT_DECISION`) || permissions.includes(`${modId}_APPROVE`);
        }
    }

    if (!hasPerm) {
        throw new functions.https.HttpsError('permission-denied', `Missing permission to ${normalizedAction.toLowerCase()} ${modId} requests.`);
    }

    // 3. Fetch request document
    const reqRef = db.collection(collectionName).doc(requestId);
    const reqSnap = await reqRef.get();
    if (!reqSnap.exists) {
        throw new functions.https.HttpsError('not-found', `${modId} request "${requestId}" not found.`);
    }
    const reqData = reqSnap.data();
    const siteId = reqData.siteId || '';

    // 4. Site authorization check
    if (siteId && !isSuperAdmin) {
        const hasGlobalScope = permissions.includes('EMPLOYEES_VIEW_SCOPE_ALL') ||
            permissions.includes('SUBMISSIONS_VIEW_SCOPE_ALL') ||
            permissions.includes('MANAGE_SITES') ||
            permissions.includes('MANAGE_ALL_SITES') ||
            permissions.includes(`${modId}_VIEW_SCOPE_ALL`);

        let siteAuthorized = hasGlobalScope || sitesManaged.includes(siteId);

        if (!siteAuthorized) {
            const sitesSnap = await db.collection('settings').doc('sites').get();
            if (sitesSnap.exists) {
                const siteList = sitesSnap.data().sites || [];
                const targetSite = siteList.find(s => s && s.id === siteId);
                if (targetSite) {
                    const supIds = Array.isArray(targetSite.supervisorIds) ? targetSite.supervisorIds : [targetSite.supervisorId].filter(Boolean);
                    if (supIds.includes(uid)) {
                        siteAuthorized = true;
                    }
                }
            }
        }

        if (!siteAuthorized) {
            throw new functions.https.HttpsError('permission-denied', `You do not have management authority for site "${siteId}".`);
        }
    }

    // 5. Workflow level progression
    const wfSnap = await db.collection('settings').doc('workflows').get();
    const wfConfigs = wfSnap.exists ? (wfSnap.data().configs || []) : [];
    const wfConfig = wfConfigs.find(c => c && c.moduleId === modId);
    const levels = wfConfig && Array.isArray(wfConfig.levels) ? wfConfig.levels : [];
    const maxLevels = levels.length > 0 ? Math.max(...levels.map(l => l.level)) : 1;
    const currentLevel = Number(reqData.currentLevel) || 1;

    let newStatus = reqData.status;
    let newLevel = currentLevel;
    let nextLevelRoleId = null;
    let isProcessed = reqData.isProcessed;

    const historyEntry = {
        level: currentLevel,
        actionBy: callerName,
        actionByRole: callerRoleName,
        timestamp: new Date().toISOString(),
        status: normalizedAction === 'APPROVE' ? 'Approved' : (normalizedAction === 'REJECT' ? 'Rejected' : 'Reverted'),
        comments: comment || (normalizedAction === 'REVERT' ? `Reverted to Level ${targetLevel || 1}` : '')
    };

    const sideEffects = [];

    if (normalizedAction === 'REJECT') {
        newStatus = 'Rejected';
    } else if (normalizedAction === 'REVERT') {
        newStatus = 'Pending';
        newLevel = Number(targetLevel) || 1;

        // If reverting an already approved leave request, refund the deducted days!
        if (collectionName === 'leave_requests' && reqData.status === 'Approved') {
            const [sY, sM, sD] = String(reqData.startDate || '').split('-').map(Number);
            const [eY, eM, eD] = String(reqData.endDate || '').split('-').map(Number);
            if (!isNaN(sY) && !isNaN(eY)) {
                const daysTaken = Math.round((Date.UTC(eY, eM - 1, eD) - Date.UTC(sY, sM - 1, sD)) / (1000 * 3600 * 24)) + 1;
                const keyMap = {
                    'Casual Leave': 'casual',
                    'Sick Leave': 'sick',
                    'Earned Leave': 'earned',
                    'Privilege Leave': 'privilege'
                };
                const balanceKey = keyMap[reqData.leaveType] || String(reqData.leaveType || '').toLowerCase();
                sideEffects.push(async (batch) => {
                    const empSnap = await resolveEmployeeDocAdmin(db, reqData.employeeId);
                    if (empSnap && empSnap.exists) {
                        batch.update(empSnap.ref, {
                            [`leaveBalance.${balanceKey}`]: admin.firestore.FieldValue.increment(daysTaken)
                        });
                    }
                });
            }
        }
    } else if (normalizedAction === 'APPROVE') {
        if (!isBypass && currentLevel < maxLevels) {
            // Advance to next workflow level that has an assigned role
            let nextLvl = currentLevel + 1;
            let foundNext = levels.find(l => l.level === nextLvl && l.roleId);
            while (!foundNext && nextLvl < maxLevels) {
                nextLvl++;
                foundNext = levels.find(l => l.level === nextLvl && l.roleId);
            }
            if (foundNext) {
                newLevel = nextLvl;
                newStatus = 'Pending';
                nextLevelRoleId = foundNext.roleId;
            } else {
                // No higher active levels configured, advance directly to Final Approval
                newStatus = 'Approved';
                newLevel = maxLevels;
            }
        } else {
            // Final Approval
            newStatus = 'Approved';
            newLevel = maxLevels;
        }

        if (newStatus === 'Approved') {
            if (collectionName === 'leave_requests') {
                const [sY, sM, sD] = String(reqData.startDate || '').split('-').map(Number);
                const [eY, eM, eD] = String(reqData.endDate || '').split('-').map(Number);
                if (!isNaN(sY) && !isNaN(eY)) {
                    const daysTaken = Math.round((Date.UTC(eY, eM - 1, eD) - Date.UTC(sY, sM - 1, sD)) / (1000 * 3600 * 24)) + 1;
                    const keyMap = {
                        'Casual Leave': 'casual',
                        'Sick Leave': 'sick',
                        'Earned Leave': 'earned',
                        'Privilege Leave': 'privilege'
                    };
                    const balanceKey = keyMap[reqData.leaveType] || String(reqData.leaveType || '').toLowerCase();
                    sideEffects.push(async (batch) => {
                        const empSnap = await resolveEmployeeDocAdmin(db, reqData.employeeId);
                        if (empSnap && empSnap.exists) {
                            batch.update(empSnap.ref, {
                                [`leaveBalance.${balanceKey}`]: admin.firestore.FieldValue.increment(-daysTaken)
                            });
                        }
                    });
                }
            } else if (collectionName === 'account_updates') {
                const fieldId = reqData.fieldId;
                const requestedValue = reqData.requestedValue;
                if (fieldId) {
                    sideEffects.push(async (batch) => {
                        const empSnap = await resolveEmployeeDocAdmin(db, reqData.employeeId);
                        if (empSnap && empSnap.exists) {
                            const empUpdates = {
                                [`profileData.${fieldId}`]: requestedValue,
                                [`data.${fieldId}`]: requestedValue,
                                lastUpdated: new Date().toISOString()
                            };

                            // Comprehensive matching: field ID, label, name, and standard UUIDs
                            const checkText = `${fieldId} ${reqData.fieldLabel || ''} ${reqData.fieldName || ''}`.toLowerCase();
                            if (/pan/i.test(checkText)) empUpdates.panNumber = String(requestedValue).toUpperCase().trim();
                            if (/aadhaar|aadhar/i.test(checkText)) empUpdates.aadhaarNumber = String(requestedValue).replace(/\s+/g, '');
                            if (/uan/i.test(checkText)) empUpdates.uanNumber = String(requestedValue).replace(/\s+/g, '');
                            if (/esic/i.test(checkText)) empUpdates.esicNumber = String(requestedValue).trim();
                            if (/phone|mobile/i.test(checkText)) empUpdates.phoneNumber = String(requestedValue).trim();
                            if (/\bname\b|applicant/i.test(checkText) && !/father|mother|spouse|guardian|nominee/i.test(checkText)) {
                                empUpdates.applicantName = requestedValue;
                            }
                            if (/bank\s*acc|account\s*num/i.test(checkText)) empUpdates.bankAccountNumber = requestedValue;
                            if (/ifsc/i.test(checkText)) empUpdates.ifscCode = String(requestedValue).toUpperCase().trim();

                            batch.update(empSnap.ref, empUpdates);

                            const subSnap = await resolveSubmissionDocAdmin(db, reqData.employeeId, empSnap.id);
                            if (subSnap && subSnap.exists) {
                                const subUpdates = {
                                    [`formData.${fieldId}`]: requestedValue,
                                    [`data.${fieldId}`]: requestedValue,
                                    lastUpdated: new Date().toISOString()
                                };
                                if (empUpdates.panNumber) subUpdates.panNumber = empUpdates.panNumber;
                                if (empUpdates.aadhaarNumber) subUpdates.aadhaarNumber = empUpdates.aadhaarNumber;
                                if (empUpdates.uanNumber) subUpdates.uanNumber = empUpdates.uanNumber;
                                if (empUpdates.esicNumber) subUpdates.esicNumber = empUpdates.esicNumber;
                                if (empUpdates.phoneNumber) subUpdates.phoneNumber = empUpdates.phoneNumber;
                                if (empUpdates.applicantName) subUpdates.applicantName = empUpdates.applicantName;

                                batch.update(subSnap.ref, subUpdates);
                            }
                        }
                    });
                }
            } else if (collectionName === 'resignations') {
                const effectiveRelDate = updatedRelievingDate || reqData.relievingDate;
                const today = new Date();
                today.setHours(23, 59, 59, 999);
                const relDateObj = new Date(effectiveRelDate);
                const isPastOrToday = !isNaN(relDateObj.getTime()) && relDateObj <= today;

                sideEffects.push(async (batch) => {
                    const empSnap = await resolveEmployeeDocAdmin(db, reqData.employeeId);
                    if (empSnap && empSnap.exists) {
                        if (isPastOrToday) {
                            batch.update(empSnap.ref, {
                                isActive: false,
                                status: 'Relieved',
                                isRelieved: true,
                                relievingDate: effectiveRelDate,
                                relievingReason: reqData.reason || 'Resignation'
                            });
                            isProcessed = true;
                        } else {
                            batch.update(empSnap.ref, {
                                resignationStatus: 'Notice Period',
                                pendingRelievingDate: effectiveRelDate,
                                relievingDate: effectiveRelDate,
                                relievingReason: reqData.reason || 'Resignation'
                            });
                            isProcessed = false;
                        }

                        const subSnap = await resolveSubmissionDocAdmin(db, reqData.employeeId, empSnap.id);
                        if (subSnap && subSnap.exists) {
                            if (isPastOrToday) {
                                batch.update(subSnap.ref, {
                                    isActive: false,
                                    status: 'Relieved',
                                    isRelieved: true,
                                    relievingDate: effectiveRelDate,
                                    relievingReason: reqData.reason || 'Resignation'
                                });
                            } else {
                                batch.update(subSnap.ref, {
                                    resignationStatus: 'Notice Period',
                                    pendingRelievingDate: effectiveRelDate,
                                    relievingDate: effectiveRelDate,
                                    relievingReason: reqData.reason || 'Resignation'
                                });
                            }
                        }
                    }
                });
            }
        }
    }

    // 6. Execute atomic batch write
    const batch = db.batch();

    for (const effect of sideEffects) {
        await effect(batch);
    }

    const reqUpdates = {
        status: newStatus,
        currentLevel: newLevel,
        approvalHistory: [...(reqData.approvalHistory || []), historyEntry],
        lastActionAt: admin.firestore.FieldValue.serverTimestamp()
    };
    if (comment) reqUpdates.adminComments = comment;
    if (updatedRelievingDate) reqUpdates.relievingDate = updatedRelievingDate;
    if (typeof isProcessed === 'boolean') reqUpdates.isProcessed = isProcessed;

    batch.update(reqRef, reqUpdates);

    // Append-only Audit Log
    const auditRef = db.collection('audit_logs').doc();
    batch.set(auditRef, {
        action: normalizedAction === 'APPROVE' ? 'APPROVAL' : (normalizedAction === 'REJECT' ? 'REJECTION' : 'STATUS_CHANGE'),
        module: modId,
        targetId: requestId,
        actorId: uid,
        actorName: callerName,
        details: `${normalizedAction} on ${modId} request for ${reqData.employeeName || reqData.employeeId} (${requestId}) - Status: ${newStatus}, Level: ${newLevel}`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    // In-App Notification to Employee
    const notifRef = db.collection('notifications').doc();
    let empMsg = `Your ${modId.replace('_', ' ')} request status is now ${newStatus}.`;
    if (normalizedAction === 'APPROVE') {
        empMsg = newStatus === 'Approved'
            ? `Your ${reqData.leaveType || modId.replace('_', ' ')} request has been fully approved.`
            : `Your ${reqData.leaveType || modId.replace('_', ' ')} request was approved at Level ${currentLevel} (now Level ${newLevel}).`;
    } else if (normalizedAction === 'REJECT') {
        empMsg = `Your ${reqData.leaveType || modId.replace('_', ' ')} request was rejected.`;
    } else if (normalizedAction === 'REVERT') {
        empMsg = `Your ${reqData.leaveType || modId.replace('_', ' ')} request was reverted to Level ${newLevel}.`;
    }

    const notifLinks = {
        'leave_requests': 'EMPLOYEE_LEAVE_REQUESTS',
        'account_updates': 'EMPLOYEE_ACCOUNT_UPDATES',
        'resignations': 'EMPLOYEE_RESIGNATION'
    };

    const adminNotifLinks = {
        'leave_requests': 'ADMIN_PORTAL_LEAVE_MANAGEMENT',
        'account_updates': 'ADMIN_PORTAL_ACCOUNT_UPDATE_MANAGEMENT',
        'resignations': 'ADMIN_PORTAL_RESIGNATION_MANAGEMENT'
    };

    batch.set(notifRef, {
        targetUserId: reqData.employeeId,
        message: empMsg,
        type: newStatus === 'Approved' ? 'success' : (newStatus === 'Rejected' ? 'error' : 'info'),
        link: notifLinks[collectionName] || 'EMPLOYEE_DASHBOARD',
        read: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        timestamp: new Date().toISOString()
    });

    // In-App Notification to next level approvers (if escalated)
    if (nextLevelRoleId) {
        const nextNotifRef = db.collection('notifications').doc();
        batch.set(nextNotifRef, {
            targetUserId: `ROLE:${nextLevelRoleId}`,
            message: `Pending ${modId.replace('_', ' ')} Approval for ${reqData.employeeName || reqData.employeeId} (Level ${newLevel})`,
            type: 'info',
            link: adminNotifLinks[collectionName] || 'ADMIN_DASHBOARD',
            read: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            timestamp: new Date().toISOString()
        });
    }

    await batch.commit();

    console.log(`[processRequestReviewServer] Successfully processed ${modId}/${requestId}: ${normalizedAction} -> Status: ${newStatus}, Level: ${newLevel}`);

    return {
        success: true,
        requestId,
        status: newStatus,
        currentLevel: newLevel
    };
});

// ─────────────────────────────────────────────────────────────────────────────
// CLOUD-5: Atomic Employee Lifecycle State Machine
// ─────────────────────────────────────────────────────────────────────────────

exports.approveOnboardingServer = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'You must be logged in to approve onboarding.');
    }

    const {
        submissionId,
        assignedEmployeeId,
        siteId,
        joiningDate,
        profileCompletionData,
        comments,
        customRecruiter,
        isBypass
    } = request.data || {};

    if (!submissionId || typeof submissionId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'submissionId is required.');
    }
    if (!assignedEmployeeId || typeof assignedEmployeeId !== 'string' || !assignedEmployeeId.trim()) {
        throw new functions.https.HttpsError('invalid-argument', 'assignedEmployeeId is required (e.g. HY123456).');
    }

    const db = admin.firestore();
    const uid = request.auth.uid;
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'super-admin';
    const permissions = Array.isArray(token.permissions) ? token.permissions : [];

    // Verify permission: SUBMISSIONS_APPROVE or SuperAdmin
    if (!isSuperAdmin && !permissions.includes('SUBMISSIONS_APPROVE')) {
        const saSnap = await db.collection('staff_accounts').doc(uid).get();
        if (saSnap.exists && (saSnap.data().isDisabled === true || saSnap.data().isActive === false)) {
            throw new functions.https.HttpsError('permission-denied', 'Account is disabled or inactive.');
        }
        const roleId = saSnap.exists ? saSnap.data().roleId : null;
        let allowed = roleId === 'role-super-admin';
        if (!allowed && roleId) {
            const roleSnap = await db.collection('roles').doc(roleId).get();
            if (roleSnap.exists && Array.isArray(roleSnap.data().permissions)) {
                allowed = roleSnap.data().permissions.includes('SUBMISSIONS_APPROVE');
            }
        }
        if (!allowed) {
            throw new functions.https.HttpsError('permission-denied', 'Missing permission SUBMISSIONS_APPROVE.');
        }
    }

    const cleanEmpId = assignedEmployeeId.trim().toUpperCase();

    // 1. Check if assigned Employee ID is already taken across employees & onboarding_submissions
    const [empDocCheck, empFieldCheck, subFieldCheck] = await Promise.all([
        db.collection('employees').doc(cleanEmpId).get(),
        db.collection('employees').where('employeeId', '==', cleanEmpId).limit(1).get(),
        db.collection('onboarding_submissions').where('employeeId', '==', cleanEmpId).limit(1).get()
    ]);
    if (empDocCheck.exists || !empFieldCheck.empty) {
        throw new functions.https.HttpsError('already-exists', `Employee ID "${cleanEmpId}" is already taken by an existing employee.`);
    }
    if (!subFieldCheck.empty && subFieldCheck.docs[0].id !== submissionId) {
        throw new functions.https.HttpsError('already-exists', `Employee ID "${cleanEmpId}" is already assigned to submission "${subFieldCheck.docs[0].id}".`);
    }

    // 2. Fetch submission doc
    const subRef = db.collection('onboarding_submissions').doc(submissionId);
    const subSnap = await subRef.get();
    if (!subSnap.exists) {
        throw new functions.https.HttpsError('not-found', `Submission "${submissionId}" not found.`);
    }
    const subData = subSnap.data();

    // 2.5 Live gatekeeper check against duplicate active employees
    if (subData.duplicateCheck && subData.duplicateCheck.isDuplicate) {
        if (subData.duplicateCheck.matchType === 'EXISTING_ACTIVE_EMPLOYEE') {
            throw new functions.https.HttpsError('failed-precondition', `Cannot Approve: Active employee "${subData.duplicateCheck.matchedName}" (${subData.duplicateCheck.matchedId}) already exists with the same ${subData.duplicateCheck.matchedField} (${subData.duplicateCheck.matchedValue}). Duplicate employment under multiple IDs is not permitted.`);
        }
        if (subData.duplicateCheck.matchType === 'DUPLICATE_SUBMISSION') {
            throw new functions.https.HttpsError('failed-precondition', `Cannot Approve: Duplicate submission detected (${subData.duplicateCheck.submissionId}).`);
        }
    }

    // 3. Site authorization check
    const subSiteId = siteId || subData.siteId || (subData.formData && subData.formData.siteId) || '';
    if (subSiteId && !isSuperAdmin) {
        const hasGlobalScope = permissions.includes('EMPLOYEES_VIEW_SCOPE_ALL') ||
            permissions.includes('SUBMISSIONS_VIEW_SCOPE_ALL') ||
            permissions.includes('MANAGE_SITES') ||
            permissions.includes('MANAGE_ALL_SITES');
        const sitesManaged = Array.isArray(token.sitesManaged) ? token.sitesManaged : [];
        if (!hasGlobalScope && !sitesManaged.includes(subSiteId)) {
            const sitesSnap = await db.collection('settings').doc('sites').get();
            const siteList = sitesSnap.exists ? (sitesSnap.data().sites || []) : [];
            const targetSite = siteList.find(s => s && s.id === subSiteId);
            const supIds = targetSite && Array.isArray(targetSite.supervisorIds) ? targetSite.supervisorIds : (targetSite ? [targetSite.supervisorId] : []);
            if (!supIds.includes(uid)) {
                throw new functions.https.HttpsError('permission-denied', `You do not have management authority for site "${subSiteId}".`);
            }
        }
    }

    const employeeName = (subData.applicantName || 'Unknown').trim();
    const newFolderName = `${cleanEmpId} - ${employeeName}`;
    const resolvedJoiningDate = joiningDate ? new Date(joiningDate).toISOString() : new Date().toISOString();
    const initialSiteId = subSiteId || 'Unassigned';

    const initialAssignment = {
        id: db.collection('_').doc().id,
        siteId: initialSiteId,
        designation: (subData.formData && subData.formData.designation) || 'Staff',
        type: 'PRIMARY',
        joiningDate: resolvedJoiningDate,
        status: 'Active'
    };
    if (subData.formData && subData.formData.subUnitId) {
        initialAssignment.subUnitId = subData.formData.subUnitId;
    }

    // Storage path migration in profile data
    const oldStoragePath = `onboarding/${submissionId}`;
    const newStoragePath = `employees/${submissionId}/joining`;
    const updatedProfileData = { ...(subData.formData || subData.data || {}) };

    try {
        const bucket = admin.storage().bucket();
        const [files] = await bucket.getFiles({ prefix: `${oldStoragePath}/` });
        for (const file of files) {
            const destPath = file.name.replace(oldStoragePath, newStoragePath);
            await file.copy(destPath);
            await file.delete().catch(() => {});
        }
        if (subData.linkedUid && subData.linkedUid !== submissionId) {
            const oldUidPath = `onboarding/${subData.linkedUid}`;
            const [uidFiles] = await bucket.getFiles({ prefix: `${oldUidPath}/` });
            for (const file of uidFiles) {
                const destPath = file.name.replace(oldUidPath, newStoragePath);
                await file.copy(destPath);
                await file.delete().catch(() => {});
            }
        }
    } catch (storageErr) {
        console.warn(`[approveOnboardingServer] Storage move warning for ${submissionId}:`, storageErr.message);
    }

    // Recursively rewrite any storage paths in profileData from onboarding/ to employees/{submissionId}/joining
    const oldPrefixes = [oldStoragePath];
    if (subData.linkedUid && subData.linkedUid !== submissionId) {
        oldPrefixes.push(`onboarding/${subData.linkedUid}`);
    }

    function rewriteStoragePathsDeep(target) {
        if (!target) return target;
        if (typeof target === 'string') {
            for (const oldPref of oldPrefixes) {
                if (target.startsWith(oldPref)) {
                    return target.replace(oldPref, newStoragePath);
                }
            }
            return target;
        }
        if (Array.isArray(target)) {
            return target.map(item => rewriteStoragePathsDeep(item));
        }
        if (typeof target === 'object') {
            const out = {};
            for (const [k, v] of Object.entries(target)) {
                out[k] = rewriteStoragePathsDeep(v);
            }
            return out;
        }
        return target;
    }

    const migratedProfileData = rewriteStoragePathsDeep(updatedProfileData);

    // Construct new Employee record
    const empDocRef = db.collection('employees').doc(submissionId);
    const newEmployee = {
        uid: subData.linkedUid || subData.uid || submissionId,
        employeeId: cleanEmpId,
        portalId: submissionId,
        profileData: migratedProfileData,
        data: migratedProfileData,
        currentSiteId: initialSiteId,
        siteName: (subData.formData && subData.formData.siteName) || 'N/A',
        activeAssignments: [initialAssignment],
        assignedSiteIds: [initialSiteId],
        assignmentHistory: [],
        employmentHistory: [],
        originalJoiningDate: resolvedJoiningDate,
        joiningDate: resolvedJoiningDate,
        leaveBalance: {
            casual: 12,
            sick: 7,
            privilege: 15
        },
        isActive: true,
        isRelieved: false,
        applicantName: employeeName,
        driveFolderName: newFolderName,
        authProvider: subData.authProvider || 'manual',
        linkedGoogleEmail: subData.linkedGoogleEmail || '',
        needsProfileCompletion: profileCompletionData?.profileCompletionStatus === 'INCOMPLETE',
        profileStatus: profileCompletionData?.profileCompletionStatus === 'INCOMPLETE' ? 'waiting_for_employee' : 'approved',
        profileCompletionStatus: profileCompletionData?.profileCompletionStatus === 'INCOMPLETE' ? 'INCOMPLETE' : 'COMPLETE',
        pendingProfileFields: profileCompletionData?.profileCompletionStatus === 'INCOMPLETE' ? (profileCompletionData?.pendingProfileFields || []) : [],
        pendingProfileNote: profileCompletionData?.profileCompletionStatus === 'INCOMPLETE' ? (profileCompletionData?.pendingProfileNote || '') : '',
        aadhaarNumber: request.data.aadhaarNumber || subData.aadhaarNumber || null,
        panNumber: request.data.panNumber || subData.panNumber || null,
        uanNumber: request.data.uanNumber || subData.uanNumber || null,
        phoneNumber: request.data.phoneNumber || subData.phoneNumber || null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        lastUpdated: new Date().toISOString()
    };

    const resolvedPasswordHash = request.data.passwordHash || subData.passwordHash || null;
    const resolvedIsDefaultPassword = request.data.isDefaultPassword !== undefined ? request.data.isDefaultPassword : (subData.isDefaultPassword || false);
    if (resolvedPasswordHash) {
        newEmployee.passwordHash = resolvedPasswordHash;
        newEmployee.isDefaultPassword = resolvedIsDefaultPassword;
    } else if (newEmployee.authProvider === 'manual') {
        const firstName = employeeName.split(' ')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
        let year = '123';
        const dataObj = subData.formData || {};
        for (const [key, val] of Object.entries(dataObj)) {
            if (typeof val === 'string' && val.match(/^\d{4}-\d{2}-\d{2}$/)) {
                const keyLower = key.toLowerCase();
                if (keyLower.includes('birth') || keyLower.includes('dob')) {
                    year = val.split('-')[0];
                    break;
                }
            }
        }
        if (year === '123') {
            for (const [key, val] of Object.entries(dataObj)) {
                if (typeof val === 'string' && val.match(/^\d{4}-\d{2}-\d{2}$/)) {
                    const y = parseInt(val.split('-')[0], 10);
                    if (y > 1950 && y < 2010) {
                        year = val.split('-')[0];
                        break;
                    }
                }
            }
        }
        const phoneOrAadhaar = request.data.phoneNumber || subData.phoneNumber || request.data.aadhaarNumber || subData.aadhaarNumber || '';
        const cleanSuffix = (phoneOrAadhaar || '').replace(/\D/g, '').slice(-4);
        const serverDefaultPassword = `${firstName}${year}${cleanSuffix ? '@' + cleanSuffix : ''}`;
        newEmployee.passwordHash = await hashPassword(serverDefaultPassword);
        newEmployee.isDefaultPassword = true;
    }

    if (customRecruiter) {
        newEmployee.recruitedBy = customRecruiter.id || null;
        newEmployee.recruitedByName = customRecruiter.name || null;
    }

    // Atomic batch
    const batch = db.batch();
    batch.set(empDocRef, newEmployee);

    // Update submission
    const historyEntry = {
        level: subData.currentLevel || 1,
        status: 'Approved',
        actionBy: token.name || 'Admin',
        actionByRole: token.roleId || 'Admin',
        comments: comments || '',
        timestamp: new Date().toISOString()
    };

    const subUpdates = {
        status: 'Approved',
        employeeId: cleanEmpId,
        formData: migratedProfileData,
        data: migratedProfileData,
        driveFolderName: newFolderName,
        applicantName: employeeName,
        joiningDate: resolvedJoiningDate,
        approvalHistory: [...(subData.approvalHistory || []), historyEntry],
        lastUpdated: new Date().toISOString()
    };
    if (profileCompletionData) {
        subUpdates.profileCompletionStatus = profileCompletionData.profileCompletionStatus;
        subUpdates.pendingProfileFields = profileCompletionData.pendingProfileFields || [];
        subUpdates.pendingProfileNote = profileCompletionData.pendingProfileNote || '';
        subUpdates.needsProfileCompletion = profileCompletionData.profileCompletionStatus === 'INCOMPLETE';
    }
    batch.update(subRef, subUpdates);

    // Link previous employee record if rehire
    if (subData.duplicateCheck?.matchType === 'EX_EMPLOYEE_REHIRE' && subData.duplicateCheck.matchedId) {
        const prevDoc = await resolveEmployeeDocAdmin(db, subData.duplicateCheck.matchedId);
        if (prevDoc && prevDoc.exists) {
            batch.update(prevDoc.ref, { rehiredAs: cleanEmpId });
        }
    }

    // Increment invite joined count if referral
    if (subData.inviteId) {
        const inviteRef = db.collection('referral_invites').doc(subData.inviteId);
        batch.update(inviteRef, { joined: admin.firestore.FieldValue.increment(1) });
    }

    // Append to audit_logs
    const auditRef = db.collection('audit_logs').doc();
    batch.set(auditRef, {
        action: 'APPROVAL',
        module: 'ONBOARDING',
        targetId: submissionId,
        actorId: uid,
        actorName: token.name || 'Admin',
        details: `Final approval for ${employeeName} (${submissionId}). Assigned Employee ID: ${cleanEmpId}`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    // In-app notification to employee
    const notifRef = db.collection('notifications').doc();
    batch.set(notifRef, {
        targetUserId: cleanEmpId,
        message: `Welcome to UDF! Your onboarding has been approved. Your Employee ID is ${cleanEmpId}.`,
        type: 'success',
        link: 'EMPLOYEE_DASHBOARD',
        read: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        timestamp: new Date().toISOString()
    });

    await batch.commit();

    console.log(`[approveOnboardingServer] Successfully approved submission ${submissionId} as ${cleanEmpId}`);
    return {
        success: true,
        submissionId,
        employeeId: cleanEmpId
    };
});

exports.relieveEmployeeServer = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'You must be logged in to relieve employees.');
    }

    const {
        employeeId,
        relievingDate,
        reason,
        remarks
    } = request.data || {};

    if (!employeeId || typeof employeeId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'employeeId is required.');
    }
    if (!relievingDate || typeof relievingDate !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'relievingDate is required.');
    }

    const db = admin.firestore();
    const uid = request.auth.uid;
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'super-admin';
    const permissions = Array.isArray(token.permissions) ? token.permissions : [];

    // Verify permission: RESIGNATIONS_APPROVE, DELETE_EMPLOYEE, or SuperAdmin
    if (!isSuperAdmin && !permissions.includes('RESIGNATIONS_APPROVE') && !permissions.includes('DELETE_EMPLOYEE')) {
        const saSnap = await db.collection('staff_accounts').doc(uid).get();
        if (saSnap.exists && (saSnap.data().isDisabled === true || saSnap.data().isActive === false)) {
            throw new functions.https.HttpsError('permission-denied', 'Account is disabled or inactive.');
        }
        const roleId = saSnap.exists ? saSnap.data().roleId : null;
        let allowed = roleId === 'role-super-admin';
        if (!allowed && roleId) {
            const roleSnap = await db.collection('roles').doc(roleId).get();
            if (roleSnap.exists && Array.isArray(roleSnap.data().permissions)) {
                allowed = roleSnap.data().permissions.includes('RESIGNATIONS_APPROVE') || roleSnap.data().permissions.includes('DELETE_EMPLOYEE');
            }
        }
        if (!allowed) {
            throw new functions.https.HttpsError('permission-denied', 'Missing permission to relieve employees.');
        }
    }

    // Resolve employee document
    const empSnap = await resolveEmployeeDocAdmin(db, employeeId);
    if (!empSnap || !empSnap.exists) {
        throw new functions.https.HttpsError('not-found', `Employee "${employeeId}" not found.`);
    }
    const empData = empSnap.data();

    // Site authority check
    const siteId = empData.currentSiteId || '';
    if (siteId && !isSuperAdmin) {
        const hasGlobalScope = permissions.includes('EMPLOYEES_VIEW_SCOPE_ALL') ||
            permissions.includes('SUBMISSIONS_VIEW_SCOPE_ALL') ||
            permissions.includes('MANAGE_SITES') ||
            permissions.includes('MANAGE_ALL_SITES');
        const sitesManaged = Array.isArray(token.sitesManaged) ? token.sitesManaged : [];
        if (!hasGlobalScope && !sitesManaged.includes(siteId)) {
            const sitesSnap = await db.collection('settings').doc('sites').get();
            const siteList = sitesSnap.exists ? (sitesSnap.data().sites || []) : [];
            const targetSite = siteList.find(s => s && s.id === siteId);
            const supIds = targetSite && Array.isArray(targetSite.supervisorIds) ? targetSite.supervisorIds : (targetSite ? [targetSite.supervisorId] : []);
            if (!supIds.includes(uid)) {
                throw new functions.https.HttpsError('permission-denied', `You do not have management authority for site "${siteId}".`);
            }
        }
    }

    const cleanReason = reason || 'Resignation';
    const cleanRemarks = remarks || '';

    const batch = db.batch();

    // 1. Mark employee record relieved
    batch.update(empSnap.ref, {
        isActive: false,
        status: 'Relieved',
        isRelieved: true,
        relievingDate,
        relievingReason: cleanReason,
        relievingRemarks: cleanRemarks,
        relievedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // 2. Sync to onboarding_submissions
    const subSnap = await resolveSubmissionDocAdmin(db, empData.employeeId, empSnap.id);
    if (subSnap && subSnap.exists) {
        batch.update(subSnap.ref, {
            isActive: false,
            status: 'Relieved',
            isRelieved: true,
            relievingDate,
            relievingReason: cleanReason,
            relievingRemarks: cleanRemarks
        });
    }

    // 3. Disable Firebase Auth account if linked UID exists
    const linkedUid = empData.linkedUid || empData.uid;
    if (linkedUid && linkedUid !== 'none' && linkedUid.length > 5) {
        try {
            await admin.auth().updateUser(linkedUid, { disabled: true });
            console.log(`[relieveEmployeeServer] Disabled Firebase Auth user ${linkedUid} for ${empData.employeeId}`);
        } catch (authErr) {
            console.warn(`[relieveEmployeeServer] Could not disable Firebase Auth user ${linkedUid}:`, authErr.message);
        }
    }

    // 4. Append to audit_logs
    const auditRef = db.collection('audit_logs').doc();
    batch.set(auditRef, {
        action: 'STATUS_CHANGE',
        module: 'EMPLOYEES',
        targetId: empData.employeeId || empSnap.id,
        actorId: uid,
        actorName: token.name || 'Admin',
        details: `Relieved employee ${empData.applicantName || empData.employeeId} (${empData.employeeId || empSnap.id}) on ${relievingDate}. Reason: ${cleanReason}`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    // 5. In-app notification
    const notifRef = db.collection('notifications').doc();
    batch.set(notifRef, {
        targetUserId: empData.employeeId || empSnap.id,
        message: `Your employment has been relieved effective ${relievingDate}. Reason: ${cleanReason}.`,
        type: 'info',
        link: 'EMPLOYEE_DASHBOARD',
        read: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        timestamp: new Date().toISOString()
    });

    await batch.commit();

    console.log(`[relieveEmployeeServer] Successfully relieved employee ${empData.employeeId || empSnap.id} on ${relievingDate}`);
    return {
        success: true,
        employeeId: empData.employeeId || empSnap.id,
        relievingDate
    };
});

exports.rejoinEmployeeServer = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'You must be logged in to rejoin employees.');
    }

    const {
        employeeId,
        newEmployeeId,
        rejoinDate,
        siteId,
        siteName,
        subUnitId,
        subUnitName,
        designation,
        foldersToCopy
    } = request.data || {};

    if (!employeeId || typeof employeeId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'employeeId is required.');
    }
    if (!rejoinDate || typeof rejoinDate !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'rejoinDate is required.');
    }

    const db = admin.firestore();
    const uid = request.auth.uid;
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'super-admin';
    const permissions = Array.isArray(token.permissions) ? token.permissions : [];

    // Verify permission: SUBMISSIONS_APPROVE or SuperAdmin
    if (!isSuperAdmin && !permissions.includes('SUBMISSIONS_APPROVE')) {
        throw new functions.https.HttpsError('permission-denied', 'Missing permission to rejoin employees.');
    }

    // Resolve original employee document
    const origEmpSnap = await resolveEmployeeDocAdmin(db, employeeId);
    if (!origEmpSnap || !origEmpSnap.exists) {
        throw new functions.https.HttpsError('not-found', `Original employee record "${employeeId}" not found.`);
    }
    const origData = origEmpSnap.data();

    const resolvedSiteId = siteId || origData.currentSiteId || 'Unassigned';
    if (!isSuperAdmin && resolvedSiteId && resolvedSiteId !== 'Unassigned') {
        const hasGlobalScope = permissions.includes('EMPLOYEES_VIEW_SCOPE_ALL') ||
            permissions.includes('SUBMISSIONS_VIEW_SCOPE_ALL') ||
            permissions.includes('MANAGE_SITES') ||
            permissions.includes('MANAGE_ALL_SITES');
        const sitesManaged = Array.isArray(token.sitesManaged) ? token.sitesManaged : [];
        if (!hasGlobalScope && !sitesManaged.includes(resolvedSiteId)) {
            throw new functions.https.HttpsError('permission-denied', `You do not have management authority for site "${resolvedSiteId}".`);
        }
    }
    const resolvedSiteName = siteName || origData.siteName || 'N/A';
    const resolvedDesignation = designation || origData.designation || 'Staff';
    const applicantName = origData.applicantName || 'Unknown';

    const cleanNewId = (newEmployeeId && typeof newEmployeeId === 'string' && newEmployeeId.trim()) 
        ? newEmployeeId.trim().toUpperCase() 
        : null;

    // PATH A: Re-hire with a NEW Employee ID
    if (cleanNewId && cleanNewId !== (origData.employeeId || origEmpSnap.id).toUpperCase()) {
        // Check if new Employee ID is already taken
        const [empDocCheck, empFieldCheck, subFieldCheck] = await Promise.all([
            db.collection('employees').doc(cleanNewId).get(),
            db.collection('employees').where('employeeId', '==', cleanNewId).limit(1).get(),
            db.collection('onboarding_submissions').where('employeeId', '==', cleanNewId).limit(1).get()
        ]);
        if (empDocCheck.exists || !empFieldCheck.empty || !subFieldCheck.empty) {
            throw new functions.https.HttpsError('already-exists', `Employee ID "${cleanNewId}" is already taken.`);
        }

        const initialAssignment = {
            id: db.collection('_').doc().id,
            siteId: resolvedSiteId,
            subUnitId: subUnitId || null,
            designation: resolvedDesignation,
            type: 'PRIMARY',
            joiningDate: rejoinDate,
            status: 'Active'
        };

        const newFolderName = `${cleanNewId} - ${applicantName}`;
        const newEmpRef = db.collection('employees').doc(cleanNewId);

        const hasJoiningDocs = Array.isArray(foldersToCopy) && foldersToCopy.includes("Joining Documents");
        const profileStatus = hasJoiningDocs ? 'approved' : 'waiting_for_employee';
        const needsCompletion = !hasJoiningDocs;

        const newEmployeeData = {
            ...origData,
            uid: '',
            employeeId: cleanNewId,
            portalId: cleanNewId,
            isActive: true,
            isRelieved: false,
            isBlocked: false,
            joiningDate: rejoinDate,
            originalJoiningDate: rejoinDate,
            currentSiteId: resolvedSiteId,
            siteName: resolvedSiteName,
            subUnitId: subUnitId || null,
            subUnitName: subUnitName || null,
            designation: resolvedDesignation,
            activeAssignments: [initialAssignment],
            assignedSiteIds: [resolvedSiteId],
            assignmentHistory: [],
            employmentHistory: [],
            driveFolderName: newFolderName,
            needsProfileCompletion: needsCompletion,
            profileStatus: profileStatus,
            importedVia: 'rejoin',
            previousEmployeeId: origData.employeeId || origEmpSnap.id,
            leaveBalance: {
                casual: 12,
                sick: 7,
                privilege: 15
            },
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            lastUpdated: new Date().toISOString()
        };

        delete newEmployeeData.relievingDate;
        delete newEmployeeData.relievingReason;
        delete newEmployeeData.relievingRemarks;
        delete newEmployeeData.relievedAt;

        const batch = db.batch();

        // 1. Create new employee record
        batch.set(newEmpRef, newEmployeeData);

        // 2. Link rehiredAs on original record
        batch.update(origEmpSnap.ref, {
            rehiredAs: cleanNewId,
            lastUpdated: new Date().toISOString()
        });

        // 3. Append to audit_logs
        const auditRef = db.collection('audit_logs').doc();
        batch.set(auditRef, {
            action: 'STATUS_CHANGE',
            module: 'EMPLOYEES',
            targetId: cleanNewId,
            actorId: uid,
            actorName: token.name || 'Admin',
            details: `Rejoined employee ${applicantName} as ${cleanNewId} (previous ID: ${origData.employeeId || origEmpSnap.id}) at ${resolvedSiteName} on ${rejoinDate}`,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        // 4. In-app notification
        const notifRef = db.collection('notifications').doc();
        batch.set(notifRef, {
            targetUserId: cleanNewId,
            message: `Welcome back to UDF! You have been rejoined as ${cleanNewId} at ${resolvedSiteName}.`,
            type: 'success',
            link: 'EMPLOYEE_DASHBOARD',
            read: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            timestamp: new Date().toISOString()
        });

        await batch.commit();

        console.log(`[rejoinEmployeeServer] Successfully rejoined ${employeeId} as ${cleanNewId}`);
        return {
            success: true,
            isNewRecord: true,
            previousEmployeeId: employeeId,
            newEmployeeId: cleanNewId
        };
    }

    // PATH B: Standard Rejoin (reactivate existing employee record)
    const historyEntry = {
        joiningDate: origData.joiningDate || new Date().toISOString(),
        relievingDate: origData.relievingDate || new Date().toISOString(),
        relievingReason: origData.relievingReason || 'Other'
    };

    const newAssignment = {
        id: db.collection('_').doc().id,
        siteId: resolvedSiteId,
        subUnitId: subUnitId || null,
        designation: resolvedDesignation,
        type: 'PRIMARY',
        joiningDate: rejoinDate,
        status: 'Active'
    };

    const batch = db.batch();

    // 1. Reactivate existing employee record
    batch.update(origEmpSnap.ref, {
        isActive: true,
        status: 'Active',
        isRelieved: false,
        isBlocked: false,
        relievingDate: admin.firestore.FieldValue.delete(),
        relievingReason: admin.firestore.FieldValue.delete(),
        relievingRemarks: admin.firestore.FieldValue.delete(),
        relievedAt: admin.firestore.FieldValue.delete(),
        joiningDate: rejoinDate,
        originalJoiningDate: origData.originalJoiningDate || origData.joiningDate || rejoinDate,
        currentSiteId: resolvedSiteId,
        siteName: resolvedSiteName,
        subUnitId: subUnitId || null,
        subUnitName: subUnitName || null,
        designation: resolvedDesignation,
        employmentHistory: [...(origData.employmentHistory || []), historyEntry],
        activeAssignments: [newAssignment],
        assignmentHistory: [...(origData.assignmentHistory || []), newAssignment],
        assignedSiteIds: [resolvedSiteId],
        lastUpdated: new Date().toISOString()
    });

    // 2. Sync to submission doc if exists
    const subSnap = await resolveSubmissionDocAdmin(db, origData.employeeId, origEmpSnap.id);
    if (subSnap && subSnap.exists) {
        batch.update(subSnap.ref, {
            isActive: true,
            status: 'Approved',
            isRelieved: false,
            relievingDate: admin.firestore.FieldValue.delete(),
            relievingReason: admin.firestore.FieldValue.delete(),
            relievingRemarks: admin.firestore.FieldValue.delete(),
            lastUpdated: new Date().toISOString()
        });
    }

    // 3. Re-enable Firebase Auth user if disabled
    const linkedUid = origData.linkedUid || origData.uid;
    if (linkedUid && linkedUid !== 'none' && linkedUid.length > 5) {
        try {
            await admin.auth().updateUser(linkedUid, { disabled: false });
            console.log(`[rejoinEmployeeServer] Re-enabled Firebase Auth user ${linkedUid} for ${origData.employeeId}`);
        } catch (authErr) {
            console.warn(`[rejoinEmployeeServer] Could not re-enable Auth user ${linkedUid}:`, authErr.message);
        }
    }

    // 4. Audit log
    const auditRef = db.collection('audit_logs').doc();
    batch.set(auditRef, {
        action: 'STATUS_CHANGE',
        module: 'EMPLOYEES',
        targetId: origData.employeeId || origEmpSnap.id,
        actorId: uid,
        actorName: token.name || 'Admin',
        details: `Rejoined employee ${applicantName} (${origData.employeeId || origEmpSnap.id}) at ${resolvedSiteName} on ${rejoinDate}`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    // 5. Notification
    const notifRef = db.collection('notifications').doc();
    batch.set(notifRef, {
        targetUserId: origData.employeeId || origEmpSnap.id,
        message: `Welcome back to UDF! Your account has been reactivated at ${resolvedSiteName}.`,
        type: 'success',
        link: 'EMPLOYEE_DASHBOARD',
        read: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        timestamp: new Date().toISOString()
    });

    await batch.commit();

    console.log(`[rejoinEmployeeServer] Successfully reactivated employee ${origData.employeeId || origEmpSnap.id}`);
    return {
        success: true,
        isNewRecord: false,
        employeeId: origData.employeeId || origEmpSnap.id,
        rejoinDate
    };
});

// ─────────────────────────────────────────────────────────────────────────────
// CLOUD-6: IMMUTABLE AUDIT TRAIL & SECURE GAMIFICATION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

exports.logClientAuditEvent = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to log audit events.');
    }

    const { action, module, details, targetId } = request.data || {};
    if (!action || !module || !details) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing action, module, or details.');
    }

    const uid = request.auth.uid;
    const token = request.auth.token || {};

    // SEC-12: Only verified staff and admins can write to corporate audit logs
    const isStaffOrAdmin = token.isAdmin || token.isSuperAdmin || (token.roleId && token.roleId !== 'none' && token.roleId !== 'role-security-guard');
    if (!isStaffOrAdmin) {
        throw new functions.https.HttpsError('permission-denied', 'Only staff and administrators can record audit log events.');
    }

    const actorName = token.name || token.email || 'Staff';
    const actorRole = token.roleId || (token.isSuperAdmin ? 'SuperAdmin' : 'Staff');

    // Extract client IP and user agent
    const rawReq = request.rawRequest || {};
    const ip = rawReq.ip || (rawReq.headers && rawReq.headers['x-forwarded-for']) || 'unknown';
    const userAgent = (rawReq.headers && rawReq.headers['user-agent']) || 'unknown';

    const db = admin.firestore();
    const docRef = db.collection('audit_logs').doc();

    const entry = {
        action: String(action).toUpperCase(),
        actionType: String(action).toUpperCase(),
        targetModule: String(module).toUpperCase(),
        details: String(details),
        targetId: targetId ? String(targetId) : null,
        actorId: uid,
        actorName,
        actorRole,
        clientIp: String(ip).split(',')[0].trim(),
        userAgent: String(userAgent).substring(0, 200),
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    };

    await docRef.set(entry);

    return { success: true, logId: docRef.id };
});

exports.completeTrainingQuizServer = secureOnCall(async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to submit quiz answers.');
    }

    const uid = request.auth.uid;
    const { questionId, selectedAnswer, quizDate } = request.data || {};

    if (!selectedAnswer) {
        throw new functions.https.HttpsError('invalid-argument', 'selectedAnswer is required.');
    }

    const db = admin.firestore();
    // SEC-10: Pinned strictly to server date to prevent past/future point farming
    const today = new Date().toISOString().split('T')[0];

    // 1. Rate-limit / Duplicate check: Has this user already completed today's quiz?
    const existingLogSnap = await db.collection('gamification_logs')
        .where('userId', '==', uid)
        .where('type', '==', 'QUIZ')
        .where('date', '==', today)
        .limit(1)
        .get();

    if (!existingLogSnap.empty) {
        throw new functions.https.HttpsError('already-exists', 'You have already completed the daily quiz today.');
    }

    // 2. Fetch gamification rules from settings/gamification_rules
    const rulesSnap = await db.collection('settings').doc('gamification_rules').get();
    const rulesData = rulesSnap.exists ? rulesSnap.data() : {};
    const quizPoints = rulesData.quizPoints ?? 5;

    // 3. Verify answer if question defined
    let correctAnswer = null;
    if (questionId) {
        const quizDoc = await db.collection('safety_quizzes').doc(questionId).get();
        if (quizDoc.exists) {
            correctAnswer = quizDoc.data().correctAnswer;
        }
    }
    if (!correctAnswer && rulesData.dailyQuiz && rulesData.dailyQuiz.correctAnswer) {
        correctAnswer = rulesData.dailyQuiz.correctAnswer;
    }

    if (!correctAnswer) {
        throw new functions.https.HttpsError('failed-precondition', 'Quiz question or correct answer not found.');
    }

    const isCorrect = (selectedAnswer === correctAnswer);

    if (!isCorrect) {
        return {
            success: true,
            isCorrect: false,
            pointsEarned: 0,
            message: 'Incorrect answer. Better luck tomorrow!'
        };
    }

    // 4. Atomically update user_engagement points and write to gamification_logs
    let targetDocId = uid;
    const requestedId = (request.data && typeof request.data.targetUserId === 'string') ? request.data.targetUserId.trim() : '';
    if (requestedId && requestedId !== uid && !requestedId.includes('/')) {
        if (request.auth.token && request.auth.token.employeeId === requestedId) {
            targetDocId = requestedId;
        } else {
            const empCheck = await db.collection('employees').doc(requestedId).get();
            if (empCheck.exists && (empCheck.data().uid === uid || empCheck.data().linkedUid === uid)) {
                targetDocId = requestedId;
            }
        }
    }
    const engagementRef = db.collection('user_engagement').doc(targetDocId);
    const logRef = db.collection('gamification_logs').doc();

    const batch = db.batch();

    batch.set(engagementRef, {
        points: admin.firestore.FieldValue.increment(quizPoints),
        lastQuizDate: today,
        lastUpdated: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    if (targetDocId !== uid) {
        batch.set(db.collection('user_engagement').doc(uid), {
            points: admin.firestore.FieldValue.increment(quizPoints),
            lastQuizDate: today,
            lastUpdated: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
    }

    batch.set(logRef, {
        userId: uid,
        type: 'QUIZ',
        questionId: questionId || 'daily_safety_quiz',
        selectedAnswer,
        pointsAwarded: quizPoints,
        date: today,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    await batch.commit();

    console.log(`[completeTrainingQuizServer] Awarded ${quizPoints} pts to ${uid} for quiz on ${today}`);
    return {
        success: true,
        isCorrect: true,
        pointsEarned: quizPoints
    };
});

// ─────────────────────────────────────────────────────────────────────────────
// CLOUD-7: NATIVE GOOGLE DRIVE & GOOGLE SHEETS DIRECT INTEGRATION (googleapis)
// ─────────────────────────────────────────────────────────────────────────────
let _google = null;
function getGoogle() {
    if (!_google) {
        _google = require('googleapis').google;
    }
    return _google;
}
const GOOGLE_FORM_MAPPING = require('./googleFormMapping');

const ROOT_DRIVE_FOLDER_ID = "1XuFLT5v5s1ZSdugKr1XzT0AdYkL-QgBX";
const APPS_SCRIPT_FALLBACK_URL = process.env.APPS_SCRIPT_FALLBACK_URL || "https://script.google.com/macros/s/AKfycbz7dCyY67bQuB9OWdwZ8UvVK9EY1XOwtkpY6UKQks0MyHFZV4drG5L6eZK5HKPO0vI/exec";
const APPS_SCRIPT_SERVER_SECRET = process.env.APPS_SCRIPT_SERVER_SECRET || '';
const DRIVE_ROOT_FOLDERS = {
    PENDING: 'Pending Employees',
    ACTIVE: 'Active Employees',
    RELIEVED: 'Relieved Employees',
    RECYCLE_BIN: 'Recycle Bin',
    BLOCKED: 'Blocked Employees'
};

function getGoogleAuthClient() {
    const GoogleAuth = getGoogle().auth.GoogleAuth;
    return new GoogleAuth({
        scopes: [
            'https://www.googleapis.com/auth/drive',
            'https://www.googleapis.com/auth/drive.file',
            'https://www.googleapis.com/auth/spreadsheets'
        ]
    });
}

/**
 * Searches for or creates a folder inside a parent folder in Google Drive.
 */
async function getOrCreateDriveFolderServer(drive, parentId, folderName) {
    try {
        const q = `'${parentId}' in parents and name = '${folderName.replace(/'/g, "\\'")}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false`;
        const res = await drive.files.list({
            q,
            fields: 'files(id, name, webViewLink)',
            spaces: 'drive',
            pageSize: 1,
            supportsAllDrives: true,
            includeItemsFromAllDrives: true
        });

        if (res.data.files && res.data.files.length > 0) {
            return res.data.files[0];
        }

        const createRes = await drive.files.create({
            requestBody: {
                name: folderName,
                mimeType: 'application/vnd.google-apps.folder',
                parents: [parentId]
            },
            fields: 'id, name, webViewLink',
            supportsAllDrives: true
        });

        return createRes.data;
    } catch (err) {
        console.warn(`[getOrCreateDriveFolderServer] Error finding/creating folder "${folderName}":`, err.message);
        throw err;
    }
}

/**
 * Streams a file directly from Firebase Cloud Storage bucket to Google Drive using googleapis.
 * Direct streaming eliminates base64 memory overhead and client timeouts.
 * Keeps permissions restricted to domain/service account without ANYONE_WITH_LINK.
 */
async function streamStorageFileToDriveServer(drive, storagePath, targetFolderId, customName) {
    const bucket = admin.storage().bucket();
    const file = bucket.file(storagePath);
    const [exists] = await file.exists();
    if (!exists) {
        throw new Error(`File not found in storage: ${storagePath}`);
    }

    const [metadata] = await file.getMetadata();
    const mimeType = metadata.contentType || 'application/octet-stream';
    const fileName = customName || storagePath.split('/').pop() || 'document.pdf';

    // Stream directly from Cloud Storage without loading entire file into memory buffer
    const readStream = file.createReadStream();

    const uploadRes = await drive.files.create({
        requestBody: {
            name: fileName,
            parents: [targetFolderId]
        },
        media: {
            mimeType,
            body: readStream
        },
        fields: 'id, name, webViewLink, webContentLink',
        supportsAllDrives: true
    });

    return {
        fileId: uploadRes.data.id,
        url: uploadRes.data.webViewLink || `https://drive.google.com/file/d/${uploadRes.data.id}/view`
    };
}

/**
 * Fallback server-side upload to Apps Script proxy if GCP Service Account Drive permissions are not yet configured on the target drive folder.
 * Executed 100% server-to-server so client browser never deals with base64 memory bloat.
 */
async function uploadFileViaAppsScriptServer(storagePath, targetName, uniqueId, folderType) {
    const bucket = admin.storage().bucket();
    const file = bucket.file(storagePath);
    const [exists] = await file.exists();
    if (!exists) throw new Error(`File not found: ${storagePath}`);

    const [buffer] = await file.download();
    const base64 = buffer.toString('base64');
    const fileName = storagePath.split('/').pop() || 'document.pdf';

    if (!APPS_SCRIPT_SERVER_SECRET) {
        throw new Error('APPS_SCRIPT_SERVER_SECRET is not configured.');
    }

    const response = await fetch(APPS_SCRIPT_FALLBACK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain' },
        body: JSON.stringify({
            filename: fileName,
            base64: base64,
            employeeName: targetName,
            operationName: folderType || 'Joining Documents',
            uniqueId: uniqueId,
            token: APPS_SCRIPT_SERVER_SECRET
        })
    });

    const result = await response.json();
    if (!result.success) throw new Error(result.error || 'Apps Script fallback failed');
    return { fileId: result.fileId, url: result.url };
}

/**
 * Core engine to sync a submission or employee record to Google Drive and Google Sheets / Form.
 */
async function syncRecordToDriveAndSheetsCore(recordId, explicitType) {
    const db = admin.firestore();
    let targetDocRef = db.collection('employees').doc(recordId);
    let targetSnap = await targetDocRef.get();
    let isEmployee = true;

    if (!targetSnap.exists || explicitType === 'submission') {
        targetDocRef = db.collection('onboarding_submissions').doc(recordId);
        targetSnap = await targetDocRef.get();
        isEmployee = false;
        if (!targetSnap.exists) {
            throw new Error(`Record ${recordId} not found in Employees or Submissions.`);
        }
    }

    const recordData = targetSnap.data() || {};
    if (recordData.driveBackupStatus === 'in_progress') {
        console.log(`[CLOUD-7] Drive backup already in progress for ${recordId}, skipping duplicate invocation.`);
        return { success: true, status: 'already_in_progress' };
    }

    // Mark in progress atomically to block concurrent duplicate executions
    await targetDocRef.update({
        driveBackupStatus: 'in_progress',
        driveBackupStartedAt: new Date().toISOString()
    });

    const applicantName = recordData.applicantName || recordData.name || (recordData.profileData && recordData.profileData.personalDetails && recordData.profileData.personalDetails.fullName) || 'Candidate';
    const folderId = recordData.employeeId || recordData.portalId || recordId;
    const formData = recordData.formData || recordData.profileData || recordData.data || {};
    const isPending = !isEmployee || folderId.startsWith('SUB-') || folderId.startsWith('UDF-') || !recordData.isActive;

    console.log(`[CLOUD-7 syncRecordToDriveAndSheetsCore] Starting sync for ${applicantName} (${folderId})...`);

    // 1. Collect all Storage paths from form data
    const storagePaths = [];
    const extractPaths = (obj, prefix = '') => {
        if (!obj || typeof obj !== 'object') return;
        for (const key of Object.keys(obj)) {
            const val = obj[key];
            if (typeof val === 'string' && (val.startsWith('onboarding/') || val.startsWith('employees/'))) {
                storagePaths.push({ field: prefix ? `${prefix}.${key}` : key, path: val });
            } else if (typeof val === 'object' && val !== null) {
                if ('storagePath' in val && typeof val.storagePath === 'string') {
                    storagePaths.push({ field: prefix ? `${prefix}.${key}` : key, path: val.storagePath });
                } else {
                    extractPaths(val, prefix ? `${prefix}.${key}` : key);
                }
            }
        }
    };
    extractPaths(formData);

    const updatedFormData = JSON.parse(JSON.stringify(formData));
    let uploadedCount = 0;
    let folderUrl = '';
    const uploadedDriveUrls = {};

    // 2. Initialize native googleapis Drive
    let driveClient = null;
    let joiningDocsFolderId = null;
    try {
        const auth = getGoogleAuthClient();
        driveClient = getGoogle().drive({ version: 'v3', auth });

        // Find or create parent folder (Pending Employees vs Active Employees)
        const parentFolderName = isPending ? DRIVE_ROOT_FOLDERS.PENDING : DRIVE_ROOT_FOLDERS.ACTIVE;
        const parentFolder = await getOrCreateDriveFolderServer(driveClient, ROOT_DRIVE_FOLDER_ID, parentFolderName);

        // Find or create candidate folder
        const candidateFolderName = `${folderId} - ${applicantName}`;
        const candidateFolder = await getOrCreateDriveFolderServer(driveClient, parentFolder.id, candidateFolderName);
        folderUrl = candidateFolder.webViewLink || `https://drive.google.com/drive/folders/${candidateFolder.id}`;

        // Find or create "Joining Documents" subfolder
        const joiningFolder = await getOrCreateDriveFolderServer(driveClient, candidateFolder.id, 'Joining Documents');
        joiningDocsFolderId = joiningFolder.id;
        console.log(`[CLOUD-7] Native Google Drive folder ready: ${candidateFolderName} (${joiningDocsFolderId})`);
    } catch (authDriveErr) {
        console.warn(`[CLOUD-7] Native Drive folder access failed (will use server fallback):`, authDriveErr.message);
    }

    // 3. Stream each file to Google Drive
    for (const item of storagePaths) {
        try {
            const fileName = item.path.split('/').pop() || 'document.pdf';
            let driveRes = null;

            if (driveClient && joiningDocsFolderId) {
                try {
                    driveRes = await streamStorageFileToDriveServer(driveClient, item.path, joiningDocsFolderId, fileName);
                    console.log(`[CLOUD-7] ✅ Streamed ${fileName} natively via googleapis to Drive (${driveRes.url})`);
                } catch (streamErr) {
                    console.warn(`[CLOUD-7] Direct stream error for ${fileName}, attempting server fallback:`, streamErr.message);
                }
            }

            if (!driveRes) {
                driveRes = await uploadFileViaAppsScriptServer(item.path, applicantName, folderId, 'Joining Documents');
                console.log(`[CLOUD-7] ✅ Uploaded ${fileName} via server fallback to Drive (${driveRes.url})`);
            }

            if (driveRes && driveRes.url) {
                uploadedCount++;
                uploadedDriveUrls[item.field] = driveRes.url;

                // Update field in updatedFormData
                const fieldParts = item.field.split('.');
                let curr = updatedFormData;
                for (let i = 0; i < fieldParts.length - 1; i++) {
                    if (!curr[fieldParts[i]]) curr[fieldParts[i]] = {};
                    curr = curr[fieldParts[i]];
                }
                const lastKey = fieldParts[fieldParts.length - 1];
                if (curr[lastKey] && typeof curr[lastKey] === 'object') {
                    curr[lastKey].driveUrl = driveRes.url;
                } else {
                    curr[lastKey] = {
                        storagePath: item.path,
                        driveUrl: driveRes.url
                    };
                }
            }
        } catch (fileErr) {
            console.warn(`[CLOUD-7] Error uploading ${item.path} to Drive:`, fileErr.message);
        }
    }

    // 4. Update document in Firestore with Drive URLs
    const updatePayload = {
        driveBackupStatus: 'completed',
        driveBackupAt: new Date().toISOString(),
        ...(folderUrl ? { driveFolderUrl: folderUrl } : {})
    };
    if (isEmployee) {
        updatePayload.data = updatedFormData;
    } else {
        updatePayload.formData = updatedFormData;
    }
    await targetDocRef.update(updatePayload);
    console.log(`[CLOUD-7] Firestore doc ${recordId} updated with ${uploadedCount} Drive links.`);

    // 5. Append row to Google Sheets via sheets.spreadsheets.values.append or Google Form
    let sheetsSyncStatus = 'pending';
    try {
        sheetsSyncStatus = await appendSubmissionToSheetsServer(recordData, updatedFormData, folderUrl);
        await targetDocRef.update({
            googleFormSyncStatus: 'synced',
            googleFormSyncedAt: new Date().toISOString(),
            googleSheetsSyncStatus: sheetsSyncStatus
        });
    } catch (sheetErr) {
        console.warn(`[CLOUD-7] Sheets sync warning for ${recordId}:`, sheetErr.message);
    }

    return {
        success: true,
        count: uploadedCount,
        folderUrl,
        driveUrls: uploadedDriveUrls,
        sheetsStatus: sheetsSyncStatus
    };
}

/**
 * Appends candidate onboarding data to Google Sheets via sheets.spreadsheets.values.append()
 * Falls back to server-side Google Form submission if no spreadsheet ID is configured.
 */
async function appendSubmissionToSheetsServer(recordData, formData, driveFolderUrl) {
    const db = admin.firestore();

    // 0. Idempotency guard: Prevent duplicate rows in Google Sheets
    if (recordData.googleFormSyncStatus === 'synced' || recordData.googleFormSyncStatus === 'in_progress') {
        console.log(`[appendSubmissionToSheetsServer] Already synced or in progress for record, skipping duplicate sheet row.`);
        return 'already_synced';
    }

    const recDocId = recordData.portalId || recordData.employeeId || recordData.id;
    if (recDocId) {
        const collectionName = recordData.employeeId ? 'employees' : 'onboarding_submissions';
        await db.collection(collectionName).doc(recDocId).update({
            googleFormSyncStatus: 'in_progress'
        }).catch(() => {});
    }

    // 1. Check for configured Spreadsheet ID
    const portalConfigSnap = await db.collection('settings').doc('portal_config').get();
    const portalConfig = portalConfigSnap.exists ? portalConfigSnap.data() : {};
    const spreadsheetId = portalConfig.googleSpreadsheetId || portalConfig.spreadsheetId || process.env.GOOGLE_SPREADSHEET_ID;

    // Resolve Candidate Email
    let email = recordData.linkedGoogleEmail || recordData.email || null;
    if (!email && formData && typeof formData === 'object') {
        if (formData.email && typeof formData.email === 'string' && formData.email.includes('@')) {
            email = formData.email.trim();
        } else if (formData.personalEmail && typeof formData.personalEmail === 'string' && formData.personalEmail.includes('@')) {
            email = formData.personalEmail.trim();
        } else if (formData.applicantEmail && typeof formData.applicantEmail === 'string' && formData.applicantEmail.includes('@')) {
            email = formData.applicantEmail.trim();
        } else {
            for (const val of Object.values(formData)) {
                if (typeof val === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val.trim())) {
                    email = val.trim();
                    break;
                }
            }
        }
    }

    // Resolve Site Name
    const SITE_FIELD_ID = '52ae217b-2602-4337-a1cd-a1f9bd36a4b0';
    let resolvedSiteName = (recordData.siteName && typeof recordData.siteName === 'string') ? recordData.siteName.trim() : '';
    const rawSiteVal = formData[SITE_FIELD_ID];
    if (!resolvedSiteName && rawSiteVal && typeof rawSiteVal === 'string') {
        try {
            const sitesSnap = await db.collection('settings').doc('sites').get();
            if (sitesSnap.exists) {
                const sitesList = sitesSnap.data()?.sites || [];
                const matchedSite = sitesList.find(s =>
                    s.id === rawSiteVal ||
                    (s.name && s.name.trim().toLowerCase() === rawSiteVal.trim().toLowerCase())
                );
                if (matchedSite && matchedSite.name) {
                    resolvedSiteName = matchedSite.name;
                }
            }
        } catch (e) {}
    }

    // Build row values according to GOOGLE_FORM_MAPPING
    const textValues = {};
    for (const [portalId, mapping] of Object.entries(GOOGLE_FORM_MAPPING.TEXT_FIELDS)) {
        let val = formData[portalId];
        if (portalId === SITE_FIELD_ID && resolvedSiteName) {
            val = resolvedSiteName;
        }
        if (val !== undefined && val !== null) {
            if (typeof val === 'string') textValues[mapping.title] = val.trim();
            else if (typeof val === 'object') textValues[mapping.title] = val.driveUrl || val.storagePath || JSON.stringify(val);
            else textValues[mapping.title] = String(val).trim();
        } else {
            textValues[mapping.title] = '';
        }
    }

    const fileValues = {};
    for (const [portalId, mapping] of Object.entries(GOOGLE_FORM_MAPPING.FILE_FIELDS)) {
        const fileData = formData[portalId];
        let url = '';
        if (typeof fileData === 'string') {
            url = fileData;
        } else if (typeof fileData === 'object' && fileData !== null) {
            url = fileData.driveUrl || fileData.storagePath || '';
        }
        fileValues[mapping.title] = url;
    }

    // Attempt direct googleapis Sheets append if spreadsheetId is configured
    if (spreadsheetId) {
        try {
            const auth = getGoogleAuthClient();
            const sheets = getGoogle().sheets({ version: 'v4', auth });

            const row = [
                new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }),
                email || '',
                textValues['Name'] || recordData.applicantName || '',
                textValues['Contact Number'] || recordData.contactNumber || '',
                textValues['Gender'] || '',
                textValues['Date of Birth'] || '',
                textValues['Citizenship'] || '',
                textValues['Blood Group'] || '',
                textValues['Height'] || '',
                textValues['Identity Marks'] || '',
                textValues['Marital Status'] || '',
                textValues['Spouse Name'] || '',
                textValues['Qualification'] || '',
                textValues['Post of Apply'] || '',
                resolvedSiteName || textValues['Unit or Facility'] || '',
                textValues['Any Police Case'] || '',
                textValues['Previous Employment History'] || '',
                textValues['Previous Company & Experience'] || '',
                textValues['Present Address'] || '',
                textValues['Permanent Address'] || '',
                textValues['Reference Name'] || '',
                textValues['Reference Relationship'] || '',
                textValues['Reference Address'] || '',
                textValues['Reference Contact No'] || '',
                textValues['Father Name'] || '',
                textValues['Mother Name'] || '',
                textValues['Father Mobile Number'] || '',
                textValues['Mother Mobile Number'] || '',
                textValues['Aadhar Card No'] || '',
                textValues['PAN Card No'] || '',
                textValues['UAN No or EPFO'] || '',
                textValues['ESI No'] || '',
                textValues['PVC (Police Verification Certificate)'] || '',
                textValues['PVC Number (If YES)'] || '',
                textValues['Bank Name'] || '',
                textValues['Account No'] || '',
                textValues['IFSC Code'] || '',
                textValues['Branch Name'] || '',
                fileValues['Aadhar Card  (Front)'] || '',
                fileValues['Aadhar Card  (Back)'] || '',
                fileValues['PAN  Card'] || '',
                fileValues['Bank Passbook or Cheque'] || '',
                fileValues['SSC - 10th, INTER, DEGREE MEMO'] || '',
                fileValues['Photo'] || '',
                fileValues['PVC'] || '',
                fileValues['Electricity Bill'] || '',
                driveFolderUrl || ''
            ];

            await sheets.spreadsheets.values.append({
                spreadsheetId,
                range: 'Sheet1!A:Z',
                valueInputOption: 'USER_ENTERED',
                requestBody: {
                    values: [row]
                }
            });

            console.log(`[CLOUD-7] ✅ Appended row directly to Google Sheets (${spreadsheetId})`);
            return 'sheets_appended';
        } catch (sheetApiErr) {
            console.warn(`[CLOUD-7] Direct Sheets API append error:`, sheetApiErr.message);
        }
    }

    // Complementary / Fallback: Submit to Google Form / Apps Script Webhook server-side
    const fields = [];
    for (const [title, value] of Object.entries({ ...textValues, ...fileValues })) {
        if (value && String(value).trim() !== '') {
            fields.push({ title, value: String(value).trim() });
        }
    }
    if (email) {
        fields.push({ title: 'Email', value: email });
        fields.push({ title: 'Email Address', value: email });
        fields.push({ title: 'Email ID', value: email });
    }

    if (!APPS_SCRIPT_SERVER_SECRET) {
        console.warn(`[CLOUD-7] APPS_SCRIPT_SERVER_SECRET is not configured.`);
        return 'form_sync_not_configured';
    }

    try {
        const res = await fetch(APPS_SCRIPT_FALLBACK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain' },
            body: JSON.stringify({
                action: 'submit_to_form',
                fields,
                email: email || null,
                token: APPS_SCRIPT_SERVER_SECRET
            })
        });
        const formRes = await res.json();
        console.log(`[CLOUD-7] Server-side Form Sync Response:`, formRes);
        return formRes.success ? 'form_synced' : 'form_sync_failed';
    } catch (formErr) {
        console.warn(`[CLOUD-7] Server-side Form sync HTTP error:`, formErr.message);
        return 'form_sync_error';
    }
}

// Callable wrapper for syncEmployeeToGoogleDriveServer
exports.syncEmployeeToGoogleDriveServer = secureOnCall({ timeoutSeconds: 300, memory: '1GiB' }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to sync Drive files.');
    }

    // SEC-13: Only SuperAdmin can trigger heavy Google Drive sync
    const callerClaims = request.auth.token || {};
    if (callerClaims.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }
    let isSuperAdmin = callerClaims.isSuperAdmin === true || callerClaims.roleId === 'role-super-admin';
    if (!isSuperAdmin) {
        const db = admin.firestore();
        const [uSnap, sSnap] = await Promise.all([
            db.collection('users').doc(request.auth.uid).get(),
            db.collection('staff_accounts').doc(request.auth.uid).get()
        ]);
        const prof = (sSnap.exists ? sSnap.data() : (uSnap.exists ? uSnap.data() : null)) || {};
        if (prof.isDisabled === true || prof.isActive === false) {
            throw new functions.https.HttpsError('permission-denied', 'Account is disabled or inactive.');
        }
        if (prof.roleId === 'role-super-admin' || prof.type === 'Admin' || (Array.isArray(prof.roles) && prof.roles.includes('super-admin'))) {
            isSuperAdmin = true;
        }
    }

    if (!isSuperAdmin) {
        throw new functions.https.HttpsError('permission-denied', 'Only SuperAdmin can trigger Google Drive file synchronization.');
    }

    const { recordId, targetType } = request.data || {};
    if (!recordId) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing recordId.');
    }

    try {
        return await syncRecordToDriveAndSheetsCore(recordId, targetType);
    } catch (err) {
        console.error(`[syncEmployeeToGoogleDriveServer] Error syncing ${recordId}:`, err);
        throw new functions.https.HttpsError('internal', err.message || 'Drive sync failed');
    }
});

// Callable wrapper for syncSubmissionToSheetsServer
exports.syncSubmissionToSheetsServer = secureOnCall({ timeoutSeconds: 120 }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to sync submission.');
    }

    // SEC-13: Only SuperAdmin can trigger Google Sheets sync
    const callerClaims = request.auth.token || {};
    if (callerClaims.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }
    let isSuperAdmin = callerClaims.isSuperAdmin === true || callerClaims.roleId === 'role-super-admin';
    if (!isSuperAdmin) {
        const db = admin.firestore();
        const [uSnap, sSnap] = await Promise.all([
            db.collection('users').doc(request.auth.uid).get(),
            db.collection('staff_accounts').doc(request.auth.uid).get()
        ]);
        const prof = (sSnap.exists ? sSnap.data() : (uSnap.exists ? uSnap.data() : null)) || {};
        if (prof.isDisabled === true || prof.isActive === false) {
            throw new functions.https.HttpsError('permission-denied', 'Account is disabled or inactive.');
        }
        if (prof.roleId === 'role-super-admin' || prof.type === 'Admin' || (Array.isArray(prof.roles) && prof.roles.includes('super-admin'))) {
            isSuperAdmin = true;
        }
    }

    if (!isSuperAdmin) {
        throw new functions.https.HttpsError('permission-denied', 'Only SuperAdmin can trigger Google Sheets synchronization.');
    }

    const { submissionId } = request.data || {};
    if (!submissionId) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing submissionId.');
    }

    try {
        const db = admin.firestore();
        const subSnap = await db.collection('onboarding_submissions').doc(submissionId).get();
        if (!subSnap.exists) {
            throw new functions.https.HttpsError('not-found', `Submission ${submissionId} not found.`);
        }
        const data = subSnap.data() || {};
        const formData = data.formData || data.data || {};
        const folderUrl = data.driveFolderUrl || '';

        const status = await appendSubmissionToSheetsServer(data, formData, folderUrl);
        await subSnap.ref.update({
            googleFormSyncStatus: 'synced',
            googleFormSyncedAt: new Date().toISOString(),
            googleSheetsSyncStatus: status
        });

        return { success: true, status };
    } catch (err) {
        console.error(`[syncSubmissionToSheetsServer] Error syncing ${submissionId}:`, err);
        throw new functions.https.HttpsError('internal', err.message || 'Sheets sync failed');
    }
});

/**
 * SEC-05: Rate-limited draft submission retrieval with 24-hour IP ban on brute-force attempts.
 */
exports.getDraftSubmissionSecure = secureOnCall(async (request) => {
    const rawIp = (request.rawRequest && (
        request.rawRequest.headers['cf-connecting-ip'] || 
        request.rawRequest.headers['x-forwarded-for'] || 
        request.rawRequest.ip
    )) || 'unknown_ip';

    const clientIp = String(rawIp).split(',')[0].trim().replace(/[^a-zA-Z0-9_-]/g, '_');
    const db = admin.firestore();
    const now = Date.now();
    const ONE_DAY_MS = 24 * 60 * 60 * 1000;

    const blockRef = db.collection('ip_rate_limits').doc(clientIp);
    const blockSnap = await blockRef.get();

    if (blockSnap.exists) {
        const blockData = blockSnap.data() || {};
        if (blockData.blockedUntil && blockData.blockedUntil > now) {
            const hoursLeft = Math.ceil((blockData.blockedUntil - now) / (60 * 60 * 1000));
            console.warn(`[SECURITY] Blocked IP ${clientIp} attempted to access draft while banned.`);
            throw new functions.https.HttpsError(
                'resource-exhausted',
                `Access temporarily denied. This IP address is blocked for ${hoursLeft} more hour(s) due to repeated invalid draft attempts.`
            );
        }
    }

    const { draftId } = request.data || {};
    if (!draftId || typeof draftId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'draftId is required.');
    }

    const cleanId = draftId.trim();
    let docSnap = await db.collection('draft_submissions').doc(cleanId).get();
    if (!docSnap.exists && cleanId.toUpperCase() !== cleanId) {
        docSnap = await db.collection('draft_submissions').doc(cleanId.toUpperCase()).get();
    }

    if (!docSnap.exists) {
        const previousAttempts = (blockSnap.exists ? (blockSnap.data().failedAttempts || 0) : 0);
        const failedAttempts = previousAttempts + 1;

        if (failedAttempts >= 5) {
            await blockRef.set({
                clientIp,
                failedAttempts,
                blockedUntil: now + ONE_DAY_MS,
                lastAttemptAt: admin.firestore.FieldValue.serverTimestamp(),
                reason: 'Brute-force draft guessing'
            });
            console.warn(`[SECURITY] IP ${clientIp} BANNED for 24 hours after ${failedAttempts} failed draft lookups.`);
            throw new functions.https.HttpsError(
                'resource-exhausted',
                'Too many invalid attempts. Your IP address has been blocked for 24 hours.'
            );
        } else {
            await blockRef.set({
                clientIp,
                failedAttempts,
                lastAttemptAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            throw new functions.https.HttpsError('not-found', `Draft not found. (Attempt ${failedAttempts} of 5)`);
        }
    }

    // Success - clear any previous failed attempt counter
    if (blockSnap.exists && blockSnap.data().failedAttempts > 0) {
        await blockRef.delete().catch(() => {});
    }

    const draftData = docSnap.data() || {};
    if (request.auth && request.auth.uid && !draftData.isGoogleDraft && draftData.ownerUid !== request.auth.uid) {
        await docSnap.ref.update({
            activeSessionUid: request.auth.uid,
            lastUpdated: new Date().toISOString()
        }).catch(() => {});
        draftData.activeSessionUid = request.auth.uid;
    }
    return { id: docSnap.id, data: draftData };
});

// ─────────────────────────────────────────────────────────────────────────────
// CLOUD-8: ENTERPRISE OPERATIONS (PERMANENT DELETE, RECYCLE RESTORE, SITE DELETE, PROMOTION, BULK IMPORT)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 1. permanentDeleteEmployeeServer
 * Cascading permanent deletion of an employee, all linked records across 8 collections,
 * Cloud Storage files, and Google Drive folders.
 */
exports.permanentDeleteEmployeeServer = secureOnCall({ timeoutSeconds: 300, memory: '1GiB' }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to delete employee records.');
    }
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const { employeeId, employeeName, deep } = request.data || {};
    if (!employeeId || typeof employeeId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'employeeId is required.');
    }

    const db = admin.firestore();
    const uid = request.auth.uid;
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'role-super-admin';
    const permissions = Array.isArray(token.permissions) ? token.permissions : [];

    // Authorization: SuperAdmin or DELETE_EMPLOYEE / SUBMISSIONS_APPROVE
    if (!isSuperAdmin && !permissions.includes('DELETE_EMPLOYEE') && !permissions.includes('SUBMISSIONS_APPROVE')) {
        const saSnap = await db.collection('staff_accounts').doc(uid).get();
        if (saSnap.exists && (saSnap.data().isDisabled === true || saSnap.data().isActive === false)) {
            throw new functions.https.HttpsError('permission-denied', 'Account is disabled or inactive.');
        }
        const roleId = saSnap.exists ? saSnap.data().roleId : null;
        let allowed = roleId === 'role-super-admin';
        if (!allowed && roleId) {
            const roleSnap = await db.collection('roles').doc(roleId).get();
            if (roleSnap.exists && Array.isArray(roleSnap.data().permissions)) {
                allowed = roleSnap.data().permissions.includes('DELETE_EMPLOYEE') || roleSnap.data().permissions.includes('SUBMISSIONS_APPROVE');
            }
        }
        if (!allowed) {
            throw new functions.https.HttpsError('permission-denied', 'Missing permission to permanently delete employee records.');
        }
    }

    // Resolve employee document
    const empSnap = await resolveEmployeeDocAdmin(db, employeeId);
    let subSnap = null;
    if (!empSnap || !empSnap.exists) {
        subSnap = await resolveSubmissionDocAdmin(db, employeeId, employeeId);
        if (!subSnap || !subSnap.exists) {
            throw new functions.https.HttpsError('not-found', `Employee or Submission "${employeeId}" not found.`);
        }
    }

    const empData = empSnap && empSnap.exists ? empSnap.data() : {};
    const subData = subSnap && subSnap.exists ? subSnap.data() : {};
    const siteId = empData.currentSiteId || subData.siteId || '';

    // Site authority check for non-SuperAdmins
    if (siteId && !isSuperAdmin) {
        const hasGlobalScope = permissions.includes('EMPLOYEES_VIEW_SCOPE_ALL') ||
            permissions.includes('SUBMISSIONS_VIEW_SCOPE_ALL') ||
            permissions.includes('MANAGE_SITES') ||
            permissions.includes('MANAGE_ALL_SITES');
        const sitesManaged = Array.isArray(token.sitesManaged) ? token.sitesManaged : [];
        if (!hasGlobalScope && !sitesManaged.includes(siteId)) {
            throw new functions.https.HttpsError('permission-denied', `You do not have management authority for site "${siteId}".`);
        }
    }

    // Collect all associated identifiers
    const allIds = new Set();
    [employeeId, empSnap?.id, empData.employeeId, empData.portalId, empData.uid, empData.linkedUid, subSnap?.id, subData.employeeId, subData.portalId, subData.uid, subData.linkedUid]
        .filter(id => id && typeof id === 'string')
        .forEach(id => allIds.add(id.trim()));

    const idList = Array.from(allIds);
    const resolvedName = employeeName || empData.applicantName || subData.applicantName || 'Employee';

    // 1. Storage & Drive Deletion if deep !== false
    if (deep !== false) {
        try {
            const bucket = admin.storage().bucket();
            const storageFolders = new Set();
            idList.forEach(id => {
                storageFolders.add(`employees/${id}/`);
                storageFolders.add(`onboarding/${id}/`);
                storageFolders.add(`draft_submissions/${id}/`);
            });

            await Promise.all(Array.from(storageFolders).map(prefix => 
                bucket.deleteFiles({ prefix, force: true }).catch(err => console.warn(`Storage delete failed for ${prefix}:`, err.message))
            ));
        } catch (storageErr) {
            console.warn(`[permanentDeleteEmployeeServer] Storage deletion non-fatal error:`, storageErr.message);
        }

        // Drive deletion via fallback if configured
        if (APPS_SCRIPT_FALLBACK_URL && APPS_SCRIPT_SERVER_SECRET) {
            try {
                await fetch(APPS_SCRIPT_FALLBACK_URL, {
                    method: 'POST',
                    headers: { 'Content-Type': 'text/plain' },
                    body: JSON.stringify({
                        action: 'delete_folder',
                        employeeName: resolvedName,
                        uniqueId: employeeId,
                        token: APPS_SCRIPT_SERVER_SECRET
                    })
                }).catch(() => {});
            } catch (driveErr) {
                console.warn(`[permanentDeleteEmployeeServer] Drive delete non-fatal error:`, driveErr.message);
            }
        }
    }

    // 2. Cascading Delete associated request and operational records in batches
    let totalDeleted = 0;
    const collectionsToClean = [
        { name: 'leave_requests', field: 'employeeId' },
        { name: 'leave_requests', field: 'uid' },
        { name: 'resignations', field: 'employeeId' },
        { name: 'resignations', field: 'uid' },
        { name: 'account_updates', field: 'employeeId' },
        { name: 'account_updates', field: 'uid' },
        { name: 'attendance', field: 'userId' },
        { name: 'attendance', field: 'employeeId' },
        { name: 'disciplinary_actions', field: 'employeeId' },
        { name: 'disciplinary_actions', field: 'targetUserId' },
        { name: 'notifications', field: 'targetUserId' },
        { name: 'gamification_logs', field: 'userId' },
        { name: 'user_engagement', directId: true },
        { name: 'leave_balances', directId: true },
        { name: 'leave_balances', field: 'employeeId' }
    ];

    for (const target of collectionsToClean) {
        if (target.directId) {
            const batch = db.batch();
            let count = 0;
            for (const id of idList) {
                batch.delete(db.collection(target.name).doc(id));
                count++;
            }
            if (count > 0) {
                await batch.commit().catch(() => {});
                totalDeleted += count;
            }
        } else {
            for (const id of idList) {
                const qSnap = await db.collection(target.name).where(target.field, '==', id).get();
                if (!qSnap.empty) {
                    const batch = db.batch();
                    qSnap.docs.forEach(docSnap => batch.delete(docSnap.ref));
                    await batch.commit().catch(() => {});
                    totalDeleted += qSnap.size;
                }
            }
        }
    }

    // 3. Delete Primary Records
    const mainBatch = db.batch();
    for (const id of idList) {
        mainBatch.delete(db.collection('employees').doc(id));
        mainBatch.delete(db.collection('onboarding_submissions').doc(id));
    }
    await mainBatch.commit().catch(() => {});

    // 4. Server Audit Log
    await db.collection('audit_logs').add({
        action: 'PERMANENT_DELETE',
        category: 'EMPLOYEES',
        targetId: employeeId,
        targetName: resolvedName,
        actorId: uid,
        actorEmail: token.email || 'Admin',
        details: `Permanently deleted employee ${resolvedName} (${employeeId}) and ${totalDeleted} associated record(s).`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    }).catch(() => {});

    return {
        success: true,
        employeeId,
        resolvedName,
        deletedRecordsCount: totalDeleted
    };
});

/**
 * 2. restoreRecycleBinServer
 * Server-enforced restoration of items from Recycle Bin with validation and sanitization.
 */
exports.restoreRecycleBinServer = secureOnCall({ timeoutSeconds: 60 }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to restore records.');
    }
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const { recycleBinItemId } = request.data || {};
    if (!recycleBinItemId || typeof recycleBinItemId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'recycleBinItemId is required.');
    }

    const db = admin.firestore();
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'role-super-admin';
    const permissions = Array.isArray(token.permissions) ? token.permissions : [];

    const binSnap = await db.collection('recycle_bin').doc(recycleBinItemId).get();
    if (!binSnap.exists) {
        throw new functions.https.HttpsError('not-found', 'Record not found in Recycle Bin or already restored.');
    }

    const binItem = binSnap.data() || {};
    const { itemType, originalId, data, metadata } = binItem;

    // SEC-07: Restoring STAFF or ROLE documents is strictly SuperAdmin only
    if (['STAFF', 'ROLE'].includes(String(itemType || '').toUpperCase()) && !isSuperAdmin) {
        throw new functions.https.HttpsError('permission-denied', 'Only SuperAdmin can restore Staff accounts or Roles.');
    }

    const nowIso = new Date().toISOString();

    switch (String(itemType || '').toUpperCase()) {
        case 'SITE': {
            const sitesRef = db.collection('settings').doc('sites');
            const sitesSnap = await sitesRef.get();
            let existingSites = sitesSnap.exists ? (sitesSnap.data().sites || []) : [];
            const filtered = existingSites.filter(s => s && s.id !== originalId);
            const restoredSite = {
                ...(data || {}),
                id: originalId,
                isActive: true,
                restoredAt: nowIso
            };
            await sitesRef.set({ sites: [...filtered, restoredSite] }, { merge: true });

            // Restore linked vacancies if present
            if (metadata && Array.isArray(metadata.linkedVacancies)) {
                for (const vac of metadata.linkedVacancies) {
                    if (vac && vac.id) {
                        await db.collection('vacancies').doc(vac.id).set({
                            ...vac,
                            status: 'Open',
                            isDeleted: false,
                            restoredAt: nowIso
                        }, { merge: true }).catch(() => {});
                    }
                }
            }
            break;
        }

        case 'STAFF': {
            const staffRef = db.collection('staff_accounts').doc(originalId);
            await staffRef.set({
                ...(data || {}),
                id: originalId,
                isDisabled: false,
                isActive: true,
                status: 'Active',
                restoredAt: nowIso
            }, { merge: true });
            await computeAndApplyUserClaims(originalId).catch(() => {});
            break;
        }

        case 'EMPLOYEE': {
            const empRef = db.collection('employees').doc(originalId);
            await empRef.set({
                ...(data || {}),
                id: originalId,
                isActive: true,
                isDeleted: false,
                deletedAt: null,
                restoredAt: nowIso
            }, { merge: true });

            // Also re-activate onboarding_submissions if present
            const subRef = db.collection('onboarding_submissions').doc(originalId);
            const subSnap = await subRef.get();
            if (subSnap.exists) {
                await subRef.update({
                    isActive: true,
                    isDeleted: false,
                    deletedAt: null,
                    restoredAt: nowIso
                }).catch(() => {});
            }
            break;
        }

        case 'SUBMISSION': {
            const subRef = db.collection('onboarding_submissions').doc(originalId);
            await subRef.set({
                ...(data || {}),
                id: originalId,
                status: (data && data.status === 'Archived') ? 'Pending Review' : (data?.status || 'Pending Review'),
                isDeleted: false,
                deletedAt: null,
                restoredAt: nowIso
            }, { merge: true });
            break;
        }

        case 'ROLE': {
            await db.collection('roles').doc(originalId).set({
                ...(data || {}),
                id: originalId,
                restoredAt: nowIso
            }, { merge: true });
            break;
        }

        case 'VACANCY': {
            await db.collection('vacancies').doc(originalId).set({
                ...(data || {}),
                id: originalId,
                status: 'Open',
                isDeleted: false,
                restoredAt: nowIso
            }, { merge: true });
            break;
        }

        case 'DESIGNATION': {
            const portalConfigRef = db.collection('settings').doc('portal_config');
            const pcSnap = await portalConfigRef.get();
            const designations = pcSnap.exists ? (pcSnap.data().designations || []) : [];
            const desName = data?.name || originalId;
            if (!designations.includes(desName)) {
                designations.push(desName);
                await portalConfigRef.update({ designations });
            }
            break;
        }

        default: {
            throw new functions.https.HttpsError('invalid-argument', `Unknown itemType: "${itemType}".`);
        }
    }

    // Delete item from Recycle Bin
    await binSnap.ref.delete();

    // Server Audit Log
    await db.collection('audit_logs').add({
        action: 'RESTORE',
        category: 'RECYCLE_BIN',
        targetId: originalId,
        itemType,
        actorId: request.auth.uid,
        actorEmail: token.email || 'Admin',
        details: `Restored ${itemType} "${originalId}" from Recycle Bin.`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    }).catch(() => {});

    return {
        success: true,
        itemType,
        originalId,
        message: `Successfully restored ${itemType} "${originalId}".`
    };
});

/**
 * 3. deleteSiteServer
 * Server-enforced site deletion with dependency validation (guards, referral invites, pending onboarding).
 */
exports.deleteSiteServer = secureOnCall({ timeoutSeconds: 60 }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to delete a site.');
    }
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const { siteId, siteName } = request.data || {};
    if (!siteId || typeof siteId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'siteId is required.');
    }

    const db = admin.firestore();
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'role-super-admin';
    const permissions = Array.isArray(token.permissions) ? token.permissions : [];

    // Authorization: SuperAdmin or SITES_DELETE / MANAGE_SITES / SITES_MANAGE
    const hasSitePerm = isSuperAdmin || 
        permissions.includes('SITES_DELETE') || 
        permissions.includes('MANAGE_SITES') || 
        permissions.includes('SITES_MANAGE');

    if (!hasSitePerm) {
        throw new functions.https.HttpsError('permission-denied', 'Missing permission to delete sites.');
    }

    // 1. Dependency Check: Active employees assigned to site
    const [empBySiteId, empByCurrentSiteId] = await Promise.all([
        db.collection('employees').where('siteId', '==', siteId).get(),
        db.collection('employees').where('currentSiteId', '==', siteId).get()
    ]);

    const activeEmployees = new Set();
    [...empBySiteId.docs, ...empByCurrentSiteId.docs].forEach(d => {
        const ed = d.data();
        if (ed.isActive !== false && ed.status !== 'Relieved') {
            activeEmployees.add(d.id);
        }
    });

    if (activeEmployees.size > 0) {
        throw new functions.https.HttpsError(
            'failed-precondition',
            `Cannot delete "${siteName || siteId}". It still has ${activeEmployees.size} active employee(s) assigned.`
        );
    }

    // 2. Dependency Check: Active referral invites
    const inviteSnap = await db.collection('referral_invites')
        .where('siteId', '==', siteId)
        .where('status', '==', 'Active')
        .get();

    if (!inviteSnap.empty) {
        throw new functions.https.HttpsError(
            'failed-precondition',
            `Cannot delete "${siteName || siteId}" because it is linked to ${inviteSnap.size} active referral invite link(s). Revoke these invites first.`
        );
    }

    // 3. Dependency Check: Pending onboarding submissions
    const subSnap = await db.collection('onboarding_submissions')
        .where('siteId', '==', siteId)
        .get();

    const pendingSubs = subSnap.docs.filter(d => {
        const s = d.data().status;
        return (s === 'Pending' || s === 'Pending Review') && !d.data().deletedAt && !d.data().isDeleted;
    });

    if (pendingSubs.length > 0) {
        throw new functions.https.HttpsError(
            'failed-precondition',
            `Cannot delete "${siteName || siteId}" because it is linked to ${pendingSubs.length} pending onboarding application(s). Resolve or reject these submissions first.`
        );
    }

    // Read site record from settings/sites
    const sitesRef = db.collection('settings').doc('sites');
    const sitesSnap = await sitesRef.get();
    const siteList = sitesSnap.exists ? (sitesSnap.data().sites || []) : [];
    const targetSite = siteList.find(s => s && s.id === siteId);

    if (!targetSite) {
        throw new functions.https.HttpsError('not-found', `Site "${siteId}" not found in settings.`);
    }

    const resolvedSiteName = targetSite.name || siteName || siteId;

    // Archive any linked vacancies
    const vacSnap = await db.collection('vacancies').where('siteId', '==', siteId).get();
    const linkedVacancies = [];
    const batch = db.batch();

    vacSnap.docs.forEach(docSnap => {
        const vd = docSnap.data();
        linkedVacancies.push({ id: docSnap.id, ...vd });
        batch.update(docSnap.ref, {
            status: 'Closed',
            isDeleted: true,
            closedReason: `Site ${resolvedSiteName} deleted`,
            deletedAt: new Date().toISOString()
        });
    });

    // Remove site from settings/sites
    const updatedSites = siteList.filter(s => s && s.id !== siteId);
    batch.update(sitesRef, { sites: updatedSites });

    // Move to Recycle Bin
    const binRef = db.collection('recycle_bin').doc();
    batch.set(binRef, {
        itemType: 'SITE',
        originalId: siteId,
        title: resolvedSiteName,
        subtitle: `${targetSite.city || ''}, ${targetSite.state || ''}`.trim().replace(/^,\s*|,\s*$/g, ''),
        data: targetSite,
        metadata: {
            linkedVacancies
        },
        deletedAt: new Date().toISOString(),
        deletedBy: request.auth.uid,
        deletedByEmail: token.email || 'Admin',
        autoPurgeAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
    });

    // Server Audit Log
    const auditRef = db.collection('audit_logs').doc();
    batch.set(auditRef, {
        action: 'DELETE',
        category: 'SITES',
        targetId: siteId,
        targetName: resolvedSiteName,
        actorId: request.auth.uid,
        actorEmail: token.email || 'Admin',
        details: `Deleted site "${resolvedSiteName}" and archived ${linkedVacancies.length} linked vacancy(ies) to Recycle Bin.`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    await batch.commit();

    return {
        success: true,
        siteId,
        siteName: resolvedSiteName,
        message: `Site "${resolvedSiteName}" moved to Recycle Bin.`
    };
});

/**
 * 4. promoteEmployeeServer
 * Server-enforced employee designation promotion with site verification and official reference tracking.
 */
exports.promoteEmployeeServer = secureOnCall({ timeoutSeconds: 60 }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to promote an employee.');
    }
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const { employeeId, newDesignation, effectiveDate, newSiteId, newSiteName, referenceNo, remarks, promotedBy } = request.data || {};
    if (!employeeId || typeof employeeId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'employeeId is required.');
    }
    if (!newDesignation || typeof newDesignation !== 'string' || !newDesignation.trim()) {
        throw new functions.https.HttpsError('invalid-argument', 'newDesignation is required.');
    }

    const db = admin.firestore();
    const uid = request.auth.uid;
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'role-super-admin';
    const permissions = Array.isArray(token.permissions) ? token.permissions : [];

    // Authorization check
    const hasPerm = isSuperAdmin ||
        permissions.includes('EMPLOYEES_MANAGE_DEPLOYMENTS') ||
        permissions.includes('SUBMISSIONS_APPROVE');

    if (!hasPerm) {
        throw new functions.https.HttpsError('permission-denied', 'Missing permission to promote employees.');
    }

    const empSnap = await resolveEmployeeDocAdmin(db, employeeId);
    if (!empSnap || !empSnap.exists) {
        throw new functions.https.HttpsError('not-found', `Employee "${employeeId}" not found.`);
    }

    const empData = empSnap.data();
    const currentSiteId = empData.currentSiteId || '';

    // Multi-tenant Site scope check
    if (!isSuperAdmin) {
        const hasGlobalScope = permissions.includes('EMPLOYEES_VIEW_SCOPE_ALL') ||
            permissions.includes('SUBMISSIONS_VIEW_SCOPE_ALL') ||
            permissions.includes('MANAGE_SITES') ||
            permissions.includes('MANAGE_ALL_SITES');
        const sitesManaged = Array.isArray(token.sitesManaged) ? token.sitesManaged : [];

        if (!hasGlobalScope) {
            if (currentSiteId && !sitesManaged.includes(currentSiteId)) {
                throw new functions.https.HttpsError('permission-denied', `You do not have management authority for site "${currentSiteId}".`);
            }
            if (newSiteId && !sitesManaged.includes(newSiteId)) {
                throw new functions.https.HttpsError('permission-denied', `You do not have management authority for target transfer site "${newSiteId}".`);
            }
        }
    }

    const currentDesignation = empData.designation || empData.profileData?.designation || 'Staff';
    const applicantName = empData.applicantName || empData.employeeName || 'Employee';
    const cleanEffectiveDate = effectiveDate || new Date().toISOString().split('T')[0];
    const year = new Date().getFullYear();
    const randCode = Math.random().toString(36).substring(2, 7).toUpperCase();
    const cleanRefNo = (referenceNo && referenceNo.trim()) ? referenceNo.trim() : `UDF/PRM/${year}/${randCode}`;

    const promotionRecord = {
        id: `prm_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
        fromDesignation: currentDesignation,
        toDesignation: newDesignation.trim(),
        effectiveDate: cleanEffectiveDate,
        siteId: newSiteId || currentSiteId || null,
        siteName: newSiteName || empData.siteName || null,
        referenceNo: cleanRefNo,
        remarks: remarks || '',
        promotedAt: new Date().toISOString(),
        promotedBy: promotedBy || token.name || token.email || 'Admin'
    };

    const updates = {
        designation: newDesignation.trim(),
        'profileData.designation': newDesignation.trim(),
        promotionHistory: admin.firestore.FieldValue.arrayUnion(promotionRecord),
        lastPromotionDate: cleanEffectiveDate,
        lastUpdated: new Date().toISOString()
    };

    if (newSiteId) {
        updates.currentSiteId = newSiteId;
        if (newSiteName) updates.siteName = newSiteName;
    }

    if (Array.isArray(empData.activeAssignments) && empData.activeAssignments.length > 0) {
        updates.activeAssignments = empData.activeAssignments.map(a => {
            if (a.type === 'PRIMARY') {
                return {
                    ...a,
                    designation: newDesignation.trim(),
                    ...(newSiteId ? { siteId: newSiteId } : {})
                };
            }
            return a;
        });
    }

    const batch = db.batch();
    batch.update(empSnap.ref, updates);

    // Send notification to employee
    const targetUid = empData.uid || empSnap.id;
    const notifRef = db.collection('notifications').doc();
    batch.set(notifRef, {
        title: 'Promotion Confirmed',
        message: `Congratulations! You have been promoted to ${newDesignation.trim()} (Ref: ${cleanRefNo}).`,
        targetUserId: targetUid,
        type: 'PROMOTION',
        read: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Server Audit Log
    const auditRef = db.collection('audit_logs').doc();
    batch.set(auditRef, {
        action: 'PROMOTION',
        category: 'EMPLOYEES',
        targetId: employeeId,
        targetName: applicantName,
        actorId: uid,
        actorEmail: token.email || 'Admin',
        details: `Promoted ${applicantName} (${employeeId}) from "${currentDesignation}" to "${newDesignation.trim()}" (Ref: ${cleanRefNo}).`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    await batch.commit();

    return {
        success: true,
        promotionRecord
    };
});

/**
 * 5. bulkImportEmployeesServer
 * Server-enforced batch import of employee records from validated spreadsheet data.
 */
exports.bulkImportEmployeesServer = secureOnCall({ timeoutSeconds: 300, memory: '1GiB' }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to bulk import employees.');
    }
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const { rows, options } = request.data || {};
    if (!Array.isArray(rows) || rows.length === 0) {
        throw new functions.https.HttpsError('invalid-argument', 'rows array is required and must not be empty.');
    }
    if (rows.length > 2000) {
        throw new functions.https.HttpsError('invalid-argument', 'Maximum 2,000 rows can be imported per batch.');
    }

    const db = admin.firestore();
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'role-super-admin';
    const permissions = Array.isArray(token.permissions) ? token.permissions : [];

    if (!isSuperAdmin && !permissions.includes('EMPLOYEES_IMPORT')) {
        throw new functions.https.HttpsError('permission-denied', 'Missing permission EMPLOYEES_IMPORT.');
    }

    const { generateIds = true, overwriteMode = 'skip', idPrefix = 'HY' } = options || {};

    const sitesSnap = await db.collection('settings').doc('sites').get();
    const siteList = sitesSnap.exists ? (sitesSnap.data().sites || []) : [];

    let successfulImports = 0;
    let failedImports = 0;
    const errors = [];
    const warnings = [];

    const now = new Date();
    const nowIso = now.toISOString();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');

    // Process in batches of 400
    const CHUNK_SIZE = 400;
    for (let c = 0; c < rows.length; c += CHUNK_SIZE) {
        const chunk = rows.slice(c, c + CHUNK_SIZE);
        const batch = db.batch();
        let batchOps = 0;

        for (let i = 0; i < chunk.length; i++) {
            const rowNum = c + i + 1;
            const row = chunk[i];

            try {
                if (!row.fullName || typeof row.fullName !== 'string') {
                    errors.push({ row: rowNum, error: 'Missing required field: Full Name' });
                    failedImports++;
                    continue;
                }

                // Resolve site
                const loc = (row.location || '').trim();
                const matchedSite = siteList.find(s => s && (
                    (s.name && s.name.toLowerCase() === loc.toLowerCase()) ||
                    (s.code && s.code.toLowerCase() === loc.toLowerCase()) ||
                    (s.id && s.id.toLowerCase() === loc.toLowerCase())
                ));

                const siteId = matchedSite?.id || '';
                const siteName = matchedSite?.name || loc;

                // Resolve Employee ID
                let empId = (row.employeeId || '').trim();
                if (!empId && generateIds) {
                    const randDigits = Math.floor(100000 + Math.random() * 900000);
                    empId = `${idPrefix}${randDigits}`;
                }
                if (!empId) {
                    empId = `EMP${Date.now()}${i}`;
                }

                // High entropy submission ID
                const randBuf = new Uint32Array(2);
                require('crypto').getRandomValues(randBuf);
                const baseToken = (randBuf[0].toString(36) + randBuf[1].toString(36)).replace(/[^a-zA-Z0-9]/g, '').slice(0, 6).toUpperCase();
                const submissionId = `UDF-${year}${month}-${baseToken}`;

                // Default password hash
                const rawDob = row.dateOfBirth ? String(row.dateOfBirth).replace(/[^0-9]/g, '') : '01011990';
                const rawPhone = row.phoneNumber ? String(row.phoneNumber).slice(-4) : '1234';
                const defaultPassword = `${row.fullName.split(' ')[0]}@${rawPhone || rawDob.slice(0, 4)}`;
                const passwordHash = await hashPassword(defaultPassword);

                const employeeRecord = {
                    applicantName: row.fullName.trim(),
                    employeeId: empId,
                    portalId: submissionId,
                    currentSiteId: siteId,
                    siteName: siteName,
                    designation: (row.designation || 'Security Guard').trim(),
                    phoneNumber: row.phoneNumber || '',
                    dateOfBirth: row.dateOfBirth || '',
                    joiningDate: row.joiningDate || nowIso.split('T')[0],
                    isActive: true,
                    isRelieved: false,
                    profileStatus: 'active',
                    passwordHash,
                    isDefaultPassword: true,
                    importedAt: nowIso,
                    importedBy: request.auth.uid,
                    profileData: {
                        applicantName: row.fullName.trim(),
                        phoneNumber: row.phoneNumber || '',
                        designation: (row.designation || 'Security Guard').trim(),
                        ...(row.formData || {})
                    }
                };

                const empRef = db.collection('employees').doc(empId);
                const subRef = db.collection('onboarding_submissions').doc(submissionId);

                batch.set(empRef, employeeRecord, { merge: overwriteMode === 'overwrite' });
                batch.set(subRef, {
                    ...employeeRecord,
                    status: 'Approved',
                    submissionDate: nowIso,
                    approvedAt: nowIso,
                    approvedBy: token.name || 'Bulk Import'
                }, { merge: overwriteMode === 'overwrite' });

                batchOps += 2;
                successfulImports++;
            } catch (rowErr) {
                errors.push({ row: rowNum, error: rowErr.message });
                failedImports++;
            }
        }

        if (batchOps > 0) {
            await batch.commit();
        }
    }

    // Server Audit Log
    await db.collection('audit_logs').add({
        action: 'BULK_IMPORT',
        category: 'EMPLOYEES',
        actorId: request.auth.uid,
        actorEmail: token.email || 'Admin',
        details: `Bulk imported ${successfulImports} employee(s) with ${failedImports} error(s).`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    }).catch(() => {});

    return {
        success: true,
        totalRows: rows.length,
        successfulImports,
        failedImports,
        errors,
        warnings
    };
});



/**
 * 6. recordDailyStreakServer
 * Server-enforced daily attendance streak and point crediting strictly under Asia/Kolkata (IST).
 * Prevents client-side date forgery, point inflation, and duplicate visits.
 */
exports.recordDailyStreakServer = secureOnCall({ timeoutSeconds: 30 }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to record streak.');
    }
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const uid = request.auth.uid;
    const db = admin.firestore();

    // Determine target user document
    let targetDocId = uid;
    const requestedId = (request.data && typeof request.data.userId === 'string') ? request.data.userId.trim() : '';
    const userName = (request.data && typeof request.data.userName === 'string') ? request.data.userName.trim() : (token.name || token.email || 'Employee');

    if (requestedId && requestedId !== uid && !requestedId.includes('/')) {
        if (token.employeeId === requestedId || token.portalId === requestedId || token.isSuperAdmin === true || token.isAdmin === true) {
            targetDocId = requestedId;
        } else {
            const empCheck = await db.collection('employees').doc(requestedId).get();
            if (empCheck.exists && (empCheck.data().uid === uid || empCheck.data().linkedUid === uid)) {
                targetDocId = requestedId;
            }
        }
    }

    // Force date evaluation strictly under India Standard Time (IST = Asia/Kolkata)
    const now = new Date();
    const istString = now.toLocaleString("en-US", { timeZone: "Asia/Kolkata" });
    const d = new Date(istString);
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    const today = `${year}-${month}-${day}`;

    const dYest = new Date(istString);
    dYest.setDate(dYest.getDate() - 1);
    const yYear = dYest.getFullYear();
    const yMonth = String(dYest.getMonth() + 1).padStart(2, '0');
    const yDay = String(dYest.getDate()).padStart(2, '0');
    const yesterday = `${yYear}-${yMonth}-${yDay}`;

    // Read streak points from gamification_rules
    let streakPoints = 1;
    try {
        const rulesSnap = await db.collection('settings').doc('gamification_rules').get();
        if (rulesSnap.exists) {
            streakPoints = rulesSnap.data().streakPoints ?? 1;
        }
    } catch (e) {
        console.warn('[recordDailyStreakServer] Failed to read gamification_rules:', e);
    }

    const engagementRef = db.collection('user_engagement').doc(targetDocId);
    let streakResult = null;

    await db.runTransaction(async (transaction) => {
        const streakSnap = await transaction.get(engagementRef);

        if (!streakSnap.exists) {
            streakResult = {
                userId: targetDocId,
                userName,
                streakCount: 1,
                lastVisitDate: today,
                points: streakPoints
            };
            transaction.set(engagementRef, {
                ...streakResult,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                lastUpdated: admin.firestore.FieldValue.serverTimestamp()
            });

            // Log to gamification_logs
            const logRef = db.collection('gamification_logs').doc();
            transaction.set(logRef, {
                userId: targetDocId,
                type: 'STREAK',
                streakCount: 1,
                pointsAwarded: streakPoints,
                date: today,
                timestamp: admin.firestore.FieldValue.serverTimestamp()
            });
            return;
        }

        const data = streakSnap.data();
        const lastVisit = data.lastVisitDate;
        let newCount = data.streakCount || 0;
        let currentPoints = data.points || 0;

        if (lastVisit === today) {
            // Already visited today — keep existing streak and points
            streakResult = {
                userId: targetDocId,
                userName: data.userName || userName,
                streakCount: newCount,
                lastVisitDate: today,
                points: currentPoints,
                alreadyRecordedToday: true
            };
            return;
        } else if (lastVisit === yesterday) {
            // Consecutive visit
            newCount += 1;
            currentPoints += streakPoints;
        } else {
            // Broken streak, reset to 1
            newCount = 1;
            currentPoints += streakPoints;
        }

        streakResult = {
            userId: targetDocId,
            userName,
            streakCount: newCount,
            lastVisitDate: today,
            points: currentPoints
        };

        transaction.set(engagementRef, {
            ...streakResult,
            lastUpdated: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        // Log streak points
        const logRef = db.collection('gamification_logs').doc();
        transaction.set(logRef, {
            userId: targetDocId,
            type: 'STREAK',
            streakCount: newCount,
            pointsAwarded: streakPoints,
            date: today,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
    });

    return {
        success: true,
        streak: streakResult
    };
});

/**
 * 7. redeemRewardServer
 * Atomic point verification and voucher generation for employee reward redemptions.
 * Prevents race conditions, double-spending of points, and unauthorized voucher creation.
 */
exports.redeemRewardServer = secureOnCall({ timeoutSeconds: 30 }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to redeem a reward.');
    }
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const uid = request.auth.uid;
    const db = admin.firestore();

    const { rewardTitle, pointsSpent } = request.data || {};
    const cost = Number(pointsSpent);

    if (!rewardTitle || typeof rewardTitle !== 'string' || !rewardTitle.trim()) {
        throw new functions.https.HttpsError('invalid-argument', 'rewardTitle is required.');
    }
    if (isNaN(cost) || cost <= 0) {
        throw new functions.https.HttpsError('invalid-argument', 'pointsSpent must be a positive number.');
    }

    // Determine target user document
    let targetDocId = uid;
    const requestedId = (request.data && typeof request.data.userId === 'string') ? request.data.userId.trim() : '';
    const userName = (request.data && typeof request.data.userName === 'string') ? request.data.userName.trim() : (token.name || token.email || 'Employee');

    if (requestedId && requestedId !== uid && !requestedId.includes('/')) {
        if (token.employeeId === requestedId || token.portalId === requestedId || token.isSuperAdmin === true || token.isAdmin === true) {
            targetDocId = requestedId;
        } else {
            const empCheck = await db.collection('employees').doc(requestedId).get();
            if (empCheck.exists && (empCheck.data().uid === uid || empCheck.data().linkedUid === uid)) {
                targetDocId = requestedId;
            }
        }
    }

    const engagementRef = db.collection('user_engagement').doc(targetDocId);
    const redemptionRef = db.collection('reward_redemptions').doc();
    const logRef = db.collection('gamification_logs').doc();

    const randToken = Math.random().toString(36).substring(2, 7).toUpperCase();
    const year = new Date().getFullYear();
    const voucherCode = `UDF-RWD-${year}-${randToken}`;
    let remainingPoints = 0;

    await db.runTransaction(async (transaction) => {
        const engagementSnap = await transaction.get(engagementRef);
        const currentPoints = engagementSnap.exists ? (engagementSnap.data().points || 0) : 0;

        if (currentPoints < cost) {
            throw new functions.https.HttpsError(
                'failed-precondition',
                `Insufficient points. You have ${currentPoints} points, but ${cost} are required.`
            );
        }

        remainingPoints = currentPoints - cost;

        // Deduct points
        transaction.set(engagementRef, {
            points: remainingPoints,
            lastUpdated: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        // Create redemption record
        transaction.set(redemptionRef, {
            id: redemptionRef.id,
            userId: targetDocId,
            userName,
            rewardTitle: rewardTitle.trim(),
            pointsSpent: cost,
            voucherCode,
            status: 'pending',
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });

        // Add to immutable gamification_logs
        transaction.set(logRef, {
            userId: targetDocId,
            type: 'REDEMPTION',
            rewardTitle: rewardTitle.trim(),
            pointsDeducted: cost,
            voucherCode,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
    });

    return {
        success: true,
        redemptionId: redemptionRef.id,
        voucherCode,
        pointsSpent: cost,
        remainingPoints
    };
});

/**
 * 8. sendNotificationServer
 * Server-authorized notification dispatcher. Prevents unprivileged clients from broadcasting
 * fake ROLE: announcements or spamming other employee accounts.
 */
exports.sendNotificationServer = secureOnCall({ timeoutSeconds: 30 }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to send notifications.');
    }
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const { targetUserId, message, type, link, metadata, id: clientProvidedId } = request.data || {};

    if (!targetUserId || typeof targetUserId !== 'string' || !targetUserId.trim()) {
        throw new functions.https.HttpsError('invalid-argument', 'targetUserId is required.');
    }
    if (!message || typeof message !== 'string' || !message.trim()) {
        throw new functions.https.HttpsError('invalid-argument', 'message is required.');
    }

    const uid = request.auth.uid;
    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'role-super-admin';
    const isAdmin = isSuperAdmin || token.isAdmin === true || token.type === 'Staff' || !!token.roleId;

    const trimmedTarget = targetUserId.trim();

    // 1. Check broadcast permissions
    const isBroadcast = trimmedTarget.startsWith('ROLE:') || trimmedTarget === 'all_admins' || trimmedTarget === 'admin';

    if (isBroadcast) {
        if (trimmedTarget.startsWith('ROLE:') && !isAdmin) {
            throw new functions.https.HttpsError('permission-denied', 'Only administrators can broadcast role-based notifications.');
        }
        // Non-admins can message 'all_admins' or 'admin' (e.g. for support/grievances)
    } else {
        // Individual recipient check: Non-admins can only send notifications addressed to themselves or an admin
        const isSelf = (trimmedTarget === uid || trimmedTarget === token.employeeId || trimmedTarget === token.portalId);
        if (!isSelf && !isAdmin) {
            throw new functions.https.HttpsError('permission-denied', 'Non-administrative users cannot send notifications to other users.');
        }
    }

    const db = admin.firestore();
    const notifId = (typeof clientProvidedId === 'string' && clientProvidedId.trim()) ? clientProvidedId.trim() : db.collection('notifications').doc().id;

    const notifDoc = {
        id: notifId,
        targetUserId: trimmedTarget,
        message: message.trim(),
        type: type || 'info',
        link: link || null,
        metadata: metadata || null,
        read: false,
        senderId: uid,
        senderName: token.name || token.email || 'System',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        timestamp: new Date().toISOString()
    };

    await db.collection('notifications').doc(notifId).set(notifDoc);

    return {
        success: true,
        notificationId: notifId
    };
});

/**
 * 9. completeBgvReviewServer
 * Server-enforced Background Verification approval, rejection, and atomic employee badge sync.
 * Prevents clients from spoofing BGV clearance without audited authority.
 */
exports.completeBgvReviewServer = secureOnCall({ timeoutSeconds: 60 }, async (request) => {
    if (!request.auth) {
        throw new functions.https.HttpsError('unauthenticated', 'Must be authenticated to review BGV.');
    }
    const token = request.auth.token || {};
    if (token.isDisabled === true) {
        throw new functions.https.HttpsError('permission-denied', 'Account is disabled.');
    }

    const {
        recordId,
        employeeId,
        action, // 'APPROVE' | 'REJECT'
        notes,
        rejectionReason,
        bgvDocumentUrl,
        bgvDocumentPath,
        bgvDocumentName,
        vendorName,
        vendorCaseId
    } = request.data || {};

    if (!recordId || typeof recordId !== 'string') {
        throw new functions.https.HttpsError('invalid-argument', 'recordId is required.');
    }
    if (action !== 'APPROVE' && action !== 'REJECT') {
        throw new functions.https.HttpsError('invalid-argument', 'action must be "APPROVE" or "REJECT".');
    }

    const isSuperAdmin = token.isSuperAdmin === true || token.roleId === 'role-super-admin';
    const permissions = Array.isArray(token.permissions) ? token.permissions : [];
    const hasBgvPerm = isSuperAdmin ||
        permissions.includes('BGV_APPROVE_REJECT') ||
        permissions.includes('BGV_MANAGE');

    if (!hasBgvPerm) {
        throw new functions.https.HttpsError('permission-denied', 'Missing permission to approve or reject BGV.');
    }

    const db = admin.firestore();
    const bgvRef = db.collection('bgv_records').doc(recordId);
    const bgvSnap = await bgvRef.get();

    if (!bgvSnap.exists) {
        throw new functions.https.HttpsError('not-found', `BGV record "${recordId}" not found.`);
    }

    const bgvData = bgvSnap.data();
    const targetEmpId = employeeId || bgvData.employeeId;
    const empSnap = await resolveEmployeeDocAdmin(db, targetEmpId);

    const approverName = token.name || token.email || 'Admin';
    const nowIso = new Date().toISOString();
    const batch = db.batch();

    let finalStatus = '';
    let notificationMessage = '';

    if (action === 'APPROVE') {
        finalStatus = 'Completed';
        const bgvUpdates = {
            status: finalStatus,
            approvedBy: approverName,
            approvedDate: nowIso,
            approvedAt: admin.firestore.FieldValue.serverTimestamp(),
            notes: (notes || bgvData.notes || '').trim(),
            updatedAt: nowIso
        };
        if (bgvDocumentUrl) bgvUpdates.bgvDocumentUrl = bgvDocumentUrl;
        if (bgvDocumentPath) bgvUpdates.bgvDocumentPath = bgvDocumentPath;
        if (bgvDocumentName) bgvUpdates.bgvDocumentName = bgvDocumentName;
        if (vendorName) bgvUpdates.vendorName = vendorName.trim();
        if (vendorCaseId) bgvUpdates.vendorCaseId = vendorCaseId.trim();

        batch.update(bgvRef, bgvUpdates);

        if (empSnap && empSnap.exists) {
            batch.update(empSnap.ref, {
                bgvStatus: finalStatus,
                bgvCompletedAt: nowIso,
                bgvNotes: (notes || '').trim(),
                updatedAt: nowIso
            });
        }

        notificationMessage = 'Your Background Verification (BGV) has been verified and marked Completed.';
    } else {
        finalStatus = 'Failed';
        const reason = (rejectionReason || notes || 'Adverse findings').trim();
        const bgvUpdates = {
            status: finalStatus,
            rejectionReason: reason,
            rejectedBy: approverName,
            rejectedDate: nowIso,
            rejectedAt: admin.firestore.FieldValue.serverTimestamp(),
            notes: `Adverse / Rejected by ${approverName}: ${reason}`,
            updatedAt: nowIso
        };

        batch.update(bgvRef, bgvUpdates);

        if (empSnap && empSnap.exists) {
            batch.update(empSnap.ref, {
                bgvStatus: finalStatus,
                bgvNotes: `Adverse / Rejected: ${reason}`,
                updatedAt: nowIso
            });
        }

        notificationMessage = `Your Background Verification (BGV) status was updated: Adverse findings recorded. Reason: ${reason}`;
    }

    // Direct notification to employee
    if (empSnap && empSnap.exists) {
        const notifTarget = empSnap.data().employeeId || empSnap.id;
        const notifRef = db.collection('notifications').doc();
        batch.set(notifRef, {
            id: notifRef.id,
            targetUserId: notifTarget,
            message: notificationMessage,
            type: action === 'APPROVE' ? 'success' : 'error',
            read: false,
            senderId: request.auth.uid,
            senderName: approverName,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            timestamp: nowIso
        });
    }

    // Audit Log
    const auditRef = db.collection('audit_logs').doc();
    batch.set(auditRef, {
        action: action === 'APPROVE' ? 'BGV_APPROVE' : 'BGV_REJECT',
        category: 'BGV',
        targetId: recordId,
        actorId: request.auth.uid,
        actorEmail: token.email || 'Admin',
        details: `${approverName} marked BGV for ${targetEmpId || recordId} as "${finalStatus}". Notes/Reason: ${notes || rejectionReason || 'None'}`,
        timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    await batch.commit();

    return {
        success: true,
        recordId,
        employeeId: targetEmpId,
        status: finalStatus
    };
});
