"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const app_1 = require("firebase-admin/app");
const auth_1 = require("firebase-admin/auth");
const firestore_1 = require("firebase-admin/firestore");
async function main() {
    const email = process.argv[2]?.trim().toLowerCase();
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        throw new Error("Usage: npm run set-admin -- admin@example.com");
    }
    (0, app_1.initializeApp)();
    const auth = (0, auth_1.getAuth)();
    const db = (0, firestore_1.getFirestore)();
    const user = await auth.getUserByEmail(email);
    if (!user.emailVerified) {
        throw new Error("Verify the administrator email in Firebase Authentication first.");
    }
    await auth.setCustomUserClaims(user.uid, {
        ...user.customClaims,
        admin: true,
    });
    await db.collection("users").doc(user.uid).set({
        email,
        emailLower: email,
        emailVerified: true,
        role: "admin",
        accountStatus: "active",
        isActive: true,
        createdAt: firestore_1.FieldValue.serverTimestamp(),
    }, { merge: true });
    console.log(`Administrator role assigned to ${email}.`);
}
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
