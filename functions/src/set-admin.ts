import { initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { FieldValue, getFirestore } from "firebase-admin/firestore";

async function main() {
  const email = process.argv[2]?.trim().toLowerCase();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    throw new Error("Usage: npm run set-admin -- admin@example.com");
  }

  initializeApp();
  const auth = getAuth();
  const db = getFirestore();
  const user = await auth.getUserByEmail(email);
  if (!user.emailVerified) {
    throw new Error("Verify the administrator email in Firebase Authentication first.");
  }

  await auth.setCustomUserClaims(user.uid, {
    ...user.customClaims,
    admin: true,
  });
  await db.collection("users").doc(user.uid).set(
    {
      email,
      emailLower: email,
      emailVerified: true,
      role: "admin",
      accountStatus: "active",
      isActive: true,
      createdAt: FieldValue.serverTimestamp(),
    },
    { merge: true },
  );
  console.log(`Administrator role assigned to ${email}.`);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
