import { createHash, randomBytes } from "node:crypto";
import { initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import {
  FieldValue,
  Timestamp,
  getFirestore,
} from "firebase-admin/firestore";
import { HttpsError, onCall } from "firebase-functions/v2/https";

initializeApp();

const db = getFirestore();
const auth = getAuth();
const region = "us-central1";
const challengeLifetimeMs = 10 * 60 * 1000;
const attemptWindowMs = 15 * 60 * 1000;
const attemptLimit = 5;

const scenarios = [
  {
    question:
      "A teammate reports an unexpected multi-factor authentication prompt. What is the safest first response?",
    answers: [
      "Deny the prompt and report it through the approved security channel.",
      "Approve it once to stop the notifications.",
      "Share the prompt details with a coworker in a public chat.",
      "Ignore it and continue using the account.",
    ],
    correct: 0,
  },
  {
    question:
      "A browser warns that an internal service certificate is invalid. What should you do?",
    answers: [
      "Stop and report the issue; do not bypass the certificate warning.",
      "Disable certificate checks for the session.",
      "Continue if the page looks familiar.",
      "Copy the warning into a public forum with the service URL.",
    ],
    correct: 0,
  },
  {
    question:
      "You receive an unexpected attachment asking you to review an urgent invoice. What is the safest action?",
    answers: [
      "Do not open it; report it using the organization's phishing process.",
      "Open it in your normal account to identify the sender.",
      "Forward it to teammates to ask whether it is legitimate.",
      "Reply to the sender requesting proof of identity.",
    ],
    correct: 0,
  },
  {
    question: "A production device may be compromised. What should you prioritize?",
    answers: [
      "Follow the incident-response plan, limit exposure, and preserve evidence.",
      "Delete files that look suspicious before notifying anyone.",
      "Post system details in an unrestricted chat for quick help.",
      "Reinstall immediately without recording what happened.",
    ],
    correct: 0,
  },
  {
    question:
      "A colleague asks for administrator access to complete a short task. What is the best practice?",
    answers: [
      "Grant only the minimum required access for the shortest necessary time.",
      "Share your own administrator credentials.",
      "Grant permanent administrator access to avoid future delays.",
      "Disable access controls until the task is complete.",
    ],
    correct: 0,
  },
  {
    question:
      "A backup job reports success. What best demonstrates that recovery is dependable?",
    answers: [
      "Perform controlled restore tests and verify data integrity.",
      "Assume the job worked because it returned a success message.",
      "Keep the only backup on the same device as the source.",
      "Wait until an incident to find out whether restoration works.",
    ],
    correct: 0,
  },
  {
    question: "You suspect your password was exposed. What is the safest response?",
    answers: [
      "Report it and change it through the trusted account recovery path.",
      "Reuse it with a small change on all work systems.",
      "Send it to the security team in ordinary email.",
      "Wait to see whether an account alert arrives.",
    ],
    correct: 0,
  },
];

function requireAuth(authContext: {
  uid: string;
  token: Record<string, unknown>;
} | null | undefined) {
  if (!authContext) {
    throw new HttpsError("unauthenticated", "Sign in to continue.");
  }
  return authContext;
}

async function requireAdmin(authContext: {
  uid: string;
  token: Record<string, unknown>;
} | null | undefined) {
  const current = requireAuth(authContext);
  if (current.token.admin !== true) {
    throw new HttpsError("permission-denied", "Administrator access is required.");
  }
  const profile = await requireActiveProfile(current.uid);
  if (profile.role !== "admin") {
    throw new HttpsError("permission-denied", "Administrator access is required.");
  }
  return current;
}

function challengeHash(token: string, optionId: string) {
  return createHash("sha256").update(`${token}:${optionId}`).digest("hex");
}

function tokenHash(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

function randomId() {
  return randomBytes(12).toString("base64url");
}

function recordAudit(
  actorUid: string | null,
  subjectUid: string,
  eventType: string,
) {
  return db.collection("accountAuditLog").add({
    actorUid,
    subjectUid,
    eventType,
    createdAt: FieldValue.serverTimestamp(),
  });
}

async function requireActiveProfile(uid: string) {
  const snapshot = await db.collection("users").doc(uid).get();
  const profile = snapshot.data();
  if (!profile || profile.accountStatus !== "active" || profile.isActive !== true) {
    throw new HttpsError("permission-denied", "This account is not active.");
  }
  return profile;
}

export const healthCheck = onCall({ region, enforceAppCheck: true }, async () => {
  await db.collection("_system").doc("health").set(
    { checkedAt: FieldValue.serverTimestamp() },
    { merge: true },
  );
  return { status: "ok", project: process.env.GCLOUD_PROJECT };
});

export const submitRegistration = onCall(
  { region, enforceAppCheck: true },
  async (request) => {
    const current = requireAuth(request.auth);
    const user = await auth.getUser(current.uid);
    if (!user.email) {
      throw new HttpsError("failed-precondition", "An email address is required.");
    }
    const email = user.email;

    const profileRef = db.collection("users").doc(current.uid);
    await db.runTransaction(async (transaction) => {
      const profile = await transaction.get(profileRef);
      if (profile.exists) return;
      transaction.create(profileRef, {
        email,
        emailLower: email.toLowerCase(),
        emailVerified: user.emailVerified,
        role: "user",
        accountStatus: "pending_review",
        isActive: false,
        createdAt: FieldValue.serverTimestamp(),
      });
    });
    await recordAudit(null, current.uid, "registration_submitted");
    return { status: "pending_review" };
  },
);

export const syncEmailVerification = onCall(
  { region, enforceAppCheck: true },
  async (request) => {
    const current = requireAuth(request.auth);
    const user = await auth.getUser(current.uid);
    const profileRef = db.collection("users").doc(current.uid);
    const profile = await profileRef.get();
    if (!profile.exists) {
      throw new HttpsError("not-found", "Registration request was not found.");
    }
    await profileRef.update({ emailVerified: user.emailVerified });
    return { emailVerified: user.emailVerified };
  },
);

export const beginOnboarding = onCall(
  { region, enforceAppCheck: true },
  async (request) => {
    const current = requireAuth(request.auth);
    if (current.token.email_verified !== true) {
      throw new HttpsError("failed-precondition", "Verify your email before onboarding.");
    }
    const profileRef = db.collection("users").doc(current.uid);
    const now = Timestamp.now();
    const challengeToken = randomBytes(32).toString("base64url");
    const scenario = scenarios[randomBytes(4).readUInt32BE(0) % scenarios.length];
    const correctText = scenario.answers[scenario.correct];
    const options = scenario.answers.map((text) => ({ id: randomId(), text }));
    for (let index = options.length - 1; index > 0; index -= 1) {
      const swapIndex = randomBytes(4).readUInt32BE(0) % (index + 1);
      [options[index], options[swapIndex]] = [options[swapIndex], options[index]];
    }
    const correctOptionId = options.find((option) => option.text === correctText)?.id;
    if (!correctOptionId) {
      throw new HttpsError("internal", "Unable to prepare the challenge.");
    }

    const challengeRef = db.collection("onboardingChallenges").doc(tokenHash(challengeToken));
    await db.runTransaction(async (transaction) => {
      const profileSnapshot = await transaction.get(profileRef);
      const profile = profileSnapshot.data();
      if (!profile || profile.accountStatus !== "challenge_required") {
        throw new HttpsError("permission-denied", "The account is not awaiting onboarding.");
      }

      const windowStartedAt = profile.challengeWindowStartedAt as Timestamp | undefined;
      let attempts = Number(profile.challengeAttempts ?? 0);
      if (windowStartedAt && now.toMillis() - windowStartedAt.toMillis() >= attemptWindowMs) {
        attempts = 0;
      }
      if (attempts >= attemptLimit) {
        throw new HttpsError("resource-exhausted", "Too many attempts. Try again later.");
      }

      transaction.create(challengeRef, {
        uid: current.uid,
        question: scenario.question,
        options,
        answerHash: challengeHash(challengeToken, correctOptionId),
        createdAt: now,
        expiresAt: Timestamp.fromMillis(now.toMillis() + 10 * 60 * 1000),
        consumed: false,
      });
      transaction.update(profileRef, {
        challengeWindowStartedAt: windowStartedAt ?? now,
        challengeAttempts: attempts,
      });
    });
    await recordAudit(null, current.uid, "challenge_issued");
    return {
      challengeToken,
      challenge: {
        question: scenario.question,
        options,
        expiresAt: Timestamp.fromMillis(now.toMillis() + challengeLifetimeMs).toDate().toISOString(),
      },
    };
  },
);

export const answerOnboarding = onCall(
  { region, enforceAppCheck: true },
  async (request) => {
    const current = requireAuth(request.auth);
    const challengeToken = request.data?.challengeToken;
    const optionId = request.data?.optionId;
    if (
      typeof challengeToken !== "string" ||
      challengeToken.length < 32 ||
      typeof optionId !== "string" ||
      optionId.length < 8
    ) {
      throw new HttpsError("invalid-argument", "Challenge response is invalid.");
    }

    const challengeRef = db.collection("onboardingChallenges").doc(tokenHash(challengeToken));
    const profileRef = db.collection("users").doc(current.uid);
    const now = Timestamp.now();
    const result: { outcome: "correct" | "incorrect" | "limited" | "invalid" } = {
      outcome: "invalid",
    };
    await db.runTransaction(async (transaction) => {
      const [challengeSnapshot, profileSnapshot] = await Promise.all([
        transaction.get(challengeRef),
        transaction.get(profileRef),
      ]);
      const challenge = challengeSnapshot.data();
      const profile = profileSnapshot.data();
      if (
        !challenge ||
        challenge.uid !== current.uid ||
        challenge.consumed === true ||
        !profile ||
        profile.accountStatus !== "challenge_required"
      ) {
        result.outcome = "invalid";
        return;
      }
      if ((challenge.expiresAt as Timestamp).toMillis() <= now.toMillis()) {
        transaction.update(challengeRef, { consumed: true });
        result.outcome = "invalid";
        return;
      }

      const windowStartedAt = profile.challengeWindowStartedAt as Timestamp | undefined;
      let attempts = Number(profile.challengeAttempts ?? 0);
      if (windowStartedAt && now.toMillis() - windowStartedAt.toMillis() >= attemptWindowMs) {
        attempts = 0;
      }
      if (attempts >= attemptLimit) {
        result.outcome = "limited";
        return;
      }

      const allowedOption = (challenge.options as Array<{ id: string }>).some(
        (option) => option.id === optionId,
      );
      if (
        !allowedOption ||
        challengeHash(challengeToken, optionId) !== challenge.answerHash
      ) {
        attempts += 1;
        transaction.update(challengeRef, { consumed: true });
        transaction.update(profileRef, {
          challengeAttempts: attempts,
          challengeWindowStartedAt: windowStartedAt ?? now,
        });
        result.outcome = attempts >= attemptLimit ? "limited" : "incorrect";
        return;
      }

      transaction.update(challengeRef, { consumed: true });
      transaction.update(profileRef, {
        accountStatus: "active",
        isActive: true,
        challengeAttempts: 0,
        challengeWindowStartedAt: FieldValue.delete(),
        activatedAt: FieldValue.serverTimestamp(),
      });
      result.outcome = "correct";
    });

    if (result.outcome !== "correct") {
      await recordAudit(null, current.uid, "challenge_failed");
      if (result.outcome === "limited") {
        throw new HttpsError("resource-exhausted", "Too many attempts. Try again later.");
      }
      if (result.outcome === "incorrect") {
        throw new HttpsError("invalid-argument", "That answer is incorrect. Request a new challenge.");
      }
      throw new HttpsError("unauthenticated", "Challenge is invalid, expired, or already used.");
    }

    await recordAudit(null, current.uid, "challenge_passed");
    const profile = await profileRef.get();
    return {
      status: "logged_in",
      user: {
        id: current.uid,
        username: profile.get("email"),
        role: profile.get("role"),
        account_status: profile.get("accountStatus"),
        is_active: profile.get("isActive"),
      },
    };
  },
);

export const adminOverview = onCall(
  { region, enforceAppCheck: true },
  async (request) => {
    await requireAdmin(request.auth);
    const [users, conversations, messages] = await Promise.all([
      db.collection("users").get(),
      db.collection("conversations").count().get(),
      db.collectionGroup("messages").count().get(),
    ]);
    const rows = users.docs.map((document) => {
      const user = document.data();
      return {
        id: document.id,
        username: user.email,
        role: user.role,
        is_active: user.isActive === true,
        account_status: user.accountStatus,
        email_verified: user.emailVerified === true,
        created_at: user.createdAt instanceof Timestamp
          ? user.createdAt.toDate().toISOString()
          : null,
      };
    });
    return {
      counts: {
        users: rows.length,
        active_users: rows.filter((user) => user.is_active).length,
        conversations: conversations.data().count,
        messages: messages.data().count,
      },
      users: rows,
    };
  },
);

export const reviewUser = onCall(
  { region, enforceAppCheck: true },
  async (request) => {
    const admin = await requireAdmin(request.auth);
    const userId = request.data?.userId;
    const decision = request.data?.decision;
    if (typeof userId !== "string" || !["approve", "reject"].includes(decision)) {
      throw new HttpsError("invalid-argument", "Review request is invalid.");
    }
    const profileRef = db.collection("users").doc(userId);
    const profile = await profileRef.get();
    if (!profile.exists) throw new HttpsError("not-found", "User was not found.");
    if (profile.get("role") === "admin") {
      throw new HttpsError("failed-precondition", "Administrator accounts cannot be reviewed.");
    }
    const currentStatus = profile.get("accountStatus");
    const allowedStatuses = decision === "approve"
      ? ["pending_review"]
      : ["pending_review", "challenge_required"];
    if (!allowedStatuses.includes(currentStatus)) {
      throw new HttpsError("failed-precondition", "This account cannot be changed through applicant review.");
    }
    const authUser = await auth.getUser(userId);
    if (decision === "approve" && !authUser.emailVerified) {
      throw new HttpsError("failed-precondition", "The applicant must verify their email first.");
    }
    const accountStatus = decision === "approve" ? "challenge_required" : "rejected";
    await profileRef.update({ accountStatus, isActive: false });
    await recordAudit(
      admin.uid,
      userId,
      decision === "approve"
        ? "registration_approved"
        : currentStatus === "pending_review"
          ? "registration_rejected"
          : "approval_revoked",
    );
    return { id: userId, username: profile.get("email"), account_status: accountStatus };
  },
);

export const setUserStatus = onCall(
  { region, enforceAppCheck: true },
  async (request) => {
    const admin = await requireAdmin(request.auth);
    const userId = request.data?.userId;
    const isActive = request.data?.isActive;
    if (typeof userId !== "string" || typeof isActive !== "boolean") {
      throw new HttpsError("invalid-argument", "Account status request is invalid.");
    }
    if (userId === admin.uid && !isActive) {
      throw new HttpsError("failed-precondition", "You cannot disable your own account.");
    }

    const profileRef = db.collection("users").doc(userId);
    const profile = await profileRef.get();
    if (!profile.exists) throw new HttpsError("not-found", "User was not found.");
    const role = profile.get("role");
    const currentStatus = profile.get("accountStatus");
    if (isActive && currentStatus !== "disabled" && currentStatus !== "active") {
      throw new HttpsError(
        "failed-precondition",
        "Pending or rejected applicants must complete onboarding before activation.",
      );
    }
    if (!isActive && role === "admin") {
      const activeAdmins = await db.collection("users")
        .where("role", "==", "admin")
        .where("accountStatus", "==", "active")
        .count()
        .get();
      if (activeAdmins.data().count <= 1) {
        throw new HttpsError("failed-precondition", "The last active administrator cannot be disabled.");
      }
    }
    await profileRef.update({
      accountStatus: isActive ? "active" : "disabled",
      isActive,
    });
    await auth.updateUser(userId, { disabled: !isActive });
    await recordAudit(admin.uid, userId, isActive ? "account_enabled" : "account_disabled");
    return {
      id: userId,
      username: profile.get("email"),
      is_active: isActive,
      account_status: isActive ? "active" : "disabled",
    };
  },
);

export const getOrCreateConversation = onCall(
  { region, enforceAppCheck: true },
  async (request) => {
    const current = requireAuth(request.auth);
    await requireActiveProfile(current.uid);
    const email = request.data?.email;
    if (typeof email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      throw new HttpsError("invalid-argument", "Enter a valid recipient email.");
    }
    const matches = await db.collection("users")
      .where("emailLower", "==", email.trim().toLowerCase())
      .limit(1)
      .get();
    const recipient = matches.docs[0];
    if (!recipient || recipient.get("accountStatus") !== "active") {
      throw new HttpsError("not-found", "An active recipient was not found.");
    }
    if (recipient.id === current.uid) {
      throw new HttpsError("invalid-argument", "You cannot message yourself.");
    }

    const participants = [current.uid, recipient.id].sort();
    const conversationId = participants.join("_");
    const conversationRef = db.collection("conversations").doc(conversationId);
    await conversationRef.create({
      participants,
      participantEmails: participants.map((uid) =>
        uid === current.uid ? request.auth?.token.email : recipient.get("email"),
      ),
      createdAt: FieldValue.serverTimestamp(),
    }).catch(async (error: { code?: number | string }) => {
      if (error.code !== 6 && error.code !== "already-exists") throw error;
    });
    return { conversation_id: conversationId };
  },
);

export const logClientSecurityEvent = onCall(
  { region, enforceAppCheck: true },
  async (request) => {
    const current = requireAuth(request.auth);
    await requireActiveProfile(current.uid);
    const eventType = request.data?.eventType;
    if (
      typeof eventType !== "string" ||
      !["message_sent", "message_read"].includes(eventType)
    ) {
      throw new HttpsError("invalid-argument", "Security event type is invalid.");
    }
    await recordAudit(current.uid, current.uid, eventType);
    return { status: "recorded" };
  },
);
