/**
 * ASN Social Network — Dirty Dozen Adversarial Security Test Specification
 * Designed to verify PERMISSION_DENIED against Firebase Emulator / @firebase/rules-unit-testing.
 */

export interface SecurityTestCase {
  id: number;
  name: string;
  collectionPath: string;
  operation: 'create' | 'update' | 'get' | 'list' | 'delete';
  actor: { uid: string; email: string; email_verified: boolean };
  payload?: Record<string, unknown>;
  expected: 'PERMISSION_DENIED';
}

export const DIRTY_DOZEN_TESTS: SecurityTestCase[] = [
  {
    id: 1,
    name: 'Self-Role Escalation on Profile Create',
    collectionPath: 'users_public/attacker1',
    operation: 'create',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      uid: 'attacker1',
      displayName: 'Attacker',
      username: 'attacker1',
      bio: '',
      photoURL: '',
      coverURL: '',
      location: '',
      website: '',
      followersCount: 0,
      followingCount: 0,
      postsCount: 0,
      isVerifiedCreator: true,
      monetizationStatus: 'approved',
      accountStatus: 'active',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 2,
    name: 'Ghost Field Injection on Post Create',
    collectionPath: 'posts/post_ghost',
    operation: 'create',
    actor: { uid: 'user1', email: 'user1@example.com', email_verified: true },
    payload: {
      authorId: 'user1',
      content: 'Hello',
      isPromoted: true,
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 3,
    name: 'Spoofed Author ID on Post Create',
    collectionPath: 'posts/post_spoof',
    operation: 'create',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      authorId: 'victim_uid',
      content: 'Impersonated post',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 4,
    name: 'PII Snooping on users_private',
    collectionPath: 'users_private/victim_uid',
    operation: 'get',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 5,
    name: 'Fake Revenue Injection on users_private',
    collectionPath: 'users_private/attacker1',
    operation: 'update',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      totalEarningsCents: 9999999,
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 6,
    name: 'Unauthorized Payout Withdrawal Without Approval',
    collectionPath: 'payout_requests/payout1',
    operation: 'create',
    actor: { uid: 'unapproved_user', email: 'u@example.com', email_verified: true },
    payload: {
      userId: 'unapproved_user',
      amountCents: 5000,
      payoutDestination: 'bank-123',
      status: 'pending',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 7,
    name: 'Timestamp Forgery on Post Create',
    collectionPath: 'posts/post_time',
    operation: 'create',
    actor: { uid: 'user1', email: 'user1@example.com', email_verified: true },
    payload: {
      authorId: 'user1',
      content: 'Backdated post',
      createdAt: '2020-01-01T00:00:00Z',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 8,
    name: 'Unsynced Like Counter Manipulation',
    collectionPath: 'posts/post1',
    operation: 'update',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      likesCount: 1000,
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 9,
    name: 'Unauthorized Message Eavesdropping',
    collectionPath: 'conversations/userA_userB/messages',
    operation: 'list',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 10,
    name: 'Terminal State Bypass on Friend Request',
    collectionPath: 'friend_requests/req_accepted',
    operation: 'update',
    actor: { uid: 'userB', email: 'userb@example.com', email_verified: true },
    payload: {
      status: 'pending',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 11,
    name: 'Unverified Admin Email Spoof',
    collectionPath: 'platform_config/global',
    operation: 'update',
    actor: { uid: 'spoof_admin', email: 'latifleghari25@gmail.com', email_verified: false },
    payload: {
      maintenanceMode: true,
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 12,
    name: 'Resource Poisoning via Oversized Content',
    collectionPath: 'posts/post_poison',
    operation: 'create',
    actor: { uid: 'user1', email: 'user1@example.com', email_verified: true },
    payload: {
      authorId: 'user1',
      content: 'A'.repeat(5000),
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 13,
    name: 'Unauthorized Page Impersonation on Post Create',
    collectionPath: 'posts/post_page_spoof',
    operation: 'create',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      authorId: 'attacker1',
      contextType: 'page',
      contextId: 'page_owned_by_victim',
      content: 'Fake post on someone else page',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 14,
    name: 'Forged Friendship Edge Without Accepted Request',
    collectionPath: 'users_public/victim_uid/friends/attacker1',
    operation: 'create',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      uid: 'attacker1',
      displayName: 'Attacker',
      username: 'attacker1',
      photoURL: '',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 15,
    name: 'Fake Ad Spend or Unbacked Click Inflation',
    collectionPath: 'ads/ad1',
    operation: 'update',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      clicksCount: 500,
      budgetCents: 999999,
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 16,
    name: 'Non-Admin Creating Admin Audit Log',
    collectionPath: 'admin_logs/log_spoof',
    operation: 'create',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      adminId: 'attacker1',
      action: 'user_verified',
      targetType: 'user',
      targetId: 'attacker1',
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 17,
    name: 'User Self-Approving Boost Request',
    collectionPath: 'boost_requests/boost_spoof',
    operation: 'create',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      requesterId: 'attacker1',
      targetType: 'post',
      targetId: 'post1',
      status: 'approved',
      budgetCents: 2000,
    },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 18,
    name: 'Reading Another User Scheduled Post',
    collectionPath: 'posts/scheduled_post_other',
    operation: 'get',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    expected: 'PERMISSION_DENIED',
  },
  {
    id: 19,
    name: 'Non-Admin Spoofing Engagement Offset on Own Post',
    collectionPath: 'posts/own_post',
    operation: 'update',
    actor: { uid: 'attacker1', email: 'attacker1@example.com', email_verified: true },
    payload: {
      adminLikesOffset: 5000,
      isBoosted: true,
    },
    expected: 'PERMISSION_DENIED',
  },
];

