# ASN Social Network — Security Specification

## Data Invariants
1. **PII, Block & Restrict List Isolation**: User email, phone, birth year, payout destination, verified earnings, user block lists (`users_private/{uid}/blocked/{blockedUid}`), and user restrict lists (`users_private/{uid}/restricted/{targetUid}`) reside exclusively under `users_private/{uid}` and are readable only by the owning user (`request.auth.uid == uid`) or a verified Admin (block/restrict lists are strictly owner-only).
2. **Server-Side Admin Authority & Immutable Audit Logs**: Admin status is checked exclusively via `admins/{uid}` existence or the verified bootstrap owner emails (`'latifleghari25@gmail.com'`, `'kl3961463@gmail.com'` with `request.auth.token.email_verified == true`). Every admin action is recorded in `admin_logs/{logId}`, which is strictly immutable (`update, delete: if false`) and admin-only.
3. **Immutable Ownership & Timestamps**: Author/owner UIDs (`uid`, `authorId`, `ownerId`, `fromId`, `senderId`, `reporterId`, `userId`, `requesterId`) must equal `request.auth.uid` on create and remain immutable on update. `createdAt` must equal `request.time` on create and remain immutable on update.
4. **Atomic Relational Counters & Transparent Engagement**: Likes, comments, shares, follows, and group memberships across both `posts` and `reels` must update parent counters atomically inside the same batch (`+1` / `-1`) with `existsAfter` / `getAfter` validation. Client mutations are blocked if `engagementDisabled == true`. Admin engagement adjustments are stored exclusively in separate `admin*Offset` fields so genuine user counters remain transparent.
5. **Verified Monetization & Boost Integrity**: Users cannot self-approve `monetizationStatus` or credit `totalEarningsCents`. Withdrawal requests (`payout_requests`) require `users_public/{uid}.monetizationStatus == 'approved'` and `amountCents <= users_private/{uid}.totalEarningsCents`. Boost requests (`boost_requests`) are always created as `'pending'`; only verified Admins can approve, reject, or pause boosts.
6. **Scheduled Post Privacy & Ads Integrity**: Posts with `status == 'scheduled'` are readable and editable solely by their `authorId` or Admins until published (`status == 'active'`). Ad campaigns (`ads/{adId}`) and advertiser accounts (`advertiser_accounts/{uid}`) are admin-managed; genuine ad impressions/clicks increment counters by `+1` paired with an atomic `ads/{adId}/events/{eventId}` audit record.
7. **Auth, Verification & Storage Gates**: Page creation and editing require an active authenticated account (`ownerId == request.auth.uid` or authorized page manager). Posts, reels, comments, likes, messaging, privacy/blocking/restricting actions, reports, boosts, and monetization actions additionally require verified auth. Storage uploads are scoped to `users/{request.auth.uid}/...` with strict MIME type and size caps (5 MB images, 100 MB videos).
8. **Friends, Follow & Page Identity Separation**: Friendships are tracked separately (`friend_requests` + symmetric `users_public/{uid}/friends/{friendId}`) from personal follows (`users_public/{uid}/following`) and page follows (`pages/{pageId}/followers` + `users_public/{uid}/following_pages/{pageId}`).

## Adversarial Payloads Covered
1. **Self-Role Escalation on Profile Create**: Creating `users_public/{uid}` with `monetizationStatus: 'approved'` or `isVerifiedCreator: true` or `accountStatus: 'suspended'`.
2. **Ghost Field Injection**: Creating/updating a `post` or `reel` with an undeclared shadow field like `isPromoted: true` or `isAdminPost: true`.
3. **Spoofed Author ID**: Creating a `post`, `reel`, or `comment` with `authorId` set to another user's UID.
4. **PII Snooping**: Reading `users_private/{otherUid}` or `users_private/{otherUid}/blocked` as a non-admin signed-in user.
5. **Fake Revenue Injection**: Updating `users_private/{uid}` to set `totalEarningsCents: 999999`.
6. **Unauthorized Payout Withdrawal**: Creating a `payout_requests` doc when `monetizationStatus != 'approved'` or `amountCents > totalEarningsCents`.
7. **Timestamp Forgery**: Creating a `post` or `reel` with a backdated `createdAt` timestamp not equal to `request.time`.
8. **Orphaned / Unsynced Like Counter**: Updating `posts/{postId}` or `reels/{reelId}` `likesCount` by `+100` without an atomic like document, or creating a `likes/{uid}` doc without incrementing `likesCount` by `1`.
9. **Unauthorized Message Eavesdropping**: Listing or reading `conversations/{convId}/messages` when `request.auth.uid` is not in `participantIds`.
10. **Terminal State Bypass on Friend Request**: Updating an already `'accepted'` `friend_requests/{id}` back to `'pending'` or modifying `fromId`/`toId`.
11. **Unverified Admin Email Spoof**: Accessing admin resources with `email_verified: false`.
12. **Resource Poisoning via Oversized ID or String**: Creating a document with an invalid ID (`../admin` or >128 chars) or `content` > 2000 chars.
13. **Unauthorized Page Impersonation**: Creating a `post` or `reel` with `contextType: 'page'` and `contextId` pointing to a page the caller neither owns nor manages.
14. **Forged Friendship Edge**: Creating `users_public/{victimUid}/friends/{attackerUid}` without an accepted `friend_requests` approval from the recipient.
15. **Fake Ad Campaign / Spend Manipulation**: Non-admin creating `ads/{adId}` or arbitrarily inflating `budgetCents` / `clicksCount` by `+500`.
16. **Unauthorized Admin Audit Log Forgery**: Non-admin writing to `admin_logs/{logId}` or admin attempting to delete/edit an existing `admin_logs/{logId}`.
17. **Self-Approved Boost Request**: Creating `boost_requests/{boostId}` with `status: 'approved'` or updating own pending boost to `'approved'`.
18. **Scheduled Post Leak**: Reading another user's post with `status: 'scheduled'` before publication.
19. **Admin Offset Spoofing on Post**: Non-admin updating `adminLikesOffset` or `isBoosted` on their own post.

