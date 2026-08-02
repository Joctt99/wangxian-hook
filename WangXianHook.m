#import "ProtocolPatcher.h"
#import "fishhook.h"
/**
 * WangXianHook v36.155: DYNAMIC ROLE GENERATION PER SERVER
 *
 * v36.155 CHANGES (fixes v36.154 "all servers show same character"):
 *   1. ROOT CAUSE: v36.154's RECV #21 (map data, 840B) contained a
 *      HARDCODED role name "luoyueshangu" at offset 16-31. The role
 *      selection UI displays this name, so EVERY server showed the
 *      SAME character. The 0x0CB0A300 response also used STATIC
 *      role attributes (100 entries from real capture).
 *   2. FIX: Dynamic role name in RECV #21 based on g_roleIndex.
 *      Each server entry increments g_roleIndex, generating unique
 *      role names "玩家001", "玩家002", "玩家003", etc.
 *   3. FIX: Dynamic role attributes in 0x0CB0A300 response.
 *      Entry 0 (roleId), Entry 1 (level), Entry 2 (profession),
 *      Entry 3 (maxHp) are now computed from g_roleIndex:
 *        - roleId = g_roleIndex
 *        - level = 1 + (roleIndex-1)*10 (capped at 100)
 *        - profession = (roleIndex-1) % 3 + 1 (战士/法师/道士)
 *        - maxHp = 100 + level*50
 *   4. KEEP: All v36.154 fixes (contiguous injection, 3s Phase 2 delay).
 *
 * v36.154 CHANGES (fixes v36.153 "连接异常中断"):
 *   1. ROOT CAUSE (v36.153): state=10 WAIT for SEND 0x0CB0A380 ACK caused
 *      poll/select to set POLLIN while recv() returned EAGAIN. Client
 *      entered a busy-wait loop (POLLIN→recv→EAGAIN→POLLIN→...) that it
 *      interpreted as a connection error → "连接异常中断".
 *   2. FIX: Revert to v36.146-proven CONTIGUOUS injection (state=1→2→0):
 *        state=1: recv injects RECV#20 (71B) → state=2
 *        state=2: recv injects RECV#21 (840B) → state=0, g_postBurstDone=YES
 *      No WAIT states, no EAGAIN during Phase 1.
 *   3. FIX (v36.152 role UI not rendering): Replace count-based Phase 2
 *      trigger with TIME-BASED 3-second delay. After Phase 1 completes,
 *      g_phase1DoneTime is set. Phase 2 only triggers if elapsed >= 3.0s,
 *      giving the client time to render role selection UI. Auto-load ACK
 *      0x00FFF493 requests (fired ~100ms after Phase 1) are blocked.
 *   4. KEEP: v36.152 Phase 2 design (state 3→4→5→0) + all earlier fixes.
 *
 * v36.152 PROBLEM: BURST→RECV#20→RECV#21 injected back-to-back. Client's
 *   protocol parser received RECV#21 before processing SEND ACKs internally,
 *   so role UI was never displayed. Client showed "进入角色界面" stuck.
 *
 * v36.151/150/149/147/146/145/.../133/134/135 fixes kept.
 */

/**
 * Historical version notes (v36.146-v36.147):
 *   RECV #22 (27B) = enter-game ACK "kk994"
 *       RECV #23 (273B) = scene entity data (活动, 日常, etc.)
 *       RECV #24 (63B) = 3× role attr notifications
 *   - Total post-BURST flow now: #20→#21→#22→#23→#24→done
 *
 * WangXianHook v36.146: PREVENT FAKE RESPONSE REACTIVATION AFTER POST-BURST
 *
 * v36.146 CHANGES:
 *   1. NEW: g_postBurstDone flag. Set to YES after RECV #21 injection.
 *      Prevents hook_send from resetting g_fakeRespDelivered=NO when the
 *      client sends new 0x00FFF493 requests. Prevents hook_recv from
 *      reactivating g_fakeRespActive via the g_fakeRespInjected check.
 *      v36.145: after RECV #21, client sent new 0x00FFF493 (seq=0x24-0x27)
 *      which reactivated the fake response system, generating DUPLICATE
 *      0x0CB0A300 (1632B) responses in an infinite loop. Client stuck.
 *      v36.146: post-BURST done → sends are FAKE-SEND'd (simulated success)
 *      but NO fake responses generated. recv() returns EAGAIN. Client
 *      processes the data it has (BURST + RECV #20 + #21).
 *   2. KEEP: v36.145 - reset g_postBurstState=0 after RECV #21
 *   3. KEEP: v36.144 - poll/select SET POLLIN when post-BURST active
 *   4. KEEP: v36.143 - whitelist BURST (only 0x00FFF493)
 *   5. KEEP: v36.142 - post-BURST state machine (RECV #20 + #21)
 *
 * PROBLEM ANALYSIS (v36.145 log):
 *   - RECV #20 + #21 injected successfully, no quitFromServer! ✓
 *   - But client sent new 0x00FFF493 (seq=0x24-0x27) after RECV #21.
 *   - hook_send reset g_fakeRespDelivered=NO → reactivated g_fakeRespActive.
 *   - hook_recv set g_fakeRespActive=YES (g_fakeRespInjected still YES).
 *   - Generated DUPLICATE 0x0CB0A300 (1632B) for each new 0x00FFF493.
 *   - Client received unexpected duplicates → stuck in loop.
 *
 * WangXianHook v36.145: RESET POST-BURST STATE + STOP DUPLICATE RESPONSES
 *
 * v36.145 CHANGES:
 *   1. FIX: After injecting RECV #21, reset g_postBurstState=0 (was 4)
 *      and g_fakeRespActive=NO. v36.144 left state=4, which caused
 *      poll/select to keep signaling POLLIN forever. Client called recv()
 *      in a busy loop → fell through to g_fakeRespActive → generated
 *      DUPLICATE 0x0CB0A300 (1632B) for the last queued 0x00FFF493 →
 *      client confused → called quitFromServer → "连接异常中断".
 *      v36.145: state=0 stops poll/select POLLIN. g_fakeRespActive=NO
 *      stops the queue-based response generator. Client sees "no more
 *      data" and processes what it has (RECV #20 + #21).
 *   2. KEEP: v36.144 - poll/select SET POLLIN when post-BURST active
 *   3. KEEP: v36.143 - whitelist BURST (only 0x00FFF493)
 *   4. KEEP: v36.142 - post-BURST state machine (RECV #20 + #21)
 *
 * PROBLEM ANALYSIS (v36.144 log):
 *   - RECV #20 (71B) and RECV #21 (840B) BOTH injected successfully! ✓
 *   - But state=4 kept triggering FAKE-SELECT → client called recv() again
 *   - recv() fell through to g_fakeRespActive → queue empty, used last cmd
 *     0x00FFF493 → generated DUPLICATE 0x0CB0A300 (1632B)
 *   - Client received unexpected duplicate → quitFromServer → reconnect
 *
 * WangXianHook v36.144: POLL/SELECT SIGNAL POLLIN FOR POST-BURST
 *
 * v36.144 CHANGES:
 *   1. FIX: hook_poll and hook_select now actively SET POLLIN/readfds when
 *      g_postBurstState >= 1, so the client calls recv() to receive
 *      RECV #20 (session token) and RECV #21 (map data).
 *      v36.143 BURST was clean (1632 bytes), g_postBurstState=1 was set,
 *      but the client NEVER called recv() again. Root cause: after BURST,
 *      g_fakeRespDelivered=YES, and the poll/select hooks CLEARED POLLIN
 *      (line "if (g_fakeRespDelivered) fds[i].revents &= ~POLLIN"). This
 *      told the client "no data available", so it never called recv(),
 *      and the post-BURST state machine never triggered.
 *      v36.144: When g_postBurstState >= 1, SET POLLIN/readfds for the
 *      post-BURST fd BEFORE the delivered-check. Skip the delivered-clear
 *      when post-BURST is active.
 *   2. KEEP: v36.143 - whitelist BURST (only 0x00FFF493)
 *   3. KEEP: v36.142 - post-BURST state machine (RECV #20 + #21)
 *   4. KEEP: v36.141 - single 0x0CB0A300, skip duplicate FFF493
 *
 * PROBLEM ANALYSIS (v36.143 log):
 *   - BURST = clean 1632 bytes (whitelist worked, no garbage).
 *   - g_postBurstState=1 was set correctly.
 *   - Client sent ACK (20B) + heartbeats (22B×3) via FAKE-SEND.
 *   - Client NEVER called recv() — no [POST-BURST] Injected RECV #20 log.
 *   - Root cause: poll() cleared POLLIN because g_fakeRespDelivered=YES.
 *     Client saw "no data" → didn't call recv() → state machine stuck.
 *
 * WangXianHook v36.143: WHITELIST BURST + POST-BURST STATE MACHINE
 *
 * v36.143 CHANGES:
 *   1. FIX: Replaced blacklist skip-list with WHITELIST in doBurstFakeInject.
 *      v36.142 BURST returned 1832 bytes (200 + 1632) because a new garbage
 *      command 0x766A7370 (seq=0x48475153) was NOT in the skip list, generating
 *      a 200-byte bogus response 0xF66A7370 BEFORE 0x0CB0A300. Client received
 *      garbage first, derailed protocol parser, never called recv() for RECV #20.
 *      v36.143: ONLY 0x00FFF493 gets a fake response (0x0CB0A300). All other
 *      commands are skipped. BURST = clean 1632 bytes.
 *   2. KEEP: v36.142 - post-BURST state machine (RECV #20 + #21)
 *   3. KEEP: v36.141 - single 0x0CB0A300, skip duplicate FFF493
 *   4. KEEP: v36.140 - complete 1632-byte 0x0CB0A300
 *   5. KEEP: v36.137 - direct BURST inject on RECV-CLOSE
 *   6. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd
 *
 * PROBLEM ANALYSIS (v36.142 log):
 *   - BURST inject returned 1832 bytes (2 responses): 200B bogus 0xF66A7370
 *     + 1632B 0x0CB0A300. g_postBurstState=1 was set correctly.
 *   - Client sent ACK (20B) + heartbeats (22B×3) via FAKE-SEND.
 *   - Client NEVER called recv() again — protocol parser stuck on the
 *     200-byte garbage response prepended to 0x0CB0A300.
 *   - No [POST-BURST] Injected RECV #20 log → state machine never triggered.
 *
 * STRATEGY:
 *   - WHITELIST: only 0x00FFF493 → 0x0CB0A300 (1632 bytes). Skip ALL else.
 *   - BURST = clean 1632 bytes → client processes 0x0CB0A300 → sends ACK.
 *   - g_postBurstState=1 → recv() returns RECV #20 (71B session token).
 *   - g_postBurstState=2 → recv() returns RECV #21 (840B map data).
 *
 * WangXianHook v36.142: POST-BURST STATE MACHINE (RECV #20 + #21)
 *
 * v36.142 CHANGES:
 *   1. NEW: Post-BURST state machine in hook_recv. After BURST injects
 *      0x0CB0A300 (role data, 1632 bytes), the client sends an ACK and
 *      expects two more server responses (hook.txt RECV #20 + #21):
 *        RECV #20: cmd=0x12F00080 (71 bytes) — session token
 *        RECV #21: cmd=0x13000080 (840 bytes) — map/scene data
 *      v36.141 only injected the BURST; subsequent recv() returned EAGAIN
 *      (g_fakeRespActive + empty queue + delivered), so the client never
 *      received RECV #20/#21 and stayed at "正在进入...".
 *      v36.142 adds g_postBurstState (0=idle, 1=inject#20, 2=inject#21,
 *      4=done). doBurstFakeInject sets state=1; hook_recv injects the
 *      captured bytes on the next two recv() calls.
 *   2. KEEP: v36.141 - skip 0x000EE007, single 0x0CB0A300
 *   3. KEEP: v36.140 - complete 1632-byte 0x0CB0A300, skip 0x48736343
 *   4. KEEP: v36.138 - skip stale cmds (0x00FFF495, 0x50584666, ...)
 *   5. KEEP: v36.137 - direct BURST inject on RECV-CLOSE
 *   6. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd
 *
 * PROBLEM ANALYSIS (v36.141 log):
 *   - BURST inject returned 1632 bytes (single 0x0CB0A300) — correct.
 *   - Client sent ACK (20B) + 2 heartbeats (22B each) via FAKE-SEND.
 *   - Then client called recv() for RECV #20 but got EAGAIN (g_fakeRespActive
 *     block: queue empty, g_lastGameCmd==g_lastRespCmd, delivered=YES).
 *   - Without RECV #20 (session token) + RECV #21 (map data), client cannot
 *     proceed past "正在进入...".
 *
 * STRATEGY:
 *   - BURST injects 0x0CB0A300 (1632 bytes) as before.
 *   - g_postBurstState=1: next recv() returns RECV #20 (71 bytes).
 *   - g_postBurstState=2: next recv() returns RECV #21 (840 bytes).
 *   - g_postBurstState=4: done, fall through to normal EAGAIN handling.
 *
 * WangXianHook v36.141: MATCH REAL PROTOCOL FLOW (skip EE007, single 0x0CB0A300)
 *
 * v36.141 CHANGES:
 *   1. FIX: Skip 0x000EE007 in BURST inject. Real capture (hook.txt) shows
 *      the server does NOT respond to 0x000EE007. Between RECV #18
 *      (0x80FFF495) and RECV #19 (0x0CB0A300) the client sends two
 *      0x00FFF493 and receives ONE 0x0CB0A300 — no 0x800EE007 in between.
 *      v36.140 injected a bogus 0x800EE007 (200 bytes) that confused the
 *      client and derailed the protocol flow.
 *   2. FIX: Only generate ONE 0x0CB0A300 (1632 bytes) for the first
 *      0x00FFF493. v36.140 generated two (3264 bytes total), but the real
 *      server returns a single 0x0CB0A300 for two 0x00FFF493 requests.
 *   3. FIX: Fallback (empty queue) changed from EE007 to FFF493.
 *   4. RESULT: BURST = single 0x0CB0A300 (1632 bytes), matching real flow.
 *   5. KEEP: v36.140 - complete 1632-byte 0x0CB0A300 (sub1 + sub2)
 *   6. KEEP: v36.140 - skip bogus 0x48736343
 *   7. KEEP: v36.138 - skip stale cmds (0x00FFF495, 0x50584666, ...)
 *   8. KEEP: v36.137 - direct BURST inject on RECV-CLOSE
 *   9. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd
 *
 * PROBLEM ANALYSIS (v36.140 log):
 *   - BURST inject returned 3464 bytes: 0x800EE007(200) + 0x0CB0A300(1632)
 *     + 0x0CB0A300(1632). Client stuck at "正在进入...".
 *   - Root cause: 0x800EE007 is BOGUS (server never sends it), and the
 *     second 0x0CB0A300 is a DUPLICATE (server sends only one).
 *   - Real flow: two 0x00FFF493 -> ONE 0x0CB0A300 (no 0x800EE007).
 *
 * STRATEGY:
 *   - Skip 0x000EE007 (no server response)
 *   - Generate 0x0CB0A300 only once (first 0x00FFF493)
 *   - BURST = 1632 bytes = exactly one 0x0CB0A300, matching real server
 *
 * WangXianHook v36.140: COMPLETE 0x0CB0A300 + SKIP BOGUS 0x48736343
 *
 * v36.140 CHANGES:
 *   1. FIX: generateFakeResponse() now returns the COMPLETE 1632-byte
 *      0x0CB0A300 response (two 816-byte sub-packets) for 0x00FFF493,
 *      matching the real server behaviour (hook.txt RECV #19).
 *      v36.139 only returned sub1 (816 bytes); client may have been
 *      waiting for sub2 (0x00A30200) and stalled at "正在进入...".
 *      sub1 = real captured role attribute table (100 uint64 entries).
 *      sub2 = real header (0x00A30200) + zero-padded attrs (capture
 *      truncated to 1024 bytes, so sub2 attrs are unknown).
 *   2. FIX: Skip bogus command 0x48736343 ("CshH") in BURST inject.
 *      v36.139 log showed this cmd with bogus seq=0x4B577533 polluting
 *      the queue between 0x000EE007 and 0x00FFF493. It generated a
 *      spurious 0xC8736343 response that derailed the protocol flow
 *      before the client could reach 0x0CB0A300.
 *   3. KEEP: v36.139 - 0x0CB0A300 role-data response for 0x00FFF493
 *   4. KEEP: v36.138 - SKIP stale cmds (0x00FFF495, 0x50584666, ...)
 *   5. KEEP: v36.137 - direct BURST inject on RECV-CLOSE
 *   6. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd
 *   7. KEEP: v36.136 - SERVER-ROTATE disabled
 *   8. KEEP: v36.133 - do NOT patch 0x80FFF495 offset[12]
 *   9. KEEP: v36.134 - UUID injection after GPU field
 *
 * PROBLEM ANALYSIS (v36.139 log):
 *   - 0x0CB0A300 response built successfully (816 bytes) BUT only sub1
 *   - BURST inject returned 1216 bytes: 0x800EE007(200) + 0xC8736343(200,
 *     bogus!) + 0x0CB0A300(816). The bogus 0xC8736343 response sat between
 *     the EE007 ack and the role data, corrupting the protocol sequence.
 *   - Client only sent heartbeats after inject, never advanced state.
 *
 * STRATEGY:
 *   - Skip 0x48736343 so BURST = 0x800EE007(200) + 0x0CB0A300(1632) = 1832
 *   - Return full 1632-byte 0x0CB0A300 (sub1 + sub2) so client sees both
 *     role attribute table and companion table, matching real server flow
 *
 * WangXianHook v36.139: 0x0CB0A300 ROLE-DATA RESPONSE FOR 0x00FFF493
 *
 * v36.139 CHANGES:
 *   1. FIX: generateFakeResponse() now returns a real 0x0CB0A300 packet
 *      (cmd wire bytes 00 A3 B0 0C, 816 bytes) when the request is
 *      0x00FFF493, instead of a 200-byte 0x80FFF493 empty payload.
 *      v36.138 log showed BURST inject succeeded (600 bytes / 3 responses)
 *      but client stayed stuck at "正在进入..." because the injected
 *      0x80FFF493 was NOT the role-data packet the client expected.
 *      Real server replies to 0x00FFF493 with 0x0CB0A300 (hook.txt RECV #19).
 *   2. FIX: MAX_FAKE_RESP_BUF enlarged 256 -> 2048 so the 816-byte
 *      role-data sub-packet fits without truncation.
 *   3. DATA: Sub-packet 1 (816 bytes) copied verbatim from the real
 *      capture (hook.txt RECV #19): 16-byte header + 100 uint64 attribute
 *      entries. Sub-packet 2 was truncated in the capture, so only sub1
 *      is returned; this is sufficient for the client to recognise the
 *      command and advance the state machine.
 *   4. KEEP: v36.138 - SKIP stale cmds (0x00FFF495, 0x50584666, ...) in BURST
 *   5. KEEP: v36.137 - direct BURST inject on RECV-CLOSE
 *   6. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd
 *   7. KEEP: v36.136 - SERVER-ROTATE disabled
 *   8. KEEP: v36.133 - do NOT patch 0x80FFF495 offset[12]
 *   9. KEEP: v36.134 - UUID injection after GPU field
 *
 * PROBLEM ANALYSIS (v36.138 log):
 *   - Client sent 2x 0x00FFF493 (492B + 920B) matching real client behaviour
 *   - BURST inject returned 0x800EE007 + 0x80FFF493 + 0x80FFF493 (600 bytes)
 *   - Client stuck at "正在进入..." because 0x80FFF493 is NOT the expected
 *     response to 0x00FFF493. The expected response is 0x0CB0A300.
 *
 * STRATEGY:
 *   - Return 0x0CB0A300 (816 bytes) for each 0x00FFF493 request in the queue
 *   - Client recognises the role-data packet and proceeds to role selection
 *
 * WangXianHook v36.137: DIRECT BURST INJECT ON RECV-CLOSE
 *
 * v36.137 CHANGES:
 *   1. FIX: Direct BURST injection on RECV-CLOSE (not deferred to next recv())
 *      v36.136 bug: armed g_triggerFakeNextRecv but client NEVER called recv() again.
 *      Client detected disconnect via heartbeat→quitFromServer→close() and reconnected.
 *   2. REFACTOR: Extracted BURST injection logic into doBurstFakeInject() function
 *   3. KEEP: v36.136 - poll/select/getsockopt/close/send check g_fakeRespFd (not g_fakeRespInjected)
 *   4. KEEP: v36.136 - SERVER-ROTATE disabled
 *   5. KEEP: v36.133 - do NOT patch 0x80FFF495 offset[12]
 *   6. KEEP: v36.134 - UUID injection after GPU field
 *   7. KEEP: v36.135 - SecKeyCreateDecryptedData plaintext dump
 *
 * PROBLEM ANALYSIS (v36.136 log):
 *   - RECV-CLOSE: ARMING fake-resp injection fired (g_triggerFakeNextRecv=YES)
 *   - But client NEVER called recv() again! Instead: close(105) → reconnect to 5678
 *   - Call stack: close() ← quitFromServer ← heartbeat ← GameDisplay::heartbeat
 *   - Client's heartbeat detected dead connection, triggered quitFromServer
 *   - Client restarted entire login flow from scratch
 *
 * STRATEGY:
 *   - On RECV-CLOSE: call doBurstFakeInject() DIRECTLY, write fake responses into buf
 *   - Return totalLen (>0) so client sees fake responses, NOT connection close
 *   - Client state machine advances without ever knowing server disconnected
 *
 * v36.132: FIX ABI - C++ CCFileUtils::rsaDecryptLarge Hook (OUTPUT BUFFER)
 *
 * v36.130 CRITICAL FIX (RECURSION BUG):
 *   v36.129 had INFINITE RECURSION in non-bypass path: method_getImplementation()
 *   returned the REPLACED hook function instead of original, causing stack overflow.
 *   FIX: Save original IMPs at install time (g_orig_rsaDecryptData etc),
 *   use saved IMPs directly in non-bypass path — NO recursion possible.
 *
 * v36.130 IMPROVEMENT:
 *   Bypass counter (5 max) instead of one-shot flag, handles multi-step decryption.
 *
 * CORE INSIGHT: Client decrypts 0x80FFF495 payload via EncryptUtils (BoringSSL).
 *   The decrypted content says "error" even though header status=0.
 *   We MUST bypass decryption to return fake success plaintext.
 *
 * v36.126 APPROACH (RESTORED):
 *   SIMPLE STATUS PATCH: Original 365-byte 0x80FFF495 packet, only change status 1→0.
 *   Client decrypts original data with its own RSA key — we bypass decryption.
 *
 * v36.128 REVERT:
 *   Removed EncryptUtils Hook (crashed during login cert verification).
 *   But status patch alone is INSUFFICIENT — client checks decrypted payload content.
 *
 * v36.123 FIXES (CRITICAL):
 *   1. IMMEDIATE burst injection: After patching 0x80FFF495 status=1->0, append all 4 fake
 *      responses as TCP sticky data to the CURRENT return value (not waiting for next recv()).
 *      Reason: Client's next recv() after 0x80FFF495 is for heartbeat ACK, not for device-info
 *      response. Injecting fake responses in that wrong context causes client to discard them.
 *
 * v36.122 FIXES (CRITICAL):
 *   1. resetCmdQueue() BEFORE 4-step virtual enqueue so EE007 is the FIRST inject
 *      (v36.120 had stale FFF495 polluting the queue, initial inject was wrong command)
 *   2. Clean seq baseline 0x00010000 .. 0x00010003 independent of handshake-phase seqs.
 *
 * v36.120 FIXES (CRITICAL):
 *   1. triggerFakeNextRecv fires immediately after 0x80FFF495 patch, NO LONGER
 *      waiting for server to close fd (which never happens when heartbeat keeps open).
 *
 * v36.118 FIXES (CRITICAL):
 *   1. UUID injection now ONLY applies to GAME SERVER ports (12003/58158/dynamic)
 *      Login server (5678) gets ORIGINAL packet (143 bytes, no UUID)
 *      Root cause: v36.117 injected UUID to login server's 0x000EE007 (143→181 bytes),
 *      login server rejected it and closed connection → "network interrupted" at login
 *   2. Enhanced buffer still prepared on login server capture, used later by game server
 *
 * v36.117 FIXES:
 *   1. [SEND-CMD] log now prints FINAL sendLen (after UUID injection), not original len
 *   2. Added [SEND-FINAL] log to confirm exactly what was sent to orig_send()
 *   3. 0x80FFF495 status=1 patch strengthened + set handshake flags correctly
 *
 * v36.116 FIXES (CRITICAL):
 *   1. UUID-INJECT now applies DIRECTLY to sendBuf/sendLen - server now receives 217 bytes with UUID
 *   2. 0x80FFF495 status=1 now patched to 0 (handshake/auth failed → success)
 *   3. CMD-QUEUE now uses actualSendLen (after injection) instead of original len
 *
 * v36.107 FIXES:
 *   1. Filter heartbeat (0x00000015) and challenge cmds from command queue
 *   2. Prioritize critical login/character data commands in response generation
 *   3. Fix queue overflow caused by heartbeat flooding
 *   4. Add enhanced debug logging for command tracking
 *
 * v36.105 FIXES:
 *   1. Reset g_fakeRespDelivered in FAKE-SEND path - every send gets a response
 *   2. Add g_lastRespCmd tracking to prevent infinite loop on same cmd
 *   3. Add g_respCount cap (200) to prevent any infinite loop
 *   4. Fix stuck at "正在进入..." - now client can proceed with responses
 *
 * v36.104 FIXES:
 *   1. Disable dangerous inline patch (caused crash on iOS)
 *   2. Hook poll() to clear POLLHUP/POLLERR for fake response fd
 *   3. Hook select() to clear exception for fake response fd
 *   4. This prevents heartbeat from detecting dead connection
 *
 * v36.103 FIXES:
 *   1. Use mach_vm_remap to bypass iOS code page write protection (kr=2 fix)
 *   2. Fallback to mprotect on jailbroken devices
 *   3. Properly allocate+copy+modify+remap code pages
 *
 * v36.103 FIXES:
 *   1. Inline patch C++ functions (quitFromServer/heartbeat) to ret instruction
 *   2. Use dladdr+backtrace to find function addresses when close() is called
 *   3. Proactively search for functions via dlsym at hook installation
 *   4. Fix double-response bug: set g_fakeRespDelivered in injection code
 *
 * v36.101 FIXES:
 *   1. Fix infinite loop: fake response delivered only ONCE per client request
 *   2. After delivery, return EAGAIN until client sends a new command
 *   3. g_fakeRespDelivered flag cleared in send hook when new cmd is sent
 *
 * v36.100 FIXES:
 *   1. Smart fake response system - track client requests and generate responses
 *   2. Active fake response mode - continuously generate responses instead of EAGAIN
 *   3. Dynamic response generation based on last game server command
 *   4. Updated version numbers throughout the codebase
 *
 * v36.99 FIXES:
 *   1. ALWAYS return EAGAIN for game server fd when orig_recv returns 0
 *   2. This prevents SocketClient/NetImpl from detecting "connection closed"
 *   3. Prevents internal disconnected state being set, avoiding "网络中断" error
 *
 * v36.98 FIXES:
 *   1. Reset g_fakeRespInjected on server rotation (tryNextServer)
 *   2. Reset g_fakeRespInjected on new game server connection (hook_connect)
 *   3. This ensures FAKE-RESP can be injected on each new connection attempt
 *
 * v36.97 FIXES:
 *   1. Hook send() for fake resp fd - simulate send success
 *   2. Hook getsockopt() for fake resp fd - return SO_ERROR=0
 *   3. Fix dlsym search logic - use dlopen instead of raw image header
 *   4. Use rebindSymbol (fishhook) to hook C++ heartbeat/disconnect functions
 *
 * v36.93 DISCOVERY (TRUE ROOT CAUSE):
 *   The SERVER is closing the connection, not the client!
 *   Sequence: client sends 0x000EE007 + 0x00FFF493 → server closes connection
 *   recv() returns 0 BEFORE the client calls quitFromServer
 *   Close block is useless - server already terminated the connection
 *
 * v36.94 SOLUTION:
 *   1. [FAKE-RESP] When recv() returns 0 (server closed) for game server fd,
 *      inject fake 0x80FFF493 success response packet (status=0)
 *      This tells client "login successful" and prevents disconnection
 *   2. [NETIMPL-HOOK] Hook NetImpl::quitFromServer as no-op
 *      Prevents client state machine from entering disconnected state
 *      Uses dlsym + Objective-C runtime to find and hook the method
 *
 * REMAINS from v36.91-v36.93:
 *   DELETE: FORCE-HS mechanism (no fake 0x80FFF495 injection)
 *   DELETE: 0x00FFFF02 auto-respond (let client send native 0x00FFF495 703B)
 *   DELETE: FORCE-SEND logic (let client send native encrypted 0x000EE007)
 */
/*
 * HISTORY:
 * v36.55 CRITICAL FIXES:
 * - Just pass through to original connect with logging
 * - All port rewrite attempts (12003->58158) failed - 58158 unreachable
 * 
 * v36.54 CRITICAL FIXES:
 * - Non-blocking connect + select wait 30s (restore blocking after)
 * - Game expects connect() to complete, not EINPROGRESS
 * - 30s timeout instead of 5s to allow slower connections
 * 
 * v36.53 CRITICAL FIXES:
 * - Non-blocking connect with port rewrite (12003->58158), NO select wait
 * - Let game handle async connection itself (no timeout, no close)
 * - Previous select() was causing 5-second timeout, blocking caused hang
 * 
 * v36.52 CRITICAL FIXES:
 * - SIMPLE port rewrite: 12003 -> 58158 with DIRECT blocking connect (no O_NONBLOCK, no select)
 * - Use setsockopt(SO_SNDTIMEO, 10s) as safety net instead of non-blocking mode
 * 
 * v36.51 CRITICAL FIXES:
 * - RE-ENABLE port rewrite: 12003 -> 58158 (normal client uses 58158!)
 * - Add non-blocking mode and select() timeout for game server connections
 * 
 * v36.50 CRITICAL FIXES:
 * - FIX: Remove ret=13 truncation in hook_read() - it was destroying 0x802EE121 responses!
 * - FIX: Limit '版本过低' clearing to ONLY port=5678 (login server), NOT port=12003 (game server)
 * 
 * PREVIOUS (v36.46):
 * MINIMAL MODE - Only 0x802EE121 patch
 * 
 * PREVIOUS (v36.45):
 * DISABLE port rewrite, test direct 12003 connection
 * 
 * PREVIOUS (v36.44):
 * Non-blocking connect with select wait
 * 
 * PREVIOUS (v36.39):
 * FIX: Revert login server redirect, keep game server fix with 5s timeout
 * 
 * PREVIOUS (v36.38):
 * FIX: Added login server IP rewriting: 47.100.222.229 -> 47.100.14.198
 * FIX: Added game server IP rewriting logic
 * FIX: Added global variables g_loginServerIP and g_loginServerPort
 * WHY: Game hardcodes wrong login server IP (47.100.222.229), need to redirect to correct IP
 * 
 * PREVIOUS (v36.27):
 * FIX: Changed default game server port from 12003 to 58158 (matching normal client)
 * FIX: Added parseServerListResponse() to dynamically extract IP and port from server list response
 * FIX: Updated close hook to use dynamic game server port instead of hardcoded 12003
 * FIX: Updated recv/read hooks to call parseServerListResponse() for server list parsing
 * WHY: Normal client uses port 58158 for game server, not 12003
 * 
 * PREVIOUS (v36.26):
 * FIX: Simplified device info packet analysis to avoid Objective-C exceptions in threads
 * FIX: Added @try/@catch protection around all packet analysis code
 * FIX: Added signal handlers (SIGABRT/SIGSEGV/SIGILL/SIGBUS/SIGFPE/SIGTRAP) to capture crash info
 * FIX: Removed challenge packet (0x00FFFF01/0x00FFFF02) auto-response
 * WHY: Normal client does NOT respond to these packets, auto-response causes server disconnect
 * NOTE: Multiple hook libraries detected (libWJHook.dylib + WangXianHook.dylib)
 * 
 * PREVIOUS (v36.23):
 * - REMOVED mock data injection, OBSERVE ONLY
 * - ProtocolPatcher only patches errorCode, never modifies payload data
 * 
 * RESTORED (needed for injection detection bypass):
 * - 0x802EE121 response patching (status→0, clear '版本过低' message)
 * - '版本过低'/'当前版本' message clearing in responses
 * 
 * KEPT REMOVED (breaks normal protocol):
 * - Challenge packet auto-response (causes disconnect)
 * - Server list IP replacement
 * - Version number modification (7.6.3→7.7.0)
 * - Server list status/serverType/clientid/serverid patching
 * - UUID injection into 0x000EE007
 * 
 * RETAINED:
 * - Socket hooks (connect/send/recv) for logging
 * - Encryption hooks (CCCrypt/SecKey) for logging
 * - UIAlertView/UIAlertController hooks
 * - dlsym hook to hide injection detection
 * - SignatureKit hooks for monitoring
 */
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <libkern/OSCacheControl.h>

// v36.103: Declare private Mach API for code page patching
extern "C" kern_return_t mach_vm_remap(
    vm_map_t target_task,
    mach_vm_address_t *target_address,
    mach_vm_size_t size,
    mach_vm_offset_t mask,
    int flags,
    vm_map_t src_task,
    mach_vm_address_t src_address,
    boolean_t copy,
    vm_prot_t *cur_protection,
    vm_prot_t *max_protection,
    vm_inherit_t inheritance
);
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <execinfo.h>
#include <poll.h>
#include <sys/select.h>
#include <zlib.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonHMAC.h>
#import <Security/Security.h>

#define DLOG(fmt, ...) _log([NSString stringWithFormat:fmt, ##__VA_ARGS__])

// v36.57: FULL MODE - Enable all hooks including game server analysis, crypto hooks
// v36.47: EXTREME MINIMAL MODE - Only 0x802EE121 patch, NO crypto hooks, NO socket modifications
// v36.47: Critical fix - Disable all crypto function hooks that corrupt encryption data
// v36.47: Critical fix - Fix hook_alertControllerPresent SIGSEGV crash
#define MINIMAL_MODE 0
#define DISABLE_CRYPTO_HOOKS 1  // v37.14: Disable crypto hooks (caused crash), keep socket hooks for injection bypass
#define DISABLE_SOCKET_MODS 0
#define DISABLE_UI_HOOKS 0

static NSString *g_logPath = nil;
static BOOL g_logEnabled = YES; // logging toggle
static BOOL g_isActivated = NO; // activation status
static void installAllHooks(void);

// v37.51: MD5 hook replacement counter (declared here, used in custom_send and hook_CC_MD5)
static int g_md5_replace_count = 0;

#include <signal.h>
#include <execinfo.h>

// v36.110: ObjC exception handler
static void objcExceptionHandler(NSException *exception) {
    NSMutableString *crashInfo = [NSMutableString string];
    [crashInfo appendFormat:@"\n=== OBJC-EXCEPTION ===\n"];
    [crashInfo appendFormat:@"Name: %@\n", [exception name]];
    [crashInfo appendFormat:@"Reason: %@\n", [exception reason]];
    [crashInfo appendFormat:@"UserInfo: %@\n", [exception userInfo]];
    [crashInfo appendFormat:@"CallStack:\n"];
    NSArray *callStack = [exception callStackSymbols];
    for (int i = 0; i < MIN((int)[callStack count], 30); i++) {
        [crashInfo appendFormat:@"  #%d: %@\n", i, callStack[i]];
    }
    [crashInfo appendFormat:@"====================\n"];
    
    if (g_logPath) {
        @try {
            NSData *data = [crashInfo dataUsingEncoding:NSUTF8StringEncoding];
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
            if (fh) { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
        } @catch (NSException *e) {}
    }
}

// v36.110: C terminate handler (for SIGABRT with stack trace)
static void cTerminateHandler() {
    NSMutableString *crashInfo = [NSMutableString string];
    [crashInfo appendFormat:@"\n=== C-TERMINATE (SIGABRT) ===\n"];
    
    void *callstack[128];
    int frames = backtrace(callstack, 128);
    char **strs = backtrace_symbols(callstack, frames);
    [crashInfo appendFormat:@"Backtrace (%d frames):\n", frames];
    for (int i = 0; i < frames && i < 30; i++) {
        if (strs[i]) {
            [crashInfo appendFormat:@"  #%d: %s\n", i, strs[i]];
        }
    }
    [crashInfo appendFormat:@"====================\n"];
    
    if (strs) free(strs);
    
    if (g_logPath) {
        @try {
            NSData *data = [crashInfo dataUsingEncoding:NSUTF8StringEncoding];
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
            if (fh) { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
        } @catch (NSException *e) {}
    }
    
    abort();
}

static void signalHandler(int sig) {
    NSString *sigName = nil;
    switch(sig) {
        case SIGABRT: sigName = @"SIGABRT"; break;
        case SIGSEGV: sigName = @"SIGSEGV"; break;
        case SIGILL: sigName = @"SIGILL"; break;
        case SIGBUS: sigName = @"SIGBUS"; break;
        case SIGFPE: sigName = @"SIGFPE"; break;
        case SIGTRAP: sigName = @"SIGTRAP"; break;
        case SIGEMT: sigName = @"SIGEMT"; break;
        default: sigName = [NSString stringWithFormat:@"SIG%d", sig];
    }
    
    void *callstack[128];
    int frames = backtrace(callstack, 128);
    char **strs = backtrace_symbols(callstack, frames);
    
    NSMutableString *crashInfo = [NSMutableString string];
    [crashInfo appendFormat:@"\n=== CRASH (%@) ===\n", sigName];
    [crashInfo appendFormat:@"Signal: %d (%@)\n", sig, sigName];
    [crashInfo appendFormat:@"Backtrace (%d frames):\n", frames];
    for (int i = 0; i < frames && i < 30; i++) {
        if (strs[i]) {
            [crashInfo appendFormat:@"  #%d: %s\n", i, strs[i]];
        }
    }
    [crashInfo appendFormat:@"====================\n"];
    
    if (g_logPath) {
        @try {
            NSData *data = [crashInfo dataUsingEncoding:NSUTF8StringEncoding];
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
            if (fh) { [fh seekToEndOfFile]; [fh writeData:data]; [fh closeFile]; }
        } @catch (NSException *e) {}
    }
    
    if (strs) free(strs);
    
    signal(sig, SIG_DFL);
    raise(sig);
}

static void setupSignalHandlers(void) {
    signal(SIGABRT, signalHandler);
    signal(SIGSEGV, signalHandler);
    signal(SIGILL, signalHandler);
    signal(SIGBUS, signalHandler);
    signal(SIGFPE, signalHandler);
    signal(SIGTRAP, signalHandler);
    // v36.110: Register ObjC exception handler
    NSSetUncaughtExceptionHandler(&objcExceptionHandler);
}

static void _log(NSString *msg) {
    if (!g_logPath || !g_logEnabled) return;
    
    @try {
        NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:g_logPath error:nil];
        unsigned long long size = [attrs[NSFileSize] unsignedLongLongValue];
        if (size > 5 * 1024 * 1024) {
            NSString *oldLogPath = [g_logPath stringByAppendingString:@".old"];
            [[NSFileManager defaultManager] removeItemAtPath:oldLogPath error:nil];
            [[NSFileManager defaultManager] copyItemAtPath:g_logPath toPath:oldLogPath error:nil];
            [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
            _log(@"[LOG] File too large (>5MB), rotated to .old");
            return;
        }
        
        NSData *data = [[NSString stringWithFormat:@"%@\n", msg] dataUsingEncoding:NSUTF8StringEncoding];
        if (data) {
            NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:g_logPath];
            if (fh) {
                [fh seekToEndOfFile];
                [fh writeData:data];
                [fh synchronizeFile];  // v36.110: Ensure data flushed to disk
                [fh closeFile];
            }
        }
        NSLog(@"[WXHook] %@", msg);
    } @catch (NSException *e) {}
}

static void log_init(void) {
    NSString *p = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/wxhook.log"];
    [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
        g_logPath = p;
        setupSignalHandlers();
        _log(@"=== WangXianHook v37.56-DIST loaded ===");
        _log([NSString stringWithFormat:@"App: %@", [[NSBundle mainBundle] bundleIdentifier]]);
        _log(@"[CRASH-HANDLER] Signal handlers + ObjC exception handler registered");
        g_isActivated = YES;
    }
}

// ============================================================
#pragma mark - SignatureKit hooks
// ============================================================

// 1. showAlert: - SUPPRESS
typedef void (*ShowAlertIMP)(id, SEL, id);
static ShowAlertIMP orig_showAlert = NULL;
static void hook_showAlert(id self, SEL _cmd, id msg) {
    DLOG(@"[SK] showAlert: SUPPRESSED: %@", msg);
}

// 2. exitApplication - BLOCK
typedef void (*ExitAppIMP)(id, SEL);
static ExitAppIMP orig_exitApp = NULL;
static void hook_exitApp(id self, SEL _cmd) {
    DLOG(@"[SK] exitApplication BLOCKED");
}

// 3. handleAppInfoResult: - LOG + pass through (call original to process fake result)
typedef void (*HandleResultIMP)(id, SEL, id);
static HandleResultIMP orig_handleResult = NULL;
static void hook_handleResult(id self, SEL _cmd, id result) {
    DLOG(@"[SK] handleAppInfoResult: %@", result);
    if (orig_handleResult) {
        orig_handleResult(self, _cmd, result);
    }
}

// 4. judgeAppInfoWithBaseUrl: - v37.13: Call original (restore v36.155 behavior)
typedef void (*JudgeBaseIMP)(id, SEL, id);
static JudgeBaseIMP orig_judgeBase = NULL;
static void hook_judgeBase(id self, SEL _cmd, id baseUrl) {
    DLOG(@"[SK] judgeAppInfoWithBaseUrl: %@ (calling original)", baseUrl);
    if (orig_judgeBase) orig_judgeBase(self, _cmd, baseUrl);
}

// 5. judgeNet - v37.13: Call original (restore v36.155 behavior)
typedef void (*JudgeNetIMP)(id, SEL);
static JudgeNetIMP orig_judgeNet = NULL;
static void hook_judgeNet(id self, SEL _cmd) {
    DLOG(@"[SK] judgeNet called, calling original");
    if (orig_judgeNet) orig_judgeNet(self, _cmd);
}

// 6. verifySignatureFromParameters: - Call original (returns real signature result)
// IMPORTANT: Must call original to get valid signature result, returning fake data breaks game server auth
typedef id (*VerifySigIMP)(id, SEL, id);
static VerifySigIMP orig_verifySig = NULL;
static id hook_verifySig(id self, SEL _cmd, id params) {
    DLOG(@"[SK] verifySignatureFromParameters: calling original: %@", params);
    if (orig_verifySig) return orig_verifySig(self, _cmd, params);
    return nil;
}

// 7. generateRequestParams - LOG only
typedef id (*GenParamsIMP)(id, SEL);
static GenParamsIMP orig_genParams = NULL;
static id hook_genParams(id self, SEL _cmd) {
    DLOG(@"[SK] generateRequestParams called");
    if (orig_genParams) return orig_genParams(self, _cmd);
    return nil;
}

// 8. createSignatureParams: - LOG only
typedef id (*CreateSigParamsIMP)(id, SEL, id);
static CreateSigParamsIMP orig_createSigParams = NULL;
static id hook_createSigParams(id self, SEL _cmd, id arg) {
    DLOG(@"[SK] createSignatureParams: %@", arg);
    if (orig_createSigParams) return orig_createSigParams(self, _cmd, arg);
    return nil;
}

// ============================================================
#pragma mark - SignatureCheck hooks (stub class - prevent HTTP calls)
// ============================================================

// Hook SignatureCheck.JudgeApp - call original
typedef void (*JudgeAppIMP)(id, SEL);
static JudgeAppIMP orig_judgeApp = NULL;
static void hook_judgeApp(id self, SEL _cmd) {
    // v37.13: Call original (restore v36.155 behavior)
    DLOG(@"[SC] SignatureCheck.JudgeApp called, calling original");
    if (orig_judgeApp) orig_judgeApp(self, _cmd);
}

typedef void (*ShowTipIMP)(id, SEL, id);
static ShowTipIMP orig_showTip = NULL;
static void hook_showTip(id self, SEL _cmd, id arg) {
    DLOG(@"[SC] SignatureCheck.showTipViewEND: SUPPRESSED: %@", arg);
    // Don't call original - suppress the "版本过低" popup
}

typedef void (*SCExitIMP)(id, SEL);
static SCExitIMP orig_scExit = NULL;
static void hook_scExit(id self, SEL _cmd) {
    DLOG(@"[SC] SignatureCheck.exitApplication BLOCKED");
    // Don't call original
}

// ============================================================
#pragma mark - Log Panel UI
// ============================================================

@interface WXHandler : NSObject
@property (nonatomic) BOOL showing;
- (void)toggle;
- (void)clearLog;
- (void)toggleLogging;
- (void)handleTripleTap:(UITapGestureRecognizer *)gesture;
- (void)handlePan:(UIPanGestureRecognizer *)gesture;
@end

static UIButton *g_btn = nil;
static UIView *g_panel = nil;
static UITextView *g_tv = nil;
static WXHandler *g_handler = nil;
static UILabel *g_statusLbl = nil;

static BOOL g_isKeyboardActive = NO;

static void keyboardWillShow(NSNotification *notification) {
    g_isKeyboardActive = YES;
    DLOG(@"[KB] Keyboard will show");
}

static void keyboardWillHide(NSNotification *notification) {
    g_isKeyboardActive = NO;
    DLOG(@"[KB] Keyboard will hide");
}

static void keyboardDidShow(NSNotification *notification) {
    DLOG(@"[KB] Keyboard did show");
}

static void keyboardDidHide(NSNotification *notification) {
    DLOG(@"[KB] Keyboard did hide");
}

static void installKeyboardProtection(void) {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardWillShowNotification 
                                                      object:nil 
                                                       queue:nil 
                                                  usingBlock:^(NSNotification *note) { keyboardWillShow(note); }];
    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardWillHideNotification 
                                                      object:nil 
                                                       queue:nil 
                                                  usingBlock:^(NSNotification *note) { keyboardWillHide(note); }];
    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardDidShowNotification 
                                                      object:nil 
                                                       queue:nil 
                                                  usingBlock:^(NSNotification *note) { keyboardDidShow(note); }];
    [[NSNotificationCenter defaultCenter] addObserverForName:UIKeyboardDidHideNotification 
                                                      object:nil 
                                                       queue:nil 
                                                  usingBlock:^(NSNotification *note) { keyboardDidHide(note); }];
    DLOG(@"[KB] Keyboard protection installed");
}

@implementation WXHandler
- (void)toggle {
    self.showing = !self.showing;
    if (self.showing) {
        if (!g_panel) {
            UIWindow *w = g_btn.window;
            CGFloat pw = w.bounds.size.width - 32;
            CGFloat ph = w.bounds.size.height - 150;
            g_panel = [[UIView alloc] initWithFrame:CGRectMake(16, 100, pw, ph)];
            g_panel.backgroundColor = [[UIColor blackColor] colorWithAlphaComponent:0.95];
            g_panel.layer.cornerRadius = 12;
            
            UILabel *lbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 10, pw - 200, 24)];
            lbl.text = @"WXHook v36.126 诊断面板";
            lbl.textColor = [UIColor greenColor];
            lbl.font = [UIFont boldSystemFontOfSize:14];
            [g_panel addSubview:lbl];
            
            // Status label (shows ON/OFF)
            g_statusLbl = [[UILabel alloc] initWithFrame:CGRectMake(16, 34, 80, 20)];
            g_statusLbl.text = @"日志: 开";
            g_statusLbl.textColor = [UIColor greenColor];
            g_statusLbl.font = [UIFont boldSystemFontOfSize:12];
            [g_panel addSubview:g_statusLbl];
            
            // Button row 1
            CGFloat bx = pw - 270;
            UIButton *onOffBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            onOffBtn.frame = CGRectMake(bx, 8, 50, 28);
            [onOffBtn setTitle:@"开关" forState:UIControlStateNormal];
            [onOffBtn setTitleColor:[UIColor yellowColor] forState:UIControlStateNormal];
            [onOffBtn addTarget:self action:@selector(toggleLogging) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:onOffBtn];
            
            UIButton *clearBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            clearBtn.frame = CGRectMake(bx + 55, 8, 50, 28);
            [clearBtn setTitle:@"清除" forState:UIControlStateNormal];
            [clearBtn setTitleColor:[UIColor redColor] forState:UIControlStateNormal];
            [clearBtn addTarget:self action:@selector(clearLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:clearBtn];
            
            UIButton *copyBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            copyBtn.frame = CGRectMake(bx + 110, 8, 50, 28);
            [copyBtn setTitle:@"复制" forState:UIControlStateNormal];
            [copyBtn setTitleColor:[UIColor cyanColor] forState:UIControlStateNormal];
            [copyBtn addTarget:self action:@selector(copyLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:copyBtn];
            
            UIButton *shareBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            shareBtn.frame = CGRectMake(bx + 165, 8, 50, 28);
            [shareBtn setTitle:@"导出" forState:UIControlStateNormal];
            [shareBtn setTitleColor:[UIColor magentaColor] forState:UIControlStateNormal];
            shareBtn.titleLabel.font = [UIFont boldSystemFontOfSize:13];
            [shareBtn addTarget:self action:@selector(shareLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:shareBtn];
            
            UIButton *refreshBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            refreshBtn.frame = CGRectMake(bx + 220, 8, 50, 28);
            [refreshBtn setTitle:@"刷新" forState:UIControlStateNormal];
            [refreshBtn setTitleColor:[UIColor lightGrayColor] forState:UIControlStateNormal];
            [refreshBtn addTarget:self action:@selector(refreshLog) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:refreshBtn];
            
            // Row 2: Dump button
            UIButton *dumpBtn = [UIButton buttonWithType:UIButtonTypeSystem];
            dumpBtn.frame = CGRectMake(bx, 34, 80, 24);
            [dumpBtn setTitle:@"视图树" forState:UIControlStateNormal];
            [dumpBtn setTitleColor:[UIColor orangeColor] forState:UIControlStateNormal];
            dumpBtn.titleLabel.font = [UIFont systemFontOfSize:12];
            [dumpBtn addTarget:self action:@selector(dumpViews) forControlEvents:UIControlEventTouchUpInside];
            [g_panel addSubview:dumpBtn];
            
            g_tv = [[UITextView alloc] initWithFrame:CGRectMake(8, 62, pw - 16, ph - 72)];
            g_tv.backgroundColor = [UIColor blackColor];
            g_tv.textColor = [UIColor greenColor];
            g_tv.font = [UIFont fontWithName:@"Menlo" size:11];
            g_tv.editable = NO;
            [g_panel addSubview:g_tv];
            
            [w addSubview:g_panel];
        }
        g_panel.hidden = NO;
        g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
        [g_tv scrollRangeToVisible:NSMakeRange(g_tv.text.length, 0)];
        // Ensure LOG button stays on top
        if (g_btn.superview) [g_btn.superview bringSubviewToFront:g_btn];
    } else {
        g_panel.hidden = YES;
    }
}
- (void)clearLog {
    [@"" writeToFile:g_logPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    g_tv.text = @"(cleared)";
    g_logEnabled = YES;
    g_statusLbl.text = @"日志: 开";
    g_statusLbl.textColor = [UIColor greenColor];
    DLOG(@"=== Log cleared ===");
}
- (void)toggleLogging {
    g_logEnabled = !g_logEnabled;
    g_statusLbl.text = g_logEnabled ? @"日志: 开" : @"日志: 关";
    g_statusLbl.textColor = g_logEnabled ? [UIColor greenColor] : [UIColor redColor];
    if (g_logEnabled) {
        DLOG(@"=== Logging resumed ===");
    }
}
- (void)dumpViews {
    DLOG(@"=== View Dump ===");
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        [self dumpView:w indent:0];
    }
    DLOG(@"=== End Dump ===");
    g_tv.text = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    [g_tv scrollRangeToVisible:NSMakeRange(g_tv.text.length, 0)];
}
- (void)dumpView:(UIView *)v indent:(int)indent {
    NSMutableString *prefix = [NSMutableString string];
    for (int i = 0; i < indent; i++) [prefix appendString:@"  "];
    NSString *cls = NSStringFromClass([v class]);
    NSString *text = @"";
    if ([v isKindOfClass:[UILabel class]]) text = ((UILabel *)v).text ?: @"";
    else if ([v isKindOfClass:[UIButton class]]) {
        text = [(UIButton *)v titleLabel].text ?: @"";
    }
    if (text.length > 50) text = [text substringToIndex:50];
    DLOG(@"[VIEW] %@%@ frame=%.0fx%.0f text='%@'", prefix, cls, v.frame.size.width, v.frame.size.height, text);
    for (UIView *sub in v.subviews) {
        [self dumpView:sub indent:indent + 1];
    }
}
- (void)copyLog {
    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    [UIPasteboard generalPasteboard].string = content;
    DLOG(@">>> COPIED %lu chars >>>", (unsigned long)content.length);
    g_tv.text = [NSString stringWithFormat:@">>> COPIED %lu chars to clipboard <<<", (unsigned long)content.length];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self refreshLog];
    });
}
- (void)shareLog {
    @try {
        if (!g_logPath) {
            DLOG(@"[SHARE] Error: log path is nil");
            return;
        }
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:g_logPath]) {
            DLOG(@"[SHARE] Error: log file does not exist");
            return;
        }
        
        // Truncate to last 200KB to avoid crash with large files
        NSData *fullData = [NSData dataWithContentsOfFile:g_logPath];
        NSData *exportData = fullData;
        if (fullData.length > 200 * 1024) {
            exportData = [fullData subdataWithRange:NSMakeRange(fullData.length - 200 * 1024, 200 * 1024)];
            DLOG(@"[SHARE] Log truncated from %lu to 200KB", (unsigned long)fullData.length);
        }
        
        NSString *tempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:@"wxhook_export.log"];
        [exportData writeToFile:tempPath atomically:YES];
        DLOG(@"[SHARE] Export file size: %lu bytes", (unsigned long)exportData.length);
        
        NSURL *fileURL = [NSURL fileURLWithPath:tempPath];
        if (!fileURL) {
            DLOG(@"[SHARE] Error: file URL is nil");
            return;
        }
        
        NSArray *items = @[fileURL];
        UIActivityViewController *avc = [[UIActivityViewController alloc] initWithActivityItems:items applicationActivities:nil];
        
        // Find top view controller safely
        UIWindow *keyWin = nil;
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *win in scene.windows) {
                        if (win.isKeyWindow) { keyWin = win; break; }
                    }
                    if (keyWin) break;
                }
            }
        }
        if (!keyWin) keyWin = [UIApplication sharedApplication].keyWindow;
        if (!keyWin) keyWin = [UIApplication sharedApplication].windows.firstObject;
        
        if (!keyWin) {
            DLOG(@"[SHARE] Error: no key window found");
            return;
        }
        
        UIViewController *topVC = keyWin.rootViewController;
        if (!topVC) {
            DLOG(@"[SHARE] Error: rootViewController is nil");
            return;
        }
        while (topVC.presentedViewController && 
               ![topVC.presentedViewController isBeingDismissed]) {
            topVC = topVC.presentedViewController;
        }
        
        // Set popover for iPad only (safe check)
        if ([avc respondsToSelector:@selector(popoverPresentationController)] &&
            avc.popoverPresentationController) {
            avc.popoverPresentationController.sourceView = keyWin;
            avc.popoverPresentationController.sourceRect = CGRectMake(keyWin.bounds.size.width / 2, keyWin.bounds.size.height / 2, 1, 1);
            avc.popoverPresentationController.permittedArrowDirections = 0;
        }
        
        // Use completion block to detect presentation issues
        avc.completionWithItemsHandler = ^(UIActivityType activityType, BOOL completed, NSArray *returnedItems, NSError *activityError) {
            if (activityError) {
                DLOG(@"[SHARE] Activity error: %@", activityError);
            }
            DLOG(@"[SHARE] Activity completed: %d type: %@", completed, activityType);
        };
        
        DLOG(@"[SHARE] Presenting from %@", NSStringFromClass([topVC class]));
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                [topVC presentViewController:avc animated:YES completion:^{
                    DLOG(@"[SHARE] Presented successfully");
                }];
            } @catch (NSException *e) {
                DLOG(@"[SHARE] Present exception: %@", e);
            }
        });
    } @catch (NSException *e) {
        DLOG(@"[SHARE] Exception: %@", e);
    }
}
- (void)refreshLog {
    NSString *content = [NSString stringWithContentsOfFile:g_logPath encoding:NSUTF8StringEncoding error:nil] ?: @"";
    g_tv.text = content;
    if (content.length > 0) {
        [g_tv scrollRangeToVisible:NSMakeRange(content.length - 1, 0)];
    }
}
- (void)handleTripleTap:(UITapGestureRecognizer *)gesture {
    if (g_btn) {
        g_btn.hidden = !g_btn.hidden;
        if (!g_btn.hidden) {
            DLOG(@"[UI] Log button shown via triple-tap");
        } else {
            DLOG(@"[UI] Log button hidden via triple-tap");
        }
    }
}
- (void)handlePan:(UIPanGestureRecognizer *)gesture {
    if (!g_btn || g_btn.hidden) return;
    UIView *v = gesture.view;
    CGPoint translation = [gesture translationInView:v.superview];
    CGPoint newCenter = CGPointMake(v.center.x + translation.x, v.center.y + translation.y);
    CGRect bounds = v.superview.bounds;
    newCenter.x = MAX(25, MIN(bounds.size.width - 25, newCenter.x));
    newCenter.y = MAX(25, MIN(bounds.size.height - 25, newCenter.y));
    v.center = newCenter;
    [gesture setTranslation:CGPointZero inView:v.superview];
}
@end

// ============================================================
// NOTE: NSArray count hook REMOVED - causes crashes during keyboard input
// Server list handling is now done at the protocol level (hook_recv/recvfrom/recvmsg)
// ============================================================

// ============================================================
#pragma mark - NSURLSession hooks (HTTP response manipulation)
// ============================================================

static id (*orig_JSONObjectWithData)(Class, SEL, NSData *, NSJSONReadingOptions, NSError **);

static id hook_JSONObjectWithData(Class self, SEL _cmd, NSData *data, NSJSONReadingOptions opt, NSError **error) {
    id ret = orig_JSONObjectWithData(self, _cmd, data, opt, error);
    
    @try {
        if (ret && [ret isKindOfClass:[NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)ret;
            NSNumber *status = dict[@"status"];
            NSString *msg = dict[@"msg"] ?: @"";
            NSString *result = dict[@"result"] ?: @"";
            
            DLOG(@"[JSON-PARSE] JSONObjectWithData: status=%@ msg=%@ result=%@", status, msg, result);
            
            BOOL hasFail = NO;
            if ([result isKindOfClass:[NSString class]]) {
                hasFail = [(NSString *)result containsString:@"fail"];
            }
            BOOL hasVersionMsg = NO;
            if ([msg isKindOfClass:[NSString class]]) {
                hasVersionMsg = [(NSString *)msg containsString:@"版本"] || 
                               [(NSString *)msg containsString:@"更新"] || 
                               [(NSString *)msg containsString:@"升级"];
            }
            if (hasVersionMsg || hasFail) {
                DLOG(@"[JSON-PATCH] Detected version check failure, modifying...");
            }
        }
    } @catch (NSException *e) {
        DLOG(@"[JSON-PARSE] Exception: %@", e);
    }
    
    return ret;
}

static void installJSONSerializationHook(void) {
    Class jsonCls = [NSJSONSerialization class];
    if (!jsonCls) {
        DLOG(@"[JSON-HOOK] NSJSONSerialization class not found");
        return;
    }
    
    Method jsonObjMethod = class_getClassMethod(jsonCls, @selector(JSONObjectWithData:options:error:));
    if (!jsonObjMethod) {
        DLOG(@"[JSON-HOOK] JSONObjectWithData:options:error: not found");
        return;
    }
    
    orig_JSONObjectWithData = (id(*)(Class, SEL, NSData*, NSJSONReadingOptions, NSError**))method_getImplementation(jsonObjMethod);
    method_setImplementation(jsonObjMethod, (IMP)hook_JSONObjectWithData);
    DLOG(@"[JSON-HOOK] Installed NSJSONSerialization hook");
}

// ============================================================
#pragma mark - NSURLSessionDataDelegate hooks
// ============================================================

static void (*orig_urlSessionDataTaskDidReceiveData)(id, SEL, NSURLSession*, NSURLSessionDataTask*, NSData*) = NULL;

static void hook_urlSessionDataTaskDidReceiveData(id self, SEL _cmd, NSURLSession *session, NSURLSessionDataTask *dataTask, NSData *data) {
    NSString *url = dataTask.currentRequest.URL.absoluteString;
    DLOG(@"[HTTP-DATA] urlSession:dataTask:didReceiveData: len=%zu url=%@", (unsigned long)[data length], url);
    
    NSString *dataStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (dataStr) {
        if ([dataStr containsString:@"版本"] || [dataStr containsString:@"server"] || 
            [dataStr containsString:@"status"] || [dataStr containsString:@"maintenance"] ||
            [dataStr containsString:@"ispass"] || [dataStr containsString:@"md5xor"] ||
            [dataStr containsString:@"code"] || [dataStr containsString:@"sign"] ||
            [dataStr containsString:@"ENDTIME"]) {
            DLOG(@"[HTTP-DATA] Response contains key info: %@", dataStr);
            [ProtocolPatcher patchServerResponse:[dataStr dataUsingEncoding:NSUTF8StringEncoding]];
        }
    }
    
    // Patch delegate-mode responses for sign/cert APIs
    if (dataStr && url && ([url containsString:@"judgeAppInfoSignApi"] || [url containsString:@"judgeAppInfoApi"] || [dataStr containsString:@"ENDTIME"])) {
        DLOG(@"[HTTP-DATA-PATCH] Patching delegate-mode cert/sign API response");
        NSString *newBody = dataStr;
        // Extend ENDTIME to future
        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"\"ENDTIME\":\"[^\"]*\"" options:0 error:nil];
        newBody = [regex stringByReplacingMatchesInString:newBody options:0 range:NSMakeRange(0, newBody.length) withTemplate:@"\"ENDTIME\":\"2027-12-31 23:59:59\""];
        newBody = [newBody stringByReplacingOccurrencesOfString:@"\"END\":1" withString:@"\"END\":0"];
        newBody = [newBody stringByReplacingOccurrencesOfString:@"\"OPEN\":0" withString:@"\"OPEN\":1"];
        newBody = [newBody stringByReplacingOccurrencesOfString:@"\"code\":0" withString:@"\"code\":1"];
        NSData *newData = [newBody dataUsingEncoding:NSUTF8StringEncoding];
        DLOG(@"[HTTP-DATA-PATCH] Patched delegate response: %@", newBody);
        if (orig_urlSessionDataTaskDidReceiveData) {
            orig_urlSessionDataTaskDidReceiveData(self, _cmd, session, dataTask, newData);
            return;
        }
    }
    
    if (orig_urlSessionDataTaskDidReceiveData) {
        orig_urlSessionDataTaskDidReceiveData(self, _cmd, session, dataTask, data);
    }
}

static void installNSURLSessionHooks(void) {
    Class sessionCls = [NSURLSession class];
    if (!sessionCls) {
        DLOG(@"[HTTP-HOOK] NSURLSession class not found");
        return;
    }
    
    Method dataTaskMethod = class_getInstanceMethod(sessionCls, @selector(dataTaskWithRequest:completionHandler:));
    if (!dataTaskMethod) {
        DLOG(@"[HTTP-HOOK] dataTaskWithRequest:completionHandler: not found");
    } else {
        DLOG(@"[HTTP-HOOK] NSURLSession dataTaskWithRequest:completionHandler: found");
    }
    
    Class dataTaskCls = NSClassFromString(@"__NSCFLocalDataTask");
    if (!dataTaskCls) dataTaskCls = NSClassFromString(@"__NSCFLNetworkDataTask");
    if (!dataTaskCls) dataTaskCls = NSClassFromString(@"NSURLSessionDataTask");
    
    if (dataTaskCls) {
        DLOG(@"[HTTP-HOOK] NSURLSessionDataTask class found: %@", NSStringFromClass(dataTaskCls));
    }
    
    // Hook URLSession:dataTask:didReceiveData: on classes that implement it
    // This intercepts delegate-mode responses (used by judgeAppInfoSignApi)
    unsigned int classCount = 0;
    Class *classes = (Class *)malloc(sizeof(Class) * 0x10000);
    if (classes) {
        int numClasses = objc_getClassList(classes, 0x10000);
        int hookedCount = 0;
        for (int i = 0; i < numClasses; i++) {
            Class cls = classes[i];
            Method m = class_getInstanceMethod(cls, @selector(URLSession:dataTask:didReceiveData:));
            if (m) {
                IMP currentImp = method_getImplementation(m);
                if (currentImp != (IMP)hook_urlSessionDataTaskDidReceiveData) {
                    orig_urlSessionDataTaskDidReceiveData = (void(*)(id, SEL, NSURLSession*, NSURLSessionDataTask*, NSData*))currentImp;
                    method_setImplementation(m, (IMP)hook_urlSessionDataTaskDidReceiveData);
                    DLOG(@"[HTTP-HOOK] Hooked URLSession:dataTask:didReceiveData: on class: %@", NSStringFromClass(cls));
                    hookedCount++;
                    if (hookedCount >= 5) break;
                }
            }
        }
        free(classes);
        if (hookedCount > 0) {
            DLOG(@"[INIT] URLSession:dataTask:didReceiveData: hooked on %d classes", hookedCount);
        }
    }
}

// ============================================================
#pragma mark - ServerInfoForClient hooks (trace server list parsing)
// ============================================================

static IMP orig_msi_init = NULL;
static IMP orig_msi_initWithDict = NULL;
static IMP orig_msi_status = NULL;

static id msi_init_hook(id self, SEL _cmd);
static id msi_initWithDict_hook(id self, SEL _cmd, NSDictionary *dict);
static NSNumber *msi_status_hook(id self, SEL _cmd);
static NSString *msi_ip_hook(id self, SEL _cmd);
static NSString *msi_category_hook(id self, SEL _cmd);
static NSNumber *msi_serverType_hook(id self, SEL _cmd);
static NSString *msi_string_hook(id self, SEL _cmd);
static NSInteger msi_int_hook(id self, SEL _cmd);

// ============================================================
#pragma mark - UITableView DataSource hooks (OBSERVE ONLY, NO MODIFICATION)
// ============================================================

static IMP orig_tableView_numberOfRows = NULL;
static IMP orig_tableView_cellForRow = NULL;
static IMP orig_tableView_numberOfSections = NULL;

static BOOL isServerListDataSource(id self) {
    @try {
        if ([self respondsToSelector:@selector(dataSource)]) {
            id ds = [self dataSource];
            if (ds) {
                NSString *dsName = NSStringFromClass([ds class]);
                return ([dsName containsString:@"Server"] || [dsName containsString:@"server"] || 
                        [dsName containsString:@"List"] || [dsName containsString:@"list"] ||
                        [dsName containsString:@"Login"] || [dsName containsString:@"login"]);
            }
        }
        Class cls = [self class];
        NSString *clsName = NSStringFromClass(cls);
        return ([clsName containsString:@"Server"] || [clsName containsString:@"server"] || 
                [clsName containsString:@"List"] || [clsName containsString:@"list"] ||
                [clsName containsString:@"Login"] || [clsName containsString:@"login"]);
    } @catch (NSException *e) {
        return NO;
    }
}

static NSInteger hook_numberOfRowsInSection(id self, SEL _cmd, NSInteger section) {
    NSInteger (*origFunc)(id, SEL, NSInteger) = (NSInteger(*)(id, SEL, NSInteger))orig_tableView_numberOfRows;
    NSInteger ret = origFunc(self, _cmd, section);
    
    Class cls = [self class];
    NSString *clsName = NSStringFromClass(cls);
    
    if (isServerListDataSource(self)) {
        DLOG(@"[TV-OBSERVE] -[%@ numberOfRowsInSection:%ld] -> %ld", clsName, (long)section, (long)ret);
        
        @try {
            id dataSource = [self respondsToSelector:@selector(dataSource)] ? [self dataSource] : nil;
            if (dataSource) {
                NSString *dsCls = NSStringFromClass([dataSource class]);
                DLOG(@"[TV-OBSERVE] dataSource=%@ (%@)", dataSource, dsCls);
                
                if ([dataSource respondsToSelector:@selector(serverList)] || [dataSource respondsToSelector:@selector(servers)]) {
                    id serverList = [dataSource performSelector:[dataSource respondsToSelector:@selector(serverList)] ? @selector(serverList) : @selector(servers)];
                    if ([serverList isKindOfClass:[NSArray class]]) {
                        DLOG(@"[TV-OBSERVE] serverList count=%lu", (unsigned long)[serverList count]);
                        for (NSUInteger i = 0; i < [serverList count] && i < 5; i++) {
                            id item = serverList[i];
                            DLOG(@"[TV-OBSERVE]   [%lu] = %@ (%@)", i, item, NSStringFromClass([item class]));
                            if ([item isKindOfClass:[NSDictionary class]]) {
                                NSDictionary *dict = (NSDictionary *)item;
                                DLOG(@"[TV-OBSERVE]     keys=%@", [dict allKeys]);
                                DLOG(@"[TV-OBSERVE]     name=%@ ip=%@ port=%@ status=%@", dict[@"name"], dict[@"ip"], dict[@"port"], dict[@"status"]);
                            } else if ([item respondsToSelector:@selector(name)] && [item respondsToSelector:@selector(ip)] && [item respondsToSelector:@selector(port)]) {
                                DLOG(@"[TV-OBSERVE]     name=%@ ip=%@ port=%@", 
                                     [item performSelector:@selector(name)], 
                                     [item performSelector:@selector(ip)], 
                                     [item performSelector:@selector(port)]);
                            }
                        }
                    } else {
                        DLOG(@"[TV-OBSERVE] serverList is NOT NSArray: %@", serverList ? NSStringFromClass([serverList class]) : @"nil");
                    }
                }
                
                if ([dataSource respondsToSelector:@selector(dataArray)] || [dataSource respondsToSelector:@selector(items)]) {
                    id data = [dataSource performSelector:[dataSource respondsToSelector:@selector(dataArray)] ? @selector(dataArray) : @selector(items)];
                    if ([data isKindOfClass:[NSArray class]]) {
                        DLOG(@"[TV-OBSERVE] dataArray/items count=%lu", (unsigned long)[data count]);
                    }
                }
            }
        } @catch (NSException *e) {
            DLOG(@"[TV-OBSERVE] Exception: %@", e);
        }
    }
    return ret;
}

static UITableViewCell *hook_cellForRowAtIndexPath(id self, SEL _cmd, NSIndexPath *indexPath) {
    UITableViewCell *(*origFunc)(id, SEL, NSIndexPath*) = (UITableViewCell*(*)(id, SEL, NSIndexPath*))orig_tableView_cellForRow;
    UITableViewCell *ret = origFunc(self, _cmd, indexPath);
    
    Class cls = [self class];
    NSString *clsName = NSStringFromClass(cls);
    
    if (isServerListDataSource(self)) {
        NSString *text = @"";
        if (ret && ret.textLabel) text = ret.textLabel.text ?: @"";
        NSString *detailText = @"";
        if (ret && [ret respondsToSelector:@selector(detailTextLabel)] && [(UITableViewCell*)ret detailTextLabel]) {
            detailText = [(UITableViewCell*)ret detailTextLabel].text ?: @"";
        }
        
        DLOG(@"[TV-OBSERVE] -[%@ cellForRowAtIndexPath:{%ld,%ld}] -> text='%@' detail='%@'", clsName, 
             (long)indexPath.section, (long)indexPath.row, text, detailText);
        
        @try {
            id dataSource = [self respondsToSelector:@selector(dataSource)] ? [self dataSource] : nil;
            if (dataSource) {
                if ([dataSource respondsToSelector:@selector(serverList)] || [dataSource respondsToSelector:@selector(servers)]) {
                    id serverList = [dataSource performSelector:[dataSource respondsToSelector:@selector(serverList)] ? @selector(serverList) : @selector(servers)];
                    if ([serverList isKindOfClass:[NSArray class]] && indexPath.row < [serverList count]) {
                        id item = serverList[indexPath.row];
                        DLOG(@"[TV-OBSERVE] Row %ld data: %@ (%@)", (long)indexPath.row, item, NSStringFromClass([item class]));
                        if ([item isKindOfClass:[NSDictionary class]]) {
                            NSDictionary *dict = (NSDictionary *)item;
                            DLOG(@"[TV-OBSERVE]   name=%@ status=%@ ip=%@ port=%@", 
                                 dict[@"name"], dict[@"status"], dict[@"ip"], dict[@"port"]);
                        } else if ([item respondsToSelector:@selector(name)] && [item respondsToSelector:@selector(ip)]) {
                            DLOG(@"[TV-OBSERVE]   name=%@ ip=%@", 
                                 [item performSelector:@selector(name)], 
                                 [item performSelector:@selector(ip)]);
                        }
                    }
                }
            }
        } @catch (NSException *e) {
            DLOG(@"[TV-OBSERVE] Exception: %@", e);
        }
    }
    return ret;
}

static NSInteger hook_numberOfSections(id self, SEL _cmd) {
    NSInteger (*origFunc)(id, SEL) = (NSInteger(*)(id, SEL))orig_tableView_numberOfSections;
    NSInteger ret = origFunc(self, _cmd);
    
    Class cls = [self class];
    NSString *clsName = NSStringFromClass(cls);
    
    if (isServerListDataSource(self)) {
        DLOG(@"[TV-OBSERVE] -[%@ numberOfSections] -> %ld", clsName, (long)ret);
    }
    return ret;
}

// ============================================================
#pragma mark - ServerInfoForClient helper
// ============================================================

static void msi_log_properties(id self) {
    @try {
        unsigned int count = 0;
        objc_property_t *props = class_copyPropertyList([self class], &count);
        for (unsigned int i = 0; i < count; i++) {
            const char *propName = property_getName(props[i]);
            id value = [self valueForKey:[NSString stringWithUTF8String:propName]];
            if (value) {
                DLOG(@"[MSI-PROP] %s = %@", propName, value);
            }
        }
        if (props) free(props);
    } @catch (NSException *e) {
        DLOG(@"[MSI-PROP] Exception: %@", e);
    }
}

static id msi_init_hook(id self, SEL _cmd) {
    id (*origFunc)(id, SEL) = (id(*)(id, SEL))orig_msi_init;
    id ret = origFunc(self, _cmd);
    if (ret) {
        DLOG(@"[MSI-CALL] -[%@ init] -> %p", NSStringFromClass([self class]), ret);
        msi_log_properties(ret);
    }
    return ret;
}

// ============================================================
// ServerInfoForClient Stub Class Implementation
// ============================================================

// Game server config variables (defined early for stub class access)
static int g_gameServerPort = 0;  // v36.61: Default to 0 (not set yet), will be parsed from server list
static char g_gameServerIP[64] = "47.100.14.198";
static BOOL g_gameServerInfoUpdated = YES;

// v36.61: Track game server connection state
static BOOL g_gameServerConnected = NO;  // Whether game server handshake completed
static int g_gameServerFd = -1;  // Track which fd is connected to game server
static NSTimeInterval g_gameConnectTime = 0;  // Time of game server connection

// v36.66: Store 0x000EE007 device info packet for forced send to game server
#define MAX_DEVICE_INFO_SIZE 512
static uint8_t g_deviceInfoPacket[MAX_DEVICE_INFO_SIZE];
static ssize_t g_deviceInfoPacketLen = 0;
static BOOL g_deviceInfoCaptured = NO;
static BOOL g_deviceInfoSentToGame = NO;

// v36.123: Fixed IDFV for [UIDevice identifierForVendor] hook
// Returns consistent UUID so client NATIVELY builds UUID-containing 0x000EE007
// (Avoids send-level buffer modification per Experience 1423135)
static NSUUID *g_fixedIDFV = nil;
static NSUUID* (*orig_identifierForVendor)(UIDevice *self, SEL _cmd) = NULL;

// v36.87: Enhanced device info packet (with UUID injected) for game server
// Login server (5678) sends 143-byte version (no UUID)
// Game server expects 179-byte version (with UUID field)
static uint8_t g_deviceInfoEnhanced[MAX_DEVICE_INFO_SIZE];
static ssize_t g_deviceInfoEnhancedLen = 0;
static BOOL g_deviceInfoEnhancedReady = NO;

// v36.68: Sticky packet leftover buffer - for splitting sticky packets
// When 0x80FFF494 and heartbeat ACK arrive in same TCP buffer,
// we split them so the game client only sees the handshake response
#define MAX_STICKY_LEFTOVER 4096
static uint8_t g_stickyLeftoverBuf[MAX_STICKY_LEFTOVER];
static ssize_t g_stickyLeftoverLen = 0;
static int g_stickyLeftoverFd = -1;

// v36.68: Local heartbeat ACK buffer - for faking heartbeat responses
// When game sends heartbeat to game server during handshake, we intercept
// and return a local ACK to prevent server from including it in handshake response
#define MAX_LOCAL_HEARTBEAT_ACK 256
static uint8_t g_localHeartbeatAckBuf[MAX_LOCAL_HEARTBEAT_ACK];
static ssize_t g_localHeartbeatAckLen = 0;
static int g_localHeartbeatAckFd = -1;

// v36.68: Global handshake state tracking (moved from hook_recv for cross-function access)
static BOOL g_handshakeComplete = NO;
static int g_heartbeatCount = 0;

// v36.79: Store game server public key for RSA encrypt
// Extracted from 0x80FFF494 response (Base64-encoded DER public key)
#define MAX_PUBKEY_BASE64 1024
static char g_pubKeyBase64[MAX_PUBKEY_BASE64];
static size_t g_pubKeyBase64Len = 0;
static BOOL g_pubKeyCaptured = NO;

// v36.79: Track if we already auto-responded to 0x00FFFF02
static BOOL g_challengeResponded = NO;
static int g_challengeFd = -1;

// v36.83: Force handshake complete packet buffer
// When client sends heartbeat after challenge response (server didn't send 0x80FFF495),
// we prepare a fake 0x80FFF495 handshake complete response
#define MAX_FORCE_HS_BUF 256
static BOOL g_forceHandshakeComplete = NO;
static int g_forceHandshakeFd = -1;
static uint8_t g_forceHandshakeBuf[MAX_FORCE_HS_BUF];
static uint32_t g_forceHandshakeLen = 0;

// v36.107: Smart fake response system - track ALL client requests in a queue with sequence numbers
// Command queue - track ALL game server commands for ordered response
#define MAX_CMD_QUEUE 64
typedef struct {
    uint32_t cmd;
    int fd;
    uint32_t sendLen;
    uint32_t seqNum;  // v36.107: Sequence number from original request for correct response matching
} GameCmdEntry;

static GameCmdEntry g_cmdQueue[MAX_CMD_QUEUE];
static int g_cmdQueueHead = 0;   // Next command to dequeue
static int g_cmdQueueTail = 0;   // Next slot to enqueue
static int g_cmdQueueCount = 0;  // Number of commands in queue

// Track last game server command for generating appropriate fake responses
static uint32_t g_lastGameCmd = 0;
static int g_lastGameCmdFd = -1;
static uint32_t g_lastSeqNum = 0;  // v36.107: Last sequence number for fallback responses
static BOOL g_fakeRespActive = NO;
static BOOL g_fakeRespDelivered = NO;
static uint32_t g_lastRespCmd = 0;
static int g_respCount = 0;

// v36.107: Command queue functions - filter heartbeat and challenge cmds, track sequence numbers
static BOOL isFilteredCmd(uint32_t cmd) {
    if (cmd == 0x00000015) return YES;  // Heartbeat
    if (cmd == 0x00FFFF01) return YES;  // Challenge response 1
    if (cmd == 0x00FFFF02) return YES;  // Challenge response 2
    if (cmd == 0x80000015) return YES;  // Heartbeat (response direction)
    return NO;
}

static void enqueueGameCmd(uint32_t cmd, int fd, uint32_t sendLen, uint32_t seqNum) {
    // v36.107: Filter heartbeat and challenge commands to prevent queue flooding
    if (isFilteredCmd(cmd)) {
        DLOG(@"[CMD-QUEUE] v36.107: Filtered cmd=0x%08X seq=0x%08X (heartbeat/challenge)", cmd, seqNum);
        return;
    }
    
    if (g_cmdQueueCount >= MAX_CMD_QUEUE) {
        // Queue full - discard oldest
        g_cmdQueueHead = (g_cmdQueueHead + 1) % MAX_CMD_QUEUE;
        g_cmdQueueCount--;
        DLOG(@"[CMD-QUEUE] v36.107: Queue full, discarding oldest");
    }
    g_cmdQueue[g_cmdQueueTail].cmd = cmd;
    g_cmdQueue[g_cmdQueueTail].fd = fd;
    g_cmdQueue[g_cmdQueueTail].sendLen = sendLen;
    g_cmdQueue[g_cmdQueueTail].seqNum = seqNum;
    g_cmdQueueTail = (g_cmdQueueTail + 1) % MAX_CMD_QUEUE;
    g_cmdQueueCount++;
    DLOG(@"[CMD-QUEUE] v36.107: Enqueued cmd=0x%08X seq=0x%08X fd=%d sendLen=%u (queue=%d)", 
         cmd, seqNum, fd, sendLen, g_cmdQueueCount);
}

static BOOL dequeueGameCmd(GameCmdEntry *entry) {
    if (g_cmdQueueCount <= 0) return NO;
    *entry = g_cmdQueue[g_cmdQueueHead];
    g_cmdQueueHead = (g_cmdQueueHead + 1) % MAX_CMD_QUEUE;
    g_cmdQueueCount--;
    return YES;
}

static void resetCmdQueue(void) {
    g_cmdQueueHead = 0;
    g_cmdQueueTail = 0;
    g_cmdQueueCount = 0;
}

// v36.106: Generate response based on queued command
static BOOL g_quitFromServerPatched = NO;
static BOOL g_heartbeatPatched = NO;

// v36.104: Disabled inline patch (caused crash) - using poll/select hook instead
static BOOL patchFunctionToReturn(void *funcAddr, const char *funcName) {
    // v36.104: Inline patching causes crash on iOS - disabled
    // Instead, we hook poll()/select() to prevent heartbeat from detecting dead connection
    DLOG(@"[INLINE-PATCH] v36.104: Inline patch disabled (caused crash), using poll/select hook instead");
    (void)funcAddr; (void)funcName;
    return NO;
}

// v36.103: Find and patch C++ functions using backtrace from close() call
static void findAndPatchDisconnectFunctions(void) {
    if (g_quitFromServerPatched && g_heartbeatPatched) return;
    
    void *callstack[32];
    int frames = backtrace(callstack, 32);
    
    DLOG(@"[INLINE-PATCH] v36.103: Scanning %d backtrace frames for C++ functions...", frames);
    
    for (int i = 0; i < frames; i++) {
        Dl_info info;
        if (dladdr(callstack[i], &info) && info.dli_sname) {
            const char *name = info.dli_sname;
            
            // Check for quitFromServer
            if (!g_quitFromServerPatched && strstr(name, "quitFromServer")) {
                DLOG(@"[INLINE-PATCH] v36.103: Found %s at addr=%p (frame %d, ret=%p)", 
                     name, info.dli_saddr, i, callstack[i]);
                if (patchFunctionToReturn(info.dli_saddr, name)) {
                    g_quitFromServerPatched = YES;
                }
            }
            
            // Check for heartbeat
            if (!g_heartbeatPatched && strstr(name, "heartbeat") && strstr(name, "NetImpl")) {
                DLOG(@"[INLINE-PATCH] v36.103: Found %s at addr=%p (frame %d, ret=%p)", 
                     name, info.dli_saddr, i, callstack[i]);
                if (patchFunctionToReturn(info.dli_saddr, name)) {
                    g_heartbeatPatched = YES;
                }
            }
        }
    }
    
    if (!g_quitFromServerPatched && !g_heartbeatPatched) {
        DLOG(@"[INLINE-PATCH] v36.103: No C++ functions found in backtrace");
    }
}

// v36.103: Proactively search for C++ functions in main binary and patch them
static void proactivePatchCppFunctions(void) {
    if (g_quitFromServerPatched && g_heartbeatPatched) return;
    
    DLOG(@"[INLINE-PATCH] v36.103: Proactively searching for C++ functions in main binary...");
    
    const char *targetNames[] = {
        "_ZN7NetImpl14quitFromServerEv",
        "_ZN7NetImpl9heartbeatEv",
        NULL
    };
    
    int imageCount = _dyld_image_count();
    for (int idx = 0; idx < imageCount; idx++) {
        const char *imageName = _dyld_get_image_name(idx);
        if (!imageName) continue;
        
        // Skip non-main binaries
        if (!strstr(imageName, "wangxian") && !strstr(imageName, "WangXian")) continue;
        
        DLOG(@"[INLINE-PATCH] v36.103: Searching in main binary: %s (slide=0x%lx)", 
             imageName, (unsigned long)_dyld_get_image_vmaddr_slide(idx));
        
        void *handle = dlopen(imageName, RTLD_NOLOAD | RTLD_LAZY);
        if (!handle) continue;
        
        for (int n = 0; targetNames[n] != NULL; n++) {
            void *sym = dlsym(handle, targetNames[n]);
            if (sym) {
                DLOG(@"[INLINE-PATCH] v36.103: Found %s at %p via dlsym", targetNames[n], sym);
                
                if (strstr(targetNames[n], "quitFromServer") && !g_quitFromServerPatched) {
                    if (patchFunctionToReturn(sym, targetNames[n])) {
                        g_quitFromServerPatched = YES;
                    }
                }
                if (strstr(targetNames[n], "heartbeat") && !g_heartbeatPatched) {
                    if (patchFunctionToReturn(sym, targetNames[n])) {
                        g_heartbeatPatched = YES;
                    }
                }
            }
        }
        
        dlclose(handle);
        
        if (g_quitFromServerPatched && g_heartbeatPatched) break;
    }
    
    // Also try RTLD_DEFAULT
    if (!g_quitFromServerPatched) {
        void *sym = dlsym(RTLD_DEFAULT, "_ZN7NetImpl14quitFromServerEv");
        if (sym) {
            DLOG(@"[INLINE-PATCH] v36.103: Found quitFromServer via RTLD_DEFAULT at %p", sym);
            if (patchFunctionToReturn(sym, "quitFromServer")) {
                g_quitFromServerPatched = YES;
            }
        }
    }
    if (!g_heartbeatPatched) {
        void *sym = dlsym(RTLD_DEFAULT, "_ZN7NetImpl9heartbeatEv");
        if (sym) {
            DLOG(@"[INLINE-PATCH] v36.103: Found heartbeat via RTLD_DEFAULT at %p", sym);
            if (patchFunctionToReturn(sym, "heartbeat")) {
                g_heartbeatPatched = YES;
            }
        }
    }
    
    DLOG(@"[INLINE-PATCH] v36.103: Proactive search complete: quitFromServer=%d heartbeat=%d", 
         g_quitFromServerPatched, g_heartbeatPatched);
}

// v36.155: Role rotation index. Increments each time a new server is
// entered, so each server shows a DIFFERENT character (name, profession,
// level). Without this, all servers show the same hardcoded "玩家001"
// warrior with level 1, which is unrealistic — each server should have
// a unique character. MUST be declared BEFORE generateFakeResponse() which uses it.
static int g_roleIndex = 0;

// v36.107: Generate fake response based on request command with correct sequence number
// Returns response length, 0 if no response needed
static uint32_t generateFakeResponse(uint32_t requestCmd, uint8_t *respBuf, uint32_t bufSize, uint32_t seqNum) {
    if (!respBuf || bufSize < 16) return 0;

    // v36.139: For 0x00FFF493 (role request) the server replies with a
    // 0x0CB0A300 packet (cmd bytes on wire: 00 A3 B0 0C). The previous
    // versions returned a 200-byte 0x80FFF493 empty payload which the
    // client could not parse, leaving it stuck at "正在进入...".
    //
    // Real captured response (hook.txt RECV #19, ret=1632) is composed of
    // two 816-byte sub-packets:
    //   sub1: pktLen=0x330, cmd=0x00A3B00C (role attribute table, 100 entries x 8 bytes)
    //   sub2: pktLen=0x330, cmd=0x00A30200 (companion data table)
    // Because the capture was truncated to 1024 bytes we only have the
    // complete sub1. Returning sub1 alone is enough for the client to
    // recognise the 0x0CB0A300 command and advance the state machine.
    //
    // Layout of sub1:
    //   bytes 0-3   : pktLen = 0x00000330 (816) big-endian
    //   bytes 4-7   : cmd    = 0x00A3B00C big-endian (wire bytes 00 A3 B0 0C)
    //   bytes 8-11  : seq    = 0x08887D80 (server-side seq, kept from real capture)
    //   bytes 12-15 : count  = 0x00000064 (100 attribute entries)
    //   bytes 16+   : 100 x uint64 attribute values (big-endian)
    if (requestCmd == 0x00FFF493) {
        // Sub-packet 1 header (16 bytes) from real capture (hook.txt RECV #19)
        static const uint8_t roleHeader[16] = {
            0x00, 0x00, 0x03, 0x30,  // pktLen = 816
            0x00, 0xA3, 0xB0, 0x0C,  // cmd = 0x00A3B00C (0x0CB0A300 response)
            0x08, 0x88, 0x7D, 0x80,  // server seq (from real capture)
            0x00, 0x00, 0x00, 0x64   // count = 100 entries
        };
        // 100 attribute entries (8 bytes each) copied verbatim from the real
        // RECV #19 capture (hook.txt lines 870-920). Big-endian uint64 values
        // representing the role's attributes. Using real values avoids
        // client-side validation failures.
        static const uint8_t roleAttrs[800] = {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1F, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x49, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x27,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x56, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3C,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5E, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4A,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x16, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x19, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x27,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3B, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4E,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x52, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5C,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x44, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4A, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2A,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x57, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x62,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x58, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5F,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4F, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2C,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1C,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x59, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2F, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5D,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5B,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4D,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5E, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x63,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3B,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1D,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x44, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x61,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x52, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0D,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2C, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x46,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3C,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x16, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0B, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x51, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x41,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x35,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x54,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x12,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1C, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x62, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x47,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1D, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2B,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x33, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3C, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x37, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4A, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5D,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1A, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x24,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x41, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3F,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x22, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5F, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x55,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x56, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x13
        };

        // v36.140: Return the COMPLETE 1632-byte response (two 816-byte
        // sub-packets) to match the real server behaviour (hook.txt RECV #19).
        // v36.139 only returned sub1 (816 bytes); the client may have been
        // waiting for sub2 and stalled at "正在进入...".
        if (bufSize < 1632) {
            // Not enough room for both sub-packets — fall back to sub1 only.
            if (bufSize < 816) {
                DLOG(@"[FAKE-RESP] v36.140: 0x0CB0A300 needs 816 bytes, bufSize=%u — skip", bufSize);
                return 0;
            }
            DLOG(@"[FAKE-RESP] v36.140: 0x0CB0A300 partial (sub1 only, 816 bytes) bufSize=%u", bufSize);
            memcpy(respBuf, roleHeader, 16);
            memcpy(respBuf + 16, roleAttrs, 800);
            return 816;
        }
        // Sub-packet 1 (816 bytes): role attribute table
        memcpy(respBuf, roleHeader, 16);
        memcpy(respBuf + 16, roleAttrs, 800);
        // v36.155: Dynamic role attributes based on g_roleIndex.
        // Modify key attribute entries so each server gets unique character
        // stats (roleId, level, profession, etc.). Without this, all servers
        // share identical attribute values from the real capture.
        if (g_roleIndex > 0) {
            // Entry 0 (offset 16): role ID — set to g_roleIndex (big-endian uint64)
            uint32_t rid = (uint32_t)g_roleIndex;
            respBuf[16] = (rid >> 24) & 0xFF; respBuf[17] = (rid >> 16) & 0xFF;
            respBuf[18] = (rid >> 8) & 0xFF; respBuf[19] = rid & 0xFF;
            respBuf[20] = 0x00; respBuf[21] = 0x00; respBuf[22] = 0x00; respBuf[23] = 0x00;

            // Entry 1 (offset 24): level — 1 + (roleIndex-1)*10, capped at 100
            uint32_t level = 1 + (g_roleIndex - 1) * 10;
            if (level > 100) level = 100;
            respBuf[24] = (level >> 24) & 0xFF; respBuf[25] = (level >> 16) & 0xFF;
            respBuf[26] = (level >> 8) & 0xFF; respBuf[27] = level & 0xFF;

            // Entry 2 (offset 32): profession/class — cycle through 3 types
            // 1=战士(warrior), 2=法师(mage), 3=道士(taoist)
            uint32_t prof = (uint32_t)((g_roleIndex - 1) % 3) + 1;
            respBuf[32] = 0x00; respBuf[33] = 0x00; respBuf[34] = 0x00; respBuf[35] = prof;
            respBuf[36] = 0x00; respBuf[37] = 0x00; respBuf[38] = 0x00; respBuf[39] = 0x00;

            // Entry 3 (offset 40): max HP — scale with level
            uint32_t maxHp = 100 + level * 50;
            respBuf[40] = (maxHp >> 24) & 0xFF; respBuf[41] = (maxHp >> 16) & 0xFF;
            respBuf[42] = (maxHp >> 8) & 0xFF; respBuf[43] = maxHp & 0xFF;

            DLOG(@"[FAKE-RESP] v36.155: 0x0CB0A300 dynamic attrs — roleId=%u level=%u prof=%u maxHp=%u (roleIndex=%d)",
                 rid, level, prof, maxHp, g_roleIndex);
        }
        // Sub-packet 2 (816 bytes): companion table.
        // Real capture (hook.txt line 921) header: 00 00 03 30 00 02 a3 0c
        // 08 88 7d 81 00 00 00 64. The 100 attribute entries were truncated
        // by the 1024-byte capture limit, so zero-pad them here. The client
        // sees a well-formed 816-byte sub-packet and can advance.
        static const uint8_t sub2Header[16] = {
            0x00, 0x00, 0x03, 0x30,  // pktLen = 816
            0x00, 0x02, 0xA3, 0x0C,  // cmd = 0x00A30200 (wire bytes 00 02 A3 0C)
            0x08, 0x88, 0x7D, 0x81,  // server seq (sub1 seq + 1)
            0x00, 0x00, 0x00, 0x64   // count = 100 entries
        };
        memcpy(respBuf + 816, sub2Header, 16);
        memset(respBuf + 832, 0, 800);  // zero-padded attribute entries

        DLOG(@"[FAKE-RESP] v36.155: 0x0CB0A300 role-data response built (1632 bytes, 2 sub-packets: 0x00A3B00C + 0x00A30200) for req=0x%08X seq=0x%08X roleIndex=%d",
             requestCmd, seqNum, g_roleIndex);
        return 1632;
    }

    uint32_t respCmd = requestCmd | 0x80000000;  // Response cmd = request cmd | 0x80000000
    
    // v36.107: Extract sequence number bytes for reuse
    uint8_t seqBytes[4];
    seqBytes[0] = (seqNum >> 24) & 0xFF;
    seqBytes[1] = (seqNum >> 16) & 0xFF;
    seqBytes[2] = (seqNum >> 8) & 0xFF;
    seqBytes[3] = seqNum & 0xFF;
    
    // v36.123: ALL responses use 200-byte format with zero-padded payload
    // Previous 16-byte responses caused SIGSEGV in handlers like handle_CHOOSE_WOOD_BOX_RES
    // which read payload beyond the 16-byte header.
    // 200 bytes matches the v36.88 FORCE-HS-PREP approach that was proven safe.
    uint32_t respLen = (bufSize >= 200) ? 200 : bufSize;
    
    memset(respBuf, 0, respLen);
    
    // Header (bytes 0-3): packet length (big-endian)
    respBuf[0] = (respLen >> 24) & 0xFF;
    respBuf[1] = (respLen >> 16) & 0xFF;
    respBuf[2] = (respLen >> 8) & 0xFF;
    respBuf[3] = respLen & 0xFF;
    
    // Header (bytes 4-7): response cmd
    respBuf[4] = (respCmd >> 24) & 0xFF;
    respBuf[5] = (respCmd >> 16) & 0xFF;
    respBuf[6] = (respCmd >> 8) & 0xFF;
    respBuf[7] = respCmd & 0xFF;
    
    // Header (bytes 8-11): sequence number
    respBuf[8] = seqBytes[0]; respBuf[9] = seqBytes[1];
    respBuf[10] = seqBytes[2]; respBuf[11] = seqBytes[3];
    
    // Status (byte 12): 0 = success for ALL responses
    respBuf[12] = 0x00;
    
    // For 0x80FFF495 (handle_CHOOSE_WOOD_BOX_RES), byte 13 = 0x88 format flag
    if (requestCmd == 0x00FFF495) {
        respBuf[13] = 0x88;  // Format flag from v36.88 FORCE-HS-PREP
    }

    // v36.123: For 0x80FFF49F (role list response), construct a MINIMAL valid
    // role entry so the UI actually presents a "select character" screen instead
    // of silently hanging (all-zero payload may be interpreted as empty/no roles).
    // Layout assumption (common for this class of MMO protocols):
    //   byte 13     : numRoles = 1
    //   bytes 14-15 : roleId (LE 0x0001)
    //   bytes 16-47 : UTF-8 role name "玩家001" (padded with spaces or \0)
    //   bytes 48-49 : level (LE 0x0001 = Lv.1)
    //   bytes 50-51 : profession / class id (LE 0x0001 = 战士)
    //   bytes 52-55 : mapId / serverId
    //   remaining   : zero
    // v36.155: Dynamic role data based on g_roleIndex — each server gets
    // a DIFFERENT character with unique name, profession, and level.
    if (requestCmd == 0x00FFF49E) {
        // Rotate through 3 professions: 战士(1), 法师(2), 道士(3)
        int professions[3] = {1, 2, 3};
        int profIdx = (g_roleIndex - 1) % 3;
        int roleId = g_roleIndex;
        int level = 1 + (g_roleIndex - 1) * 10;  // Lv.1, Lv.11, Lv.21, ...
        if (level > 100) level = 100;  // Cap at Lv.100

        respBuf[13] = 0x01;  // numRoles = 1
        // roleId = g_roleIndex, little-endian uint16 at offset 14
        respBuf[14] = (roleId & 0xFF); respBuf[15] = ((roleId >> 8) & 0xFF);

        // Build role name dynamically: "玩家" + zero-padded 3-digit number
        char roleNameBuf[48] = {0};
        snprintf(roleNameBuf, sizeof(roleNameBuf), "\xE7\x8E\xA9\xE5\xAE\xB6%03d", g_roleIndex);
        // Ensure exactly 32 bytes (UTF-8 "玩家"=6bytes + 3digits + padding)
        int nameLen = (int)strlen(roleNameBuf);
        memcpy(respBuf + 16, roleNameBuf, MIN(nameLen, 32));

        // level = computed level, uint16 LE at offset 48
        respBuf[48] = (level & 0xFF); respBuf[49] = ((level >> 8) & 0xFF);
        // profession = rotated profession, uint16 LE at offset 50
        respBuf[50] = professions[profIdx]; respBuf[51] = 0x00;
        // mapId / serverId at offset 52 = g_roleIndex
        respBuf[52] = (roleId & 0xFF); respBuf[53] = ((roleId >> 8) & 0xFF);
        respBuf[54] = 0x00; respBuf[55] = 0x00;

        DLOG(@"[FAKE-RESP] v36.155: Role list — roleId=%d name=%s level=%d prof=%d",
             roleId, roleNameBuf, level, professions[profIdx]);
    }

    // v36.123: For 0x80FFF4A1 (enter game / select role response), put minimal
    // success data so the client transitions from "select role" to "loading map".
    // Byte 13 = 0x01 (accepted), bytes 14-17 = new mapId = 1, bytes 18-21 = x, y.
    if (requestCmd == 0x00FFF4A0) {
        respBuf[13] = 0x01;   // accept flag
        respBuf[14] = 0x01; respBuf[15] = 0x00; // mapId=1
        respBuf[16] = 0x00; respBuf[17] = 0x00;
        respBuf[18] = 0x40; respBuf[19] = 0xE2; // x = some coord (57920)
        respBuf[20] = 0x01; respBuf[21] = 0x00;
        respBuf[22] = 0x70; respBuf[23] = 0xFA; // y = some coord (64112)
        respBuf[24] = 0xFF; respBuf[25] = 0xFF;
    }

    // Bytes 14-199: zero-padded payload (safe for all handlers)
    
    return respLen;
}

// v36.95: Track when client sends login packets to game server
// This replaces g_challengeResponded for fake response injection trigger
static BOOL g_loginPacketsSent = NO;

// v36.94: Fake login success response injection
// When server closes connection (recv returns 0) after client sends login packets,
// inject fake 0x80FFF493 success response to prevent disconnection
// v36.139: Enlarged from 256 to 2048 to hold the 0x0CB0A300 role-data
// response (816 bytes for sub-packet 1). The previous 256-byte cap forced
// generateFakeResponse() to truncate the role data, leaving the client
// state machine stalled at "正在进入..." because it never received a
// complete 0x0CB0A300 packet.
#define MAX_FAKE_RESP_BUF 2048
static BOOL g_fakeRespInjected = NO;
static int g_fakeRespFd = -1;
static uint8_t g_fakeRespBuf[MAX_FAKE_RESP_BUF];
static uint32_t g_fakeRespLen = 0;
static int g_fakeRespSentCount = 0;  // Track how many fake responses sent

// v36.123: Force immediate fake-response activation after 0x80FFF495 patch,
// no longer waiting for server to RECV-CLOSE (which never happens when the
// game server keeps the heartbeat alive while ignoring our plaintext EE007).
static BOOL g_triggerFakeNextRecv = NO;
static int g_triggerFakeFd = -1;

// v36.124: New flag for IMMEDIATE burst injection after patch
// Instead of waiting for the next client recv() call (which may be for heartbeat ACK),
// append all fake responses to the CURRENT return as a TCP sticky buffer.
static BOOL g_burstInjectAfterPatch = NO;
static int g_burstInjectFd = -1;

// v36.142: Post-BURST protocol continuation.
// Real capture (hook.txt) shows that after receiving 0x0CB0A300 (role data),
// the client sends an ACK (0x80A3B00C, 20 bytes), then the server sends:
//   RECV #20: cmd=0x1200F080 (71 bytes) — session token notification
//   RECV #21: cmd=0x13000080 (840 bytes) — map/scene data with file paths
// Without these, the client enters heartbeat mode and stays at "正在进入...".
// State machine:
//   0 = idle
//   1 = BURST injected, next recv() should return RECV #20
//   2 = RECV #20 injected, waiting for client to send 0x00FFF493 (enter game)
//   3 = Client sent 0x00FFF493, next recv() should return RECV #21
//   4 = RECV #21 injected, done
static int g_postBurstState = 0;
static int g_postBurstFd = -1;
// v36.146: Set to YES after RECV #21 is injected. Prevents hook_send from
// reactivating g_fakeRespActive when the client sends new 0x00FFF493 requests.
// Without this, each new 0x00FFF493 resets g_fakeRespDelivered=NO, reactivating
// the fake response system and generating DUPLICATE 0x0CB0A300 responses.
static BOOL g_postBurstDone = NO;
// v36.150: Phase 2 trigger counter. 0=not triggered, 1=first 0x00FFF493 (role
// select) triggers Phase 2, >1=subsequent requests return EAGAIN.
// Reset to 0 on BURST inject so re-login works.
static int g_phase2TriggerCount = 0;
// v36.154: Timestamp when Phase 1 completed (RECV #21 injected). Phase 2
// trigger requires at least 3 seconds elapsed since Phase 1 completion,
// giving the client sufficient time to render the role selection UI.
// Without this delay, auto-load ACK 0x00FFF493 requests (fired within
// ~100ms of Phase 1) trigger Phase 2 too early — before the user can
// even see the role list — causing the client to skip the role UI.
static double g_phase1DoneTime = 0;
// RECV #20 data (71 bytes) from hook.txt line 944.
static const uint8_t kRecv20Data[71] = {
    0x00,0x00,0x00,0x47, 0x80,0x00,0xF0,0x12, 0x00,0x00,0x00,0x1A, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x20,0x31, 0x32,0x30,0x66,0x62, 0x35,0x64,0x39,0x65,
    0x35,0x66,0x62,0x30, 0x31,0x36,0x65,0x32, 0x32,0x35,0x65,0x61, 0x66,0x64,0x38,0x64,
    0x65,0x37,0x32,0x32, 0x31,0x31,0x38
};

// RECV #21 data (840 bytes) from hook.txt lines 1002-1054.
// cmd=0x13000080 (wire: 80 00 00 13), seq=0x1C.
// Contains role name "luoyueshangu", map info, and .xtl file paths.
// First 288 bytes are meaningful; rest is zero-padded with sparse non-zero values.
static const uint8_t kRecv21Head[288] = {
    0x00,0x00,0x03,0x48, 0x80,0x00,0x00,0x13, 0x00,0x00,0x00,0x1C, 0x00,0x00,0x00,0x01,
    0x00,0x0C,0x6C,0x75, 0x6F,0x79,0x75,0x65, 0x73,0x68,0x61,0x6E, 0x67,0x75,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0xFF,
    0x00,0x00,0x00,0x00, 0x00,0x01,0x49,0x00, 0x00,0x01,0x49,0x00, 0x00,0x00,0xFA,0x00,
    0x00,0x00,0xFA,0x24, 0x3F,0xB0,0x29,0x39, 0x53,0x40,0x10,0x00, 0x06,0xE7,0x9C,0x8B,
    0xE7,0x9C,0x8B,0x00, 0x02,0xFF,0xFF,0xFF, 0xFF,0x05,0x00,0x00, 0x00,0x05,0x00,0x00,
    0x00,0x05,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0xC3,0x50, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x01,0x5A, 0x00,0x00,0x00,0x00, 0x00,0x00,0x05,0x10, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x32,0xA0, 0x09,0x00,0x02,0x00, 0x02,0x5A,0x4A,0x00, 0x00,0x00,0x04,0x00,
    0x14,0x2F,0x70,0x61, 0x72,0x74,0x2F,0x5A, 0x4A,0x5F,0x73,0x68, 0x6F,0x75,0x6B,0x75,
    0x69,0x2E,0x78,0x74, 0x6C,0x00,0x1E,0x2F, 0x70,0x61,0x72,0x74, 0x2F,0x6C,0x69,0x61,
    0x6E,0x64,0x61,0x6F, 0x30,0x36,0x5F,0x5A, 0x4A,0x5F,0x73,0x68, 0x6F,0x75,0x6B,0x75,
    0x69,0x2E,0x78,0x74, 0x6C,0x00,0x1B,0x2F, 0x70,0x61,0x72,0x74, 0x2F,0x79,0x69,0x66,
    0x75,0x30,0x30,0x5F, 0x5A,0x4A,0x5F,0x73, 0x68,0x6F,0x75,0x6B, 0x75,0x69,0x2E,0x78,
    0x74,0x6C,0x00,0x1C, 0x2F,0x70,0x61,0x72, 0x74,0x2F,0x6C,0x69, 0x61,0x6E,0x64,0x61,
    0x6F,0x5F,0x5A,0x4A, 0x5F,0x73,0x68,0x6F, 0x75,0x6B,0x75,0x69, 0x2E,0x78,0x74,0x6C,
    0x00,0x00,0x00,0x04, 0x00,0x01,0x02,0x0D, 0xFF,0x00,0x00,0x07, 0xD0,0x00,0x00,0x00
};
// Sparse non-zero bytes in the zero-padded tail (offset, value pairs).
static const struct { uint16_t off; uint8_t val; } kRecv21Sparse[] = {
    { 0x120, 0x96 },  // byte 288
    { 0x1F6, 0x36 },  // byte 502
    { 0x1FC, 0x14 },  // byte 508
    { 0x265, 0x14 },  // byte 613
    { 0x2E0, 0x28 },  // byte 736
    { 0, 0 }          // sentinel
};

// v36.147: RECV #22 (27 bytes) from hook.txt line 1082.
// cmd=0x80FFF490 (wire: 80 FF F4 90). Enter-game ACK/response.
// Format flag 0x08 0x88, payload = "kk994" + zero padding.
static const uint8_t kRecv22Data[27] = {
    0x00,0x00,0x00,0x1B, 0x80,0xFF,0xF4,0x90, 0x08,0x88,0x7F,0xA1, 0x00,0x05,0x6B,0x6B,
    0x39,0x39,0x34,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00
};

// v36.147: RECV #23 (273 bytes) from hook.txt lines 1112-1129.
// cmd=0x16000080 (wire: 80 00 00 16). Scene/entity data.
// Contains multiple sub-packets: scene state, 活动通知, 日常, etc.
static const uint8_t kRecv23Data[273] = {
    0x00,0x00,0x00,0xB4, 0x80,0x00,0x00,0x16, 0x00,0x00,0x00,0x1E, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x01,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x01,0x00, 0x00,0x00,0x00,0x05, 0x00,0x00,0x00,0x05, 0x00,0x00,0x02,0x43,
    0x00,0x00,0x00,0xFA, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x07, 0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x01,
    0x00,0x00,0x00,0x18, 0x00,0x00,0x00,0x23, 0x00,0x00,0x00,0x05, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x06, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x04,0x93,0xE0, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x0F,0x42,0x40, 0x00,0x00,0x00,0x10, 0x0F,0x10,0x00,0x08, 0x08,0x88,0x88,0x04,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x18, 0x80,0xF0,0xEF,0x83, 0x08,0x88,0x88,0x05,
    0x00,0x06,0xE6,0xB4, 0xBB,0xE5,0x8A,0xA8, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x18,
    0x80,0xF0,0xEF,0x83, 0x08,0x88,0x88,0x06, 0x00,0x06,0xE6,0x97, 0xA5,0xE5,0xB8,0xB8,
    0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x10, 0x80,0xFF,0xF0,0x08, 0x08,0x88,0x88,0x07,
    0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x0D, 0x80,0xFF,0xF0,0x06, 0x08,0x88,0x88,0x08,
    0x00
};

// v36.147: RECV #24 (63 bytes) from hook.txt lines 1134-1137.
// Contains 3 concatenated 0x80FFF161 (attr notifications) + 0x01AE0E80.
static const uint8_t kRecv24Data[63] = {
    0x00,0x00,0x00,0x11, 0x80,0xFF,0xF1,0x61, 0x08,0x88,0x88,0x09, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x11,0x80,0xFF,0xF1, 0x61,0x08,0x88,0x88, 0x0A,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x11,0x80,0xFF, 0xF1,0x61,0x08,0x88, 0x88,0x0B,0x00,0x00,
    0x00,0x03,0x00,0x00, 0x00,0x00,0x0C,0x80, 0x0E,0xAE,0x01,0x00, 0x28,0xB3,0x43
};

// v36.125: NEW — Force valid decryption mode for game server responses
// When client decrypts 0x80FFF495 payload, return valid plaintext
// instead of letting decryption fail (no AES key available)
// NOTE: g_forceValidDecrypt must NOT be static because it's referenced from
// inline ARM64 assembly in cpp_stub_force() (linker needs external symbol)
BOOL g_forceValidDecrypt = NO;
static int g_forceValidDecryptFd = -1;

// v37.28: CCCrypt L4 hook gate — only active AFTER game server challenge
// response (0x80FFF495) is received. Before that (login server phase),
// CCCrypt calls pass through unchanged to avoid crashing JudgeApp.
static BOOL g_cccrypt_l4_active = NO;

// v37.35: Save AES key+iv from FFF493#1 ENC call, and extended plaintext
// from FFF493#2 ENC call. In send hook, intercept FFF493#2 packet and
// replace it with our own encrypted extended plaintext.
static uint8_t g_saved_aes_key[32] = {0};
static uint8_t g_saved_aes_iv[32] = {0};
static size_t g_saved_key_len = 0;
static uint32_t g_saved_alg = 0;
static uint32_t g_saved_options = 0;
static BOOL g_aes_key_saved = NO;
static char *g_ext_plaintext = NULL;   // extended plaintext for FFF493#2
static size_t g_ext_plaintext_len = 0;
static uint32_t g_fff493_2_seq = 0;    // seqNum of FFF493#2 to match in send hook
// v37.44: Save FFF493#2 native plaintext for send-hook field replacement
static char *g_fff493_2_native_plain = NULL;
static size_t g_fff493_2_native_len = 0;

// v37.35: Forward declare CCCrypt types so send hook (line ~3873) can use orig_CCCrypt
typedef int (*CCCryptFunc)(uint32_t op, uint32_t alg, uint32_t options,
                           const void *key, size_t keyLen,
                           const void *iv,
                           const void *dataIn, size_t dataInLen,
                           void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);
static CCCryptFunc orig_CCCrypt = NULL;

// v36.130: EncryptUtils bypass counter + original IMPs (defined here for forward access)
static int g_bypassRemaining = 0;
static IMP g_orig_rsaDecryptData = NULL;
static IMP g_orig_rsaDecryptLarge = NULL;
static IMP g_orig_aesDecryptData = NULL;

// v36.124: NEW — Wait for client to send native commands with REAL seq numbers
// Instead of pre-generating responses with wrong seq (0x10000+), wait for the
// client to send EE007/FFF493 etc., capture the REAL seq, and use it for responses.
static BOOL g_waitingForClientCmds = NO;
static int g_waitingFd = -1;

// Forward declaration (actual definition is after hook_recv closesocket logic,
// we will pull it above here as an independent reusable block).
static ssize_t triggerInitialFakeInjection(int fd, void *buf, size_t len);

// v36.94: Hook for NetImpl::quitFromServer
// This C++ method is called when heartbeat detects dead connection
// Making it a no-op prevents client state machine from entering disconnected state
typedef void (*NetImplQuitFunc)(void);
static NetImplQuitFunc orig_NetImpl_quitFromServer = NULL;
static BOOL g_quitFromServerHooked = NO;

// v36.97: MSHookFunction variables for heartbeat and disconnect
typedef void (*HeartbeatFunc)(void);
typedef void (*DisconnectFunc)(void);
static HeartbeatFunc orig_heartbeat_func = NULL;
static DisconnectFunc orig_disconnect_func = NULL;

// v36.97: No-op functions for MSHookFunction
static void noop_heartbeat(void) {
    DLOG(@"[NETIMPL-BLOCK] v36.97: HEARTBEAT BLOCKED (no-op)");
}

static void noop_disconnect(void) {
    DLOG(@"[NETIMPL-BLOCK] v36.97: DISCONNECT BLOCKED (no-op)");
}

// v36.57: Server list for rotation/retry
#define MAX_SERVERS 20
typedef struct {
    char ip[64];
    int port;
} ServerInfo;

static ServerInfo g_serverList[MAX_SERVERS];
static int g_serverCount = 0;
static int g_currentServerIndex = 0;
static int g_connectionFailCount = 0;

static NSMutableDictionary *g_msiStubData = nil;

static id msiStub_init(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient init] called");
    if (!g_msiStubData) {
        g_msiStubData = [[NSMutableDictionary alloc] init];
        [g_msiStubData setObject:@1 forKey:@"status"];
        [g_msiStubData setObject:@1 forKey:@"serverType"];
        [g_msiStubData setObject:@1 forKey:@"serverid"];
        [g_msiStubData setObject:@1 forKey:@"clientid"];
        [g_msiStubData setObject:@"一区" forKey:@"category"];
        [g_msiStubData setObject:@"运行" forKey:@"description"];
        // v36.59: Do NOT hardcode ip/port here - let initWithDictionary set them
        DLOG(@"[MSI-STUB] Initialized empty (ip/port to be filled by caller)");
    }
    return self;
}

static id msiStub_initWithDict(id self, SEL _cmd, NSDictionary *dict) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient initWithDictionary:] called");
    if (!g_msiStubData) {
        g_msiStubData = [[NSMutableDictionary alloc] init];
    }
    
    if (dict) {
        // v36.59: Use the provided dictionary - preserve ORIGINAL ip and port from game server list!
        [g_msiStubData setDictionary:dict];
        DLOG(@"[MSI-STUB] Using original dict values from server list response");
    }
    
    // Ensure critical fields are set (ONLY if missing from dict)
    if (![g_msiStubData objectForKey:@"status"])
        [g_msiStubData setObject:@1 forKey:@"status"];
    if (![g_msiStubData objectForKey:@"serverType"])
        [g_msiStubData setObject:@1 forKey:@"serverType"];
    if (![g_msiStubData objectForKey:@"category"])
        [g_msiStubData setObject:@"一区" forKey:@"category"];
    // v36.59: FIX description field - replace '维护' with '运行'
    NSString *desc = [g_msiStubData objectForKey:@"description"];
    if (!desc || [desc isEqualToString:@"维护"]) {
        [g_msiStubData setObject:@"运行" forKey:@"description"];
    }
    
    // v36.59: DO NOT override ip and port! Keep ORIGINAL values from dict!
    // Game knows which server it selected - don't interfere with its choice!
    
    // Log all properties
    @try {
        for (NSString *key in g_msiStubData) {
            DLOG(@"[MSI-STUB]   %@ = %@", key, g_msiStubData[key]);
        }
    } @catch (NSException *e) {
        DLOG(@"[MSI-STUB] Exception logging: %@", e.reason);
    }
    
    return self;
}

static NSNumber *msiStub_status(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient status] -> 1");
    return @1;
}

static NSString *msiStub_ip(id self, SEL _cmd) {
    // v36.59: Return ip from g_msiStubData (original value from dict), NOT hardcoded g_gameServerIP!
    NSString *ip = [g_msiStubData objectForKey:@"ip"];
    if (!ip) ip = [NSString stringWithUTF8String:g_gameServerIP];
    DLOG(@"[MSI-STUB] -[ServerInfoForClient ip] -> %@", ip);
    return ip;
}

static NSNumber *msiStub_port(id self, SEL _cmd) {
    // v36.59: Return port from g_msiStubData (original value from dict), NOT hardcoded g_gameServerPort!
    NSNumber *portNum = [g_msiStubData objectForKey:@"port"];
    int port = portNum ? [portNum intValue] : g_gameServerPort;
    DLOG(@"[MSI-STUB] -[ServerInfoForClient port] -> %d", port);
    return @(port);
}

static NSString *msiStub_category(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient category] -> 一区");
    return @"一区";
}

static NSNumber *msiStub_serverType(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] -[ServerInfoForClient serverType] -> 1");
    return @1;
}

static NSInteger msiStub_integer(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] integer method called -> 1");
    return 1;
}

static NSString *msiStub_string(id self, SEL _cmd) {
    DLOG(@"[MSI-STUB] string method called -> stub");
    return @"stub";
}

static void createServerInfoForClientStub(void) {
    @try {
        // Check if class already exists
        Class existingClass = NSClassFromString(@"ServerInfoForClient");
        if (existingClass) {
            DLOG(@"[MSI-STUB] ServerInfoForClient class already exists");
            return;
        }
        
        // Create stub class
        Class stubClass = objc_allocateClassPair([NSObject class], "ServerInfoForClient", 0);
        if (stubClass) {
            // Add instance methods
            class_addMethod(stubClass, @selector(init), (IMP)msiStub_init, "@@:");
            class_addMethod(stubClass, @selector(initWithDictionary:), (IMP)msiStub_initWithDict, "@@:@");
            class_addMethod(stubClass, @selector(status), (IMP)msiStub_status, "@@:");
            class_addMethod(stubClass, @selector(statusValue), (IMP)msiStub_status, "@@:");
            class_addMethod(stubClass, @selector(ip), (IMP)msiStub_ip, "@@:");
            class_addMethod(stubClass, @selector(port), (IMP)msiStub_serverType, "@@:");
            class_addMethod(stubClass, @selector(category), (IMP)msiStub_category, "@@:");
            class_addMethod(stubClass, @selector(serverType), (IMP)msiStub_serverType, "@@:");
            class_addMethod(stubClass, @selector(serverid), (IMP)msiStub_integer, "l@:");
            class_addMethod(stubClass, @selector(clientid), (IMP)msiStub_integer, "l@:");
            class_addMethod(stubClass, @selector(description), (IMP)msiStub_string, "@@:");
            class_addMethod(stubClass, @selector(objectForKey:), (IMP)msiStub_string, "@@:@");
            
            // Register the class
            objc_registerClassPair(stubClass);
            DLOG(@"[MSI-STUB] Created ServerInfoForClient stub class successfully");
            
            // Verify class exists
            Class verifyClass = NSClassFromString(@"ServerInfoForClient");
            if (verifyClass) {
                DLOG(@"[MSI-STUB] Verified: ServerInfoForClient class is now available");
                
                // Log all methods
                unsigned int mcount = 0;
                Method *methods = class_copyMethodList(verifyClass, &mcount);
                for (unsigned int i = 0; i < mcount; i++) {
                    SEL sel = method_getName(methods[i]);
                    DLOG(@"[MSI-STUB]   Method: %@", NSStringFromSelector(sel));
                }
                if (methods) free(methods);
            }
        } else {
            DLOG(@"[MSI-STUB] Failed to create ServerInfoForClient stub class");
        }
    } @catch (NSException *e) {
        DLOG(@"[MSI-STUB] Exception creating stub class: %@", e.reason);
    }
}

static id msi_initWithDict_hook(id self, SEL _cmd, NSDictionary *dict) {
    NSMutableDictionary *mutDict = nil;
    if (dict) {
        mutDict = [dict mutableCopy];
        
        if ([mutDict objectForKey:@"status"]) {
            NSNumber *status = mutDict[@"status"];
            if ([status isKindOfClass:[NSNumber class]] && [status intValue] != 1) {
                DLOG(@"[MSI-PATCH] status=%@ -> 1", status);
                mutDict[@"status"] = @1;
            }
        }
        
        if ([mutDict objectForKey:@"serverType"]) {
            NSNumber *serverType = mutDict[@"serverType"];
            if ([serverType isKindOfClass:[NSNumber class]] && [serverType intValue] != 1) {
                DLOG(@"[MSI-PATCH] serverType=%@ -> 1", serverType);
                mutDict[@"serverType"] = @1;
            }
        }
        
        if ([mutDict objectForKey:@"clientid"]) {
            NSNumber *clientid = mutDict[@"clientid"];
            if ([clientid isKindOfClass:[NSNumber class]] && [clientid intValue] != 1) {
                DLOG(@"[MSI-PATCH] clientid=%@ -> 1", clientid);
                mutDict[@"clientid"] = @1;
            }
        }
        
        if ([mutDict objectForKey:@"serverid"]) {
            NSNumber *serverid = mutDict[@"serverid"];
            if ([serverid isKindOfClass:[NSNumber class]] && [serverid intValue] != 1) {
                DLOG(@"[MSI-PATCH] serverid=%@ -> 1", serverid);
                mutDict[@"serverid"] = @1;
            }
        }
        
        if ([mutDict objectForKey:@"category"]) {
            NSString *category = mutDict[@"category"];
            if ([category isKindOfClass:[NSString class]]) {
                BOOL isAllDots = YES;
                for (NSInteger i = 0; i < category.length; i++) {
                    if ([category characterAtIndex:i] != '.') { isAllDots = NO; break; }
                }
                if (isAllDots || [category length] == 0) {
                    DLOG(@"[MSI-PATCH] category=%@ -> 一区", category);
                    mutDict[@"category"] = @"一区";
                }
            }
        }
        
        if ([mutDict objectForKey:@"description"]) {
            NSString *desc = mutDict[@"description"];
            if ([desc isKindOfClass:[NSString class]] && [desc containsString:@"维护"]) {
                DLOG(@"[MSI-PATCH] description=%@ -> 运行", desc);
                mutDict[@"description"] = @"运行";
            }
        }
        
        // NO IP REPLACEMENT - keep original server IP
        // Normal client connects to 47.100.14.198 for both login and game servers
        if ([mutDict objectForKey:@"ip"]) {
            NSString *ip = mutDict[@"ip"];
            if ([ip isKindOfClass:[NSString class]]) {
                DLOG(@"[MSI] Server IP: %@ (not modified)", ip);
            }
        }
        
        DLOG(@"[MSI-CALL] -[%@ initWithDictionary:] (patched) -> %@", NSStringFromClass([self class]), [mutDict allKeys]);
        for (NSString *key in mutDict) {
            DLOG(@"[MSI-DICT]   %@ = %@", key, mutDict[key]);
        }
    }
    
    id (*origFunc)(id, SEL, NSDictionary*) = (id(*)(id, SEL, NSDictionary*))orig_msi_initWithDict;
    id ret = origFunc(self, _cmd, mutDict ?: dict);
    
    if (ret) {
        msi_log_properties(ret);
    }
    return ret;
}

static NSNumber *msi_status_hook(id self, SEL _cmd) {
    NSNumber *(*origFunc)(id, SEL) = (NSNumber*(*)(id, SEL))orig_msi_status;
    NSNumber *ret = origFunc(self, _cmd);
    if (ret && [ret intValue] != 1) {
        DLOG(@"[MSI-PATCH-STATUS] status=%@ -> 1 (property access)", ret);
        return @1;
    }
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSString *msi_ip_hook(id self, SEL _cmd) {
    NSString *ret = ((NSString*(*)(id, SEL))objc_msgSend)(self, _cmd);
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSString *msi_category_hook(id self, SEL _cmd) {
    NSString *ret = ((NSString*(*)(id, SEL))objc_msgSend)(self, _cmd);
    if (ret) {
        BOOL isAllDots = YES;
        for (NSInteger i = 0; i < ret.length; i++) {
            if ([ret characterAtIndex:i] != '.') { isAllDots = NO; break; }
        }
        if (isAllDots || [ret length] == 0) {
            DLOG(@"[MSI-PATCH-CAT] category=%@ -> 一区 (property access)", ret);
            return @"一区";
        }
    }
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSNumber *msi_serverType_hook(id self, SEL _cmd) {
    NSNumber *ret = ((NSNumber*(*)(id, SEL))objc_msgSend)(self, _cmd);
    if (ret && [ret intValue] != 1) {
        DLOG(@"[MSI-PATCH-TYPE] serverType=%@ -> 1 (property access)", ret);
        return @1;
    }
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSString *msi_string_hook(id self, SEL _cmd) {
    NSString *ret = ((NSString*(*)(id, SEL))objc_msgSend)(self, _cmd);
    DLOG(@"[MSI-CALL] -[%@ %@] -> %@", NSStringFromClass([self class]), NSStringFromSelector(_cmd), ret);
    return ret;
}

static NSInteger msi_int_hook(id self, SEL _cmd) {
    NSInteger ret = ((NSInteger(*)(id, SEL))objc_msgSend)(self, _cmd);
    DLOG(@"[MSI-CALL] -[%@ %@] -> %ld", NSStringFromClass([self class]), NSStringFromSelector(_cmd), (long)ret);
    return ret;
}

static void createLogButton(UIWindow *w) {
    if (!w || g_btn) return;
    g_handler = [[WXHandler alloc] init];
    g_btn = [UIButton buttonWithType:UIButtonTypeCustom];
    g_btn.frame = CGRectMake(w.bounds.size.width - 60, 200, 50, 50);
    g_btn.layer.cornerRadius = 25;
    g_btn.clipsToBounds = YES;
    
    NSString *imagePath = [[NSBundle mainBundle] pathForResource:@"123" ofType:@"jpg"];
    if (imagePath && [[NSFileManager defaultManager] fileExistsAtPath:imagePath]) {
        UIImage *btnImage = [UIImage imageWithContentsOfFile:imagePath];
        if (btnImage) {
            btnImage = [btnImage imageWithRenderingMode:UIImageRenderingModeAlwaysOriginal];
            [g_btn setImage:btnImage forState:UIControlStateNormal];
            g_btn.imageView.contentMode = UIViewContentModeScaleAspectFill;
            DLOG(@"[UI] Log button using custom image: %@", imagePath);
        } else {
            [g_btn setTitle:@"LOG" forState:UIControlStateNormal];
            [g_btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            g_btn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];
        }
    } else {
        [g_btn setTitle:@"LOG" forState:UIControlStateNormal];
        [g_btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        g_btn.backgroundColor = [UIColor colorWithRed:1 green:0.4 blue:0 alpha:0.9];
    }
    
    g_btn.titleLabel.font = [UIFont systemFontOfSize:10];
    g_btn.hidden = YES;
    g_btn.userInteractionEnabled = YES;
    [g_btn addTarget:g_handler action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [w addSubview:g_btn];
    [w bringSubviewToFront:g_btn];
    
    // Pan gesture for moving the log button (drag to reposition)
    UIPanGestureRecognizer *panGesture = [[UIPanGestureRecognizer alloc] initWithTarget:g_handler action:@selector(handlePan:)];
    panGesture.cancelsTouchesInView = NO;
    panGesture.requiresExclusiveTouchType = NO;
    [g_btn addGestureRecognizer:panGesture];
    
    UITapGestureRecognizer *tripleTap = [[UITapGestureRecognizer alloc] initWithTarget:g_handler action:@selector(handleTripleTap:)];
    tripleTap.numberOfTapsRequired = 2;
    tripleTap.numberOfTouchesRequired = 3;
    tripleTap.cancelsTouchesInView = NO;
    tripleTap.delaysTouchesEnded = NO;
    tripleTap.delaysTouchesBegan = NO;
    tripleTap.requiresExclusiveTouchType = NO;
    [w addGestureRecognizer:tripleTap];
    
    _log(@"[UI] Button created on window (hidden, triple-tap to show)");
}

static void __attribute__((noinline)) tryHookMieshiServerInfo(int attempt) {
    Class msiCls = NSClassFromString(@"ServerInfoForClient");
    if (msiCls) {
        DLOG(@"[MSI-RETRY] ServerInfoForClient class FOUND at attempt #%d!", attempt);
        
        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(msiCls, &mcount);
        for (unsigned int i = 0; i < mcount; i++) {
            SEL sel = method_getName(methods[i]);
            NSString *selName = NSStringFromSelector(sel);
            DLOG(@"[MSI-RETRY] -[%@ %@]", NSStringFromClass(msiCls), selName);
        }
        if (methods) free(methods);
        
        if (!orig_msi_init) {
            Method m_init = class_getInstanceMethod(msiCls, @selector(init));
            if (m_init) {
                orig_msi_init = method_getImplementation(m_init);
                method_setImplementation(m_init, (IMP)msi_init_hook);
                DLOG(@"[MSI-HOOK] Hooked: init");
            }
        }
        
        if (!orig_msi_initWithDict) {
            Method m_initDict = class_getInstanceMethod(msiCls, @selector(initWithDictionary:));
            if (m_initDict) {
                orig_msi_initWithDict = method_getImplementation(m_initDict);
                method_setImplementation(m_initDict, (IMP)msi_initWithDict_hook);
                DLOG(@"[MSI-HOOK] Hooked: initWithDictionary:");
            }
        }
        
        if (!orig_msi_status) {
            Method m_status = class_getInstanceMethod(msiCls, @selector(status));
            if (m_status) {
                orig_msi_status = method_getImplementation(m_status);
                method_setImplementation(m_status, (IMP)msi_status_hook);
                DLOG(@"[MSI-HOOK] Hooked: status");
            }
        }
        
        Method m_statusValue = class_getInstanceMethod(msiCls, @selector(statusValue));
        if (m_statusValue) {
            method_setImplementation(m_statusValue, (IMP)msi_status_hook);
            DLOG(@"[MSI-HOOK] Hooked: statusValue");
        }
        
        Method m_ip = class_getInstanceMethod(msiCls, @selector(ip));
        if (m_ip) {
            method_setImplementation(m_ip, (IMP)msi_ip_hook);
            DLOG(@"[MSI-HOOK] Hooked: ip");
        }
        
        Method m_category = class_getInstanceMethod(msiCls, @selector(category));
        if (m_category) {
            method_setImplementation(m_category, (IMP)msi_category_hook);
            DLOG(@"[MSI-HOOK] Hooked: category");
        }
        
        Method m_serverType = class_getInstanceMethod(msiCls, @selector(serverType));
        if (m_serverType) {
            method_setImplementation(m_serverType, (IMP)msi_serverType_hook);
            DLOG(@"[MSI-HOOK] Hooked: serverType");
        }
        
        Method m_serverId = class_getInstanceMethod(msiCls, @selector(serverid));
        if (m_serverId) {
            method_setImplementation(m_serverId, (IMP)msi_serverType_hook);
            DLOG(@"[MSI-HOOK] Hooked: serverid");
        }
        
        Method m_clientId = class_getInstanceMethod(msiCls, @selector(clientid));
        if (m_clientId) {
            method_setImplementation(m_clientId, (IMP)msi_serverType_hook);
            DLOG(@"[MSI-HOOK] Hooked: clientid");
        }
    } else {
        DLOG(@"[MSI-RETRY] ServerInfoForClient class not found at attempt #%d", attempt);

        // v37.4: DISABLED stub class creation — creating a fake ServerInfoForClient
        //        class interferes with client's native server list parsing.
        //        capture_real.js (Frida diagnostic) never created this stub and
        //        client worked perfectly. The stub's ip/port methods return invalid
        //        values, causing '网络连接中断' when client tries to connect game server.
        if (attempt >= 2) {
            DLOG(@"[MSI-STUB] v37.4: STUB CREATION DISABLED — letting client parse natively");
            return;
        }

        if (attempt < 3) {
            double delays[] = {2.0, 5.0, 10.0};
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delays[attempt] * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                tryHookMieshiServerInfo(attempt + 1);
            });
        }
    }
}

#pragma mark - Deep Diagnostics (trace server list display)
// ============================================================

static NSArray *(*orig_arrayWithObjects)(Class, SEL, const id *, unsigned int);
static NSArray *hook_arrayWithObjects(Class self, SEL _cmd, const id *objects, unsigned int count) {
    NSArray *ret = orig_arrayWithObjects(self, _cmd, objects, count);
    DLOG(@"[DIAG-ARRAY] +[NSArray arrayWithObjects:] count=%u", count);
    for (unsigned int i = 0; i < count && i < 5; i++) {
        if (objects[i]) {
            DLOG(@"[DIAG-ARRAY]   obj[%u] = %@ (%@)", i, objects[i], NSStringFromClass([objects[i] class]));
        }
    }
    return ret;
}

static NSUInteger (*orig_tableViewNumberOfRows)(id, SEL, UITableView *, NSInteger);
static NSUInteger hook_tableViewNumberOfRows(id self, SEL _cmd, UITableView *tableView, NSInteger section) {
    NSUInteger ret = orig_tableViewNumberOfRows(self, _cmd, tableView, section);
    DLOG(@"[DIAG-TABLE] -[DataSource numberOfRowsInSection:%ld] -> %lu", (long)section, (unsigned long)ret);
    return ret;
}

static NSInteger (*orig_tableViewNumberOfSections)(id, SEL, UITableView *);
static NSInteger hook_tableViewNumberOfSections(id self, SEL _cmd, UITableView *tableView) {
    NSInteger ret = orig_tableViewNumberOfSections(self, _cmd, tableView);
    DLOG(@"[DIAG-TABLE] -[DataSource numberOfSections] -> %ld", (long)ret);
    return ret;
}

static void (*orig_alertViewShow)(id, SEL);
static void hook_alertViewShow(id self, SEL _cmd) {
    NSString *title = [self performSelector:@selector(title)];
    NSString *msg = [self performSelector:@selector(message)];
    DLOG(@"[DIAG-ALERT] UIAlertView show: title='%@' msg='%@'", title, msg);
    
    NSArray *stack = [NSThread callStackSymbols];
    for (NSUInteger i = 0; i < [stack count] && i < 20; i++) {
        DLOG(@"[DIAG-ALERT-STACK] %@", stack[i]);
    }
    
    NSString *lowerMsg = [msg lowercaseString];
    NSString *lowerTitle = [title lowercaseString];
    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] || 
        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||
        [lowerMsg containsString:@"升级"]) {
        DLOG(@"[ALERT-BLOCK] Blocked version check alert: title='%@' msg='%@'", title, msg);
        return;
    }
    
    orig_alertViewShow(self, _cmd);
}

// v36.59: COMPLETE FIX - Correct method signature!
// -[UIViewController presentViewController:animated:completion:] has 3 params after self/_cmd:
//   arg1 = viewControllerToPresent (UIViewController*)
//   arg2 = animated (BOOL)
//   arg3 = completion (dispatch_block_t)
// Previous hook had WRONG parameter order causing SIGSEGV when calling the "completion"
// which was actually a BOOL value (0x0 or 0x1) interpreted as block pointer!
static void (*orig_alertControllerPresent)(id, SEL, id, BOOL, dispatch_block_t);
static void hook_alertControllerPresent(id self, SEL _cmd, id viewControllerToPresent, BOOL animated, dispatch_block_t completion) {
    @try {
        // Check orig function pointer
        if (!orig_alertControllerPresent) {
            DLOG(@"[DIAG-ALERT] orig_alertControllerPresent is NULL, passthrough");
            // Even if orig is NULL we can't proceed - but avoid crash
            return;
        }
        
        // v36.59: Check self (presenting VC)
        if (!self) {
            DLOG(@"[DIAG-ALERT] self (presenting VC) is nil/NULL");
            return;
        }
        
        // v36.59: Check viewControllerToPresent (the one being presented, could be UIAlertController)
        if (!viewControllerToPresent) {
            DLOG(@"[DIAG-ALERT] viewControllerToPresent is nil/NULL");
            return;
        }
        
        // Check if the presented VC is UIAlertController - that's what we want to intercept
        BOOL isAlert = NO;
        @try {
            if ([viewControllerToPresent isKindOfClass:[UIAlertController class]]) {
                isAlert = YES;
                UIAlertController *alert = (UIAlertController *)viewControllerToPresent;
                NSString *title = [alert title];
                NSString *msg = [alert message];
                DLOG(@"[DIAG-ALERT] UIAlertController present: title='%@' msg='%@' presentingVC=%@", 
                     title ? title : @"<nil>", msg ? msg : @"<nil>", 
                     NSStringFromClass([self class]));
                
                // Block version-related alerts
                if (title || msg) {
                    NSString *lowerMsg = msg ? [[msg lowercaseString] copy] : @"";
                    NSString *lowerTitle = title ? [[title lowercaseString] copy] : @"";
                    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] || 
                        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||
                        [lowerMsg containsString:@"升级"] || [lowerMsg containsString:@"version"] ||
                        [lowerMsg containsString:@"update"]) {
                        DLOG(@"[ALERT-BLOCK] Blocked version check UIAlertController: title='%@' msg='%@'", 
                             title ? title : @"", msg ? msg : @"");
                        return;  // Do not present!
                    }
                }
            }
        } @catch (NSException *e) {
            DLOG(@"[DIAG-ALERT] Exception checking alert: %@", e.reason);
            isAlert = NO;  // On error, just passthrough
        }
        
        // v36.59: SAFE completion handling with Block_copy to avoid stack-block crash
        dispatch_block_t safeCompletion = NULL;
        if (completion != NULL) {
            // Copy the block to heap in case it's a stack-allocated block
            @try {
                safeCompletion = [completion copy];  // ARC-style or Block_copy equivalent
            } @catch (NSException *e) {
                DLOG(@"[DIAG-ALERT] Exception copying completion block: %@", e.reason);
                safeCompletion = NULL;
            }
        }
        if (!safeCompletion) {
            // Provide a static empty block (heap-allocated by compiler)
            safeCompletion = ^{};
        }
        
        // v36.59: Use __weak self to avoid dangling pointers on async dispatch
        __weak id weakPresentingVC = self;
        __weak id weakPresentedVC = viewControllerToPresent;
        dispatch_block_t copiedCompletion = [safeCompletion copy];
        
        void (*callOrig)(id, SEL, id, BOOL, dispatch_block_t) = orig_alertControllerPresent;
        
        if ([NSThread isMainThread]) {
            @try {
                callOrig(self, _cmd, viewControllerToPresent, animated, copiedCompletion);
            } @catch (NSException *e) {
                DLOG(@"[DIAG-ALERT] Exception calling orig present (main thread): %@", e.reason);
            } @catch (...) {
                DLOG(@"[DIAG-ALERT] Unknown C++/signal exception calling orig present (main thread)");
            }
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                @try {
                    id strongPresenting = weakPresentingVC;
                    id strongPresented = weakPresentedVC;
                    if (strongPresenting && strongPresented) {
                        callOrig(strongPresenting, _cmd, strongPresented, animated, copiedCompletion);
                    } else {
                        DLOG(@"[DIAG-ALERT] Async present aborted: presentingVC or presentedVC deallocated");
                    }
                } @catch (NSException *e) {
                    DLOG(@"[DIAG-ALERT] Exception calling orig present (async main thread): %@", e.reason);
                } @catch (...) {
                    DLOG(@"[DIAG-ALERT] Unknown exception calling orig present (async main thread)");
                }
            });
        }
    } @catch (NSException *e) {
        DLOG(@"[DIAG-ALERT] Exception in alert hook OUTER: %@", e.reason);
    } @catch (...) {
        DLOG(@"[DIAG-ALERT] Unknown C++/foreign exception in alert hook OUTER");
    }
}

// ============================================================
#pragma mark - Gzip utilities
// ============================================================

static BOOL isGzipData(const unsigned char *data, size_t len) {
    return (len >= 3 && data[0] == 0x1F && data[1] == 0x8B && data[2] == 0x08);
}

static unsigned char *gzipDecompress(const unsigned char *data, size_t len, size_t *outLen) {
    if (!data || len < 10 || !isGzipData(data, len)) return NULL;
    
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    
    if (inflateInit2(&strm, MAX_WBITS + 16) != Z_OK) return NULL;
    
    strm.next_in = (Bytef *)data;
    strm.avail_in = len;
    
    size_t bufSize = len * 4;
    unsigned char *buf = (unsigned char *)malloc(bufSize);
    if (!buf) { inflateEnd(&strm); return NULL; }
    
    unsigned char *outBuf = buf;
    size_t totalOut = 0;
    
    do {
        strm.next_out = (Bytef *)buf;
        strm.avail_out = bufSize;
        
        int ret = inflate(&strm, Z_NO_FLUSH);
        
        size_t produced = bufSize - strm.avail_out;
        if (produced > 0) {
            totalOut += produced;
            unsigned char *newBuf = (unsigned char *)realloc(outBuf, totalOut + bufSize);
            if (!newBuf) { free(outBuf); inflateEnd(&strm); return NULL; }
            buf = newBuf + totalOut - produced;
            outBuf = newBuf;
        }
        
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK) { free(outBuf); inflateEnd(&strm); return NULL; }
        
    } while (strm.avail_in > 0);
    
    inflateEnd(&strm);
    
    unsigned char *finalBuf = (unsigned char *)realloc(outBuf, totalOut + 1);
    if (finalBuf) {
        finalBuf[totalOut] = '\0';
        *outLen = totalOut;
        return finalBuf;
    }
    
    free(outBuf);
    return NULL;
}

static unsigned char *gzipCompress(const unsigned char *data, size_t len, size_t *outLen) {
    if (!data || len == 0) return NULL;
    
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return NULL;
    
    strm.next_in = (Bytef *)data;
    strm.avail_in = len;
    
    size_t bufSize = len + (len / 10) + 12;
    unsigned char *buf = (unsigned char *)malloc(bufSize);
    if (!buf) { deflateEnd(&strm); return NULL; }
    
    unsigned char *outBuf = buf;
    size_t totalOut = 0;
    
    do {
        strm.next_out = (Bytef *)buf;
        strm.avail_out = bufSize;
        
        int ret = deflate(&strm, Z_FINISH);
        
        size_t produced = bufSize - strm.avail_out;
        if (produced > 0) {
            totalOut += produced;
            unsigned char *newBuf = (unsigned char *)realloc(outBuf, totalOut + bufSize);
            if (!newBuf) { free(outBuf); deflateEnd(&strm); return NULL; }
            buf = newBuf + totalOut - produced;
            outBuf = newBuf;
        }
        
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK) { free(outBuf); deflateEnd(&strm); return NULL; }
        
    } while (strm.avail_in > 0);
    
    deflateEnd(&strm);
    
    *outLen = totalOut;
    return outBuf;
}

// ============================================================
#pragma mark - BSD socket hooks (detect game network traffic)
// ============================================================

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <execinfo.h>
#include <sys/time.h>
#include <fcntl.h>

// === Socket hook functions ===
typedef int (*ConnectFunc)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*SendFunc)(int, const void *, size_t, int);
typedef ssize_t (*RecvFunc)(int, void *, size_t, int);
typedef ssize_t (*WriteFunc)(int, const void *, size_t);
typedef ssize_t (*ReadFunc)(int, void *, size_t);
typedef ssize_t (*RecvfromFunc)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*RecvmsgFunc)(int, struct msghdr *, int);
typedef int (*CloseFunc)(int);
typedef int (*GetsockoptFunc)(int, int, int, void *, socklen_t *);
typedef int (*PollFunc)(struct pollfd *, nfds_t, int);
typedef int (*SelectFunc)(int, fd_set *, fd_set *, fd_set *, struct timeval *);

static ConnectFunc orig_connect = NULL;
static SendFunc orig_send = NULL;
static RecvFunc orig_recv = NULL;
static RecvfromFunc orig_recvfrom = NULL;
static RecvmsgFunc orig_recvmsg = NULL;
static WriteFunc orig_write = NULL;
static ReadFunc orig_read = NULL;
static CloseFunc orig_close = NULL;
static GetsockoptFunc orig_getsockopt = NULL;
static PollFunc orig_poll = NULL;
static SelectFunc orig_select = NULL;

#define MAX_TRACKED_FDS 64
static int g_trackedFds[MAX_TRACKED_FDS];
static char g_trackedHosts[MAX_TRACKED_FDS][64];
static int g_trackedPorts[MAX_TRACKED_FDS];
static int g_trackedCount = 0;
static BOOL g_trackedActive[MAX_TRACKED_FDS];

// Note: g_gameServerPort, g_gameServerIP, g_gameServerInfoUpdated defined earlier for stub class access

static void clearTrackedFd(int fd) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd) {
            DLOG(@"[FD-CLOSE] fd=%d %s:%d removed from tracking", fd, g_trackedHosts[i], g_trackedPorts[i]);
            g_trackedActive[i] = NO;
            g_trackedFds[i] = -1;
            g_trackedHosts[i][0] = '\0';
            g_trackedPorts[i] = 0;
            return;
        }
    }
}

static void trackFd(int fd, const char *host, int port) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd) {
            DLOG(@"[FD-UPDATE] fd=%d updated from %s:%d to %s:%d", fd, 
                 g_trackedHosts[i], g_trackedPorts[i], host, port);
            strncpy(g_trackedHosts[i], host, 63);
            g_trackedPorts[i] = port;
            g_trackedActive[i] = YES;
            return;
        }
    }
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == -1) {
            g_trackedFds[i] = fd;
            strncpy(g_trackedHosts[i], host, 63);
            g_trackedPorts[i] = port;
            g_trackedActive[i] = YES;
            DLOG(@"[FD-REUSE] fd=%d %s:%d reused slot %d", fd, host, port, i);
            return;
        }
    }
    if (g_trackedCount >= MAX_TRACKED_FDS) {
        DLOG(@"[FD-ERROR] Max tracked fds reached (%d)", MAX_TRACKED_FDS);
        return;
    }
    g_trackedFds[g_trackedCount] = fd;
    strncpy(g_trackedHosts[g_trackedCount], host, 63);
    g_trackedPorts[g_trackedCount] = port;
    g_trackedActive[g_trackedCount] = YES;
    g_trackedCount++;
}

static const char *getHostForFd(int fd) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd && g_trackedActive[i]) return g_trackedHosts[i];
    }
    return NULL;
}

static int getPortForFd(int fd) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd && g_trackedActive[i]) return g_trackedPorts[i];
    }
    return 0;
}

// v36.134: Inject UUID into 0x000EE007 device info packet for game server
// Login server (5678) sends 143-byte packet without UUID field
// Game server expects 179-byte packet with UUID TLV after GPU field
//
// REAL CAPTURE FORMAT (hook.txt SEND #29, 178 bytes):
//   ...GPU TLV (2-byte len + data)...
//   00 00 00 00 00 00 00  - 7 bytes reserved (zero)
//   24                    - 1 byte UUID length (0x24 = 36)
//   [36-byte UUID string]
//   00                    - 1 byte suffix (zero)
//   01 00                 - 2 bytes trailer
//
// v36.134 FIX: Previous versions injected UUID at offset 34 (after device ID)
//   with wrong format (2-byte len + UUID). Correct position is AFTER GPU field,
//   with format: 7-byte zero + 1-byte len + UUID + 1-byte zero.
static ssize_t injectUUIDIntoDeviceInfo(const uint8_t *src, size_t srcLen,
                                         uint8_t *dst, size_t dstMaxLen) {
    if (!src || srcLen < 36 || !dst || dstMaxLen < srcLen + 40) {
        DLOG(@"[UUID-INJECT] Invalid params: srcLen=%zu dstMaxLen=%zu", srcLen, dstMaxLen);
        return -1;
    }

    // Get UUID (prefer IDFV, fallback to fixed)
    const char *fakeUUID = "00000000-0000-0000-0000-000000000001";
    @try {
        UIDevice *device = [UIDevice currentDevice];
        if (device && [device respondsToSelector:@selector(identifierForVendor)]) {
            NSUUID *idfv = [device identifierForVendor];
            if (idfv) {
                NSString *uuidStr = [idfv UUIDString];
                if (uuidStr && uuidStr.length == 36) {
                    fakeUUID = uuidStr.UTF8String;
                }
            }
        }
    } @catch (NSException *e) {}

    size_t uuidStrLen = strlen(fakeUUID);  // 36

    // v36.134: Parse all TLV fields to find GPU field
    // Header: 4(pktLen) + 4(cmd) + 4(seq) = 12 bytes
    // Then: sequence of TLV fields (2-byte big-endian len + N bytes data)
    size_t offset = 12;
    int fieldCount = 0;
    size_t gpuFieldEnd = 0;

    while (offset + 2 <= srcLen && fieldCount < 30) {
        uint16_t fieldLen = ((uint16_t)src[offset] << 8) | (uint16_t)src[offset + 1];
        if (fieldLen > 200 || offset + 2 + fieldLen > srcLen) {
            DLOG(@"[UUID-INJECT] v36.134: Invalid field at offset %zu: len=%u srcLen=%zu",
                 offset, fieldLen, srcLen);
            break;
        }

        // Check if this is GPU field (contains "GPU" substring)
        if (fieldLen >= 3 && offset + 2 + fieldLen <= srcLen) {
            const uint8_t *fieldData = src + offset + 2;
            for (uint16_t i = 0; i + 3 <= fieldLen; i++) {
                if (fieldData[i] == 'G' && fieldData[i+1] == 'P' && fieldData[i+2] == 'U') {
                    gpuFieldEnd = offset + 2 + fieldLen;
                    DLOG(@"[UUID-INJECT] v36.134: Found GPU field at offset %zu, ends at %zu (len=%u)",
                         offset, gpuFieldEnd, fieldLen);
                    break;
                }
            }
            if (gpuFieldEnd > 0) break;
        }

        offset += 2 + fieldLen;
        fieldCount++;
    }

    if (gpuFieldEnd == 0) {
        DLOG(@"[UUID-INJECT] v36.134: GPU field NOT found, falling back to old logic");
        // Fallback: old logic (inject after first TLV field)
        uint16_t firstFieldLen = ((uint16_t)src[12] << 8) | (uint16_t)src[13];
        if (firstFieldLen > 200 || 14 + firstFieldLen > srcLen) return -1;
        size_t insertOffset = 12 + 2 + firstFieldLen;
        size_t newPayloadSize = srcLen + 2 + uuidStrLen;
        if (newPayloadSize > dstMaxLen) return -1;
        memcpy(dst, src, insertOffset);
        dst[insertOffset] = (uuidStrLen >> 8) & 0xFF;
        dst[insertOffset + 1] = uuidStrLen & 0xFF;
        memcpy(dst + insertOffset + 2, fakeUUID, uuidStrLen);
        memcpy(dst + insertOffset + 2 + uuidStrLen, src + insertOffset, srcLen - insertOffset);
        uint32_t newTotalLen = (uint32_t)newPayloadSize;
        dst[0] = (newTotalLen >> 24) & 0xFF;
        dst[1] = (newTotalLen >> 16) & 0xFF;
        dst[2] = (newTotalLen >> 8) & 0xFF;
        dst[3] = newTotalLen & 0xFF;
        return (ssize_t)newPayloadSize;
    }

    // v36.134: Check trailing structure after GPU field
    // Expected: 9 bytes zero + 01 00 (trailer)
    // Target:   7 bytes zero + 1 byte len(0x24) + 36 bytes UUID + 1 byte zero + 01 00
    size_t tailStart = srcLen - 2;  // position of "01 00"
    if (srcLen < 2 || src[tailStart] != 0x01 || src[tailStart + 1] != 0x00) {
        DLOG(@"[UUID-INJECT] v36.134: Trailer 01 00 not found at end (srcLen=%zu)", srcLen);
        return -1;
    }

    size_t midLen = tailStart - gpuFieldEnd;  // bytes between GPU end and trailer
    DLOG(@"[UUID-INJECT] v36.134: midLen=%zu (between GPU end and trailer)", midLen);

    // Build new packet:
    // [header + TLV fields up to GPU end] + [7 zero + 1 len + 36 UUID + 1 zero] + [01 00]
    size_t uuidBlockLen = 7 + 1 + uuidStrLen + 1;  // 7+1+36+1 = 45
    size_t newLen = gpuFieldEnd + uuidBlockLen + 2;  // +2 for trailer
    if (newLen > dstMaxLen) {
        DLOG(@"[UUID-INJECT] v36.134: Output too large: need %zu max %zu", newLen, dstMaxLen);
        return -1;
    }

    // Copy [header + TLV fields up to GPU end]
    memcpy(dst, src, gpuFieldEnd);

    // Write 7 bytes zero (reserved)
    memset(dst + gpuFieldEnd, 0, 7);

    // Write 1 byte UUID length (0x24 = 36)
    dst[gpuFieldEnd + 7] = (uint8_t)uuidStrLen;

    // Write UUID string (36 bytes)
    memcpy(dst + gpuFieldEnd + 8, fakeUUID, uuidStrLen);

    // Write 1 byte zero (suffix)
    dst[gpuFieldEnd + 8 + uuidStrLen] = 0;

    // Write trailer (01 00)
    dst[gpuFieldEnd + 8 + uuidStrLen + 1] = 0x01;
    dst[gpuFieldEnd + 8 + uuidStrLen + 2] = 0x00;

    // Update packet length in header (bytes 0-3, big-endian)
    uint32_t newTotalLen = (uint32_t)newLen;
    dst[0] = (newTotalLen >> 24) & 0xFF;
    dst[1] = (newTotalLen >> 16) & 0xFF;
    dst[2] = (newTotalLen >> 8) & 0xFF;
    dst[3] = newTotalLen & 0xFF;

    DLOG(@"[UUID-INJECT] v36.134: SUCCESS %zu -> %zu bytes (UUID at GPU+7, midLen was %zu, UUID=%.*s)",
         srcLen, newLen, midLen, 8, fakeUUID);

    return (ssize_t)newLen;
}

// v36.71: Check if a command is from game server protocol (not login server)
// Game server cmd ranges:
//   0x00FFxxxx / 0x80FFxxxx - Handshake/challenge/response
//   0x000Exxxx / 0x800Exxxx - Device info related
//   0x00EExxxx / 0x80EExxxx - Extended device info responses
// Login server uses 0x802Exxxx range
static BOOL isGameCmd(uint32_t cmd) {
    uint32_t prefix = cmd & 0xFFFF0000;
    // Game server: 0x00FFxxxx, 0x80FFxxxx, 0x000Exxxx, 0x800Exxxx, 0x00EExxxx, 0x80EExxxx
    if (prefix == 0x00FF0000 || prefix == 0x80FF0000 ||
        prefix == 0x000E0000 || prefix == 0x800E0000 ||
        prefix == 0x00EE0000 || prefix == 0x80EE0000) {
        return YES;
    }
    return NO;
}

// v36.112: Unified game port detection function
static BOOL isGameServerPort(int port) {
    // Known game server ports
    if (port == 12003 || port == 58158 || port == 5679 || port == 5680 || port == 5681) {
        return YES;
    }
    // Dynamic detection: if we have a tracked game port, match against it
    if (g_gameServerPort >= 1024 && port == g_gameServerPort) {
        return YES;
    }
    // Range-based detection for dynamically assigned ports
    if (port >= 5000 && port <= 65535 && g_gameServerPort >= 1024) {
        return YES;
    }
    return NO;
}

static void updateFdHostPort(int fd, const char *host, int port) {
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd) {
            strncpy(g_trackedHosts[i], host, 63);
            g_trackedPorts[i] = port;
            DLOG(@"[FD-UPDATE] Updated fd=%d to %s:%d", fd, host, port);
            return;
        }
    }
    // Not found, add new entry
    trackFd(fd, host, port);
}

static void parseServerListResponse(const unsigned char *data, ssize_t len) {
    if (!data || len < 12) return;
    
    @try {
        NSString *bodyStr = [[NSString alloc] initWithBytes:data+12 length:(NSUInteger)(len-12) encoding:NSUTF8StringEncoding];
        if (bodyStr && bodyStr.length > 0) {
            DLOG(@"[SERVERLIST-PARSE] Response body length: %lu", (unsigned long)bodyStr.length);
            
            NSRegularExpression *ipRegex = [NSRegularExpression regularExpressionWithPattern:@"\"ip\"\\s*:\\s*\"([^\"]+)\"" options:0 error:nil];
            NSArray *ipMatches = [ipRegex matchesInString:bodyStr options:0 range:NSMakeRange(0, bodyStr.length)];
            NSMutableArray *ips = [NSMutableArray array];
            for (NSTextCheckingResult *match in ipMatches) {
                NSString *ipStr = [bodyStr substringWithRange:[match rangeAtIndex:1]];
                [ips addObject:ipStr];
                DLOG(@"[SERVERLIST-PARSE] Found IP: %@", ipStr);
            }
            
            NSRegularExpression *portRegex = [NSRegularExpression regularExpressionWithPattern:@"\"port\"\\s*:\\s*(\\d+)" options:0 error:nil];
            NSArray *portMatches = [portRegex matchesInString:bodyStr options:0 range:NSMakeRange(0, bodyStr.length)];
            NSMutableArray *ports = [NSMutableArray array];
            for (NSTextCheckingResult *match in portMatches) {
                NSString *portStr = [bodyStr substringWithRange:[match rangeAtIndex:1]];
                int portInt = [portStr intValue];
                [ports addObject:portStr];
                DLOG(@"[SERVERLIST-PARSE] Found port: %@ (int=%d)", portStr, portInt);
            }
            
            if (ips.count > 0 && ports.count > 0) {
                // v36.57: Store servers in list for rotation
                g_serverCount = 0;
                for (NSUInteger i = 0; i < MIN(ips.count, ports.count) && g_serverCount < MAX_SERVERS; i++) {
                    int portInt = [ports[i] intValue];
                    if (portInt > 0 && portInt < 65536) {
                        NSString *ipStr = ips[i];
                        DLOG(@"[SERVERLIST-PARSE] Server %d: %@:%d", g_serverCount, ipStr, portInt);
                        
                        // Store in server list for rotation
                        strncpy(g_serverList[g_serverCount].ip, [ipStr UTF8String], 63);
                        g_serverList[g_serverCount].port = portInt;
                        g_serverCount++;
                        
                        // Set first valid server as default
                        if (g_serverCount == 1) {
                            strncpy(g_gameServerIP, [ipStr UTF8String], 63);
                            g_gameServerPort = portInt;
                            g_currentServerIndex = 0;
                            DLOG(@"[SERVERLIST-PARSE] Set default game server: %s:%d", g_gameServerIP, g_gameServerPort);
                        }
                    }
                }
                DLOG(@"[SERVERLIST-PARSE] Stored %d servers for rotation", g_serverCount);
            }
        } else {
            DLOG(@"[SERVERLIST-PARSE] Binary/mixed response, parsing...");
            DLOG(@"[SERVERLIST-PARSE] First 64 bytes hex:");
            for (int i = 0; i < MIN(64, len-12); i++) {
                printf("%02x ", data[12+i]);
                if ((i+1) % 16 == 0) printf("\n");
            }
            printf("\n");
            
            const unsigned char *body = data + 12;
            ssize_t bodyLen = len - 12;
            
            // v36.60: CLEAN REWRITE of binary parsing
            // BUG in v36.59: Raw 4-byte IP scan produced 100% false positives!
            //   e.g. bytes of ASCII strings ("47.100.14.198" encoded) got treated as binary IP
            //   resulting in garbage servers like "16.228.184.128:58764" being stored FIRST,
            //   crowding out the 12 real ASCII IPs that were found but never stored (MAX_SERVERS=20).
            // FIX:
            //   1. DISABLE raw 4-byte IP scan entirely.
            //   2. ONLY use ASCII IP pattern scan (we know it finds real IPs from the log).
            //   3. If we can't find a port near an ASCII IP, DEFAULT TO PORT 12003!
            //      (from previous tests v36.55 we know at least 12003 accepts connections and completes handshake,
            //       whereas 58158 hangs completely)
            
            g_serverCount = 0;
            NSMutableArray *foundServers = [NSMutableArray array];
            const int DEFAULT_GAME_PORT = 58158;  // v36.62: Force default port to 58158
            
            DLOG(@"[SERVERLIST-PARSE] (v36.62) Scanning ONLY for ASCII IP patterns, port FORCED to 58158");
            DLOG(@"[SERVERLIST-PARSE] (v36.62) Binary port parsing DISABLED (was causing 11776 misparse)");
            
            for (ssize_t offset = 0; offset < bodyLen - 7 && g_serverCount < MAX_SERVERS; offset++) {
                if (body[offset] >= '1' && body[offset] <= '9') {
                    char candidate[128];
                    ssize_t i = 0;
                    ssize_t start = offset;
                    while (offset < bodyLen && i < 63 &&
                           ((body[offset] >= '0' && body[offset] <= '9') || body[offset] == '.')) {
                        candidate[i++] = (char)body[offset++];
                    }
                    candidate[i] = '\0';
                    
                    int dots = 0;
                    int octets[4] = {0, 0, 0, 0};
                    int octIdx = 0;
                    int curVal = 0;
                    BOOL validFormat = YES;
                    for (ssize_t j = 0; candidate[j]; j++) {
                        if (candidate[j] == '.') {
                            if (j == 0 || candidate[j+1] == '.' || candidate[j+1] == '\0') { validFormat = NO; break; }
                            dots++;
                            if (curVal > 255) { validFormat = NO; break; }
                            octets[octIdx++] = curVal;
                            curVal = 0;
                        } else if (candidate[j] >= '0' && candidate[j] <= '9') {
                            curVal = curVal * 10 + (candidate[j] - '0');
                            if (curVal > 255) { validFormat = NO; break; }
                        } else {
                            validFormat = NO;
                            break;
                        }
                    }
                    if (octIdx < 3) validFormat = NO;  // need at least 3 dots (i.e. 4 octets)
                    if (validFormat && dots == 3) {
                        octets[3] = curVal;
                        if (octets[3] > 255) validFormat = NO;
                    }
                    if (octets[0] == 0 || octets[0] == 127 || octets[0] >= 224) validFormat = NO;
                    if (octets[3] == 0) validFormat = NO;
                    
                    if (dots == 3 && validFormat && i > 6) {
                        DLOG(@"[SERVERLIST-PARSE] Valid ASCII IP at %zd: '%s' (octets=%d.%d.%d.%d)",
                             start, candidate, octets[0], octets[1], octets[2], octets[3]);
                        
                        int assignedPort = DEFAULT_GAME_PORT;
                        BOOL portFound = NO;
                        
                        // Try to find ASCII port first - pattern after IP: "port":12003 or :12003
                        // Search up to 60 bytes after IP for the first : followed by digits
                        ssize_t maxSearch = (offset + 100 < bodyLen) ? (offset + 100) : bodyLen;
                        for (ssize_t pOffset = offset; pOffset < maxSearch - 6 && !portFound; pOffset++) {
                            // Try ASCII: :<number>
                            if (body[pOffset] == ':' && (body[pOffset+1] >= '1' && body[pOffset+1] <= '9')) {
                                ssize_t k = pOffset + 1;
                                int p = 0;
                                while (k < maxSearch && body[k] >= '0' && body[k] <= '9' && p < 65536) {
                                    p = p * 10 + (body[k] - '0');
                                    k++;
                                }
                                if (p >= 1024 && p < 65536) {
                                    assignedPort = p;
                                    portFound = YES;
                                    DLOG(@"[SERVERLIST-PARSE]   -> Found ASCII port %d at offset %zd", assignedPort, pOffset);
                                }
                            }
                            
                            // Also check for "port":<digits> pattern
                            if (pOffset + 7 < maxSearch &&
                                body[pOffset]=='p' && body[pOffset+1]=='o' && body[pOffset+2]=='r' &&
                                body[pOffset+3]=='t' && body[pOffset+5]=='\"' &&
                                body[pOffset+6] >= '1' && body[pOffset+6] <= '9') {
                                ssize_t k = pOffset + 6;
                                int p = 0;
                                while (k < maxSearch && body[k] >= '0' && body[k] <= '9' && p < 65536) {
                                    p = p * 10 + (body[k] - '0');
                                    k++;
                                }
                                if (p >= 1024 && p < 65536) {
                                    assignedPort = p;
                                    portFound = YES;
                                    DLOG(@"[SERVERLIST-PARSE]   -> Found port via \"port\" keyword: %d at offset %zd",
                                         assignedPort, pOffset);
                                }
                            }
                            
                        // v36.62: DISABLE binary port parsing - it was causing 11776 misparse
                        // (0x2E00 is the low byte of 0xE32E = 58158, not a real port)
                        // Always use DEFAULT_GAME_PORT (58158) instead of trying to parse binary ports
                        assignedPort = DEFAULT_GAME_PORT;
                        portFound = YES;  // Mark as found (using default)
                        DLOG(@"[SERVERLIST-PARSE]   -> Port forced to %d (binary parsing disabled to prevent 11776 misparse)", assignedPort);
                        }
                        
                        if (!portFound) {
                            DLOG(@"[SERVERLIST-PARSE]   -> No port found, using DEFAULT port %d",
                                 DEFAULT_GAME_PORT);
                        }
                        
                        // De-dupe and store
                        NSString *key = [NSString stringWithFormat:@"%s:%d", candidate, assignedPort];
                        BOOL duplicate = NO;
                        for (NSString *s in foundServers) {
                            if ([s isEqualToString:key]) { duplicate = YES; break; }
                        }
                        if (!duplicate && g_serverCount < MAX_SERVERS) {
                            [foundServers addObject:key];
                            strncpy(g_serverList[g_serverCount].ip, candidate, 63);
                            g_serverList[g_serverCount].port = assignedPort;
                            DLOG(@"[SERVERLIST-PARSE] STORED server %d: %s:%d (portSource=%@)",
                                 g_serverCount,
                                 g_serverList[g_serverCount].ip,
                                 g_serverList[g_serverCount].port,
                                 portFound ? @"detected" : @"DEFAULT");
                            
                            if (g_serverCount == 0) {
                                strncpy(g_gameServerIP, candidate, 63);
                                g_gameServerPort = assignedPort;
                                g_currentServerIndex = 0;
                                DLOG(@"[SERVERLIST-PARSE] Set DEFAULT game server: %s:%d",
                                     g_gameServerIP, g_gameServerPort);
                            }
                            g_serverCount++;
                        }
                    }
                }
            }
            
            if (g_serverCount > 0) {
                DLOG(@"[SERVERLIST-PARSE] Final: Stored %d servers for rotation", g_serverCount);
                for (int i = 0; i < g_serverCount; i++) {
                    DLOG(@"[SERVERLIST-PARSE]   [%d] %s:%d",
                         i, g_serverList[i].ip, g_serverList[i].port);
                }
            } else {
                DLOG(@"[SERVERLIST-PARSE] No servers found! (Game may still use its own internal parsing)");
                // v36.60: If even ASCII scan fails, at least populate with known-working defaults
                // so that the rotation mechanism has something to try (in case we're called for fallback)
                const char *defaultIP = "47.100.14.198";
                if (strlen(g_gameServerIP) < 7) {
                    strncpy(g_gameServerIP, defaultIP, 63);
                }
                if (g_gameServerPort < 1024) {
                    g_gameServerPort = DEFAULT_GAME_PORT;
                }
                strncpy(g_serverList[0].ip, g_gameServerIP, 63);
                g_serverList[0].port = g_gameServerPort;
                g_serverCount = 1;
                g_currentServerIndex = 0;
                DLOG(@"[SERVERLIST-PARSE] Populated fallback server %s:%d as last resort",
                     g_gameServerIP, g_gameServerPort);
            }
        }
    } @catch (NSException *e) {
        DLOG(@"[SERVERLIST-PARSE] Exception: %@", e.reason);
    }
}

// v36.62: Function to try next server in rotation (IP rotation, port always 58158)
static BOOL tryNextServer(void) {
    if (g_serverCount <= 1) {
        DLOG(@"[SERVER-ROTATE] Only %d server(s) available, cannot rotate", g_serverCount);
        return NO;
    }
    
    g_connectionFailCount++;
    g_currentServerIndex = (g_currentServerIndex + 1) % g_serverCount;
    
    // v36.63: Override port to 12003 (the only confirmed working port)
    strncpy(g_gameServerIP, g_serverList[g_currentServerIndex].ip, 63);
    g_gameServerPort = 12003;  // Always use 12003, the only confirmed working port
    
    DLOG(@"[SERVER-ROTATE] Switching to server %d/%d: %s:12003 (forced port, parsed was %d, fail count=%d)", 
         g_currentServerIndex + 1, g_serverCount, g_gameServerIP, g_serverList[g_currentServerIndex].port, g_connectionFailCount);
    
    // v36.98: Reset fake response state for new connection
    // This ensures the new connection can trigger fake response injection again
    g_fakeRespInjected = NO;
    g_fakeRespActive = NO;
    g_fakeRespDelivered = NO;
    g_fakeRespFd = -1;
    g_fakeRespSentCount = 0;
    g_lastRespCmd = 0;
    g_respCount = 0;
    resetCmdQueue();  // v36.106: Reset command queue for new connection
    g_loginPacketsSent = NO;
    g_handshakeComplete = NO;
    g_heartbeatCount = 0;
    g_lastGameCmd = 0;  // v36.107: Reset last game command
    g_lastSeqNum = 0;  // v36.107: Reset last sequence number
    g_lastGameCmdFd = -1;
    DLOG(@"[SERVER-ROTATE] v36.101: Reset fake response state for new connection");
    
    // Update stub data
    if (g_msiStubData) {
        [g_msiStubData setObject:[NSString stringWithUTF8String:g_gameServerIP] forKey:@"ip"];
        [g_msiStubData setObject:@(12003) forKey:@"port"];  // Force 12003 in stub too
    }
    
    return YES;
}

// v36.97: Hook getsockopt to prevent heartbeat from detecting dead connection
// When fake response fd is used, SO_ERROR should return 0 (no error)
static int hook_getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen) {
    if (!orig_getsockopt) orig_getsockopt = (GetsockoptFunc)dlsym(RTLD_NEXT, "getsockopt");
    
    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so SO_ERROR=0 is returned
    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).
    // If this is the fake response fd and checking SO_ERROR, return 0
    if (g_fakeRespFd == fd && level == SOL_SOCKET && optname == SO_ERROR) {
        if (optval && optlen && *optlen >= sizeof(int)) {
            *(int *)optval = 0;  // No error
            *optlen = sizeof(int);
            DLOG(@"[FAKE-SOCKOPT] v36.136: Returning SO_ERROR=0 for fake resp fd=%d (injected=%d)", fd, g_fakeRespInjected);
            return 0;
        }
    }
    
    return orig_getsockopt ? orig_getsockopt(fd, level, optname, optval, optlen) : -1;
}

// v36.104: Hook poll() to prevent heartbeat from detecting dead connection
// When server closes connection, poll() returns POLLHUP/POLLERR
// We clear these flags for the fake response fd to pretend connection is alive
static int hook_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (!orig_poll) orig_poll = (PollFunc)dlsym(RTLD_NEXT, "poll");
    if (!orig_poll || !fds) return -1;
    
    int result = orig_poll(fds, nfds, timeout);

    // v36.144: Post-BURST state machine — actively signal POLLIN so the
    // client calls recv() to receive RECV #20/#21. Without this, the
    // g_fakeRespDelivered check below clears POLLIN, and the client never
    // calls recv() again (stuck at "正在进入...").
    // v36.149: Reverted to >= 1 (continuous injection, no wait states).
    // Also set POLLIN when g_fakeRespActive and !g_fakeRespDelivered (post-BURST responses).
    if ((g_postBurstState >= 1 || (g_fakeRespActive && !g_fakeRespDelivered)) && g_postBurstFd >= 0) {
        for (nfds_t i = 0; i < nfds; i++) {
            if (fds[i].fd == g_postBurstFd) {
                fds[i].revents |= POLLIN;
                fds[i].revents &= ~(POLLHUP | POLLERR);
                if (result <= 0) result = 1;
                DLOG(@"[FAKE-POLL] v36.149: SET POLLIN for post-BURST fd=%d state=%d active=%d delivered=%d", fds[i].fd, g_postBurstState, g_fakeRespActive, g_fakeRespDelivered);
                break;
            }
        }
    }
    
    // v36.104: If fake response fd is in the poll set, clear error flags
    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so flags are cleared
    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).
    if (g_fakeRespFd >= 0 && result > 0) {
        for (nfds_t i = 0; i < nfds; i++) {
            if (fds[i].fd == g_fakeRespFd) {
                // Clear POLLHUP and POLLERR flags - pretend connection is alive
                if (fds[i].revents & (POLLHUP | POLLERR)) {
                    DLOG(@"[FAKE-POLL] v36.136: Clearing POLLHUP/POLLERR for fake resp fd=%d (was 0x%x injected=%d)", 
                         fds[i].fd, fds[i].revents, g_fakeRespInjected);
                    fds[i].revents &= ~(POLLHUP | POLLERR);
                    // If only error flags were set, set POLLIN instead so recv can return EAGAIN
                    if (fds[i].revents == 0) {
                        fds[i].revents = 0;  // No events - connection appears idle
                        result = 0;  // No events ready
                    }
                }
                // Clear POLLIN for fake response fd if response already delivered
                // v36.144: Skip this if post-BURST state machine is active (handled above)
                if (g_fakeRespDelivered && g_postBurstState < 1) {
                    fds[i].revents &= ~POLLIN;
                }
            }
        }
        // Recalculate result
        result = 0;
        for (nfds_t i = 0; i < nfds; i++) {
            if (fds[i].revents != 0) result++;
        }
    }
    
    return result;
}

// v36.104: Hook select() to prevent heartbeat from detecting dead connection
static int hook_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    if (!orig_select) orig_select = (SelectFunc)dlsym(RTLD_NEXT, "select");
    if (!orig_select) return -1;
    
    int result = orig_select(nfds, readfds, writefds, exceptfds, timeout);

    // v36.144: Post-BURST state machine — actively set readfds so the
    // client calls recv() to receive RECV #20/#21. Without this, the
    // g_fakeRespDelivered check below clears readfds, and the client
    // never calls recv() again (stuck at "正在进入...").
    // v36.149: Reverted to >= 1 (continuous injection, no wait states).
    // Also set readfds when g_fakeRespActive and !g_fakeRespDelivered (post-BURST responses).
    if ((g_postBurstState >= 1 || (g_fakeRespActive && !g_fakeRespDelivered)) && g_postBurstFd >= 0) {
        if (readfds && g_postBurstFd < nfds) {
            FD_SET(g_postBurstFd, readfds);
        }
        if (exceptfds && g_postBurstFd < nfds) {
            FD_CLR(g_postBurstFd, exceptfds);
        }
        if (result <= 0) result = 1;
        DLOG(@"[FAKE-SELECT] v36.149: SET readfds for post-BURST fd=%d state=%d active=%d delivered=%d", g_postBurstFd, g_postBurstState, g_fakeRespActive, g_fakeRespDelivered);
    }
    
    // v36.104: If fake response fd is in the except set, clear it
    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so exception is cleared
    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).
    if (g_fakeRespFd >= 0 && result >= 0) {
        if (exceptfds && FD_ISSET(g_fakeRespFd, exceptfds)) {
            DLOG(@"[FAKE-SELECT] v36.136: Clearing exception for fake resp fd=%d (injected=%d)", g_fakeRespFd, g_fakeRespInjected);
            FD_CLR(g_fakeRespFd, exceptfds);
            // Recalculate result
            result = 0;
            if (readfds) {
                for (int i = 0; i < nfds; i++) {
                    if (FD_ISSET(i, readfds)) result++;
                }
            }
            if (writefds) {
                for (int i = 0; i < nfds; i++) {
                    if (FD_ISSET(i, writefds)) result++;
                }
            }
        }
        // Also clear readfds for fake response fd if response already delivered
        // v36.144: Skip this if post-BURST state machine is active (handled above)
        if (readfds && g_fakeRespDelivered && g_postBurstState < 1 && FD_ISSET(g_fakeRespFd, readfds)) {
            FD_CLR(g_fakeRespFd, readfds);
        }
    }
    
    return result;
}

static int hook_close(int fd) {
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    
    // v36.97: Also block close for fake response fd
    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so close is blocked
    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).
    if (g_fakeRespFd == fd) {
        DLOG(@"[FAKE-CLOSE] v36.136: Blocking close(%d) for fake resp fd (injected=%d)", fd, g_fakeRespInjected);
        // v36.103: Use this opportunity to find and patch C++ disconnect functions
        // The backtrace from close() should include quitFromServer and heartbeat
        findAndPatchDisconnectFunctions();
        return 0;
    }
    
    // v37.16: DISABLED CLOSE-BLOCK — server already closed connection, blocking close() is useless.
    // User confirmed: "CLOSE-BLOCK 阻止了 close 调用，但连接已被服务器关闭，无济于事"
    if (0) {
    // v36.93: Track game server port closures and BLOCK them during login flow
    for (int i = 0; i < g_trackedCount; i++) {
        if (g_trackedFds[i] == fd && g_trackedActive[i]) {
            int port = g_trackedPorts[i];
            BOOL isGamePort = (port == 58158 || port == 12003 || 
                               (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
            if (isGamePort) {
                DLOG(@"[CLOSE-BLOCK] v36.93 BLOCKING close(%d) for game server %s:%d (port=%d)", fd, g_trackedHosts[i], port, port);
                
                // v36.93: Log call stack for debugging
                void *callstack[8];
                int frames = backtrace(callstack, 8);
                char **strs = backtrace_symbols(callstack, frames);
                if (strs) {
                    for (int j = 1; j < frames && j < 8; j++) {
                        DLOG(@"[CLOSE-BT] %d: %s", j, strs[j] ? strs[j] : "?");
                    }
                    free(strs);
                }
                
                // v36.93: BLOCK close() for game server fd during login handshake
                // This prevents quitFromServer() from disconnecting the game server
                // while client is still sending login packets (0x000EE007, 0x00FFF493)
                // Return 0 (success) to trick the client into thinking close succeeded
                DLOG(@"[CLOSE-BLOCK] v36.93: Returning 0 (blocked) to prevent game server disconnect");
                return 0;  // Block the close, return success
            }
        }
    }
    }  // end if(0) CLOSE-BLOCK disabled

    clearTrackedFd(fd);
    return orig_close ? orig_close(fd) : -1;
}

static int hook_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    char host[64] = "unknown";
    int port = 0;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
        port = ntohs(in->sin_port);
        
        // v36.63: REVERT to port 12003 (the only port confirmed to connect and complete handshake)
        // Port 58158 is unreachable - ALL tests since v36.51 showed timeout/hang
        // If game uses non-standard port (like 11776), rewrite to 12003
        BOOL isGameServerPort = (port == 12003 || port == 58158 || 
                                 (port >= 10000 && port <= 65535 && port != 5678));
        BOOL needPortRewrite = (port != 5678 && port != 12003);  // Rewrite any non-login, non-12003 port to 12003
        
        int origPort = port;
        char origHost[64];
        strncpy(origHost, host, 63);
        origHost[63] = '\0';
        
        struct sockaddr_in newAddr = *in;
        
        if (needPortRewrite && isGameServerPort) {
            // v36.63: Force rewrite non-standard game ports (like 11776) to 12003
            newAddr.sin_port = htons(12003);
            port = 12003;
            DLOG(@"[REWRITE-PORT] FORCE game server %s:%d -> %s:12003 (only confirmed working port)", 
                 origHost, origPort, origHost);
        }
        
        // v36.63: Track fd BEFORE connect with target port
        trackFd(sockfd, host, port);
        
        DLOG(@"[SOCK] connect START fd=%d target=%s:%d origPort=%d rewrite=%d isGamePort=%d",
             sockfd, host, port, origPort, needPortRewrite ? 1 : 0, isGameServerPort ? 1 : 0);
        
        if (!orig_connect) {
            DLOG(@"[SOCK] FATAL: orig_connect is NULL! dlsym failed.");
            errno = EACCES;
            return -1;
        }
        
        // v36.63: Set SO_SNDTIMEO 10s timeout as safety net for blocking connect
        // Prevents hanging forever on unreachable ports
        struct timeval tv;
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        // v36.63: SIMPLE blocking connect with timeout protection
        const struct sockaddr *actualAddr = needPortRewrite ? (struct sockaddr *)&newAddr : addr;
        socklen_t actualAddrLen = needPortRewrite ? sizeof(newAddr) : addrlen;
        
        struct timeval startTV;
        gettimeofday(&startTV, NULL);
        
        int result = orig_connect(sockfd, actualAddr, actualAddrLen);
        int connectErrno = errno;
        
        // v36.63: Clear the timeout after connect
        struct timeval tvZero;
        tvZero.tv_sec = 0;
        tvZero.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tvZero, sizeof(tvZero));
        
        struct timeval endTV;
        gettimeofday(&endTV, NULL);
        double elapsed = (endTV.tv_sec - startTV.tv_sec) + (endTV.tv_usec - startTV.tv_usec) / 1000000.0;
        
        if (result == 0) {
            // v36.63: Track game server connection state
            if (isGameServerPort) {
                g_gameServerConnected = YES;
                g_gameServerFd = sockfd;
                g_gameConnectTime = [[NSDate date] timeIntervalSince1970];
                DLOG(@"[GAME-CONNECT] Game server connected fd=%d target=%s:%d (confirmed working port)", 
                     sockfd, host, port);
                
                // v36.98: Reset fake response state on new game server connection
                // This ensures the new connection can trigger fake response injection
                if (g_fakeRespInjected || g_fakeRespActive) {
                    DLOG(@"[GAME-CONNECT] v36.101: Resetting fake response state on new connection (old fd=%d, new fd=%d)", g_fakeRespFd, sockfd);
                    g_fakeRespInjected = NO;
                    g_fakeRespActive = NO;
                    g_fakeRespDelivered = NO;  // v36.101: Reset delivered flag
                    g_fakeRespFd = -1;
                    g_fakeRespSentCount = 0;
                    g_loginPacketsSent = NO;
                    g_handshakeComplete = NO;
                    g_heartbeatCount = 0;
                    g_lastGameCmd = 0;
                    g_lastSeqNum = 0;  // v36.107: Reset sequence number on new connect
                    g_lastGameCmdFd = -1;
                }
            }
            DLOG(@"[SOCK] connect END fd=%d SUCCESS target=%s:%d origPort=%d elapsed=%.3fs",
                 sockfd, host, port, origPort, elapsed);
        } else {
            DLOG(@"[SOCK] connect END fd=%d FAILED target=%s:%d origPort=%d errno=%d(%s) elapsed=%.3fs",
                 sockfd, host, port, origPort, connectErrno, strerror(connectErrno), elapsed);
            
            // v36.63: Game server failed: try IP rotation (port stays 12003)
            if (isGameServerPort) {
                DLOG(@"[SOCK] Game server %s:%d FAILED -> attempting IP rotation...", host, port);
                @try {
                    BOOL rotated = tryNextServer();
                    if (rotated) {
                        DLOG(@"[SOCK] Rotation succeeded: %s:12003 (index %d/%d)",
                             g_gameServerIP, g_currentServerIndex + 1, g_serverCount);
                    } else {
                        DLOG(@"[SOCK] Rotation unavailable (servers=%d)", g_serverCount);
                    }
                } @catch (NSException *e) {
                    DLOG(@"[SOCK] Exception during rotation: %@", e.reason);
                }
            }
        }
        
        errno = connectErrno;
        return result;
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
        port = ntohs(in6->sin6_port);
        trackFd(sockfd, host, port);
        DLOG(@"[SOCK] connect6 START fd=%d [%s]:%d", sockfd, host, port);
        
        int result = orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
        DLOG(@"[SOCK] connect6 END fd=%d [%s]:%d result=%d errno=%d(%s)", sockfd, host, port, result, errno, strerror(errno));
        return result;
    }
    
    int result = orig_connect ? orig_connect(sockfd, addr, addrlen) : -1;
    return result;
}

static ssize_t hook_send(int fd, const void *buf, size_t len, int flags) {
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    
    // v36.123: If this is the fake response fd, pretend send succeeds
    // This prevents heartbeat from detecting the dead connection via send()
    // v36.123: Enqueue new commands AND reset delivered flag
    // v36.136: Check g_fakeRespFd (not g_fakeRespInjected) so send succeeds
    // even BEFORE fake response is injected (between RECV-CLOSE and BURST injection).
    if (g_fakeRespFd == fd) {
        // Check if this is a new command (not heartbeat)
        BOOL isNewCmd = NO;
        uint32_t newCmd = 0;
        uint32_t newSeq = 0;
        if (len >= 12) {
            const unsigned char *p = (const unsigned char *)buf;
            newCmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                           ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
            newSeq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                     ((uint32_t)p[10] << 8)  | (uint32_t)p[11];
            // Only reset for game commands, not heartbeat
            // v36.146: After post-BURST completion, don't reactivate fake
            // response system. Client's new 0x00FFF493 requests should be
            // FAKE-SEND'd without generating duplicate 0x0CB0A300 responses.
            // v36.150: Phase 2 in progress (g_postBurstState >= 3) must NOT
            // enqueue — otherwise duplicate 0x00FFF493 generates spurious
            // 0x0CB0A300/0x80FFF490 responses that corrupt the RECV #22-#24
            // injection sequence.
            // v36.154: REVERTED to contiguous injection. No request-driven
            // sub-states. Phase 2 trigger uses TIME-BASED delay (3 seconds
            // since Phase 1 completion) instead of count threshold.
            // This fixes v36.152 (auto-load ACKs triggered Phase 2 too
            // early, before role UI rendered) and v36.153 (state=10
            // busy-wait caused "连接异常中断").
            if (newCmd != 0x00000015 && newCmd < 0x80000000 && !g_postBurstDone && g_postBurstState < 3) {
                isNewCmd = YES;
                DLOG(@"[FAKE-SEND] v36.123: New cmd=0x%08X seq=0x%08X detected, enqueuing + resetting delivered flag", newCmd, newSeq);
            } else if (g_postBurstDone && newCmd != 0x00000015 && newCmd < 0x80000000) {
                // v36.154: Phase 2 trigger — TIME-BASED 3-second delay.
                // After Phase 1 completes (RECV#21 injected), the client
                // fires auto-load ACK 0x00FFF493 within ~100ms. These are
                // NOT user clicks. Only after 3 seconds can a 0x00FFF493
                // trigger Phase 2 (RECV #22-#24), ensuring the user has
                // time to see and click the role UI.
                double elapsed = g_phase1DoneTime > 0 ?
                    (CFAbsoluteTimeGetCurrent() - g_phase1DoneTime) : 999.0;
                if (elapsed < 3.0) {
                    DLOG(@"[FAKE-SEND] v36.155: Phase 2 LOCKED (%.1fs < 3.0s) cmd=0x%08X seq=0x%08X — EAGAIN (role UI rendering)", elapsed, newCmd, newSeq);
                } else {
                    g_phase2TriggerCount++;
                    if (g_phase2TriggerCount == 1) {
                        g_postBurstDone = NO;
                        g_postBurstState = 3;  // Start Phase 2: inject RECV #22
                        DLOG(@"[POST-BURST] v36.155: Phase 2 TRIGGERED (%.1fs elapsed) by cmd=0x%08X seq=0x%08X state=3", elapsed, newCmd, newSeq);
                    } else {
                        DLOG(@"[FAKE-SEND] v36.155: Phase 2 POST (count=%d) cmd=0x%08X — EAGAIN", g_phase2TriggerCount, newCmd);
                    }
                }
            } else if (!g_postBurstDone && g_postBurstState >= 3 && newCmd != 0x00000015 && newCmd < 0x80000000) {
                // v36.150: Phase 2 in progress — don't enqueue, don't generate
                // responses. RECV #22-#24 are driven by g_postBurstState.
                DLOG(@"[FAKE-SEND] v36.150: Phase 2 IN PROGRESS, cmd=0x%08X seq=0x%08X send-only (state=%d)", newCmd, newSeq, g_postBurstState);
            }
        }
        if (isNewCmd) {
            g_fakeRespDelivered = NO;
            // v36.123: Enqueue the new command so the hook can generate a response for it
            enqueueGameCmd(newCmd, fd, (uint32_t)len, newSeq);
            g_lastGameCmd = newCmd;
            g_lastSeqNum = newSeq;
        } else {
            DLOG(@"[FAKE-SEND] v36.123: Simulating send success for fd=%d len=%zu (heartbeat/ack, keep delivered)", fd, len);
        }
        return (ssize_t)len;
    }
    
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);

    // v37.42: Replace 0x0002A018 and 0x000EE006 with clean client's versions.
    // 0x0002A018 has MD5 hash at end — can't patch fields without recomputing hash.
    // Full packet replacement (like EE121-REPL) is the only safe option.
    // 0x000EE006 has UUID — same-length replacement, no hash.
    if (port == 5678 && len >= 12) {
        const unsigned char *p = (const unsigned char *)buf;
        uint32_t eeCmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                         ((uint32_t)p[6] << 8) | (uint32_t)p[7];
        uint32_t origSeq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                           ((uint32_t)p[10] << 8) | (uint32_t)p[11];

        if (eeCmd == 0x0002A018 && len >= 100) {
            // Clean client's 0x0002A018 (223B) from hook.txt SEND #5
            // All fields correct: deviceId=656578810453350151551, channel=DYanyou0040_MIESHI,
            // model=iPhone7Plus, GPU=A10, UUID=66B0EE01-..., hash=82412726869f0fb24d24717c47566d63
            static const uint8_t cleanA018[223] = {
                0x00,0x00,0x00,0xDF, 0x00,0x02,0xA0,0x18, 0x00,0x00,0x00,0x03,
                0x00,0x14, 0x36,0x35,0x36,0x35,0x37,0x38,0x38,0x31,0x30,0x34,0x35,0x33,0x33,0x35,0x30,0x31,0x35,0x31,0x35,0x31,
                0x00,0x12, 0x44,0x59,0x61,0x6E,0x79,0x6F,0x75,0x30,0x30,0x34,0x30,0x5F,0x4D,0x49,0x45,0x53,0x48,0x49,
                0x00,0x03, 0x49,0x4F,0x53,
                0x00,0x07, 0x70,0x6E,0x67,0x5F,0x72,0x65,0x73,
                0x00,0x18, 0x41,0x70,0x70,0x6C,0x65,0x20,0x49,0x6E,0x63,0x2E,0x20,0x41,0x70,0x70,0x6C,0x65,0x20,0x41,0x31,0x30,0x20,0x47,0x50,0x55,
                0x00,0x0B, 0x69,0x50,0x68,0x6F,0x6E,0x65,0x37,0x50,0x6C,0x75,0x73,
                0x00,0x34, 0x55,0x55,0x49,0x44,0x3D,0x4D,0x41,0x43,0x41,0x44,0x44,0x52,0x45,0x53,0x53,0x3D,0x36,0x36,0x42,0x30,0x45,0x45,0x30,0x31,0x2D,0x35,0x44,0x32,0x42,0x2D,0x34,0x45,0x41,0x45,0x2D,0x42,0x46,0x42,0x33,0x2D,0x45,0x43,0x41,0x39,0x43,0x41,0x42,0x46,0x31,0x36,0x46,0x38,
                0x00,0x05, 0x37,0x2E,0x36,0x2E,0x33,
                0x00,0x03, 0x39,0x37,0x39,
                0x00,0x04, 0x57,0x49,0x46,0x49,
                0x00,0x04, 0x46,0x55,0x4C,0x4C,
                0x00,0x00,
                0x00,0x00,
                0x00,0x20, 0x38,0x32,0x34,0x31,0x32,0x37,0x32,0x36,0x38,0x36,0x39,0x66,0x30,0x66,0x62,0x32,0x34,0x64,0x32,0x34,0x37,0x31,0x37,0x63,0x34,0x37,0x35,0x36,0x36,0x64,0x36,0x33,
            };
            unsigned char *newBuf = (unsigned char *)malloc(223);
            if (newBuf) {
                memcpy(newBuf, cleanA018, 223);
                newBuf[8] = (origSeq >> 24) & 0xFF;
                newBuf[9] = (origSeq >> 16) & 0xFF;
                newBuf[10] = (origSeq >> 8) & 0xFF;
                newBuf[11] = origSeq & 0xFF;
                DLOG(@"[A018-REPL] v37.42: Replaced 0x0002A018 with clean 223B pkt, seq=%u (origLen=%zu)", origSeq, len);
                ssize_t rret = orig_send(fd, newBuf, 223, flags);
                free(newBuf);
                if (rret >= 0) return (ssize_t)len;
                return rret;
            }
        }

        if (eeCmd == 0x000EE006 && len == 56) {
            // Replace UUID in 0x000EE006 (same length, no hash)
            // Our UUID: 180C4F27-4414-4623-ACEB-0C12B30E48FD
            // Clean UUID: 66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8
            unsigned char *newBuf = (unsigned char *)malloc(56);
            if (newBuf) {
                memcpy(newBuf, p, 56);
                // UUID starts at offset 20 (after 12B header + 6B zeros + 2B len)
                static const char cleanUUID[] = "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8";
                memcpy(newBuf + 20, cleanUUID, 36);
                DLOG(@"[EE006-UUID] v37.42: Replaced UUID in 0x000EE006");
                ssize_t rret = orig_send(fd, newBuf, 56, flags);
                free(newBuf);
                if (rret >= 0) return (ssize_t)len;
                return rret;
            }
        }
    }

    // v37.40: Generic TLV scanner for ALL port 5678 packets.
    // Server sees DY_MIESHI in pre-login packets (0x0000E002, 0x002EE118,
    // 0x0002A018 etc.) and flags client as invalid BEFORE 0x002EE121.
    // Must fix ALL packets, not just EE007/EE121.
    // Scans for TLV patterns: [2B len][string] and replaces channel/model/GPU.
    if (port == 5678 && len >= 20 && len <= 4096) {
        const unsigned char *p = (const unsigned char *)buf;
        // v37.41: Only patch 0x0000E002 and 0x002EE118 (simple packets, no hash).
        // Skip 0x002EE121 (handled by EE121-REPL) and 0x0002A018 (has MD5 hash
        // at end that we can't recompute — patching channel/model/GPU without
        // updating hash causes server to detect tampering).
        uint32_t tlvCmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                          ((uint32_t)p[6] << 8) | (uint32_t)p[7];
        if ((tlvCmd == 0x0000E002 || tlvCmd == 0x002EE118) &&
            memmem(p, len, "DY_MIESHI", 9) != NULL) {
            // Reconstruct packet with TLV field replacements
            size_t bufCap = len + 64;
            unsigned char *newBuf = (unsigned char *)malloc(bufCap);
            if (newBuf) {
                // Copy header (first 12 bytes: pktLen+cmd+seq)
                size_t hdrLen = (len >= 12) ? 12 : len;
                memcpy(newBuf, p, hdrLen);
                size_t out = hdrLen;
                size_t in = hdrLen;
                uint32_t fieldsApplied = 0;
                while (in + 2 < len) {
                    uint16_t fLen = ((uint16_t)p[in] << 8) | p[in + 1];
                    if (in + 2 + fLen > len) {
                        // Can't parse remaining as TLV — copy rest as-is
                        memcpy(newBuf + out, p + in, len - in);
                        out += len - in;
                        break;
                    }
                    const unsigned char *val = p + in + 2;
                    if (fLen == 9 && memcmp(val, "DY_MIESHI", 9) == 0) {
                        newBuf[out] = 0x00; newBuf[out+1] = 0x12;
                        memcpy(newBuf + out + 2, "DYanyou0040_MIESHI", 18);
                        out += 20; in += 11; fieldsApplied |= 1;
                    } else if (fLen == 17 && memcmp(val, "iPhone 16 Pro Max", 17) == 0) {
                        newBuf[out] = 0x00; newBuf[out+1] = 0x0B;
                        memcpy(newBuf + out + 2, "iPhone7Plus", 11);
                        out += 13; in += 19; fieldsApplied |= 2;
                    } else if (fLen == 28 && memcmp(val, "Apple Inc. Apple A18 Pro GPU", 28) == 0) {
                        newBuf[out] = 0x00; newBuf[out+1] = 0x18;
                        memcpy(newBuf + out + 2, "Apple Inc. Apple A10 GPU", 24);
                        out += 26; in += 30; fieldsApplied |= 4;
                    } else {
                        memcpy(newBuf + out, p + in, 2 + fLen);
                        out += 2 + fLen; in += 2 + fLen;
                    }
                }
                if (fieldsApplied > 0) {
                    // Update total packet length (first 4 bytes BE)
                    uint32_t newPktLen = (uint32_t)out;
                    newBuf[0] = (newPktLen >> 24) & 0xFF;
                    newBuf[1] = (newPktLen >> 16) & 0xFF;
                    newBuf[2] = (newPktLen >> 8) & 0xFF;
                    newBuf[3] = newPktLen & 0xFF;
                    DLOG(@"[TLV-SCAN] v37.40: Patched port=5678 pkt origLen=%zu newLen=%zu fields=%u (ch=%u dm=%u gp=%u)",
                         len, out, fieldsApplied,
                         (fieldsApplied&1)!=0, (fieldsApplied&2)!=0, (fieldsApplied&4)!=0);
                    ssize_t rret = orig_send(fd, newBuf, out, flags);
                    free(newBuf);
                    if (rret >= 0) return (ssize_t)len;
                    return rret;
                }
                free(newBuf);
                // Fall through if no fields applied
            }
        }
    }

    // v37.27: Dump EE007 ORIGINAL hex (before CHANNEL-PATCH) for byte-level
    // comparison with clean client (hook.txt SEND #28: 178B).
    // Clean EE007 structure: pktLen(4) cmd(4) seq(4) [len(2) value(N)]×11 null(1) trailer(2)
    // Clean total=178B, ours=179B → 10B difference in non-channel fields.
    if (len >= 8) {
        const unsigned char *pp = (const unsigned char *)buf;
        uint32_t diagCmd = ((uint32_t)pp[4] << 24) | ((uint32_t)pp[5] << 16) |
                           ((uint32_t)pp[6] << 8)  | (uint32_t)pp[7];
        if (diagCmd == 0x000EE007 || diagCmd == 0x002EE121) {
            NSMutableString *ehex = [NSMutableString stringWithCapacity:len * 3];
            for (size_t i = 0; i < len; i++) {
                [ehex appendFormat:@"%02X ", pp[i]];
                if ((i + 1) % 32 == 0 && i + 1 < len) [ehex appendString:@"\n    "];
            }
            DLOG(@"[EE007-ORIG] v37.27 port=%d len=%zu ORIGINAL HEX (pre-patch):\n    %@", port, len, ehex);
        }
    }

    // v37.30-DIST: EE007 FIELD-ALIGNED reconstruction.
    //
    // Byte-level analysis (EE007-ORIG 179B vs clean 178B):
    //   FIELD         | CLEAN (178B)            | OURS (179B)               | DIFF
    //   deviceId(20)  | 00 14 "6565788104..."    | 00 14 "049576366..."       | 0
    //   channel       | 00 12 "DYanyou0040_M..."  | 00 09 "DY_MIESHI"          | -9B
    //   deviceModel   | 00 0B "iPhone7Plus"(11)  | 00 11 "iPhone 16 Pro Max"(17) | +6B
    //   GPU           | 00 18 "Apple A10 GPU"(24)| 00 1C "Apple A18 Pro GPU"(28) | +4B
    //   NET SUM       |                         |                            | +1B → 179 vs 178
    //
    // After channel replacement (+9B), our EE007 becomes 188B, but clean should be
    // 178B +9B channel extra? NO. Clean EE007 is 178B with DYanyou0040 (18B).
    // Our raw EE007 is 179B with DY_MIESHI (9B). So after channel fix we should
    // end at 179 + 9 = 188B. But clean is 178B at construction (DYanyou0040 18B).
    // So we must also SHRINK deviceModel (00 11→00 0B, "iPhone 16 Pro Max"→"iPhone7Plus")
    // and shrink GPU (00 1C→00 18, "Apple A18 Pro GPU"→"Apple A10 GPU").
    // Net changes: +9(channel) -6(model) -4(GPU) = -1B.  Starting 179B → 178B.
    if (len >= 12) {
        const unsigned char *p = (const unsigned char *)buf;
        uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                       ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        if ((cmd == 0x000EE007 || cmd == 0x002EE121) && len >= 100) {
            // v37.56: RESTORE v37.51 behavior — send clean 248B packet (seq-only replacement).
            //
            // v37.54/v37.55 sent native EE121 → server CLOSED connection (hash1/hash3
            // verifiable but WRONG due to modified binary). CC_MD5 hook only fixes hash2,
            // NOT hash1/hash3 (different algorithm based on modified binary content).
            //
            // v37.51-v37.53 behavior: send clean 248B (hash1/hash3 from DIFFERENT session)
            // → server can't verify → status=4 ACCEPT → login works but NO real sessionId/ticket.
            // v37.56 improvement: FFF493-REPL now ONLY replaces sessionId+ticket (NOT clientId/
            // MACADDRESS/md5 — those stay native to match current session).
            if (cmd == 0x002EE121) {
                // Dump original packet tail for debugging
                if (len >= 80) {
                    NSMutableString *tailHex = [NSMutableString string];
                    for (size_t i = len - 80; i < len; i++) [tailHex appendFormat:@"%02X ", p[i]];
                    DLOG(@"[EE121-ORIG] v37.56: origLen=%zu tail80B: %@", len, tailHex);
                }

                // v37.56: Send clean 248B packet (seq-only replacement, v37.51 behavior).
                uint32_t origSeq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                static const uint8_t cleanPkt[248] = {
                    0x00,0x00,0x00,0xF8, 0x00,0x2E,0xE1,0x21, 0x00,0x00,0x00,0x10,
                    0x00,0x14, 0x36,0x35,0x36,0x35,0x37,0x38,0x38,0x31,0x30,0x34,0x35,0x33,0x33,0x35,0x30,0x31,0x35,0x31,0x35,0x31,
                    0x00,0x05, 0x6B,0x6B,0x39,0x39,0x34,
                    0x00,0x06, 0x39,0x39,0x34,0x36,0x32,0x34,
                    0x00,0x05, 0x53,0x51,0x41,0x47,0x45,
                    0x00,0x03, 0x49,0x4F,0x53,
                    0x00,0x12, 0x44,0x59,0x61,0x6E,0x79,0x6F,0x75,0x30,0x30,0x34,0x30,0x5F,0x4D,0x49,0x45,0x53,0x48,0x49,
                    0x00,0x00,
                    0x00,0x0B, 0x69,0x50,0x68,0x6F,0x6E,0x65,0x37,0x50,0x6C,0x75,0x73,
                    0x00,0x18, 0x41,0x70,0x70,0x6C,0x65,0x20,0x49,0x6E,0x63,0x2E,0x20,0x41,0x70,0x70,0x6C,0x65,0x20,0x41,0x31,0x30,0x20,0x47,0x50,0x55,
                    0x00,0x24, 0x36,0x36,0x42,0x30,0x45,0x45,0x30,0x31,0x2D,0x35,0x44,0x32,0x42,0x2D,0x34,0x45,0x41,0x45,0x2D,0x42,0x46,0x42,0x33,0x2D,0x45,0x43,0x41,0x39,0x43,0x41,0x42,0x46,0x31,0x36,0x46,0x38,
                    0x00,0x04, 0x57,0x49,0x46,0x49,
                    0x00,0x05, 0x37,0x2E,0x36,0x2E,0x33,
                    0x00,0x03, 0x39,0x37,0x39,
                    0x00,0x10, 0x33,0x64,0x64,0x38,0x31,0x39,0x36,0x66,0x36,0x34,0x33,0x35,0x30,0x61,0x63,0x62,
                    0x00,0x20, 0x64,0x64,0x63,0x62,0x39,0x31,0x66,0x34,0x32,0x63,0x35,0x61,0x36,0x31,0x32,0x62,0x34,0x39,0x32,0x61,0x32,0x32,0x39,0x36,0x61,0x39,0x37,0x31,0x61,0x35,0x61,0x66,
                    0x00,0x10, 0x37,0x38,0x30,0x61,0x30,0x36,0x34,0x32,0x36,0x31,0x39,0x63,0x38,0x34,0x39,0x38,
                };
                unsigned char *fbBuf = (unsigned char *)malloc(248);
                if (fbBuf) {
                    memcpy(fbBuf, cleanPkt, 248);
                    // Replace seq (offset 8-11) ONLY — no accountId/UUID replacement (v37.51 behavior)
                    fbBuf[8] = (origSeq >> 24) & 0xFF;
                    fbBuf[9] = (origSeq >> 16) & 0xFF;
                    fbBuf[10] = (origSeq >> 8) & 0xFF;
                    fbBuf[11] = origSeq & 0xFF;
                    DLOG(@"[EE121-REPL] v37.56: Sending clean 248B pkt seq=%u (v37.51 behavior, hash1/3 unverifiable → status=4 ACCEPT)", origSeq);
                    ssize_t rret = orig_send(fd, fbBuf, 248, flags);
                    free(fbBuf);
                    if (rret >= 0) return (ssize_t)len;
                    return rret;
                }
                ssize_t ret = orig_send(fd, buf, len, flags);
                return ret;
            }
            // v37.38: Also patch 0x002EE121 login request — it sends DY_MIESHI
            // (short channel from resigning) + iPhone 16 Pro Max + A18 GPU.
            // Server rejects with "version too low" → no real accountId →
            // game server can't validate FFF493#2 → no response.
            // Locate each TLV field by scanning from offset 12 (after cmd+seq+pktLen)
            // EE007 header: pktLen(4) + cmd(4) + seq(4) = 12 bytes
            size_t off = 12;
            size_t chOff = (size_t)-1; // channel TLV
            size_t dmOff = (size_t)-1; // deviceModel TLV
            size_t gpOff = (size_t)-1; // GPU TLV
            while (off + 2 < len) {
                uint16_t fLen = ((uint16_t)p[off] << 8) | p[off + 1];
                if (off + 2 + fLen > len) break;
                const unsigned char *val = p + off + 2;
                // field detection by content match
                if (fLen == 9 && memcmp(val, "DY_MIESHI", 9) == 0) chOff = off;
                else if (fLen == 17 && memcmp(val, "iPhone 16 Pro Max", 17) == 0) dmOff = off;
                else if (fLen == 28 && memcmp(val, "Apple Inc. Apple A18 Pro GPU", 28) == 0) gpOff = off;
                // or fallback: if value contains known strings
                else if (chOff == (size_t)-1 && fLen >= 9 && memcmp(val, "DY_MIESHI", 9) == 0) chOff = off;
                else if (dmOff == (size_t)-1 && fLen >= 11 && (memmem(val, fLen, "iPhone", 6) != NULL)) dmOff = off;
                else if (gpOff == (size_t)-1 && fLen >= 24 && (memmem(val, fLen, "Apple", 5) != NULL && memmem(val, fLen, "GPU", 3) != NULL)) gpOff = off;
                off += 2 + fLen;
            }
            if (chOff != (size_t)-1 || dmOff != (size_t)-1 || gpOff != (size_t)-1) {
                // Reconstruct packet by replacing all 3 fields found
                // Use dynamic buffer, write from 0 sequentially
                size_t bufCap = len + 64;
                unsigned char *newBuf = (unsigned char *)malloc(bufCap);
                if (!newBuf) {
                    DLOG(@"[EE007-ALIGN] v37.30: malloc(%zu) FAILED, fallthrough", bufCap);
                } else {
                    memset(newBuf, 0, bufCap);
                    // Copy header (first 12 bytes: pktLen cmd seq)
                    memcpy(newBuf, p, 12);
                    size_t out = 12;
                    size_t in = 12;
                    uint32_t fieldsApplied = 0;
                    while (in + 2 < len) {
                        uint16_t fLen = ((uint16_t)p[in] << 8) | p[in + 1];
                        if (in + 2 + fLen > len) break;
                        if (in == chOff && fLen == 9) {
                            // replace channel: 00 12 + DYanyou0040_MIESHI
                            newBuf[out] = 0x00; newBuf[out + 1] = 0x12;
                            memcpy(newBuf + out + 2, "DYanyou0040_MIESHI", 18);
                            out += 20; in += 11; fieldsApplied |= 1;
                        } else if (in == dmOff) {
                            // replace deviceModel: 00 0B + iPhone7Plus (11 chars fixed canonical)
                            newBuf[out] = 0x00; newBuf[out + 1] = 0x0B;
                            memcpy(newBuf + out + 2, "iPhone7Plus", 11);
                            out += 13; in += 2 + fLen; fieldsApplied |= 2;
                        } else if (in == gpOff) {
                            // replace GPU: 00 18 + Apple Inc. Apple A10 GPU (24 chars)
                            newBuf[out] = 0x00; newBuf[out + 1] = 0x18;
                            memcpy(newBuf + out + 2, "Apple Inc. Apple A10 GPU", 24);
                            out += 26; in += 2 + fLen; fieldsApplied |= 4;
                        } else {
                            // unchanged field: copy as-is
                            memcpy(newBuf + out, p + in, 2 + fLen);
                            out += 2 + fLen; in  += 2 + fLen;
                        }
                    }
                    // Copy trailing bytes (null terminator + padding + trailer 01 00)
                    if (in < len) {
                        size_t tailC = len - in;
                        memcpy(newBuf + out, p + in, tailC);
                        out += tailC;
                    }
                    // Rewrite pktLen (4 bytes BE at [0])
                    uint32_t newPktLen = (uint32_t)out;
                    newBuf[0] = (newPktLen >> 24) & 0xFF;
                    newBuf[1] = (newPktLen >> 16) & 0xFF;
                    newBuf[2] = (newPktLen >> 8)  & 0xFF;
                    newBuf[3] =  newPktLen        & 0xFF;
                    uint32_t oldPktLen = 0;
                    if (len >= 4) oldPktLen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
                    DLOG(@"[EE007-ALIGN] v37.38 cmd=0x%08X port=%d origPktLen=%u newPktLen=%u fieldsMask=%u (ch=%u dm=%u gp=%u)",
                         cmd, port, oldPktLen, newPktLen, fieldsApplied,
                         (fieldsApplied & 1) != 0, (fieldsApplied & 2) != 0, (fieldsApplied & 4) != 0);
                    // Post-alignment hex dump for verification (first 100 bytes)
                    NSMutableString *ph = [NSMutableString stringWithCapacity:300];
                    for (size_t i = 0; i < out && i < 100; i++) [ph appendFormat:@"%02X ", newBuf[i]];
                    DLOG(@"[EE007-ALIGN] v37.30 POST first%zub: %@", out < 100 ? out : (size_t)100, ph);
                    ssize_t rret = orig_send(fd, newBuf, out, flags);
                    free(newBuf);
                    if (rret >= 0) return (ssize_t)len;
                    return rret;
                }
            }
        }
    }
    // NOTE: old CHANNEL-PATCH for DY_MIESHI only is now replaced by EE007-ALIGN above.

    // v37.26-DIST: For ALL game server packets, call orig_send directly — NO processing. L5 sendScan + L6 EE007 patch applied earlier.
    // Added verbose FULL hex dump for 0x000EE007 and 0x00FFF493 so we can do byte-by-byte
    // comparison against the clean (non-injected) client capture (hook.txt).
    if (len >= 8 && (port == 12003 || port == 58158 ||
                      (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024))) {
        const unsigned char *p = (const unsigned char *)buf;
        uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                       ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        // v37.19-DIST: Verbose hex for critical commands (EE007 device info, FFF493 role data)
        if (cmd == 0x000EE007 || cmd == 0x00FFF493) {
            NSMutableString *hex = [NSMutableString stringWithCapacity:len * 3];
            for (size_t i = 0; i < len; i++) {
                [hex appendFormat:@"%02X ", p[i]];
                if ((i + 1) % 32 == 0 && i + 1 < len) [hex appendString:@"\n    "];
            }
            DLOG(@"[GAME-SEND-HEX] cmd=0x%08X len=%zu port=%d FULL HEX:\n    %@", cmd, len, port, hex);
            // Also print tail so we can verify trailing bytes (01 00 vs 00 01 00 for EE007)
            if (len >= 8) {
                size_t tailStart = (len > 32) ? (len - 32) : 0;
                NSMutableString *tail = [NSMutableString string];
                for (size_t i = tailStart; i < len; i++) [tail appendFormat:@"%02X ", p[i]];
                DLOG(@"[GAME-SEND-TAIL] cmd=0x%08X len=%zu tail[%zu-%zu]: %@", cmd, len, tailStart, len-1, tail);
            }
        }
        // v37.44: FFF493-REPL v2 — Replace 5 fields in FFF493#2 with REAL clean client values.
        // v37.43 disabled FFF493-REPL entirely, but server rejected FFF493#2 because
        // sessionId="" and ticket="" (login server returned status=4, no 0x8234AB89).
        // v37.44 uses REAL values captured from clean client:
        //   sessionId: "zmURQCP7xCg4ejMcPEPj2rc61mFfb0Fh" (32B, from 0x8234AB89)
        //   ticket: "kk994|1785665252271|236923||SwnLPVw4w..." (366B, from 0x8234AB89)
        //   clientId: "65657881045335015151" (matches EE121-REPL clean packet)
        //   MACADDRESS: "66B0EE01-5D2B-4EAE-BFB3-ECA9CABF16F8" (matches EE006-UUID)
        //   md5: "bdf8dad65adff0f9fed3876640c9418d" (clean client binary hash)
        // Flow: take saved native plaintext → replace 5 fields → re-encrypt with saved
        // AES key+iv → Base64 → HMAC → build new packet (matches clean 1432B format).
        // v37.56: FFF493-REPL v2 RE-ENABLED with KEY CHANGE.
        // v37.44-v37.53 replaced 5 fields (sessionId+ticket+clientId+MACADDRESS+md5) → server
        // rejected FFF493#2 (only heartbeats). v37.56 ONLY replaces sessionId+ticket, keeps
        // clientId/MACADDRESS/md5 NATIVE (matches current session/binary).
        // If server only validates sessionId/ticket format (not cross-session validity) → works.
        if (cmd == 0x00FFF493 && len > 800 && g_aes_key_saved && g_fff493_2_native_plain && g_fff493_2_native_len > 500) {
            // Parse original packet to extract seqNum and algo
            if (len >= 20) {
                uint32_t origSeq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                                   ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                uint16_t origAlgo = ((uint16_t)p[14] << 8) | p[15];

                // Build new plaintext by replacing 5 fields in native plaintext
                // Use NSMutableString for easy replacement
                NSString *nativeStr = [[NSString alloc] initWithBytes:g_fff493_2_native_plain
                                                                length:g_fff493_2_native_len
                                                              encoding:NSUTF8StringEncoding];
                if (nativeStr) {
                    // v37.46: Use stringWithString: instead of mutableCopy to fix compile error
                    // (compiler inferred NSString instead of NSMutableString from mutableCopy)
                    NSMutableString *newStr = [NSMutableString stringWithString:nativeStr];

                    // 1. Replace sessionId: "" → "zmURQCP7xCg4ejMcPEPj2rc61mFfb0Fh"
                    [newStr replaceOccurrencesOfString:@"\"sessionId\": \"\""
                                            withString:@"\"sessionId\": \"zmURQCP7xCg4ejMcPEPj2rc61mFfb0Fh\""
                                               options:0 range:NSMakeRange(0, newStr.length)];

                    // v37.56: DO NOT replace clientId/MACADDRESS/md5! Keep them NATIVE.
                    // v37.44-v37.53 replaced all 5 fields → server rejected FFF493#2.
                    // v37.56 only replaces sessionId+ticket, keeps clientId/MACADDRESS/md5
                    // native (matches current session/binary). If server validates these
                    // fields against current session → should pass.

                    // 5. Replace ticket: "" → clean ticket (366B Base64 token from 0x8234AB89)
                    NSString *cleanTicket = @"kk994|1785665252271|236923||SwnLPVw4wqtqXUfBX0JETQlXLrNxbb0TElk1YQvRmrKTNJG1ImA5eVtTnqY06XALBsKbKtCRJ7iRMUJcE+yZkboYVJ55k35zIxDeoLGoe/4TAo6nQjRD5obTaa18ObMyJaz6R0TUg8Oz78N1me5vBrU9c6sImsqv1QZEebEgfZO7KY2OdU35OV8Vb6rXRBwl1f78jA1OnkTRmf7ZthPpP1q3V1Y8OnzHnbHwq/xnZP3KtEXej3RCQX6zjJf+G81+W2XSpzUPynQXQ/Q/u9qn2N/5/db/8uMz68q/giuSAb9ikNYno+NYXTgn4FLsUbV15NTU5YIVqo9He/pYQCQ==";
                    [newStr replaceOccurrencesOfString:@"\"ticket\": \"\""
                                            withString:[NSString stringWithFormat:@"\"ticket\": \"%@\"", cleanTicket]
                                               options:0 range:NSMakeRange(0, newStr.length)];

                    const char *newPlain = [newStr UTF8String];
                    size_t newPlainLen = strlen(newPlain);
                    DLOG(@"[FFF493-REPL] v37.44: Built new plaintext %zuB (native=%zuB, +sessionId+ticket)", newPlainLen, g_fff493_2_native_len);

                    // Encrypt new plaintext with saved AES key+iv
                    size_t cipherCap = ((newPlainLen + 1 + 15) / 16) * 16;
                    uint8_t *cipherBuf = (uint8_t *)malloc(cipherCap + 32);
                    size_t cipherOut = 0;
                    if (cipherBuf) {
                        int ccRet = orig_CCCrypt(0, g_saved_alg, g_saved_options,
                                                  g_saved_aes_key, g_saved_key_len, g_saved_aes_iv,
                                                  newPlain, newPlainLen,
                                                  cipherBuf, cipherCap + 32, &cipherOut);
                        if (ccRet == 0 && cipherOut > 0) {
                            // Base64 encode ciphertext
                            NSData *cipherData = [NSData dataWithBytes:cipherBuf length:cipherOut];
                            NSString *b64Str = [cipherData base64EncodedStringWithOptions:0];
                            const char *b64 = [b64Str UTF8String];
                            size_t b64Len = strlen(b64);

                            // Compute HMAC-SHA256(key=AES_key, msg=ciphertext) for aux_b64
                            uint8_t hmacOut[32] = {0};
                            CCHmac(kCCHmacAlgSHA256,
                                   g_saved_aes_key, g_saved_key_len,
                                   cipherBuf, cipherOut,
                                   hmacOut);
                            NSData *hmacData = [NSData dataWithBytes:hmacOut length:32];
                            NSString *hmacB64 = [hmacData base64EncodedStringWithOptions:0];
                            const char *hmacB64Bytes = [hmacB64 UTF8String];
                            size_t hmacB64Len = strlen(hmacB64Bytes);

                            // Build new packet:
                            // [4B total_len][4B cmd][4B seqNum][2B flags=0001][2B algo]
                            // [2B main_b64_len][main_b64][2B aux_b64_len][aux_b64]
                            size_t newPktLen = 16 + 2 + b64Len + 2 + hmacB64Len;
                            uint8_t *newPkt = (uint8_t *)malloc(newPktLen);
                            if (newPkt) {
                                // Header
                                newPkt[0] = (newPktLen >> 24) & 0xFF;
                                newPkt[1] = (newPktLen >> 16) & 0xFF;
                                newPkt[2] = (newPktLen >> 8) & 0xFF;
                                newPkt[3] = newPktLen & 0xFF;
                                memcpy(newPkt + 4, p + 4, 4); // cmd
                                newPkt[8] = (origSeq >> 24) & 0xFF; // seqNum
                                newPkt[9] = (origSeq >> 16) & 0xFF;
                                newPkt[10] = (origSeq >> 8) & 0xFF;
                                newPkt[11] = origSeq & 0xFF;
                                newPkt[12] = 0x00; newPkt[13] = 0x01; // flags
                                newPkt[14] = (origAlgo >> 8) & 0xFF; // algo
                                newPkt[15] = origAlgo & 0xFF;
                                // main_b64
                                newPkt[16] = (b64Len >> 8) & 0xFF;
                                newPkt[17] = b64Len & 0xFF;
                                memcpy(newPkt + 18, b64, b64Len);
                                // aux_b64 (HMAC)
                                size_t auxPos = 18 + b64Len;
                                newPkt[auxPos] = (hmacB64Len >> 8) & 0xFF;
                                newPkt[auxPos + 1] = hmacB64Len & 0xFF;
                                memcpy(newPkt + auxPos + 2, hmacB64Bytes, hmacB64Len);

                                // Send the new packet
                                ssize_t rret = orig_send(fd, newPkt, newPktLen, flags);
                                DLOG(@"[FFF493-REPL] v37.44: Replaced FFF493#2 origLen=%zu newLen=%zu plainLen=%zu cipherOut=%zu b64Len=%zu hmacLen=%zu seq=%u ret=%zd",
                                     len, newPktLen, newPlainLen, cipherOut, b64Len, hmacB64Len, origSeq, rret);
                                free(newPkt);
                                free(cipherBuf);
                                // Consume native plaintext (one-shot)
                                free(g_fff493_2_native_plain);
                                g_fff493_2_native_plain = NULL;
                                g_fff493_2_native_len = 0;
                                if (rret >= 0) return (ssize_t)len;
                                return rret;
                            }
                        } else {
                            DLOG(@"[FFF493-REPL] v37.44: CCCrypt FAILED ret=%d cipherOut=%zu", ccRet, cipherOut);
                        }
                        free(cipherBuf);
                    }
                }
            }
            // If replacement failed, fall through to normal send
            DLOG(@"[FFF493-REPL] v37.44: Replacement skipped, sending original packet");
        }
        // Direct orig_send for ALL game server commands — no processing at all
        ssize_t ret = orig_send(fd, buf, len, flags);
        DLOG(@"[SEND-DIRECT] v37.27: cmd=0x%08X len=%zu port=%d ret=%zd (ALL game server packets direct after CHANNEL-PATCH L5/L6)", cmd, len, port, ret);
        return ret;
    }

    void *sendBuf = (void *)buf;
    size_t sendLen = len;
    
    if (len >= 12) {
        const unsigned char *p = (const unsigned char *)buf;
        uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                       ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        // v36.61: Use dynamic game port detection (12003, 58158, or parsed port)
        BOOL isGameOrLoginPort = (port == 5678 || port == 12003 || port == 58158 || 
                                  (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
        if (isGameOrLoginPort) {
            const char *serverType;
            if (port == 5678) serverType = "LOGIN";
            else if (port == 58158) serverType = "GAME-58158";
            else if (port == 12003) serverType = "GAME-12003";
            else serverType = "GAME-DYNAMIC";
            DLOG(@"[SEND-CMD] fd=%d cmd=0x%08X len=%zu [%s port=%d]", fd, cmd, len, serverType, port);
        }
    }
    
    if (host && sendLen > 0) {
        const unsigned char *p = (const unsigned char *)sendBuf;
        NSMutableString *hex = [NSMutableString stringWithCapacity:sendLen * 3];
        NSMutableString *ascii = [NSMutableString stringWithCapacity:sendLen];
        size_t showLen = sendLen > 256 ? 256 : sendLen;
        for (size_t i = 0; i < showLen; i++) {
            [hex appendFormat:@"%02X ", p[i]];
            [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
        }
        DLOG(@"[SEND] fd=%d %s:%d len=%zu\n  hex: %@\n  txt: %@", fd, host, port, sendLen, hex, ascii);
        
        // v36.75: Log game server initial connection packets (before handshake)
        // These are packets sent right after connecting to game server
        BOOL isGamePort = (port == 12003 || port == 58158 ||
                          (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
        if (isGamePort && !g_handshakeComplete && len > 0 && len < 12) {
            DLOG(@"[GAME-INIT] Small packet to game server: len=%zu hex=%@ (may be handshake init)", len, hex);
        }
    }
    
    // Analyze device info packets (0x000EE007) - on login server (5678), game server (all ports)
    BOOL isGameOrLoginPort = (port == 5678 || port == 12003 || port == 58158 || 
                              (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
    if (len >= 12 && isGameOrLoginPort) {
        const unsigned char *dp = (const unsigned char *)buf;
        uint32_t cmd = ((uint32_t)dp[4] << 24) | ((uint32_t)dp[5] << 16) |
                       ((uint32_t)dp[6] << 8)  | (uint32_t)dp[7];
        if (cmd == 0x000EE007) {
            @try {
                // v36.61: Detailed device info packet logging
                DLOG(@"[DEVICE-INFO] ===== DEVICE INFO PACKET (0x000EE007) =====");
                DLOG(@"[DEVICE-INFO] len=%zu port=%d fd=%d gameConnected=%d", len, port, fd, g_gameServerConnected ? 1 : 0);
                
                // Hex dump - full packet
                NSMutableString *hex = [NSMutableString string];
                for (size_t i = 0; i < len && i < 128; i++) {
                    [hex appendFormat:@"%02X ", dp[i]];
                }
                if (len > 128) [hex appendFormat:@"...(truncated)"];
                DLOG(@"[DEVICE-INFO] HEX: %@", hex);
                
                // Parse header
                if (len >= 16) {
                    uint32_t pktLen = ((uint32_t)dp[0]<<24)|((uint32_t)dp[1]<<16)|((uint32_t)dp[2]<<8)|dp[3];
                    uint32_t pktCmd = ((uint32_t)dp[4]<<24)|((uint32_t)dp[5]<<16)|((uint32_t)dp[6]<<8)|dp[7];
                    uint8_t status = dp[12];
                    DLOG(@"[DEVICE-INFO] pktLen=%u cmd=0x%08X status=%u", pktLen, pktCmd, status);
                }
                
                // ASCII decode payload
                if (len > 12) {
                    NSString *payload = [[NSString alloc] initWithBytes:dp+12 length:MIN(len-12, 100) encoding:NSUTF8StringEncoding];
                    if (payload) {
                        DLOG(@"[DEVICE-INFO] payload (offset 12): '%@'", payload);
                    }
                }
                
                DLOG(@"[DEVICE-INFO] ===== END DEVICE INFO =====");
                
                // v37.16: DISABLED UUID-INJECT — was corrupting 0x000EE007 packet structure.
                // User confirmed: original 178-byte packet ends with 01 00, but UUID-injected
                // packet ends with 00 01 00 → server validation fails → connection closed.
                // Native encryption handles everything, no UUID injection needed.
                if (0 && len > 0 && len <= MAX_DEVICE_INFO_SIZE) {
                    memcpy(g_deviceInfoPacket, buf, len);
                    g_deviceInfoPacketLen = len;
                    g_deviceInfoCaptured = YES;
                    g_deviceInfoSentToGame = NO;  // Reset flag for new capture
                    g_deviceInfoEnhancedReady = NO;
                    DLOG(@"[DEVICE-INFO] CAPTURED %zd bytes for forced game server send", len);
                    
                    // v36.87: Immediately create enhanced version with UUID injected
                    // Login server (5678) sends 143-byte without UUID
                    // Game server (12003/58158) expects 179-byte with UUID
                    ssize_t enhancedLen = injectUUIDIntoDeviceInfo(
                        (const uint8_t *)buf, len,
                        g_deviceInfoEnhanced, MAX_DEVICE_INFO_SIZE
                    );
                    if (enhancedLen > 0) {
                        g_deviceInfoEnhancedLen = enhancedLen;
                        g_deviceInfoEnhancedReady = YES;
                        DLOG(@"[DEVICE-INFO] ENHANCED ready: %zd bytes (UUID injected)", enhancedLen);
                    } else {
                        // Fallback: use original if injection fails
                        DLOG(@"[DEVICE-INFO] ENHANCED FAILED, will use original %zd bytes", len);
                    }
                    
                    // v36.123: CRITICAL FIX - Apply UUID injection DIRECTLY to sendBuf/sendLen
                    // Previous bug: UUID was injected to global buffers but NOT applied to the
                    // actual send() call, so server received 179 bytes without UUID and rejected.
                    //
                    // v36.118 FIX: Only apply UUID injection to GAME SERVER (12003/58158), NOT login server (5678)!
                    // Root cause: Login server (5678) rejects UUID-injected 0x000EE007 (181 bytes),
                    //   causing "network interrupted" at login. Login server expects original 143 bytes.
                    //   Game server (12003) requires UUID-injected 181 bytes.
                    BOOL isGamePortForInject = (port == 12003 || port == 58158 ||
                                                (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
                    if (enhancedLen > 0 && isGamePortForInject) {
                        size_t newLen = (size_t)enhancedLen;
                        uint8_t *newBuf = (uint8_t *)malloc(newLen);
                        if (newBuf) {
                            memcpy(newBuf, g_deviceInfoEnhanced, newLen);
                            // Update sendBuf and sendLen BEFORE orig_send() is called
                            if (sendBuf != buf) free(sendBuf);
                            sendBuf = newBuf;
                            sendLen = newLen;
                            DLOG(@"[UUID-INJECT] v36.123: APPLIED to sendBuf (GAME port=%d): %zu -> %zu bytes (WILL be sent!)",
                                 port, len, newLen);
                            // v36.123: Immediately log corrected SEND-CMD with FINAL length
                            const char *host2 = getHostForFd(fd);
                            int port2 = getPortForFd(fd);
                            const char *serverType2 = "UNKNOWN";
                            if (port2 == 5678) serverType2 = "LOGIN";
                            else if (port2 == 58158) serverType2 = "GAME-58158";
                            else if (port2 == 12003) serverType2 = "GAME-12003";
                            else if (port2 >= 10000) serverType2 = "GAME-DYNAMIC";
                            DLOG(@"[SEND-CMD] fd=%d cmd=0x%08X len=%zu (CORRECTED after UUID inject) [%s port=%d]",
                                 fd, cmd, sendLen, serverType2, port2);
                            (void)host2;
                        }
                    } else if (enhancedLen > 0 && !isGamePortForInject) {
                        // v36.123: Login server - do NOT inject UUID, send original packet
                        // Enhanced buffer is still prepared for later game server use
                        DLOG(@"[UUID-INJECT] v36.123: SKIP inject for LOGIN port=%d (send original %zu bytes), enhanced buffer ready for game server",
                             port, len);
                    }
                }
            } @catch (NSException *e) {
                // Silently ignore any errors in packet analysis
                DLOG(@"[DEVICE-INFO] Analysis skipped due to exception: %@", e.reason);
            }
        }
        
        // v36.85: Only block heartbeats during initial handshake (BEFORE challenge response)
        // After challenge response (g_challengeResponded=YES), let heartbeats go to server
        // so we can intercept the server's heartbeat ACK and replace it with 0x80FFF495
        if (isGameOrLoginPort && (cmd == 0x00000015 || cmd == 0x00000014)) {
            BOOL isGamePortOnly = (port == 12003 || port == 58158 ||
                                   (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
            BOOL isGameCmdOnly = isGameCmd(cmd);
            
            // v36.85: Only block heartbeats BEFORE challenge response (NOT after)
            if ((isGamePortOnly || isGameCmdOnly) && !g_handshakeComplete && !g_challengeResponded) {
                @try {
                    uint8_t ackBuf[22];
                    memcpy(ackBuf, buf, 22);
                    ackBuf[4] = 0x80;  // Change command from 0x00000015 to 0x80000015
                    
                    if (g_localHeartbeatAckLen == 0 || g_localHeartbeatAckFd != fd) {
                        g_localHeartbeatAckLen = 22;
                        g_localHeartbeatAckFd = fd;
                        memcpy(g_localHeartbeatAckBuf, ackBuf, 22);
                        DLOG(@"[HEARTBEAT-BLOCK] Blocked heartbeat during handshake (cmd=0x%08X) to port=%d", cmd, port);
                    }
                } @catch (NSException *e) {
                    DLOG(@"[HEARTBEAT-BLOCK] Exception: %@", e.reason);
                }
                return len;
            }
        }
        
        // v36.74: Track client protocol behavior after handshake completion
        // Monitor what client sends in response to 0x00FFFF02 challenge
        if (g_handshakeComplete && isGameOrLoginPort && len >= 12) {
            @try {
                const unsigned char *tp = (const unsigned char *)buf;
                NSMutableString *protoTrace = [NSMutableString stringWithCapacity:256];
                uint32_t trackCmd = ((uint32_t)tp[4] << 24) | ((uint32_t)tp[5] << 16) |
                                   ((uint32_t)tp[6] << 8)  | (uint32_t)tp[7];
                uint32_t trackPktLen = ((uint32_t)tp[0] << 24) | ((uint32_t)tp[1] << 16) |
                                      ((uint32_t)tp[2] << 8)  | (uint32_t)tp[3];
                
                [protoTrace appendFormat:@"[PROTO-TRACE] Client send after handshake: cmd=0x%08X pktLen=%u port=%d\n", trackCmd, trackPktLen, port];
                
                // v36.95: Track login packets to game server for fake response injection
                // 0x000EE007 (device info) and 0x00FFF493 (encrypted login data) are the key login packets
                BOOL isGamePortOnly = (port == 12003 || port == 58158 ||
                                      (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
                if (isGamePortOnly && (trackCmd == 0x000EE007 || trackCmd == 0x00FFF493 || 
                                       trackCmd == 0x80EEE007 || trackCmd == 0x80F493)) {
                    if (!g_loginPacketsSent) {
                        g_loginPacketsSent = YES;
                        DLOG(@"[LOGIN-PACKETS] v36.95: Client sending login packets to game server (cmd=0x%08X port=%d) - FAKE-RESP armed", trackCmd, port);
                    }
                }
                
                // v36.107: Track game server commands in a QUEUE for ordered response with sequence numbers
                if (isGamePortOnly && trackCmd != 0 && trackCmd < 0x80000000) {
                    g_lastGameCmd = trackCmd;
                    g_lastGameCmdFd = fd;
                    // v36.107: Extract sequence number from packet (bytes 8-11)
                    uint32_t trackSeqNum = 0;
                    if (len >= 12) {
                        trackSeqNum = ((uint32_t)tp[8] << 24) | ((uint32_t)tp[9] << 16) |
                                      ((uint32_t)tp[10] << 8)  | (uint32_t)tp[11];
                    }
                    g_lastSeqNum = trackSeqNum;
                    // v36.116: Use actual sendLen (after UUID injection) instead of original len
                    // For 0x000EE007, sendBuf was replaced with enhanced 217 bytes (UUID injected)
                    uint32_t actualSendLen = (uint32_t)sendLen;
                    if (trackCmd == 0x000EE007 && actualSendLen == (uint32_t)len) {
                        // If injection was not applied but g_deviceInfoEnhancedReady exists, use that
                        if (g_deviceInfoEnhancedReady && g_deviceInfoEnhancedLen > 0) {
                            actualSendLen = (uint32_t)g_deviceInfoEnhancedLen;
                        }
                    }
                    // v36.107: Add to command queue with sequence number and actual send length
                    enqueueGameCmd(trackCmd, fd, actualSendLen, trackSeqNum);
                    DLOG(@"[CMD-TRACK] v36.123: Queued cmd=0x%08X seq=0x%08X fd=%d sendLen=%u (origLen=%zu queue=%d)", 
                         trackCmd, trackSeqNum, fd, actualSendLen, len, g_cmdQueueCount);
                    // v36.107: Clear delivered flag so next recv can return a response
                    g_fakeRespDelivered = NO;
                }
                
                // Categorize the command
                if (trackCmd == 0x80FFFF02) {
                    [protoTrace appendFormat:@"  [V36.74] Client sent 0x80FFFF02 - responding to 0x00FFFF02 challenge!\n"];
                } else if (trackCmd == 0x80FFFF01) {
                    [protoTrace appendFormat:@"  [V36.74] Client sent 0x80FFFF01 - responding to 0x00FFFF01 challenge\n"];
                } else if (trackCmd == 0x000EE007) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending 0x000EE007 device info (plaintext)!\n"];
                } else if (trackCmd == 0x80EEE007 || trackCmd == 0x80EE0007) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending encrypted device info!\n"];
                } else if (trackCmd == 0x00F493 || trackCmd == 0x80F493) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending encrypted game data\n"];
                } else if (trackCmd == 0x00000015) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending heartbeat (may be stuck)\n"];
                } else if (trackCmd >= 0x80000000) {
                    [protoTrace appendFormat:@"  [V36.74] Client sending server response (cmd=0x%08X)\n", trackCmd];
                } else {
                    [protoTrace appendFormat:@"  [V36.74] Unknown command (cmd=0x%08X) - tracing...\n", trackCmd];
                }
                
                // Hex dump first 32 bytes
                [protoTrace appendFormat:@"  HEX(32): "];
                for (size_t i = 0; i < MIN((size_t)32, len); i++) {
                    [protoTrace appendFormat:@"%02X ", tp[i]];
                }
                [protoTrace appendFormat:@"\n"];
                
                DLOG(@"%@", protoTrace);
            } @catch (NSException *e) {
                DLOG(@"[PROTO-TRACE] Exception: %@", e.reason);
            }
        }
    }
    
    // Analyze 0x0000F013 packet - select server / enter game
    if (len >= 12 && port == 5678) {
        const unsigned char *fp = (const unsigned char *)buf;
        uint32_t fcmd = ((uint32_t)fp[4] << 24) | ((uint32_t)fp[5] << 16) |
                        ((uint32_t)fp[6] << 8)  | (uint32_t)fp[7];
        if (fcmd == 0x0000F013) {
            @try {
                NSMutableString *detail = [NSMutableString stringWithCapacity:256];
                [detail appendFormat:@"[SERVER-SELECT] cmd=0x%08X len=%zu\n", fcmd, len];
                [detail appendFormat:@"  Full hex: "];
                for (size_t i = 0; i < len && i < 128; i++) {
                    [detail appendFormat:@"%02X ", fp[i]];
                }
                if (len > 128) [detail appendFormat:@"...\n"];
                else [detail appendFormat:@"\n"];
                
                if (len >= 12) {
                    uint32_t pktLen = ((uint32_t)fp[0] << 24) | ((uint32_t)fp[1] << 16) |
                                      ((uint32_t)fp[2] << 8)  | (uint32_t)fp[3];
                    uint32_t field1 = ((uint32_t)fp[8] << 24) | ((uint32_t)fp[9] << 16) |
                                      ((uint32_t)fp[10] << 8) | (uint32_t)fp[11];
                    [detail appendFormat:@"  Header: pktLen=%u field1=0x%08X\n", pktLen, field1];
                }
                
                // Parse TLV-style fields after header
                size_t offset = 12;
                int fieldIdx = 0;
                while (offset + 2 < len && fieldIdx < 10) {
                    uint16_t fieldLen = (fp[offset] << 8) | fp[offset + 1];
                    offset += 2;
                    if (offset + fieldLen > len) break;
                    
                    NSMutableString *fieldHex = [NSMutableString string];
                    for (uint16_t i = 0; i < fieldLen && i < 32; i++) {
                        [fieldHex appendFormat:@"%02X ", fp[offset + i]];
                    }
                    
                    NSString *fieldStr = [[NSString alloc] initWithBytes:fp+offset length:fieldLen encoding:NSUTF8StringEncoding];
                    if (fieldStr && fieldStr.length > 0 && fieldLen < 64) {
                        [detail appendFormat:@"  Field[%d] len=%u hex=[%@] str='%@'\n", fieldIdx, fieldLen, fieldHex, fieldStr];
                    } else {
                        [detail appendFormat:@"  Field[%d] len=%u hex=[%@]\n", fieldIdx, fieldLen, fieldHex];
                    }
                    offset += fieldLen;
                    fieldIdx++;
                }
                
                DLOG(@"%@", detail);
            } @catch (NSException *e) {
                DLOG(@"[SERVER-SELECT] Analysis exception: %@", e.reason);
            }
        }
    }

    // Analyze game server packets (58158 port)
    if (len >= 12 && port == 58158) {
        const unsigned char *gp = (const unsigned char *)buf;
        uint32_t gcmd = ((uint32_t)gp[4] << 24) | ((uint32_t)gp[5] << 16) |
                        ((uint32_t)gp[6] << 8)  | (uint32_t)gp[7];
        
        @try {
            // Log game data packets (0x00FFF493)
            if (gcmd == 0x00FFF493) {
                NSMutableString *detail = [NSMutableString stringWithCapacity:256];
                [detail appendFormat:@"[GAME-DATA] cmd=0x%08X len=%zu\n", gcmd, len];
                [detail appendFormat:@"  Full hex: "];
                size_t showLen = len > 64 ? 64 : len;
                for (size_t i = 0; i < showLen; i++) {
                    [detail appendFormat:@"%02X ", gp[i]];
                }
                if (len > 64) [detail appendFormat:@"...\n"];
                else [detail appendFormat:@"\n"];
                DLOG(@"%@", detail);
            }
            // Log heartbeat packets (0x00000015)
            else if (gcmd == 0x00000015) {
                NSMutableString *detail = [NSMutableString stringWithCapacity:128];
                [detail appendFormat:@"[GAME-HEARTBEAT] cmd=0x%08X len=%zu\n", gcmd, len];
                [detail appendFormat:@"  Full hex: "];
                for (size_t i = 0; i < len; i++) {
                    [detail appendFormat:@"%02X ", gp[i]];
                }
                [detail appendFormat:@"\n"];
                DLOG(@"%@", detail);
            }
            // Log server select packets (0x0000F013) on game server
            else if (gcmd == 0x0000F013) {
                NSMutableString *detail = [NSMutableString stringWithCapacity:256];
                [detail appendFormat:@"[GAME-SERVER-SELECT] cmd=0x%08X len=%zu\n", gcmd, len];
                [detail appendFormat:@"  Full hex: "];
                size_t showLen = len > 128 ? 128 : len;
                for (size_t i = 0; i < showLen; i++) {
                    [detail appendFormat:@"%02X ", gp[i]];
                }
                if (len > 128) [detail appendFormat:@"...\n"];
                else [detail appendFormat:@"\n"];
                DLOG(@"%@", detail);
            }
        } @catch (NSException *e) {
            DLOG(@"[GAME-ANALYZE] Exception: %@", e.reason);
        }
    }

    // v36.123: FINAL confirmation log right before calling orig_send()
    // This is THE authoritative log of what actually gets sent to the server
    if (sendLen >= 12 && sendBuf) {
        const unsigned char *fp = (const unsigned char *)sendBuf;
        uint32_t finalCmd = ((uint32_t)fp[4] << 24) | ((uint32_t)fp[5] << 16) |
                            ((uint32_t)fp[6] << 8)  | (uint32_t)fp[7];
        uint32_t finalPktLen = ((uint32_t)fp[0] << 24) | ((uint32_t)fp[1] << 16) |
                               ((uint32_t)fp[2] << 8)  | (uint32_t)fp[3];
        int finalPort = getPortForFd(fd);
        const char *finalType = "OTHER";
        if (finalPort == 5678) finalType = "LOGIN";
        else if (finalPort == 12003) finalType = "GAME-12003";
        else if (finalPort == 58158) finalType = "GAME-58158";
        else if (finalPort >= 10000) finalType = "GAME-DYN";
        
        // Only log critical commands (0x000EE007, 0x00FFF495, 0x00FFF493, 0x00FFF494) or GAME port
        BOOL isCritical = (finalCmd == 0x000EE007 || finalCmd == 0x00FFF495 ||
                          finalCmd == 0x00FFF493 || finalCmd == 0x00FFF494 ||
                          finalPktLen != sendLen);  // Also flag if pktLen header doesn't match send() len
        if (isCritical || (finalPort >= 10000 && finalCmd != 0x00000015)) {
            DLOG(@"[SEND-FINAL] v36.123: cmd=0x%08X pktLenHdr=%u send()=%zu fd=%d [%s port=%d] %@",
                 finalCmd, finalPktLen, sendLen, fd, finalType, finalPort,
                 (finalPktLen != sendLen) ? @"⚠️ HEADER MISMATCH!" : @"✅ OK");
        }
    }

    ssize_t ret = orig_send ? orig_send(fd, sendBuf, sendLen, flags) : -1;
    if (sendBuf != buf) free(sendBuf);
    return ret;
}

// v36.81: Manual Base64 decode function for reliable RSA public key extraction
// Standard Base64 alphabet
static const uint8_t g_base64DecodeTable[256] = {
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,63, // + /
    52,53,54,55,56,57,58,59,60,61,62,62,62,65,62,62, // 0-9 =
    62, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // A-O
    15,16,17,18,19,20,21,22,23,24,25,62,62,62,62,62, // P-Z
    62,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, // a-o
    41,42,43,44,45,46,47,48,49,50,51,62,62,62,62,62, // p-z
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,
    62,62,62,62,62,62,62,62,62,62,62,62,62,62,62,62
};

// v36.81: Manual Base64 decode with robust error handling
static int manualBase64Decode(const uint8_t *input, size_t inputLen, 
                               uint8_t *output, size_t outputBufSize, size_t *outputLen) {
    if (!input || !output || !outputLen || inputLen == 0) return -1;
    
    size_t inPos = 0;
    size_t outPos = 0;
    uint8_t group[4];
    int groupIdx = 0;
    
    // Clear output
    memset(output, 0, outputBufSize);
    
    while (inPos < inputLen) {
        uint8_t c = input[inPos];
        inPos++;
        
        // Skip whitespace and newlines
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        
        // Check for padding
        if (c == '=') {
            // Padding should only appear at the end
            if (groupIdx < 2) return -1; // Invalid padding position
            break;
        }
        
        uint8_t val = g_base64DecodeTable[c];
        if (val >= 64) {
            // Invalid character - skip it (could be protocol overhead)
            DLOG(@"[RSA-MANUAL-B64] Skipping invalid char at input pos %zu: 0x%02X", inPos-1, c);
            continue;
        }
        
        group[groupIdx++] = val;
        
        if (groupIdx == 4) {
            // Decode 4 Base64 chars to 3 bytes
            uint32_t triple = (group[0] << 18) | (group[1] << 12) | (group[2] << 6) | group[3];
            
            if (outPos + 3 > outputBufSize) return -1; // Output buffer too small
            
            output[outPos++] = (triple >> 16) & 0xFF;
            output[outPos++] = (triple >> 8) & 0xFF;
            output[outPos++] = triple & 0xFF;
            groupIdx = 0;
        }
    }
    
    // Handle remaining group (if any)
    if (groupIdx > 0) {
        if (groupIdx < 2) return -1; // Invalid: need at least 2 chars
        
        if (groupIdx == 2) {
            uint32_t triple = (group[0] << 18) | (group[1] << 12);
            if (outPos + 1 > outputBufSize) return -1;
            output[outPos++] = (triple >> 16) & 0xFF;
        } else if (groupIdx == 3) {
            uint32_t triple = (group[0] << 18) | (group[1] << 12) | (group[2] << 6);
            if (outPos + 2 > outputBufSize) return -1;
            output[outPos++] = (triple >> 16) & 0xFF;
            output[outPos++] = (triple >> 8) & 0xFF;
        }
    }
    
    *outputLen = outPos;
    return 0;
}

// v36.82: RSA encrypt challenge data using server's public key certificate
// Returns encrypted data length, or -1 on failure
static ssize_t rsaEncryptChallenge(const uint8_t *plainData, size_t plainLen,
                                    uint8_t *cipherBuf, size_t cipherBufSize) {
    if (!g_pubKeyCaptured || g_pubKeyBase64Len == 0) {
        DLOG(@"[RSA-ENCRYPT] No public key captured, cannot encrypt (captured=%d, len=%lu)", 
             g_pubKeyCaptured, (unsigned long)g_pubKeyBase64Len);
        return -1;
    }
    
    DLOG(@"[RSA-ENCRYPT] Starting encryption: pubKeyLen=%lu, plainLen=%zu", 
          (unsigned long)g_pubKeyBase64Len, plainLen);
    
    // Step 1: Manual Base64 decode (most reliable)
    uint8_t *derData = (uint8_t *)malloc(1024);
    if (!derData) {
        DLOG(@"[RSA-ENCRYPT] Failed to allocate DER buffer");
        return -1;
    }
    
    size_t derLen = 0;
    int decodeResult = manualBase64Decode((const uint8_t *)g_pubKeyBase64, 
                                           g_pubKeyBase64Len, 
                                           derData, 1024, &derLen);
    
    if (decodeResult != 0 || derLen == 0) {
        DLOG(@"[RSA-ENCRYPT] Manual Base64 decode failed (result=%d, derLen=%zu), trying NSData...", decodeResult, derLen);
        
        // Fallback: Try NSData Base64 decode
        @try {
            NSString *certStr = [[NSString alloc] initWithBytes:g_pubKeyBase64 
                                                        length:g_pubKeyBase64Len 
                                                      encoding:NSASCIIStringEncoding];
            if (certStr) {
                NSData *certDER = [[NSData alloc] initWithBase64EncodedString:certStr 
                                                                      options:NSDataBase64DecodingIgnoreUnknownCharacters];
                if (certDER && certDER.length > 0) {
                    derLen = certDER.length;
                    memcpy(derData, certDER.bytes, MIN(derLen, 1024));
                    DLOG(@"[RSA-ENCRYPT] NSData Base64 decode succeeded: %lu bytes", (unsigned long)derLen);
                } else {
                    DLOG(@"[RSA-ENCRYPT] NSData Base64 decode also failed");
                    free(derData);
                    return -1;
                }
            } else {
                DLOG(@"[RSA-ENCRYPT] Cannot create NSString from Base64 data");
                free(derData);
                return -1;
            }
        } @catch (NSException *e) {
            DLOG(@"[RSA-ENCRYPT] Exception in NSData decode: %@", e.reason);
            free(derData);
            return -1;
        }
    } else {
        DLOG(@"[RSA-ENCRYPT] Manual Base64 decode succeeded: %zu bytes", derLen);
    }
    
    // Log DER header for debugging
    if (derLen >= 8) {
        DLOG(@"[RSA-ENCRYPT] DER header: %02X %02X %02X %02X %02X %02X %02X %02X",
             derData[0], derData[1], derData[2], derData[3],
             derData[4], derData[5], derData[6], derData[7]);
    }
    
    // Step 2: Create SecKey from DER data
    SecKeyRef pubKeyRef = NULL;
    
    // Try as X.509 certificate first
    @try {
        CFDataRef certData = CFDataCreate(NULL, derData, derLen);
        SecCertificateRef certRef = SecCertificateCreateWithData(NULL, certData);
        CFRelease(certData);
        
        if (certRef) {
            DLOG(@"[RSA-ENCRYPT] Created SecCertificate from DER data");
            pubKeyRef = SecCertificateCopyKey(certRef);
            CFRelease(certRef);
            
            if (!pubKeyRef) {
                DLOG(@"[RSA-ENCRYPT] SecCertificateCopyKey failed, trying direct SecKey...");
            }
        } else {
            DLOG(@"[RSA-ENCRYPT] SecCertificateCreateWithData failed, trying direct SecKey...");
        }
    } @catch (NSException *e) {
        DLOG(@"[RSA-ENCRYPT] Exception creating certificate: %@", e.reason);
    }
    
    // Try as direct public key (not a certificate)
    if (!pubKeyRef) {
        @try {
            NSDictionary *keyAttrs = @{
                (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
                (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
                (__bridge id)kSecAttrKeySizeInBits: @2048
            };
            CFDataRef keyData = CFDataCreate(NULL, derData, derLen);
            pubKeyRef = SecKeyCreateWithData(keyData, (__bridge CFDictionaryRef)keyAttrs, NULL);
            CFRelease(keyData);
            
            if (pubKeyRef) {
                DLOG(@"[RSA-ENCRYPT] Created SecKey directly from DER data");
            } else {
                DLOG(@"[RSA-ENCRYPT] SecKeyCreateWithData also failed");
                free(derData);
                return -1;
            }
        } @catch (NSException *e) {
            DLOG(@"[RSA-ENCRYPT] Exception creating SecKey: %@", e.reason);
            free(derData);
            return -1;
        }
    }
    
    free(derData);
    DLOG(@"[RSA-ENCRYPT] Got public key reference, proceeding to encryption");
    
    // Step 3: Encrypt with RSA using SecKeyCreateEncryptedData
    // v36.86: Try PKCS1 first (most common for challenge-response), then OAEP, then Raw
    CFErrorRef encryptErr = NULL;
    SecKeyAlgorithm algo = kSecKeyAlgorithmRSAEncryptionPKCS1;
    
    // Check if the algorithm is supported
    if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {
        DLOG(@"[RSA-ENCRYPT] PKCS1 not supported, trying SHA256...");
        algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA256;
        if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {
            DLOG(@"[RSA-ENCRYPT] SHA256 not supported, trying SHA1...");
            algo = kSecKeyAlgorithmRSAEncryptionOAEPSHA1;
            if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {
                DLOG(@"[RSA-ENCRYPT] SHA1 not supported, trying Raw...");
                algo = kSecKeyAlgorithmRSAEncryptionRaw;
                if (!SecKeyIsAlgorithmSupported(pubKeyRef, kSecKeyOperationTypeEncrypt, algo)) {
                    DLOG(@"[RSA-ENCRYPT] No RSA encryption algorithm supported");
                    CFRelease(pubKeyRef);
                    return -1;
                }
            }
        }
    }
    
    DLOG(@"[RSA-ENCRYPT] Using encryption algorithm: %s",
          algo == kSecKeyAlgorithmRSAEncryptionPKCS1 ? "PKCS1" :
          algo == kSecKeyAlgorithmRSAEncryptionOAEPSHA256 ? "SHA256" :
          algo == kSecKeyAlgorithmRSAEncryptionOAEPSHA1 ? "SHA1" : "Raw");
    
    CFDataRef plainCFData = CFDataCreate(NULL, plainData, plainLen);
    CFErrorRef *encryptErrPtr = NULL;
    CFDataRef cipherCFData = SecKeyCreateEncryptedData(pubKeyRef, algo,
                                                       plainCFData, encryptErrPtr);
    CFRelease(plainCFData);
    CFRelease(pubKeyRef);
    
    if (cipherCFData) {
        size_t cipherLen = CFDataGetLength(cipherCFData);
        if (cipherLen <= cipherBufSize) {
            CFDataGetBytes(cipherCFData, CFRangeMake(0, cipherLen), cipherBuf);
            CFRelease(cipherCFData);
            DLOG(@"[RSA-ENCRYPT] SUCCESS: encrypted %lu bytes -> %lu bytes RSA cipher",
                 (unsigned long)plainLen, (unsigned long)cipherLen);
            return (ssize_t)cipherLen;
        }
        CFRelease(cipherCFData);
        DLOG(@"[RSA-ENCRYPT] Cipher buffer too small: need %lu, have %lu",
             (unsigned long)cipherLen, (unsigned long)cipherBufSize);
        return -1;
    } else {
        CFStringRef errStr = encryptErrPtr && *encryptErrPtr ? CFErrorCopyDescription(*encryptErrPtr) : NULL;
        DLOG(@"[RSA-ENCRYPT] SecKeyCreateEncryptedData failed: %@",
             errStr ? CFBridgingRelease(errStr) : @"unknown");
        if (encryptErrPtr && *encryptErrPtr) CFRelease(*encryptErrPtr);
        return -1;
    }
}

// v36.81: Auto-respond to 0x00FFFF02 challenge with RSA-encrypted 0x80FFFF02
// Returns YES if response was sent
static BOOL autoRespondToChallenge(int fd, const unsigned char *pktBuf, size_t pktLen,
                                    uint32_t cmd) {
    if (cmd != 0x00FFFF02 || pktLen < 12) return NO;
    if (g_challengeResponded && g_challengeFd == fd) {
        DLOG(@"[CHALLENGE-AUTO] Already responded to 0x00FFFF02 for fd=%d, skipping", fd);
        return NO;
    }
    if (!g_pubKeyCaptured) {
        DLOG(@"[CHALLENGE-AUTO] No public key available, cannot auto-respond (captured=%d)", g_pubKeyCaptured);
        return NO;
    }
    
    // Extract challenge payload (bytes[12..end])
    size_t payloadLen = pktLen - 12;
    const uint8_t *payloadData = pktBuf + 12;
    
    DLOG(@"[CHALLENGE-AUTO] Auto-responding to 0x00FFFF02: payload=%zu bytes, fd=%d", payloadLen, fd);
    
    // Encrypt the challenge data with RSA public key
    uint8_t encryptedData[256]; // RSA 2048-bit = 256 bytes max
    ssize_t encryptedLen = rsaEncryptChallenge(payloadData, payloadLen, encryptedData, sizeof(encryptedData));
    if (encryptedLen <= 0) {
        DLOG(@"[CHALLENGE-AUTO] RSA encryption failed, cannot auto-respond (encryptedLen=%zd)", encryptedLen);
        return NO;
    }
    
    // Construct 0x80FFFF02 response packet (with STATUS byte):
    // 4 bytes: total packet length (4 + 4 + 4 + 1 + encryptedLen)
    // 4 bytes: cmd = 0x80FFFF02
    // 4 bytes: seq (same as challenge, bytes[8-11])
    // 1 byte:  status = 0 (success)
    // encryptedLen bytes: encrypted challenge data
    uint32_t totalLen = (uint32_t)(4 + 4 + 4 + 1 + encryptedLen);
    uint8_t responseBuf[300]; // Max 4+4+4+1+256 = 269
    if (totalLen > sizeof(responseBuf)) {
        DLOG(@"[CHALLENGE-AUTO] Response too large: %u bytes", totalLen);
        return NO;
    }
    
    // Build packet with STATUS byte at offset 12
    responseBuf[0] = (totalLen >> 24) & 0xFF;
    responseBuf[1] = (totalLen >> 16) & 0xFF;
    responseBuf[2] = (totalLen >> 8) & 0xFF;
    responseBuf[3] = totalLen & 0xFF;
    
    responseBuf[4] = 0x80; responseBuf[5] = 0xFF; responseBuf[6] = 0xFF; responseBuf[7] = 0x02;
    
    // Copy seq from challenge (bytes[8-11])
    memcpy(responseBuf + 8, pktBuf + 8, 4);
    
    // STATUS byte = 0 (success)
    responseBuf[12] = 0x00;
    
    // Copy encrypted data starting at offset 13 (after STATUS)
    memcpy(responseBuf + 13, encryptedData, encryptedLen);
    
    // Send the response
    DLOG(@"[CHALLENGE-AUTO] Sending 0x80FFFF02 response: %u bytes to fd=%d (encrypted %zd bytes, WITH status byte)", totalLen, fd, encryptedLen);
    ssize_t sent = orig_send ? orig_send(fd, responseBuf, totalLen, 0) : -1;
    if (sent > 0) {
        g_challengeResponded = YES;
        g_challengeFd = fd;
        DLOG(@"[CHALLENGE-AUTO] SUCCESS: Sent 0x80FFFF02 response: %zd bytes (encrypted %zu -> %zd)",
             sent, payloadLen, encryptedLen);
        
        // Log response hex
        NSMutableString *hexStr = [NSMutableString stringWithString:@"[CHALLENGE-AUTO] Response HEX: "];
        for (uint32_t i = 0; i < totalLen && i < 64; i++) {
            [hexStr appendFormat:@"%02X ", responseBuf[i]];
        }
        if (totalLen > 64) [hexStr appendFormat:@"..."];
        DLOG(@"%@", hexStr);
        
        // v36.88: Construct 0x80FFF495 handshake complete PACKET (not fake 22-byte ACK)
        // Challenge response was sent. Server may not send 0x80FFF495, so client state
        // machine is stuck on heartbeats. We inject a REAL-SIZED 0x80FFF495 packet into recv.
        // Key: must be LARGE enough to avoid SIGSEGV in handle_CHOOSE_WOOD_BOX_RES handler,
        // which reads significant payload. We build ~200 byte packet with proper header + padding.
        {
            uint32_t hsPktSize = 200;  // Large enough to avoid out-of-bounds read
            if (hsPktSize > MAX_FORCE_HS_BUF) hsPktSize = MAX_FORCE_HS_BUF;
            
            memset(g_forceHandshakeBuf, 0, hsPktSize);
            
            // Byte[0-3]: Total packet length (big-endian)
            g_forceHandshakeBuf[0] = (hsPktSize >> 24) & 0xFF;
            g_forceHandshakeBuf[1] = (hsPktSize >> 16) & 0xFF;
            g_forceHandshakeBuf[2] = (hsPktSize >> 8) & 0xFF;
            g_forceHandshakeBuf[3] = hsPktSize & 0xFF;
            
            // Byte[4-7]: cmd = 0x80FFF495 (handshake complete, response to challenge)
            g_forceHandshakeBuf[4] = 0x80;
            g_forceHandshakeBuf[5] = 0xFF;
            g_forceHandshakeBuf[6] = 0xF4;
            g_forceHandshakeBuf[7] = 0x95;
            
            // Byte[8-11]: seq number, use same base as challenge response
            g_forceHandshakeBuf[8]  = responseBuf[8];
            g_forceHandshakeBuf[9]  = responseBuf[9];
            g_forceHandshakeBuf[10] = responseBuf[10];
            g_forceHandshakeBuf[11] = responseBuf[11];
            
            // Byte[12]: STATUS = 0 (SUCCESS)
            g_forceHandshakeBuf[12] = 0x00;
            
            // Byte[13]: format flags (copy from 0x80FFF494 style = 0x88)
            g_forceHandshakeBuf[13] = 0x88;
            
            // Byte[14...]: SAFETY PADDING - fill with recognizable Base64-like content
            // This prevents SIGSEGV when handler parses the payload.
            const char *padding = 
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzOJwUMBZ0a1FZkot1lJ"
                "+LB4rodylyGvUbq7sOO6nHgBqeqT2bp/mCShyDsVKdGGruFM8TY1cKlrHHhukEHV"
                "vr2+5zTL7Pg+ywmn+53vB4azfuaetHwVctLFmTyqrENWsTiL0uyl5w4k52TSvX7sC"
                "tuMx2grh6f1Hhb0/LqsFNjPobudwS00ypDtBG0Ung3T32DO2eFQ4JI0hXKkbCp0cyBT";
            size_t padLen = strlen(padding);
            size_t copyLen = padLen;
            if (copyLen > hsPktSize - 14) copyLen = hsPktSize - 14;
            memcpy(g_forceHandshakeBuf + 14, padding, copyLen);
            
            g_forceHandshakeLen = hsPktSize;
            g_forceHandshakeFd = fd;
            g_forceHandshakeComplete = YES;
            
            DLOG(@"[FORCE-HS-PREP] Prepared 0x80FFF495 packet size=%u bytes (fd=%d)",
                 hsPktSize, fd);
            DLOG(@"[FORCE-HS-PREP] Header: len=%u cmd=0x%02X%02X%02X%02X seq=0x%02X%02X%02X%02X status=%u",
                 hsPktSize,
                 g_forceHandshakeBuf[4], g_forceHandshakeBuf[5], g_forceHandshakeBuf[6], g_forceHandshakeBuf[7],
                 g_forceHandshakeBuf[8], g_forceHandshakeBuf[9], g_forceHandshakeBuf[10], g_forceHandshakeBuf[11],
                 g_forceHandshakeBuf[12]);
        }
        
        // v36.88: REMOVED immediate plaintext 0x000EE007 force-send.
        // Game server expects ENCRYPTED device info after handshake.
        // Force-sending plaintext (143/181/217 bytes) is silently discarded.
        // Instead, the injected 0x80FFF495 above will cause client state machine
        // to advance and send proper AES-encrypted 0x000EE007 (179 bytes) itself.
        DLOG(@"[GAME-FLOW] Waiting for FORCE-HS 0x80FFF495 injection -> client will send encrypted device info");
        
        return YES;
    } else {
        DLOG(@"[CHALLENGE-AUTO] Send failed: %zd", sent);
        return NO;
    }
}

static void applyServerListPatch(unsigned char *payload, size_t payloadLen) {
    if (!payload || payloadLen == 0) return;
    
    BOOL patched = NO;
    char *cpayload = (char *)payload;
    
    for (size_t i = 0; i + 7 < payloadLen; i++) {
        if (cpayload[i] == 's' && cpayload[i+1] == 't' && cpayload[i+2] == 'a' && 
            cpayload[i+3] == 't' && cpayload[i+4] == 'u' && cpayload[i+5] == 's' && 
            cpayload[i+6] == '=' && cpayload[i+7] != '1') {
            DLOG(@"[PROTO-PATCH] Found status=%c at offset %zu, changing to 1", cpayload[i+7], i);
            cpayload[i+7] = '1';
            patched = YES;
        }
    }
    
    for (size_t i = 0; i + 9 < payloadLen; i++) {
        if (cpayload[i] == 's' && cpayload[i+1] == 'e' && cpayload[i+2] == 'r' && 
            cpayload[i+3] == 'v' && cpayload[i+4] == 'e' && cpayload[i+5] == 'r' && 
            cpayload[i+6] == 'i' && cpayload[i+7] == 'd' && cpayload[i+8] == '=' && 
            cpayload[i+9] == '0') {
            DLOG(@"[PROTO-PATCH] Found serverid=0 at offset %zu, changing to 1", i);
            cpayload[i+9] = '1';
            patched = YES;
        }
    }
    
    for (size_t i = 0; i + 9 < payloadLen; i++) {
        if (cpayload[i] == 'c' && cpayload[i+1] == 'l' && cpayload[i+2] == 'i' && 
            cpayload[i+3] == 'e' && cpayload[i+4] == 'n' && cpayload[i+5] == 't' && 
            cpayload[i+6] == 'i' && cpayload[i+7] == 'd' && cpayload[i+8] == '=' && 
            cpayload[i+9] == '0') {
            DLOG(@"[PROTO-PATCH] Found clientid=0 at offset %zu, changing to 1", i);
            cpayload[i+9] = '1';
            patched = YES;
        }
    }
    
    for (size_t i = 0; i + 11 < payloadLen; i++) {
        if (cpayload[i] == 's' && cpayload[i+1] == 'e' && cpayload[i+2] == 'r' && 
            cpayload[i+3] == 'v' && cpayload[i+4] == 'e' && cpayload[i+5] == 'r' && 
            cpayload[i+6] == 'T' && cpayload[i+7] == 'y' && cpayload[i+8] == 'p' && 
            cpayload[i+9] == 'e' && cpayload[i+10] == '=' && cpayload[i+11] == '2') {
            DLOG(@"[PROTO-PATCH] Found serverType=2 at offset %zu, changing to 1", i);
            cpayload[i+11] = '1';
            patched = YES;
        }
    }
    
    const unsigned char newCat[] = {0xE4, 0xB8, 0x80, 0xE5, 0x8C, 0xBA};
    for (size_t i = 0; i + 11 <= payloadLen; i++) {
        if (cpayload[i] == 'c' && cpayload[i+1] == 'a' && cpayload[i+2] == 't' && 
            cpayload[i+3] == 'e' && cpayload[i+4] == 'g' && cpayload[i+5] == 'o' && 
            cpayload[i+6] == 'r' && cpayload[i+7] == 'y' && cpayload[i+8] == '=' && 
            cpayload[i+9] == '\'') {
            size_t endIdx = i + 10;
            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;
            if (endIdx < payloadLen) {
                size_t catLen = endIdx - (i + 10);
                if (catLen >= 6) {
                    DLOG(@"[PROTO-PATCH] Found category field at offset %zu, replacing with '一区'", i);
                    memcpy(payload + i + 10, newCat, 6);
                    for (size_t j = 6; j < catLen; j++) payload[i+10+j] = ' ';
                    patched = YES;
                }
            }
        }
    }
    
    const unsigned char newName[] = {0xE6, 0x9B, 0xB4, 0xE7, 0xAB, 0xAF, 0xE6, 0xB5, 0x8B, 0xE8, 0xAF, 0x95, 0x61};
    for (size_t i = 0; i + 6 <= payloadLen; i++) {
        if (cpayload[i] == 'n' && cpayload[i+1] == 'a' && cpayload[i+2] == 'm' && 
            cpayload[i+3] == 'e' && cpayload[i+4] == '=' && cpayload[i+5] == '\'') {
            size_t endIdx = i + 6;
            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;
            if (endIdx < payloadLen) {
                size_t nameLen = endIdx - (i + 6);
                if (nameLen >= 6) {
                    size_t validCharCount = 0;
                    size_t dotCount = 0;
                    for (size_t j = 0; j < nameLen && j < 30; j++) {
                        unsigned char ch = payload[i+6+j];
                        if (ch == '.') {
                            dotCount++;
                        } else if ((ch >= 0xE4 && ch <= 0xE9) || (ch >= 'a' && ch <= 'z') || 
                                   (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
                            validCharCount++;
                        }
                    }
                    if (dotCount >= nameLen / 2 || validCharCount < 3) {
                        DLOG(@"[PROTO-PATCH] Found garbage name (dots=%zu, valid=%zu) at offset %zu, replacing", 
                             dotCount, validCharCount, i);
                        memcpy(payload + i + 6, newName, 13);
                        for (size_t j = 13; j < nameLen; j++) payload[i+6+j] = ' ';
                        patched = YES;
                    }
                }
            }
        }
    }
    
    const unsigned char newRealName[] = {0xE6, 0x9B, 0xB4, 0xE7, 0xAB, 0xAF, 0xE6, 0xB5, 0x8B, 0xE8, 0xAF, 0x95, 0x61};
    for (size_t i = 0; i + 10 <= payloadLen; i++) {
        if (cpayload[i] == 'r' && cpayload[i+1] == 'e' && cpayload[i+2] == 'a' && 
            cpayload[i+3] == 'l' && cpayload[i+4] == 'n' && cpayload[i+5] == 'a' && 
            cpayload[i+6] == 'm' && cpayload[i+7] == 'e' && cpayload[i+8] == '=' && 
            cpayload[i+9] == '\'') {
            size_t endIdx = i + 10;
            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;
            if (endIdx < payloadLen) {
                size_t nameLen = endIdx - (i + 10);
                if (nameLen >= 6) {
                    size_t validCharCount = 0;
                    size_t dotCount = 0;
                    for (size_t j = 0; j < nameLen && j < 30; j++) {
                        unsigned char ch = payload[i+10+j];
                        if (ch == '.') {
                            dotCount++;
                        } else if ((ch >= 0xE4 && ch <= 0xE9) || (ch >= 'a' && ch <= 'z') || 
                                   (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
                            validCharCount++;
                        }
                    }
                    if (dotCount >= nameLen / 2 || validCharCount < 3) {
                        DLOG(@"[PROTO-PATCH] Found garbage realname (dots=%zu, valid=%zu) at offset %zu, replacing", 
                             dotCount, validCharCount, i);
                        memcpy(payload + i + 10, newRealName, 13);
                        for (size_t j = 13; j < nameLen; j++) payload[i+10+j] = ' ';
                        patched = YES;
                    }
                }
            }
        }
    }
    
    const unsigned char oldDesc[] = {0xE6, 0x9C, 0x8D, 0xE5, 0x8A, 0xA1, 0xE5, 0x99, 0xA8, 
                                     0xE7, 0xBB, 0xB4, 0xE6, 0x8A, 0xA4, 0xE4, 0xB8, 0xAD, 
                                     0x2E, 0x2E, 0x2E};
    const unsigned char newDesc[] = {0xE8, 0xBF, 0x90, 0xE8, 0xA1, 0x8C};
    for (size_t i = 0; i + 21 <= payloadLen; i++) {
        if (memcmp(payload + i, oldDesc, 21) == 0) {
            DLOG(@"[PROTO-PATCH] Found '服务器维护中...' at offset %zu, replacing with '运行'", i);
            memcpy(payload + i, newDesc, 6);
            for (size_t j = 6; j < 21; j++) payload[i+j] = ' ';
            patched = YES;
        }
    }
    
    for (size_t i = 0; i + 17 <= payloadLen; i++) {
        if (cpayload[i] == 'd' && cpayload[i+1] == 'e' && cpayload[i+2] == 's' && 
            cpayload[i+3] == 'c' && cpayload[i+4] == 'r' && cpayload[i+5] == 'i' && 
            cpayload[i+6] == 'p' && cpayload[i+7] == 't' && cpayload[i+8] == 'i' && 
            cpayload[i+9] == 'o' && cpayload[i+10] == 'n' && cpayload[i+11] == '=' && 
            cpayload[i+12] == '\'') {
            size_t endIdx = i + 13;
            while (endIdx < payloadLen && cpayload[endIdx] != '\'') endIdx++;
            if (endIdx < payloadLen) {
                size_t descLen = endIdx - (i + 13);
                if (descLen >= 6) {
                    BOOL isGarbage = YES;
                    for (size_t j = 0; j < descLen && j < 20; j++) {
                        unsigned char ch = payload[i+13+j];
                        if ((ch >= 0x20 && ch < 0x7F) || (ch >= 0xE4 && ch <= 0xE9)) {
                            isGarbage = NO;
                            break;
                        }
                    }
                    if (isGarbage) {
                        DLOG(@"[PROTO-PATCH] Found garbage description at offset %zu, replacing with '运行'", i);
                        memcpy(payload + i + 13, newDesc, 6);
                        for (size_t j = 6; j < descLen; j++) payload[i+13+j] = ' ';
                        patched = YES;
                    }
                }
            }
        }
    }
    
    for (size_t i = 0; i + 16 <= payloadLen; i++) {
        if (cpayload[i] == 'o' && cpayload[i+1] == 'n' && cpayload[i+2] == 'l' && 
            cpayload[i+3] == 'i' && cpayload[i+4] == 'n' && cpayload[i+5] == 'e' && 
            cpayload[i+6] == 'P' && cpayload[i+7] == 'l' && cpayload[i+8] == 'a' && 
            cpayload[i+9] == 'y' && cpayload[i+10] == 'e' && cpayload[i+11] == 'r' && 
            cpayload[i+12] == 'N' && cpayload[i+13] == 'u' && cpayload[i+14] == 'm' && 
            cpayload[i+15] == '=' && cpayload[i+16] == '0') {
            DLOG(@"[PROTO-PATCH] Found onlinePlayerNum=0 at offset %zu, changing to 100", i);
            cpayload[i+16] = '1';
            if (i + 17 < payloadLen && cpayload[i+17] == ',') {
                cpayload[i+17] = '0';
                cpayload[i+18] = '0';
            } else {
                cpayload[i+17] = '0';
            }
            patched = YES;
        }
    }
    
    if (patched) {
        DLOG(@"[PROTO-PATCH] Server list patched successfully");
    }
}

// v36.137: Extracted BURST injection logic as independent function
// Called from: (1) hook_recv entry when g_triggerFakeNextRecv, (2) RECV-CLOSE direct inject
static ssize_t doBurstFakeInject(int fd, void *buf, size_t len) {
    if (!buf || len < 16) return -1;

    DLOG(@"[FORCE-FAKE] v36.137: BURST inject for fd=%d (draining command queue)", fd);
    g_triggerFakeNextRecv = NO;
    g_triggerFakeFd       = -1;

    // Drain entire virtual queue (up to 16 entries)
    GameCmdEntry batch[16];
    int        batchCount = 0;
    for (int i = 0; i < 16; i++) {
        GameCmdEntry e;
        if (!dequeueGameCmd(&e)) break;
        batch[batchCount++] = e;
        DLOG(@"[FORCE-FAKE] v36.137: Batch collected [%d] cmd=0x%08X seq=0x%08X",
             batchCount - 1, e.cmd, e.seqNum);
    }

    uint32_t totalLen     = 0;
    uint32_t respCount    = 0;
    uint8_t *burstBuf    = (uint8_t *)buf;
    size_t   remaining   = len;
    // v36.141: Track whether we already generated a 0x0CB0A300 response.
    // Real server returns ONE 0x0CB0A300 (1632 bytes) for two 0x00FFF493
    // requests (hook.txt SEND #30 + #31 -> RECV #19). Duplicating it
    // pollutes the protocol flow.
    BOOL roleRespGenerated = NO;

    // v36.155: MUST increment role index BEFORE calling generateFakeResponse()
    // so that dynamic role data (name, profession, level) uses the NEW index.
    // Without this, g_roleIndex would be 0 when generating the first response,
    // and the if(g_roleIndex > 0) check in generateFakeResponse would fail,
    // producing static hardcoded attributes instead of unique per-server data.
    g_roleIndex++;
    DLOG(@"[POST-BURST] v36.155: Incremented g_roleIndex to %d (before response generation)", g_roleIndex);

    if (batchCount == 0) {
        // v36.141: Fallback changed from EE007 to FFF493 — server does NOT
        // respond to EE007, so injecting 0x800EE007 would confuse the client.
        DLOG(@"[FORCE-FAKE] v36.141: Queue empty, fallback single FFF493 inject (seq=0x10000)");
        GameCmdEntry ff; ff.cmd = 0x00FFF493; ff.seqNum = 0x00010000; ff.fd = fd; ff.sendLen = 472;
        batch[0] = ff; batchCount = 1;
    }

    for (int i = 0; i < batchCount && remaining >= 16u; i++) {
        // v36.143: WHITELIST mode — only 0x00FFF493 gets a fake response
        // (0x0CB0A300 role data). ALL other commands are skipped.
        // Previous blacklist approach (v36.138-v36.141) kept missing new
        // garbage commands (0x48736343, 0x766A7370, ...) that polluted the
        // BURST with 200-byte bogus responses before 0x0CB0A300.
        if (batch[i].cmd != 0x00FFF493) {
            DLOG(@"[FORCE-FAKE] v36.143: SKIP cmd=0x%08X seq=0x%08X (whitelist: only FFF493)",
                 batch[i].cmd, batch[i].seqNum);
            continue;
        }
        // v36.141: Only generate ONE 0x0CB0A300 for the first 0x00FFF493.
        // Real capture (hook.txt): two 0x00FFF493 -> ONE 0x0CB0A300 (1632B).
        if (roleRespGenerated) {
            DLOG(@"[FORCE-FAKE] v36.141: SKIP duplicate 0x00FFF493 seq=0x%08X (role resp already generated)",
                 batch[i].seqNum);
            continue;
        }
        uint32_t rLen = generateFakeResponse(batch[i].cmd,
                                             burstBuf + totalLen,
                                             (uint32_t)MIN(MAX_FAKE_RESP_BUF, (int)remaining),
                                             batch[i].seqNum);
        // v36.141: Mark 0x0CB0A300 as generated so subsequent 0x00FFF493 are skipped
        if (batch[i].cmd == 0x00FFF493 && rLen > 0) {
            roleRespGenerated = YES;
        }
        if (rLen == 0) {
            rLen = 200;
            if (remaining < rLen) break;
            memset(burstBuf + totalLen, 0, rLen);
            burstBuf[totalLen + 0] = (rLen >> 24) & 0xFF;
            burstBuf[totalLen + 1] = (rLen >> 16) & 0xFF;
            burstBuf[totalLen + 2] = (rLen >> 8)  & 0xFF;
            burstBuf[totalLen + 3] =  rLen & 0xFF;
            uint32_t rc2 = batch[i].cmd | 0x80000000u;
            burstBuf[totalLen + 4] = (rc2 >> 24) & 0xFF; burstBuf[totalLen + 5] = (rc2 >> 16) & 0xFF;
            burstBuf[totalLen + 6] = (rc2 >> 8)  & 0xFF; burstBuf[totalLen + 7] =  rc2 & 0xFF;
            burstBuf[totalLen + 8]  = (batch[i].seqNum >> 24) & 0xFF; burstBuf[totalLen + 9]  = (batch[i].seqNum >> 16) & 0xFF;
            burstBuf[totalLen + 10] = (batch[i].seqNum >> 8)  & 0xFF; burstBuf[totalLen + 11] =  batch[i].seqNum & 0xFF;
            burstBuf[totalLen + 12] = 0x00; // status = success
        }
        if ((uint32_t)remaining < rLen) {
            DLOG(@"[FORCE-FAKE] v36.137: Batch [%d] truncated (need %u, remaining %zu) — stop burst",
                 i, rLen, remaining);
            break;
        }

        // Copy to persistent g_fakeRespBuf for legacy readers (only first response)
        if (i == 0 && g_fakeRespLen == 0) {
            memcpy(g_fakeRespBuf, burstBuf + totalLen, MIN(rLen, (uint32_t)MAX_FAKE_RESP_BUF));
            g_fakeRespLen = rLen;
        }

        totalLen  += rLen;
        remaining -= rLen;
        respCount++;
        DLOG(@"[FORCE-FAKE] v36.137: Batch [%d] appended cmd=0x%08X -> 0x%08X seq=0x%08X len=%u (cum=%u respCount=%d)",
             i, batch[i].cmd, (batch[i].cmd | 0x80000000u), batch[i].seqNum, rLen, totalLen, respCount);
    }

    g_fakeRespInjected  = YES;
    g_fakeRespFd        = fd;
    g_fakeRespSentCount = respCount;
    g_fakeRespActive    = YES;
    g_fakeRespDelivered = YES;
    g_lastRespCmd       = batch[respCount > 0 ? respCount - 1 : 0].cmd;
    g_respCount         = respCount;

    // v36.154: REVERT to CONTIGUOUS injection (state=1→2→0). v36.153's
    // request-driven state=10 caused "连接异常中断" because poll/select
    // set POLLIN while recv() returned EAGAIN, creating a busy-wait loop
    // that the client interpreted as a connection error.
    // v36.154 FIX: Use contiguous injection (proven in v36.146 to show
    // role UI) + add 3-second time delay before Phase 2 can trigger
    // (fixes v36.152 where auto-load ACKs triggered Phase 2 too early).
    //   state=1: next recv injects RECV#20 (71B) → state=2
    //   state=2: next recv injects RECV#21 (840B) → state=0, done
    // v36.155: g_roleIndex already incremented above (before generateFakeResponse).
    // Set post-BURST state for contiguous RECV#20/#21 injection.
    if (totalLen > 0) {
        g_postBurstState = 1;  // v36.154: contiguous injection
        g_postBurstFd = fd;
        g_phase2TriggerCount = 0;
        g_phase1DoneTime = 0;  // Reset; set when RECV#21 is injected
        DLOG(@"[POST-BURST] v36.155: State=1 (contiguous inject RECV#20, roleIndex=%d)", g_roleIndex);
    }

    if (totalLen > 0) {
        DLOG(@"[FAKE-RESP] v36.137: BURST-INJECT returned %u bytes (%d responses, %zu left in recv buffer)",
             totalLen, respCount, remaining);
        NSMutableString *burstHex = [NSMutableString stringWithCapacity:256];
        for (uint32_t i = 0; i < MIN(totalLen, 64u); i++) {
            [burstHex appendFormat:@"%02X ", ((const uint8_t *)buf)[i]];
            if (i == 15 || i == 31 || i == 47) [burstHex appendString:@"\n  "];
        }
        DLOG(@"%@", burstHex);
        return (ssize_t)totalLen;
    }
    DLOG(@"[FAKE-RESP] v36.137: BURST-INJECT produced 0 bytes — returning EAGAIN");
    return -1;
}

static ssize_t hook_recv(int fd, void *buf, size_t len, int flags) {
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recv || !buf) return -1;
    
    // v37.15: DISABLED BURST injection — was causing crash on re-signed IPA.
    // Native encryption works, client sends real encrypted packets, no fake responses needed.
    if (0 && g_triggerFakeNextRecv && g_triggerFakeFd == fd &&
        g_handshakeComplete && g_loginPacketsSent && !g_fakeRespInjected) {
        ssize_t injectLen = doBurstFakeInject(fd, buf, len);
        if (injectLen > 0) return injectLen;
        errno = EAGAIN;
        return -1;
    }

    // v36.142: Post-BURST state machine — inject RECV #20 and #21.
    // Real protocol (hook.txt): after 0x0CB0A300 (role data, our BURST), the
    // client sends an ACK then expects:
    //   RECV #20: cmd=0x12F00080 (71 bytes) — session token
    //   RECV #21: cmd=0x13000080 (840 bytes) — map/scene data
    //   RECV #22: cmd=0x80FFF490 (27 bytes) — enter-game ACK
    //   RECV #23: cmd=0x16000080 (273 bytes) — scene entity data
    //   RECV #24: cmd=0x80FFF161 (63 bytes) — role attr notifications
    // v36.150: TWO-PHASE injection. Phase 1: RECV #20+#21 → client shows
    // role selection UI (v36.146 verified). Phase 2: when client sends
    // 0x00FFF493 (select role / enter game), inject RECV #22-#24.
    // v36.149 injected #22-#24 immediately after #21, causing client to
    // skip role selection and get stuck at "进入角色界面".
    // v36.154: CONTIGUOUS injection (state=1→2→0). v36.153's request-driven
    // state=10 caused "连接异常中断" (poll/select set POLLIN but recv returned
    // EAGAIN → busy-wait → client timeout). Reverted to proven v36.146 design.
    // v36.154 adds 3-second time delay before Phase 2 can trigger.
    // State: 0=idle, 1=inject RECV#20, 2=inject RECV#21→done
    //        3=RECV#22, 4=RECV#23, 5=RECV#24, 0=done
    // v37.15: DISABLED post-BURST state machine — was causing crash.
    // Native encryption works, no fake response injection needed.
    if (0 && g_postBurstState >= 1 && g_postBurstFd == fd) {
        // Phase 1: RECV #20 (71B session token)
        if (g_postBurstState == 1 && len >= 71) {
            memcpy(buf, kRecv20Data, 71);
            g_postBurstState = 2;
            DLOG(@"[POST-BURST] v36.155: Injected RECV #20 (71B) fd=%d state=2", fd);
            return 71;
        }
        // Phase 1: RECV #21 (840B map data) → Phase 1 done
        if (g_postBurstState == 2 && len >= 840) {
            memcpy(buf, kRecv21Head, 288);
            memset((uint8_t *)buf + 288, 0, 840 - 288);
            for (int i = 0; kRecv21Sparse[i].off != 0 || kRecv21Sparse[i].val != 0; i++) {
                if (kRecv21Sparse[i].off < 840)
                    ((uint8_t *)buf)[kRecv21Sparse[i].off] = kRecv21Sparse[i].val;
            }
            // v36.155: Dynamic role data in RECV #21 based on g_roleIndex.
            // The role selection UI displays this data for the character.
            // Each server must show a DIFFERENT character.
            char dynName[48] = {0};
            snprintf(dynName, sizeof(dynName), "\xE7\x8E\xA9\xE5\xAE\xB6%03d", g_roleIndex);
            int nameLen = (int)strlen(dynName);
            memcpy((uint8_t *)buf + 16, dynName, MIN(nameLen, 16));

            // v36.155: Also set dynamic mapId at offset 48-51 (uint32 LE)
            // so each server shows a unique map, not the same one.
            uint32_t mapId = (uint32_t)g_roleIndex;
            ((uint8_t *)buf)[48] = (mapId & 0xFF);
            ((uint8_t *)buf)[49] = ((mapId >> 8) & 0xFF);
            ((uint8_t *)buf)[50] = ((mapId >> 16) & 0xFF);
            ((uint8_t *)buf)[51] = ((mapId >> 24) & 0xFF);

            DLOG(@"[POST-BURST] v36.155: RECV #21 role name='%s' mapId=%u (roleIndex=%d)", dynName, mapId, g_roleIndex);
            g_postBurstState = 0;
            g_postBurstDone = YES;
            g_phase1DoneTime = CFAbsoluteTimeGetCurrent();
            DLOG(@"[POST-BURST] v36.155: Injected RECV #21 (840B) fd=%d state=0 (Phase 1 done, role '%s' displayed, Phase 2 locked for 3s)", fd, dynName);
            return 840;
        }
        // Phase 2: RECV #22-#24 (triggered by hook_send on role select)
        if (g_postBurstState == 3 && len >= 27) {
            memcpy(buf, kRecv22Data, 27);
            g_postBurstState = 4;
            DLOG(@"[POST-BURST] v36.155: Injected RECV #22 (27B) fd=%d state=4 (Phase 2)", fd);
            return 27;
        }
        if (g_postBurstState == 4 && len >= 273) {
            memcpy(buf, kRecv23Data, 273);
            g_postBurstState = 5;
            DLOG(@"[POST-BURST] v36.155: Injected RECV #23 (273B) fd=%d state=5", fd);
            return 273;
        }
        if (g_postBurstState == 5 && len >= 63) {
            memcpy(buf, kRecv24Data, 63);
            g_postBurstState = 0;
            g_postBurstDone = YES;
            DLOG(@"[POST-BURST] v36.155: Injected RECV #24 (63B) fd=%d state=0 (Phase 2 done)", fd);
            return 63;
        }
    }

    // v36.123: Queue-based fake response system (PRIORITY PATH)
    // This handles ALL subsequent recv calls after initial injection
    if (g_fakeRespActive && g_fakeRespFd == fd) {
        // v36.123: Cap total responses to prevent infinite loop
        if (g_respCount >= 200) {
            DLOG(@"[FAKE-RESP] v36.123: Response cap reached (%d), returning EAGAIN", g_respCount);
            errno = EAGAIN;
            return -1;
        }
        
        // v36.123: Try to dequeue next command with sequence number
        GameCmdEntry entry;
        uint32_t responseCmd = 0;
        uint32_t respSeqNum = 0;
        BOOL dequeued = NO;
        
        if (dequeueGameCmd(&entry)) {
            responseCmd = entry.cmd;
            respSeqNum = entry.seqNum;
            dequeued = YES;
            DLOG(@"[FAKE-RESP] v36.123: Dequeued cmd=0x%08X seq=0x%08X from queue (remaining=%d)", 
                 responseCmd, respSeqNum, g_cmdQueueCount);
        } else if (g_lastGameCmd != 0) {
            // v36.123: Queue empty but we have a last command
            responseCmd = g_lastGameCmd;
            respSeqNum = g_lastSeqNum;
            
            // Only respond if:
            // 1. Different from last response, OR
            // 2. Client sent new data (delivered flag was reset)
            if (responseCmd == g_lastRespCmd && g_fakeRespDelivered) {
                // Same command already responded to, wait for new data
                errno = EAGAIN;
                return -1;
            }
            DLOG(@"[FAKE-RESP] v36.123: Queue empty, using last cmd=0x%08X seq=0x%08X (delivered=%d)", 
                 responseCmd, respSeqNum, g_fakeRespDelivered);
        } else {
            // No commands at all
            DLOG(@"[FAKE-RESP] v36.123: No commands to respond to, returning EAGAIN");
            errno = EAGAIN;
            return -1;
        }
        
        // v36.123: Generate response for the command with correct sequence number
        uint8_t tempBuf[MAX_FAKE_RESP_BUF];
        uint32_t respLen = generateFakeResponse(responseCmd, tempBuf, sizeof(tempBuf), respSeqNum);
        
        if (respLen > 0 && respLen <= len) {
            memcpy(buf, tempBuf, respLen);
            g_fakeRespSentCount++;
            g_fakeRespDelivered = YES;
            g_lastRespCmd = responseCmd;
            g_respCount++;
            
            // v36.123: Log full response details for debugging
            NSMutableString *respHex = [NSMutableString stringWithCapacity:48];
            for (uint32_t i = 0; i < MIN(respLen, 16); i++) {
                [respHex appendFormat:@"%02X ", tempBuf[i]];
            }
            DLOG(@"[FAKE-RESP] v36.123: Delivered response for cmd=0x%08X seq=0x%08X len=%u (queue=%d, respCount=%d, hex=%@)", 
                 responseCmd, respSeqNum, respLen, g_cmdQueueCount, g_respCount, respHex);
            return (ssize_t)respLen;
        }
        
        DLOG(@"[FAKE-RESP] v36.123: generateFakeResponse returned invalid len=%u (max=%zu), returning EAGAIN", respLen, len);
        errno = EAGAIN;
        return -1;
    }
    
    // v36.96: Check for fake response state FIRST - before any real recv call
    // v36.146: Skip entirely if post-BURST is done — client has received all
    // needed fake responses (BURST + RECV #20 + #21). Further recv() calls
    // should return EAGAIN, not generate duplicate 0x0CB0A300 responses.
    if (g_fakeRespInjected && g_fakeRespFd == fd && !g_postBurstDone) {
        if (g_fakeRespSentCount >= 1) {
            // v36.101: Switch to active mode but respect delivered flag
            if (!g_fakeRespActive) {
                g_fakeRespActive = YES;
                DLOG(@"[FAKE-RESP] v36.123: Switching to ACTIVE fake response mode for fd=%d", fd);
            }
            // v36.123: Use command queue for ALL responses, not just g_lastGameCmd
            if (g_respCount >= 200) {
                errno = EAGAIN;
                return -1;
            }
            
            // v36.123: Dequeue next command from queue (fixes wrong cmd/seq in subsequent responses)
            GameCmdEntry entry;
            uint32_t activeCmd = 0;
            uint32_t activeSeq = 0;
            
            if (dequeueGameCmd(&entry)) {
                activeCmd = entry.cmd;
                activeSeq = entry.seqNum;
            } else {
                // v36.123: Queue empty - all commands have been responded to
                DLOG(@"[FAKE-RESP] v36.123: Queue empty, returning EAGAIN (all %d responses delivered)", g_respCount);
                errno = EAGAIN;
                return -1;
            }
            
            // v36.123: Generate fake response using dequeued command with correct seq
            uint8_t tempBuf[MAX_FAKE_RESP_BUF];
            uint32_t respLen = generateFakeResponse(activeCmd, tempBuf, sizeof(tempBuf), activeSeq);
            
            if (respLen > 0 && respLen <= len) {
                memcpy(buf, tempBuf, respLen);
                g_fakeRespSentCount++;
                g_fakeRespDelivered = YES;
                g_lastRespCmd = activeCmd;
                g_respCount++;
                DLOG(@"[FAKE-RESP] v36.123: Delivered response for cmd=0x%08X seq=0x%08X len=%u (total #%d, respCount=%d, queue=%d)", 
                     activeCmd, activeSeq, respLen, g_fakeRespSentCount, g_respCount, g_cmdQueueCount);
                return (ssize_t)respLen;
            }
            
            // No response needed, return EAGAIN
            errno = EAGAIN;
            return -1;
        }
        // First call after injection: return fake response data
        g_fakeRespSentCount++;
        if (g_fakeRespLen > 0 && buf) {
            ssize_t retLen = (ssize_t)g_fakeRespLen;
            if (retLen > (ssize_t)len) retLen = (ssize_t)len;
            memcpy(buf, g_fakeRespBuf, retLen);
            DLOG(@"[FAKE-RESP] v36.123: Returning stored fake response (%zd bytes) for fd=%d", retLen, fd);
            return retLen;
        }
        // No fake response data available, return EAGAIN
        DLOG(@"[FAKE-RESP] v36.123: No fake response data, returning EAGAIN for fd=%d", fd);
        errno = EAGAIN;
        return -1;
    }
    
    // v36.91: Debug log to track recv calls (FORCE-HS removed - no more fake packet injection!)
    DLOG(@"[RECV-ENTRY] fd=%d len=%zu hbAck=%zd hbFd=%d",
         fd, len, g_localHeartbeatAckLen, g_localHeartbeatAckFd);
    
    // v36.91: FORCE-HS MECHANISM COMPLETELY REMOVED!
    // v36.90 proved: injecting fake 0x80FFF495 BEFORE real server packet = state machine corruption.
    // Client receives TWO 0x80FFF495 (fake first, then real) with mismatched seq = handshake fails.
    // Only patch the REAL server 0x80FFF495 status byte = minimum intervention approach.
    
    // v36.68: Check for local heartbeat ACK first (blocked heartbeat responses)
    if (g_localHeartbeatAckLen > 0 && g_localHeartbeatAckFd == fd) {
        ssize_t ackLen = g_localHeartbeatAckLen;
        if (ackLen > (ssize_t)len) ackLen = (ssize_t)len;
        memcpy(buf, g_localHeartbeatAckBuf, ackLen);
        DLOG(@"[LOCAL-HB-ACK] Returning %zd bytes local heartbeat ACK (fd=%d)", ackLen, fd);
        g_localHeartbeatAckLen = 0;
        g_localHeartbeatAckFd = -1;
        return ackLen;
    }
    
    // v36.68: Check for leftover bytes from sticky packet split
    // When 0x80FFF494 + heartbeat ACK arrive in same TCP buffer, we split them
    if (g_stickyLeftoverLen > 0 && g_stickyLeftoverFd == fd) {
        ssize_t leftoverLen = g_stickyLeftoverLen;
        if (leftoverLen > (ssize_t)len) leftoverLen = (ssize_t)len;
        memcpy(buf, g_stickyLeftoverBuf, leftoverLen);
        DLOG(@"[STICKY-LEFTOVER] Returning %zd leftover bytes from sticky packet split (fd=%d)", leftoverLen, fd);
        
        // v36.74: DISABLED auto-response to 0x00FFFF02 in leftover path
        // Let client handle challenge naturally - it needs to construct proper RSA-encrypted response
        // Previously: auto-responded with fake 0x80FFFF02 by copying bytes and flipping cmd,
        // which server rejected because it expects RSA-encrypted data using certificate from 0x80FFF494
        
        // Shift remaining leftover bytes
        if (leftoverLen < g_stickyLeftoverLen) {
            memmove(g_stickyLeftoverBuf, g_stickyLeftoverBuf + leftoverLen, g_stickyLeftoverLen - leftoverLen);
        }
        g_stickyLeftoverLen -= leftoverLen;
        if (g_stickyLeftoverLen == 0) g_stickyLeftoverFd = -1;
        return leftoverLen;
    }
    
    ssize_t ret = orig_recv(fd, buf, len, flags);
    if (ret <= 0) {
        // Log connection close/error with context
        const char *host = ""; int port = 0;
        for (int i = 0; i < g_trackedCount; i++) {
            if (g_trackedFds[i] == fd && g_trackedActive[i]) { host = g_trackedHosts[i]; port = g_trackedPorts[i]; break; }
        }
        if (ret == 0) {
            DLOG(@"[RECV-CLOSE] fd=%d %s:%d ret=0 (server closed connection gracefully)", fd, host, port);
            // v36.61: Game server disconnected, try next server (dynamic port detection)
            BOOL isGamePort = (port == 12003 || port == 58158 || 
                               (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
            if (isGamePort) {
                // v36.99: KEY FIX - For game server fd, NEVER return 0 to client!
                // Returning 0 causes SocketClient/NetImpl to detect "connection closed"
                // and set internal disconnected state, leading to "网络中断" error.
                
                // v36.137: DIRECT BURST INJECTION on RECV-CLOSE!
                //   v36.136 bug: armed g_triggerFakeNextRecv but client NEVER called recv()
                //   again. Client detected disconnect via heartbeat→quitFromServer→close()
                //   and reconnected from scratch (login server 5678).
                //   Fix: inject fake responses DIRECTLY into buf NOW, return totalLen.
                //   This prevents client from ever seeing ret=0 on game server fd.
                // v37.15: DISABLED RECV-CLOSE BURST injection — was causing crash.
                // Native encryption works, let client handle connection close normally.
                if (0 && g_handshakeComplete && g_loginPacketsSent && !g_fakeRespInjected) {
                    DLOG(@"[RECV-CLOSE] v36.137: Game server closed connection (fd=%d). DIRECT BURST inject (handshake=%d loginSent=%d).",
                         fd, g_handshakeComplete, g_loginPacketsSent);
                    ssize_t injectLen = doBurstFakeInject(fd, buf, len);
                    if (injectLen > 0) {
                        DLOG(@"[RECV-CLOSE] v36.137: BURST inject SUCCESS %zd bytes for fd=%d — client sees fake responses, NOT connection close", injectLen, fd);
                        return injectLen;
                    }
                    DLOG(@"[RECV-CLOSE] v36.137: BURST inject FAILED, falling through to EAGAIN");
                } else {
                    DLOG(@"[RECV-CLOSE] v36.137: Game server closed connection (fd=%d). EAGAIN only (handshake=%d loginSent=%d fakeInjected=%d).",
                         fd, g_handshakeComplete, g_loginPacketsSent, g_fakeRespInjected);
                }
                
                // v36.136: DISABLED SERVER-ROTATE!
                //   Rotation caused client to reconnect to next server (101.132.180.110),
                //   which ALSO closes connection, creating an infinite reconnect loop.
                // [SERVER-ROTATE DISABLED in v36.136]
                
                errno = EAGAIN;
                return -1;
            }
        } else {
            DLOG(@"[RECV-ERR] fd=%d %s:%d ret=%zd errno=%d (%s)", fd, host, port, ret, errno, strerror(errno));
        }
        return ret;
    }
    
    const char *host = getHostForFd(fd);
    if (!host) return ret;
    
    int port = getPortForFd(fd);
    const unsigned char *p = (const unsigned char *)buf;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 256 ? 256 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[RECV] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host, port, ret, hex, ascii);
    
    if (ret >= 8) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        // Challenge packets (0x00FFFF01/0x00FFFF02) - LOG AND RESPOND
        // v36.67: Server requires response to 0x00FFFF02 to continue handshake
        if (cmd == 0x00FFFF01 || cmd == 0x00FFFF02) {
            NSMutableString *challengeDetail = [NSMutableString string];
            [challengeDetail appendFormat:@"[CHALLENGE-LOG] cmd=0x%08X len=%zd port=%d\n", cmd, (size_t)ret, port];
            [challengeDetail appendFormat:@"  Full hex: "];
            for (ssize_t i = 0; i < ret && i < 64; i++) {
                [challengeDetail appendFormat:@"%02X ", p[i]];
            }
            if (ret > 64) [challengeDetail appendFormat:@"...\n"];
            else [challengeDetail appendFormat:@"\n"];
            
            // Parse packet structure for analysis
            if (ret >= 12) {
                uint32_t pktLen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                                  ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
                uint32_t seq = ((uint32_t)p[8] << 24) | ((uint32_t)p[9] << 16) |
                               ((uint32_t)p[10] << 8) | (uint32_t)p[11];
                [challengeDetail appendFormat:@"  Parsed: pktLen=%u seq=0x%08X\n", pktLen, seq];
                
                // Check for payload data after header
                if (ret > 12) {
                    [challengeDetail appendFormat:@"  Payload (%zd bytes): ", ret - 12];
                    for (ssize_t i = 12; i < ret && i < 32; i++) {
                        [challengeDetail appendFormat:@"%02X ", p[i]];
                    }
                    if (ret > 32) [challengeDetail appendFormat:@"..."];
                    [challengeDetail appendFormat:@"\n"];
                }
                
                // Try to decode payload as ASCII
                NSString *payloadStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];
                if (payloadStr && payloadStr.length > 0) {
                    [challengeDetail appendFormat:@"  Payload text: %@\n", payloadStr];
                }
            }
            
            // v36.93: DISABLED auto-respond to 0x00FFFF02! (same as v36.91-v36.92)
            // v36.90 analysis: Hook's auto-response (0x80FFFF02) + Client's native response (0x00FFF495)
            // cause DOUBLE response to single challenge, activating FORCE-HS and corrupting state machine.
            // v36.89 observation PROVED client can handle 0x00FFFF02 challenge natively.
            // Let client send 0x00FFF495 (703B RSA response) - this is the PROPER response format!
            if (cmd == 0x00FFFF02 && ret >= 28) {
                [challengeDetail appendFormat:@"  [V36.93] SKIP AUTO-RESPOND: Let client handle 0x00FFFF02 challenge natively\n"];
                [challengeDetail appendFormat:@"  [V36.93] Client will parse RSA cert from 0x80FFF494 and send 0x00FFF495 response\n"];
                DLOG(@"[CHALLENGE] v36.93: Skipping auto-respond - let client send native 0x00FFF495 (703B RSA response)");
            } else if (cmd == 0x00FFFF01) {
                [challengeDetail appendFormat:@"  [NOTE] 0x00FFFF01 (first challenge) - game handles this normally\n"];
            }
            
            DLOG(@"%@", challengeDetail);
        }
        
        if (cmd == 0x802EE113) {
            DLOG(@"[PROTO-R] Server list response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            
            // DETAILED HEX DUMP of server list response
            DLOG(@"[SERVERLIST-HEX] Full response hex (%zd bytes):", ret);
            for (ssize_t i = 0; i < ret; i += 32) {
                NSMutableString *line = [NSMutableString string];
                for (ssize_t j = i; j < MIN(i + 32, ret); j++) {
                    [line appendFormat:@"%02X ", p[j]];
                }
                DLOG(@"[SERVERLIST-HEX]   %zd: %@", i, line);
            }
            
            // v36.45: DISABLE port patch - use original port directly
            // Just log the ports found, don't modify them
            int portCount = 0;
            for (ssize_t i = 12; i + 1 < ret; i++) {
                if (p[i] == 0x2E && p[i+1] == 0xE3) {
                    portCount++;
                }
            }
            DLOG(@"[SERVERLIST-PATCH] DISABLED: found %d occurrences of port 12003, NOT modifying", portCount);
            
            // Update global game server info from response
            parseServerListResponse((const unsigned char *)buf, ret);
            
            // Also try to decode as JSON
            NSString *jsonStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];
            if (jsonStr && jsonStr.length > 0 && [jsonStr hasPrefix:@"{"]) {
                DLOG(@"[SERVERLIST-JSON] JSON response: %@", jsonStr);
            }
        } else if (cmd == 0x802EE118 || cmd == 0x802EE120 || cmd == 0x802EE121) {
            DLOG(@"[PROTO-R] Version/auth response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            
            // v36.114: Patch status byte for ALL version/auth responses (0x802EE118/120/121)
            // v36.49: ALWAYS patch status byte for 0x802EE121 - KEEP original ret (don't truncate!)
            if ((cmd == 0x802EE121 || cmd == 0x802EE118 || cmd == 0x802EE120) && ret >= 13 && p[12] != 0) {
                DLOG(@"[PROTO-R-PATCH] v36.114: Status %u -> 0 for cmd=0x%08X (keeping %zd bytes)", p[12], cmd, ret);
                ((unsigned char *)buf)[12] = 0;
            }
        }
        
        // v36.114: TCP STICKY PACKET DETECTION for login server (port 5678)
        // Login server responses can contain multiple packets in one recv
        // Example: 0x8000E002 (120 bytes) + 0x802EE118 (13 bytes) in one recv of 133 bytes
        if (port == 5678 && ret >= 16 && pktLenBE < ret) {
            // There are extra bytes after the first packet - check for sticky sub-packets
            ssize_t offset = pktLenBE;  // Start after first packet
            while (offset < ret) {
                ssize_t remaining = ret - offset;
                if (remaining < 8) break;
                
                uint32_t subPktLen = ((uint32_t)p[offset] << 24) | ((uint32_t)p[offset+1] << 16) |
                                     ((uint32_t)p[offset+2] << 8)  | (uint32_t)p[offset+3];
                uint32_t subCmd    = ((uint32_t)p[offset+4] << 24) | ((uint32_t)p[offset+5] << 16) |
                                     ((uint32_t)p[offset+6] << 8)  | (uint32_t)p[offset+7];
                
                if (subPktLen < 8 || subPktLen > (uint32_t)remaining) break;
                
                DLOG(@"[LOGIN-STICKY] v36.114: Sub-packet at offset %zd: cmd=0x%08X pktLen=%u remaining=%zd", 
                     offset, subCmd, subPktLen, remaining);
                
                // Patch status for version/auth responses in sticky packets
                if ((subCmd == 0x802EE118 || subCmd == 0x802EE120 || subCmd == 0x802EE121) && 
                    remaining >= 13 && p[offset + 12] != 0) {
                    DLOG(@"[LOGIN-STICKY-PATCH] v36.114: Patching sticky sub-packet cmd=0x%08X status %u -> 0", 
                         subCmd, p[offset + 12]);
                    ((unsigned char *)buf)[offset + 12] = 0;
                }
                
                offset += subPktLen;
            }
        }
    }
    
    // v36.50: ONLY clear '版本过低'/'当前版本' on login server (port 5678) - NOT on game server!
    // Running on port 12003 binary data could corrupt protocol data
    if (port == 5678) {
        static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {
            if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
                DLOG(@"[PATCH-R] Cleared '版本过低' at offset %zd (port=5678 only)", i);
                memset((unsigned char *)buf + i, ' ', sizeof(verLow));
            }
        }
        static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};
        for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(curVer); i++) {
            if (memcmp(p + i, curVer, sizeof(curVer)) == 0) {
                DLOG(@"[PATCH-R] Cleared '当前版本' at offset %zd (port=5678 only)", i);
                memset((unsigned char *)buf + i, ' ', sizeof(curVer));
            }
        }
    }
    
#if !MINIMAL_MODE
    // v36.70: Enhanced game server response analysis with CMD-BASED detection
    // Analyze responses on game ports OR by command range detection
    // This ensures analysis works even when getPortForFd returns 0
    BOOL isGamePort = (port == 12003 || port == 58158 || 
                       (port >= 10000 && port <= 65535 && g_gameServerPort >= 1024));
    // v36.70: Parse cmd FIRST to enable cmd-based detection when port fails
    uint32_t rcmd_precheck = 0;
    if (ret >= 8) {
        rcmd_precheck = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                        ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
    }
    BOOL gameCmdDetected = isGameCmd(rcmd_precheck);
    // v36.70: Use BOTH port-based AND cmd-based detection
    BOOL isGameAnalysis = isGamePort || gameCmdDetected;
    
    if (isGameAnalysis && ret >= 4) {
        @try {
            uint32_t rcmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
            uint32_t pktLen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                             ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
            
            // v36.86: REMOVED ACK-REPLACE logic - it causes SIGSEGV crash!
            // 0x80FFF495 maps to handle_CHOOSE_WOOD_BOX_RES in the game client.
            // Faking this packet causes the client to call the wrong handler -> crash.
            // Instead: force-send 0x000EE007 device info directly after challenge response.
            
            const char *gamePort;
            if (port == 58158) gamePort = "58158";
            else if (port == 12003) gamePort = "12003";
            else if (port > 0) gamePort = "DYNAMIC";
            else gamePort = "CMD-DETECT";
            
            // v36.70: Log detection method for debugging
            if (gameCmdDetected && !isGamePort) {
                DLOG(@"[CMD-DETECT] Game server detected via cmd range (cmd=0x%08X, port=%d, host=%s) - port-based FAILED", 
                     rcmd_precheck, port, host);
            } else if (isGamePort) {
                DLOG(@"[CMD-DETECT] Game server detected via port (port=%d, host=%s) - cmd check=%d", 
                     port, host, gameCmdDetected ? 1 : 0);
            }
            
            // v36.57: Build comprehensive log with hex dump
            NSMutableString *detail = [NSMutableString stringWithCapacity:1024];
            [detail appendFormat:@"[GAME-RECV] cmd=0x%08X pktLen=%u recvLen=%zd port=%s fd=%d host=%s\n", 
                 rcmd, pktLen, ret, gamePort, fd, host];
            
            // Hex dump - show up to 256 bytes for thorough analysis
            [detail appendFormat:@"  HEX(%zd bytes): ", ret];
            size_t showLen = ret > 256 ? 256 : (size_t)ret;
            for (ssize_t i = 0; i < showLen; i++) {
                [detail appendFormat:@"%02X ", p[i]];
                if ((i+1) % 32 == 0 && (ssize_t)i+1 < showLen) {
                    [detail appendFormat:@"\n  CONT: "];
                }
            }
            if ((size_t)ret > 256) [detail appendFormat:@"...TRUNCATED\n"];
            else [detail appendFormat:@"\n"];
            
            // ASCII interpretation of payload (offset 12 onwards)
            if (ret > 12) {
                NSString *asciiPayload = [[NSString alloc] initWithBytes:p+12 length:MIN((NSUInteger)(ret-12), 200) encoding:NSUTF8StringEncoding];
                if (asciiPayload && asciiPayload.length > 0) {
                    // Check if it's printable text or binary
                    BOOL hasPrintable = NO;
                    for (NSUInteger i = 0; i < MIN(asciiPayload.length, 50); i++) {
                        unichar c = [asciiPayload characterAtIndex:i];
                        if ((c >= 0x20 && c < 0x7F) || c == 0x0A || c == 0x0D) { hasPrintable = YES; break; }
                    }
                    if (hasPrintable) {
                        [detail appendFormat:@"  ASCII payload: %@\n", asciiPayload];
                    }
                }
            }
            
            // v36.61: Special detailed logging for 0x80FFF494 (login response from game server)
            if (rcmd == 0x80FFF494) {
                DLOG(@"[GAME-80FFF494] ===== DETAILED ANALYSIS OF 0x80FFF494 RESPONSE =====");
                DLOG(@"[GAME-80FFF494] Total length: %zd bytes", ret);
                DLOG(@"[GAME-80FFF494] FULL HEX DUMP:");
                for (ssize_t i = 0; i < ret; i += 16) {
                    NSMutableString *line = [NSMutableString string];
                    for (ssize_t j = i; j < MIN(i + 16, ret); j++) {
                        [line appendFormat:@"%02X ", p[j]];
                    }
                    DLOG(@"[GAME-80FFF494]   %04zd: %@", i, line);
                }
                // Parse known fields
                if (ret >= 16) {
                    uint32_t pLen = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
                    uint32_t pCmd = ((uint32_t)p[4]<<24)|((uint32_t)p[5]<<16)|((uint32_t)p[6]<<8)|p[7];
                    uint8_t pStatus = p[12];
                    DLOG(@"[GAME-80FFF494] pktLen=%u cmd=0x%08X status=%u(0x%02X)", pLen, pCmd, pStatus, pStatus);
                    // Check bytes 12-20 for status/error fields
                    DLOG(@"[GAME-80FFF494] Header fields (offset 8-20):");
                    for (int i = 8; i < MIN(20, (int)ret); i++) {
                        DLOG(@"[GAME-80FFF494]   byte[%d] = %u (0x%02X)", i, p[i], p[i]);
                    }
                    // Try to decode payload
                    if (ret > 13) {
                        NSString *payload = [[NSString alloc] initWithBytes:p+13 length:(NSUInteger)(ret-13) encoding:NSUTF8StringEncoding];
                        if (payload && payload.length > 0) {
                            DLOG(@"[GAME-80FFF494] ASCII payload (offset 13+): '%@'", payload);
                        }
                    }
                }
                DLOG(@"[GAME-80FFF494] ===== END DETAILED ANALYSIS =====");
            }
            
            // v36.61: Also log all GAME-RECV packets in detail (first 128 bytes)
            [detail appendFormat:@"  [DETAIL] Full packet hex (all %zd bytes):\n", ret];
            for (ssize_t i = 0; i < ret; i += 16) {
                [detail appendFormat:@"    %04zd: ", i];
                for (ssize_t j = i; j < MIN(i + 16, ret); j++) {
                    [detail appendFormat:@"%02X ", p[j]];
                }
                [detail appendFormat:@"\n"];
            }
            if (ret >= 13) {
                uint8_t status = p[12];
                [detail appendFormat:@"  [STATUS] byte@12 = %u (0x%02X)\n", status, status];
                if (status != 0) {
                    [detail appendFormat:@"  *** WARNING: Non-zero status! Server returned error ***\n"];
                    // v36.90: SELECTIVE status patching based on 80+ version learnings:
                    //   0x80FFF494 (handshake init, status=1) -> DO NOT PATCH!
                    //       status=1 means "challenge required". Patching to 0
                    //       makes client skip challenge -> never sends 0x00FFF495 -> hangs.
                    //   0x80FFF495 (handshake complete, status=1) -> PATCH TO 0!
                    //       This is the REAL handshake completion ACK from server.
                    //       v36.89 observation confirmed server returns status=1 here,
                    //       causing client to call quitFromServer() -> "network interrupted".
                    //       Patching 1->0 allows client to proceed to send 0x000EE007 + 0x00FFF493.
                    if (rcmd == 0x80FFF494) {
                        DLOG(@"[GAME-PATCH] v36.93: NOT patching status %u for 0x80FFF494 (means 'challenge required')", status);
                        [detail appendFormat:@"  [OBSERVE] v36.93: 0x80FFF494 status NOT patched (preserve challenge signal)\n"];
                        
                        // v36.79: Extract RSA public key certificate from 0x80FFF494 response
                        // Cert starts at byte[14] (4 bytes length + 4 bytes cmd + 4 bytes field + 1 byte status + 1 byte type)
                        // byte[13] = cert format type (0x88 = X.509 cert)
                        // bytes[14..end] = Base64-encoded DER certificate data
                        if (ret > 14 && !g_pubKeyCaptured) {
                            // Debug: Log full packet structure
                            DLOG(@"[PUBKEY-DEBUG] Full 0x80FFF494 packet: ret=%zd bytes", ret);
                            DLOG(@"[PUBKEY-DEBUG] Bytes 0-15 hex: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                                 p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                                 p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
                            DLOG(@"[PUBKEY-DEBUG] Packet header analysis:");
                            DLOG(@"[PUBKEY-DEBUG]   pktLen=%u (bytes 0-3)", ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]);
                            DLOG(@"[PUBKEY-DEBUG]   cmd=0x%08X (bytes 4-7)", ((uint32_t)p[4]<<24)|((uint32_t)p[5]<<16)|((uint32_t)p[6]<<8)|p[7]);
                            DLOG(@"[PUBKEY-DEBUG]   seq=0x%08X (bytes 8-11)", ((uint32_t)p[8]<<24)|((uint32_t)p[9]<<16)|((uint32_t)p[10]<<8)|p[11]);
                            DLOG(@"[PUBKEY-DEBUG]   status=%u (byte 12)", p[12]);
                            DLOG(@"[PUBKEY-DEBUG]   format=%u (byte 13)", p[13]);
                            
                            // Try multiple offset values
                            NSArray *offsetAttempts = @[@14, @13, @12, @15, @16];
                            for (NSNumber *offsetNum in offsetAttempts) {
                                ssize_t certOffset = offsetNum.integerValue;
                                if (certOffset >= ret) continue;
                                ssize_t certLen = ret - certOffset;
                                if (certLen > 0 && certLen < MAX_PUBKEY_BASE64) {
                                    NSString *certStrTest = [[NSString alloc] initWithBytes:p+certOffset length:(NSUInteger)certLen encoding:NSASCIIStringEncoding];
                                    if (certStrTest) {
                                        // Count valid Base64 chars
                                        int validB64 = 0;
                                        int invalidB64 = 0;
                                        for (ssize_t i = 0; i < certLen; i++) {
                                            unsigned char c = p[certOffset + i];
                                            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
                                                (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '\n') {
                                                validB64++;
                                            } else {
                                                invalidB64++;
                                            }
                                        }
                                        
                                        DLOG(@"[PUBKEY-DEBUG] Offset %zd: len=%zd, validB64=%d, invalidB64=%d, starts: %@",
                                             certOffset, certLen, validB64, invalidB64,
                                             [certStrTest substringToIndex:MIN(60, certStrTest.length)]);
                                        
                                        // If most chars are valid Base64, this is likely the correct offset
                                        if (validB64 > invalidB64 * 2 && certLen > 100) {
                                            DLOG(@"[PUBKEY-DEBUG] Offset %zd looks promising (valid/invalid ratio)", certOffset);
                                        }
                                    }
                                }
                            }
                            
                            // v36.81: Improved public key extraction
                            // Find Base64 public key data starting from offset 14
                            ssize_t certOffset = 14;
                            ssize_t maxCertLen = ret - certOffset;
                            
                            if (maxCertLen > 0 && maxCertLen < MAX_PUBKEY_BASE64) {
                                // v36.81: Find the actual end of Base64 data (look for padding or non-Base64 chars)
                                ssize_t certLen = 0;
                                BOOL foundPadding = NO;
                                
                                // First pass: find the Base64 data boundaries
                                for (ssize_t i = 0; i < maxCertLen; i++) {
                                    unsigned char c = p[certOffset + i];
                                    
                                    // Valid Base64: A-Z, a-z, 0-9, +, /, =
                                    BOOL isBase64Char = (c >= 'A' && c <= 'Z') || 
                                                       (c >= 'a' && c <= 'z') || 
                                                       (c >= '0' && c <= '9') || 
                                                       c == '+' || c == '/' || c == '=';
                                    
                                    // Skip newlines (valid in Base64 but not part of key data)
                                    BOOL isWhitespace = c == '\n' || c == '\r';
                                    
                                    if (isBase64Char) {
                                        certLen = i + 1;
                                        if (c == '=') {
                                            foundPadding = YES;
                                            // Padding at end of Base64, stop here
                                            // But allow max 2 padding chars
                                            ssize_t nextI = i + 1;
                                            if (nextI >= maxCertLen || p[certOffset + nextI] != '=') {
                                                // Found single or double padding, stop
                                                break;
                                            }
                                        }
                                    } else if (!isWhitespace && i > 20) {
                                        // Found non-Base64 char after some data, stop extraction
                                        // But only if we have enough data (at least 20 chars)
                                        break;
                                    } else if (isWhitespace && i > 20) {
                                        // Whitespace after some data - could be line ending
                                        // Skip it but continue
                                        continue;
                                    }
                                }
                                
                                // Ensure we have a reasonable length (RSA 2048-bit key = ~392 chars Base64)
                                if (certLen > 100 && certLen < MAX_PUBKEY_BASE64) {
                                    // Extract only the Base64 data (skip non-Base64 chars in between)
                                    size_t cleanLen = 0;
                                    for (ssize_t i = 0; i < certLen && cleanLen < MAX_PUBKEY_BASE64; i++) {
                                        unsigned char c = p[certOffset + i];
                                        BOOL isBase64Char = (c >= 'A' && c <= 'Z') || 
                                                           (c >= 'a' && c <= 'z') || 
                                                           (c >= '0' && c <= '9') || 
                                                           c == '+' || c == '/' || c == '=';
                                        if (isBase64Char) {
                                            g_pubKeyBase64[cleanLen++] = c;
                                        }
                                    }
                                    g_pubKeyBase64Len = cleanLen;
                                    g_pubKeyCaptured = YES;
                                    g_challengeResponded = NO; // Reset challenge response flag
                                    
                                    DLOG(@"[PUBKEY-EXTRACT] v36.82: Extracted RSA cert: %lu bytes Base64 (cleaned from %zd raw bytes, offset=%zd)",
                                         (unsigned long)cleanLen, certLen, certOffset);
                                    DLOG(@"[PUBKEY-EXTRACT] Padding found: %d, Base64 length mod 4: %lu",
                                         foundPadding, (unsigned long)(cleanLen % 4));
                                    
                                    // Log first 80 chars of cert
                                    NSString *certPreview = [[NSString alloc] initWithBytes:(const void *)g_pubKeyBase64 length:MIN((NSUInteger)cleanLen, 80) encoding:NSASCIIStringEncoding];
                                    if (certPreview) {
                                        DLOG(@"[PUBKEY-EXTRACT] Cert starts: %@...", certPreview);
                                    }
                                    // Log last 30 chars
                                    if (cleanLen > 30) {
                                        NSString *certEnd = [[NSString alloc] initWithBytes:(const void *)(g_pubKeyBase64 + cleanLen - 30) length:30 encoding:NSASCIIStringEncoding];
                                        if (certEnd) {
                                            DLOG(@"[PUBKEY-EXTRACT] Cert ends: ...%@", certEnd);
                                        }
                                    }
                                } else {
                                    DLOG(@"[PUBKEY-EXTRACT] v36.82: Invalid cert length: %zd (must be 100-%d)", certLen, MAX_PUBKEY_BASE64);
                                }
                            }
                        }
                    } else if (rcmd == 0x80FFF495) {
                        // v36.133: OBSERVATION MODE - DO NOT PATCH! (based on real capture data)
                        //
                        // REAL CAPTURE ANALYSIS (hook.txt RECV #18):
                        //   00 00 01 6d 80 ff f4 95 00 00 00 17 01 5f 65 61 ...fFJA==#|74297
                        //   offset  8-11: seq = 0x00000017 (sequence number)
                        //   offset    12: 0x01 = FORMAT FLAG (0x01=response, 0x02=request)
                        //   offset    13: 0x5f = sub-type/length
                        //   offset 14+: Base64 encrypted payload
                        //
                        // KEY INSIGHT: offset 12 is NOT a status field! 0x01 is the normal
                        //   response format flag. Real client receives 0x01 and proceeds
                        //   naturally to send 0x000EE007 (178B plaintext) + 0x00FFF493 (472B encrypted).
                        //
                        // PREVIOUS BUG (v36.124-v36.132): We incorrectly treated offset 12
                        //   as "status" and patched 1→0, CORRUPTING the response format.
                        //   This caused client to fail parsing and get stuck at "正在进入...".
                        //
                        // v36.133 FIX: Do NOT modify the packet at all. Let client handle
                        //   the real 0x80FFF495 response naturally. Client will decrypt
                        //   using its own BoringSSL and proceed to send subsequent packets.

                        // Save original seq for logging
                        uint32_t origSeq = ((unsigned char *)buf)[8] << 24 |
                                           ((unsigned char *)buf)[9] << 16 |
                                           ((unsigned char *)buf)[10] << 8 |
                                           ((unsigned char *)buf)[11];
                        uint8_t origFmtFlag = ((unsigned char *)buf)[12];

                        DLOG(@"[GAME-OBSERVE] v36.134: 0x80FFF495 received — NOT PATCHING (seq=0x%08X, fmtFlag=%u, ret=%zd bytes)",
                             origSeq, origFmtFlag, ret);
                        DLOG(@"[GAME-OBSERVE] v36.134: Real client flow: recv 0x80FFF495 -> send 0x000EE007 -> send 0x00FFF493");

                        g_handshakeComplete = YES;
                        g_challengeResponded = YES;

                        // v37.28: Activate CCCrypt L4 hook NOW — game server phase begins.
                        // FFF493 will be AES-encrypted via CCCrypt, and L4 will intercept
                        // the plaintext to replace DY_MIESHI → DYanyou0040_MIESHI.
                        g_cccrypt_l4_active = YES;
                        DLOG(@"[CH-L4-GATE] v37.28: CCCrypt L4 hook ACTIVATED (0x80FFF495 received)");

                        // v36.133: DO NOT enable crypto bypass!
                        //   Real client decrypts 0x80FFF495 payload successfully on its own.
                        //   Enabling bypass returns fake JSON which client may reject.
                        // g_forceValidDecrypt = NO;  (already NO by default)
                        DLOG(@"[GAME-OBSERVE] v36.134: Crypto bypass DISABLED — client will decrypt natively");

                        // v36.133: DO NOT inject fake responses!
                        //   Real client sends 0x000EE007 + 0x00FFF493 naturally after 0x80FFF495.
                        //   Fake response injection corrupts the protocol flow.
                        DLOG(@"[GAME-OBSERVE] v36.134: Virtual queue DISABLED — client will send native packets");
                    } else {
                        [detail appendFormat:@"  *** WARNING: Non-zero status on non-handshake packet (cmd=0x%08X) ***\n", rcmd];
                        DLOG(@"[GAME-PATCH] Non-handshake packet (cmd=0x%08X) status=%u left unchanged", rcmd, status);
                    }
                }
            }
            
            // Check for specific error keywords in payload
            if (ret > 12) {
                NSData *payloadData = [NSData dataWithBytes:p+12 length:(NSUInteger)(ret-12)];
                NSString *payloadStr = [[NSString alloc] initWithData:payloadData encoding:NSUTF8StringEncoding];
                if (payloadStr && payloadStr.length > 0) {
                    if ([payloadStr containsString:@"版本过低"] || [payloadStr containsString:@"当前版本"] || 
                        [payloadStr containsString:@"版本太旧"]) {
                        [detail appendFormat:@"  *** ERROR TEXT DETECTED: %@ ***\n", payloadStr];
                        DLOG(@"[GAME-PATCH] Error text found in game server response: %@ (port=%d)", payloadStr, port);
                        // v36.70: RE-ENABLE text clearing with cmd-based detection support
                        if (isGamePort || gameCmdDetected) {
                            static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
                            static const unsigned char curVer[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};
                            for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {
                                if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
                                    DLOG(@"[GAME-PATCH] Cleared '版本过低' at offset %zd (port=%d)", i, port);
                                    memset((unsigned char *)buf + i, ' ', sizeof(verLow));
                                }
                            }
                            for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(curVer); i++) {
                                if (memcmp(p + i, curVer, sizeof(curVer)) == 0) {
                                    DLOG(@"[GAME-PATCH] Cleared '当前版本' at offset %zd (port=%d)", i, port);
                                    memset((unsigned char *)buf + i, ' ', sizeof(curVer));
                                }
                            }
                        }
                    }
                }
            }
            
            // v36.57: Categorize known game protocol commands
            if (rcmd == 0x00FFFF01 || rcmd == 0x00FFFF02) {
                [detail appendFormat:@"  [CHALLENGE] Server challenge packet (cmd=0x%08X)\n", rcmd];
            } else if (rcmd == 0x80FFFF01 || rcmd == 0x80FFFF02) {
                [detail appendFormat:@"  [RESPONSE] Challenge response packet (cmd=0x%08X)\n", rcmd];
            } else if (rcmd == 0x00EEE007 || rcmd == 0x80EEE007) {
                [detail appendFormat:@"  [DEVICE-INFO] Device info response (cmd=0x%08X)\n", rcmd];
            } else if (rcmd == 0x00F493 || rcmd == 0x80F493) {
                [detail appendFormat:@"  [ENCRYPTED] Encrypted game data (cmd=0x%08X)\n", rcmd];
            } else if (rcmd == 0x80EE0007 || rcmd == 0x80EE0700) {
                [detail appendFormat:@"  [GAME-PROTO] Game protocol packet (cmd=0x%08X)\n", rcmd];
            } else if (rcmd >= 0x80000000) {
                [detail appendFormat:@"  [SERVER-RESP] Server response (cmd=0x%08X)\n", rcmd];
            } else {
                [detail appendFormat:@"  [UNKNOWN] Unknown command (cmd=0x%08X) - possible protocol data\n", rcmd];
            }
            
            // v36.68: Track game server protocol flow (now using global g_handshakeComplete/g_heartbeatCount)
            // After handshake (0x80FFF494), client should send 0x000EE007 (device info)
            // If only heartbeats are being sent, the device info packet may be missing
            
            if (rcmd == 0x80FFF494 || rcmd == 0x80FFF495) {
                if (!g_handshakeComplete) {
                    g_handshakeComplete = YES;
                    g_heartbeatCount = 0;
                    // v36.68: Clear local heartbeat ACK buffer when handshake completes
                    g_localHeartbeatAckLen = 0;
                    g_localHeartbeatAckFd = -1;
                    DLOG(@"[GAME-FLOW] Handshake complete (cmd=0x%08X). Waiting for 0x00FFFF02 challenge...", rcmd);
                    DLOG(@"[GAME-FLOW] v36.79: Auto-responding to 0x00FFFF02 with RSA-encrypted 0x80FFFF02");
                    DLOG(@"[GAME-FLOW] After challenge response, client should send encrypted 0x000EE007 (device info)");
                }
            } else if (g_handshakeComplete && rcmd >= 0x80000000 && rcmd != 0x000EE007) {
                // Count server responses after handshake - these are likely responses to client heartbeats
                g_heartbeatCount++;
                if (g_heartbeatCount == 3) {
                    // v36.93: OBSERVATION MODE - No FALLBACK FORCE-SEND needed
                    // In v36.93, we DON'T patch status, so client sends native encrypted login packets.
                    // close() hook blocks disconnect. If client enters heartbeat loop anyway,
                    // the close block prevents disconnection and server will eventually respond.
                    DLOG(@"[GAME-FLOW] v36.93 OBSERVATION: Received %d server responses after handshake (no FORCE-SEND needed)", g_heartbeatCount);
                    DLOG(@"[GAME-FLOW] v36.93: If client in heartbeat loop, close() hook prevents disconnect");
                }
                if (g_heartbeatCount == 10) {
                    DLOG(@"[GAME-FLOW] v36.93 CRITICAL: %d heartbeats after handshake! close() blocking disconnect.", g_heartbeatCount);
                    DLOG(@"[GAME-FLOW] v36.93: close() hook still active - connection should remain alive");
                }
            }
            
            // Log if 0x000EE007 related responses are received
            if (rcmd == 0x00EEE007 || rcmd == 0x80EEE007 || rcmd == 0x00EE007) {
                DLOG(@"[GAME-FLOW] Device info response received (cmd=0x%08X). Game should be entering now.", rcmd);
                g_handshakeComplete = YES;
                g_heartbeatCount = 0;
            }
            
            // Reset handshake state on disconnect (heartbeat timeout)
            if (g_handshakeComplete && ret == 0) {
                g_handshakeComplete = NO;
                g_heartbeatCount = 0;
                // v36.95: Reset login packets sent flag
                g_loginPacketsSent = NO;
                g_fakeRespInjected = NO;
                // v36.68: Clear all leftover buffers on disconnect
                g_stickyLeftoverLen = 0;
                g_stickyLeftoverFd = -1;
                g_localHeartbeatAckLen = 0;
                g_localHeartbeatAckFd = -1;
                g_deviceInfoSentToGame = NO;
                // v36.84: Clear force handshake state
                g_forceHandshakeComplete = NO;
                g_forceHandshakeFd = -1;
                g_forceHandshakeLen = 0;
                DLOG(@"[GAME-FLOW] Connection closed, resetting handshake state");
            }
            
            DLOG(@"%@", detail);
            
            // v36.77: STICKY PACKET PATCHING (NO SPLITTING) - Return full buffer to client
            // v36.68-36.76 split sticky packets and saved extra bytes for next recv.
            // This BROKE the protocol because client needs to see 0x00FFFF02 
            // challenge IMMEDIATELY after 0x80FFF494 (same recv buffer).
            // Now: patch ALL sub-packets in buffer, return ENTIRE buffer to client.
            // Client's own parser will extract individual packets correctly.
            BOOL patchedExtra = NO;
            ssize_t scanOffset = pktLen;
            while (scanOffset < ret) {
                ssize_t scanRemaining = ret - scanOffset;
                if (scanRemaining < 8) break;
                
                uint32_t scanPktLen = ((uint32_t)p[scanOffset] << 24) | ((uint32_t)p[scanOffset+1] << 16) |
                                      ((uint32_t)p[scanOffset+2] << 8)  | (uint32_t)p[scanOffset+3];
                uint32_t scanCmd    = ((uint32_t)p[scanOffset+4] << 24) | ((uint32_t)p[scanOffset+5] << 16) |
                                      ((uint32_t)p[scanOffset+6] << 8)  | (uint32_t)p[scanOffset+7];
                
                if (scanPktLen < 8 || scanPktLen > 65535) break;
                if (scanPktLen > (uint32_t)scanRemaining) break;
                
                // v36.93: OBSERVATION MODE - No status patching for sticky sub-packets
                // Let client handle all status values naturally
                if (scanRemaining >= 13) {
                    uint8_t scanStatus = p[scanOffset + 12];
                    if (scanStatus != 0 && (scanCmd == 0x80FFF494 || scanCmd == 0x80FFF495)) {
                        DLOG(@"[STICKY-PATCH] v36.93 OBSERVATION: NOT patching status %u for %s sub-packet at offset %zd",
                             scanStatus,
                             scanCmd == 0x80FFF495 ? @"0x80FFF495" : @"0x80FFF494",
                             scanOffset);
                    }
                }
                
                // Log the sub-packet
                DLOG(@"[STICKY-SCAN] Sub-packet at offset %zd: cmd=0x%08X len=%u status=%u",
                     scanOffset, scanCmd, scanPktLen, p[scanOffset + 12]);
                
                // v36.92: DO NOT auto-respond to 0x00FFFF02! (confirmed working in v36.89)
                // Let the CLIENT handle the challenge itself. Our auto-response was
                // sending 0x80FFFF02 BEFORE the client could, and the server may have
                // rejected our format (extra status byte, wrong seq, etc.).
                // v36.89 observation confirmed client handles challenge perfectly.
                if (scanCmd == 0x00FFFF02 && scanRemaining >= 28) {
                    DLOG(@"[STICKY-SCAN] v36.93: Letting CLIENT handle 0x00FFFF02 challenge (auto-response disabled)");
                    DLOG(@"[STICKY-SCAN] Challenge data at offset %zd: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                         scanOffset,
                         p[scanOffset+12], p[scanOffset+13], p[scanOffset+14], p[scanOffset+15],
                         p[scanOffset+16], p[scanOffset+17], p[scanOffset+18], p[scanOffset+19],
                         p[scanOffset+20], p[scanOffset+21], p[scanOffset+22], p[scanOffset+23],
                         p[scanOffset+24], p[scanOffset+25], p[scanOffset+26], p[scanOffset+27]);
                }
                
                scanOffset += scanPktLen;
            }
            if (patchedExtra) {
                DLOG(@"[STICKY-PATCH] Patched extra sub-packets in buffer (no splitting, returning full %zd bytes)", ret);
            }
            
            // v36.66: TCP STICKY PACKET DETECTION - Check for multiple packets in one recv
            DLOG(@"[STICKY-DETECT] Starting sticky packet detection: ret=%zd firstPktLen=%u firstCmd=0x%08X", 
                 ret, pktLen, rcmd);
            
            ssize_t offset = 0;
            int subPacketCount = 0;
            BOOL foundSticky = NO;
            while (offset < ret) {
                ssize_t remaining = ret - offset;
                if (remaining < 8) break; // Need at least header
                
                uint32_t subPktLen = ((uint32_t)p[offset] << 24) | ((uint32_t)p[offset+1] << 16) |
                                     ((uint32_t)p[offset+2] << 8)  | (uint32_t)p[offset+3];
                uint32_t subCmd    = ((uint32_t)p[offset+4] << 24) | ((uint32_t)p[offset+5] << 16) |
                                     ((uint32_t)p[offset+6] << 8)  | (uint32_t)p[offset+7];
                
                // Validate packet length
                if (subPktLen < 8 || subPktLen > 65535) break;
                
                subPacketCount++;
                if (subPacketCount > 1) {
                    foundSticky = YES;
                    DLOG(@"[STICKY-PACKET] Sub-packet #%d at offset %zd: cmd=0x%08X pktLen=%u remaining=%zd", 
                         subPacketCount, offset, subCmd, subPktLen, remaining);
                    
                    // v36.93: OBSERVATION MODE - No status patching for detected sticky sub-packets
                    if (remaining >= 13) {
                        uint8_t subStatus = p[offset + 12];
                        if (subStatus != 0 && (subCmd == 0x80FFF494 || subCmd == 0x80FFF495)) {
                            DLOG(@"[STICKY-PACKET] v36.93 OBSERVATION: NOT patching status %u for %s sub-packet at offset %zd",
                                 subStatus,
                                 subCmd == 0x80FFF495 ? @"0x80FFF495" : @"0x80FFF494",
                                 offset);
                        }
                    }
                }
                
                // v36.93: DO NOT auto-respond to 0x00FFFF02! (confirmed working in v36.89)
                if (subCmd == 0x00FFFF02 && remaining >= 28) {
                    DLOG(@"[STICKY-AUTO] v36.93: Letting CLIENT handle 0x00FFFF02 challenge (auto-response disabled)");
                }
                
                // Move to next packet
                if (subPktLen > (uint32_t)remaining) {
                    // Packet extends beyond available data - incomplete packet
                    DLOG(@"[STICKY-PACKET] Incomplete packet at offset %zd: pktLen=%u > remaining=%zd", 
                         offset, subPktLen, remaining);
                    break;
                }
                offset += subPktLen;
            }
            if (foundSticky) {
                DLOG(@"[STICKY-PACKET] Processed %d sub-packets in one recv (total %zd bytes)", subPacketCount, ret);
            } else {
                DLOG(@"[STICKY-DETECT] No sticky packets found (single packet: cmd=0x%08X len=%u)", rcmd, pktLen);
            }
        } @catch (NSException *e) {
            DLOG(@"[GAME-RECV] Exception during analysis: %@", e.reason);
        }
        
        // v36.124: BURST injection REMOVED — using send-intercept approach instead
        // (client sends commands with real seq, we intercept in hook_send,
        //  generate matching responses in hook_recv)
    }
#endif
    
    return ret;
}

static ssize_t hook_write(int fd, const void *buf, size_t len) {
    if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    if (host && len > 0 && len < 4096) {
        const unsigned char *p = (const unsigned char *)buf;
        NSMutableString *hex = [NSMutableString stringWithCapacity:len * 3];
        NSMutableString *ascii = [NSMutableString stringWithCapacity:len];
        size_t showLen = len > 128 ? 128 : len;
        for (size_t i = 0; i < showLen; i++) {
            [hex appendFormat:@"%02X ", p[i]];
            [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
        }
        DLOG(@"[WRITE] fd=%d %s:%d len=%zu\n  hex: %@\n  txt: %@", fd, host, port, len, hex, ascii);
        
        if (len >= 8) {
            uint32_t cmd = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                           ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
            DLOG(@"[WRITE-CMD] cmd=0x%08X", cmd);
        }
    }
    // NO PACKET MODIFICATION IN WRITE HOOK
    // Version replacement removed - modifying packet data breaks integrity verification
    return orig_write ? orig_write(fd, buf, len) : -1;
}

static ssize_t hook_read(int fd, void *buf, size_t len) {
    if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
    if (!orig_read || !buf) return -1;
    
    ssize_t ret = orig_read(fd, buf, len);
    if (ret <= 0) return ret;
    
    const char *host = getHostForFd(fd);
    if (!host) return ret;
    
    int port = getPortForFd(fd);
    const unsigned char *p = (const unsigned char *)buf;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 256 ? 256 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[READ] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host, port, ret, hex, ascii);
    
    if (ret >= 8) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG-R] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        if (cmd == 0x802EE113) {
            DLOG(@"[PROTO-R] Server list response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
            
            // DETAILED HEX DUMP of server list response
            DLOG(@"[SERVERLIST-HEX2] Full response hex (%zd bytes):", ret);
            for (ssize_t i = 0; i < ret; i += 32) {
                NSMutableString *line = [NSMutableString string];
                for (ssize_t j = i; j < MIN(i + 32, ret); j++) {
                    [line appendFormat:@"%02X ", p[j]];
                }
                DLOG(@"[SERVERLIST-HEX2]   %zd: %@", i, line);
            }
            
            // DISABLED parseServerListResponse for v36.35
            DLOG(@"[SERVERLIST-HEX2] NO PARSING - leaving data untouched");
            
            NSString *jsonStr = [[NSString alloc] initWithBytes:p+12 length:(ret > 12) ? (NSUInteger)(ret-12) : 0 encoding:NSUTF8StringEncoding];
            if (jsonStr && jsonStr.length > 0 && [jsonStr hasPrefix:@"{"]) {
                DLOG(@"[SERVERLIST-JSON2] JSON response: %@", jsonStr);
            }
        } else if (cmd == 0x802EE118 || cmd == 0x802EE120 || cmd == 0x802EE121) {
            DLOG(@"[PROTO-R] Version/auth response 0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);

            // v36.50: ONLY patch on login server (port=5678), and NEVER truncate!
            if (cmd == 0x802EE121 && ret >= 13 && port == 5678) {
                if (p[12] != 0) {
                    DLOG(@"[PROTO-R-PATCH] Status %u -> 0 (read hook, keeping %zd bytes)", p[12], ret);
                    ((unsigned char *)buf)[12] = 0;
                    // v36.50: Do NOT truncate! Game needs full response with sessionId
                }
            }
        }
    }
    
    // v36.50: Remove '版本过低' clearing from read hook - it's handled in recv hook only
    // read hook should NOT modify any data to avoid double-patching issues
    
    return ret;
}

static ssize_t hook_recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvfrom || !buf) return -1;
    
    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src_addr, addrlen);
    if (ret <= 0) return ret;
    
    if (src_addr && addrlen && *addrlen > 0) {
        char host[64] = "unknown";
        int port = 0;
        if (src_addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)src_addr;
            inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
            port = ntohs(in->sin_port);
        } else if (src_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)src_addr;
            inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
            port = ntohs(in6->sin6_port);
        }
        if (port != 0) {
            updateFdHostPort(fd, host, port);
        }
    }
    
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    const unsigned char *p = (const unsigned char *)buf;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 256 ? 256 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[RECVFROM] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host ?: "unknown", port, ret, hex, ascii);
    
    if (ret >= 8) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG-RF] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        // RESTORED: Patch injection-detection error responses
        if (cmd == 0x802EE120 || cmd == 0x802EE121 || cmd == 0x802EE118) {
            DLOG(@"[PROTO-RF] Version/auth response 0x%08X", cmd);
            if (ret >= 13 && p[12] != 0) {
                DLOG(@"[PROTO-RF-PATCH] Status %u -> 0 (injection detection)", p[12]);
                ((unsigned char *)buf)[12] = 0;
            }
        }
    }
    
    // RESTORED: Clear '版本过低' messages
    static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
    for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow); i++) {
        if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
            DLOG(@"[PATCH-RF] Cleared '版本过低' at offset %zd", i);
            memset((unsigned char *)buf + i, ' ', sizeof(verLow));
        }
    }
    
    return ret;
}

static ssize_t hook_recvmsg(int fd, struct msghdr *msg, int flags) {
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_recvmsg || !msg || !msg->msg_iov || msg->msg_iovlen == 0) return -1;
    
    ssize_t ret = orig_recvmsg(fd, msg, flags);
    if (ret <= 0) return ret;
    
    if (msg->msg_name && msg->msg_namelen > 0) {
        struct sockaddr *src_addr = (struct sockaddr *)msg->msg_name;
        char host[64] = "unknown";
        int port = 0;
        if (src_addr->sa_family == AF_INET) {
            struct sockaddr_in *in = (struct sockaddr_in *)src_addr;
            inet_ntop(AF_INET, &in->sin_addr, host, sizeof(host));
            port = ntohs(in->sin_port);
        } else if (src_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)src_addr;
            inet_ntop(AF_INET6, &in6->sin6_addr, host, sizeof(host));
            port = ntohs(in6->sin6_port);
        }
        if (port != 0) {
            updateFdHostPort(fd, host, port);
        }
    }
    
    const char *host = getHostForFd(fd);
    int port = getPortForFd(fd);
    
    struct iovec *iov = msg->msg_iov;
    if (!iov->iov_base || iov->iov_len == 0) return ret;
    
    const unsigned char *p = (const unsigned char *)iov->iov_base;
    
    NSMutableString *hex = [NSMutableString stringWithCapacity:ret * 3];
    NSMutableString *ascii = [NSMutableString stringWithCapacity:ret];
    size_t showLen = ret > 256 ? 256 : (size_t)ret;
    for (size_t i = 0; i < showLen; i++) {
        [hex appendFormat:@"%02X ", p[i]];
        [ascii appendFormat:@"%c", (p[i] >= 0x20 && p[i] < 0x7F) ? p[i] : '.'];
    }
    DLOG(@"[RECVMSG] fd=%d %s:%d ret=%zd\n  hex: %@\n  txt: %@", fd, host ?: "unknown", port, ret, hex, ascii);
    
    if (ret >= 8 && iov->iov_len >= 8) {
        uint32_t pktLenBE = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                            ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
        uint32_t cmd      = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                            ((uint32_t)p[6] << 8)  | (uint32_t)p[7];
        DLOG(@"[PROTO-DBG-RM] cmd=0x%08X pktLen=%u ret=%zd", cmd, pktLenBE, ret);
        
        // RESTORED: Patch injection-detection error responses
        if (cmd == 0x802EE120 || cmd == 0x802EE121 || cmd == 0x802EE118) {
            DLOG(@"[PROTO-RM] Version/auth response 0x%08X", cmd);
            if (iov->iov_len >= 13 && p[12] != 0) {
                DLOG(@"[PROTO-RM-PATCH] Status %u -> 0 (injection detection)", p[12]);
                ((unsigned char *)iov->iov_base)[12] = 0;
            }
        }
    }
    
    // RESTORED: Clear '版本过低' messages
    static const unsigned char verLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
    for (ssize_t i = 0; i <= ret - (ssize_t)sizeof(verLow) && i <= (ssize_t)iov->iov_len - (ssize_t)sizeof(verLow); i++) {
        if (memcmp(p + i, verLow, sizeof(verLow)) == 0) {
            DLOG(@"[PATCH-RM] Cleared '版本过低' at offset %zd", i);
            memset((unsigned char *)iov->iov_base + i, ' ', sizeof(verLow));
        }
    }
    
    return ret;
}

// === Universal fishhook: patch symbol in ALL loaded images ===
static int rebindSymbol(const char *symbolName, void *replacement, void **original) {
    int totalPatched = 0;
    uint32_t imageCount = _dyld_image_count();
    size_t pageSize = 16384;
    
    for (uint32_t img = 0; img < imageCount; img++) {
        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(img);
        intptr_t slide = _dyld_get_image_vmaddr_slide(img);
        if (!header || header->magic != 0xFEEDFACF) continue;
        
        const struct load_command *cmd = (const struct load_command *)((char *)header + sizeof(struct mach_header_64));
        const struct segment_command_64 *linkeditSeg = NULL;
        struct symtab_command *symtab = NULL;
        struct dysymtab_command *dysymtab = NULL;
        
        // Collect data segments
        const struct segment_command_64 *dataSegs[8];
        int dataSegCount = 0;
        
        for (uint32_t i = 0; i < header->ncmds; i++) {
            if (cmd->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd;
                if (strcmp(seg->segname, "__LINKEDIT") == 0) linkeditSeg = seg;
                else if (strcmp(seg->segname, "__DATA") == 0 || strcmp(seg->segname, "__DATA_CONST") == 0) {
                    if (dataSegCount < 8) dataSegs[dataSegCount++] = seg;
                }
            } else if (cmd->cmd == LC_SYMTAB) {
                symtab = (struct symtab_command *)cmd;
            } else if (cmd->cmd == LC_DYSYMTAB) {
                dysymtab = (struct dysymtab_command *)cmd;
            }
            cmd = (const struct load_command *)((char *)cmd + cmd->cmdsize);
        }
        
        if (!linkeditSeg || !symtab || !dysymtab) continue;
        
        char *linkeditBase = (char *)slide + linkeditSeg->vmaddr - linkeditSeg->fileoff;
        const struct nlist_64 *syms = (const struct nlist_64 *)(linkeditBase + symtab->symoff);
        char *strtab = (char *)(linkeditBase + symtab->stroff);
        uint32_t *indirectSyms = (uint32_t *)(linkeditBase + dysymtab->indirectsymoff);
        
        for (int d = 0; d < dataSegCount; d++) {
            const struct section_64 *sec = (const struct section_64 *)((char *)dataSegs[d] + sizeof(struct segment_command_64));
            for (uint32_t s = 0; s < dataSegs[d]->nsects; s++) {
                // Check both __la_symbol_ptr and __got
                if (strcmp(sec[s].sectname, "__la_symbol_ptr") != 0 &&
                    strcmp(sec[s].sectname, "__got") != 0) continue;
                
                void **pointers = (void **)((char *)slide + sec[s].addr);
                uint32_t count = (uint32_t)(sec[s].size / sizeof(void *));
                for (uint32_t j = 0; j < count; j++) {
                    uint32_t symIdx = indirectSyms[sec[s].reserved1 + j];
                    if (symIdx >= symtab->nsyms) continue;
                    const char *name = strtab + syms[symIdx].n_un.n_strx;
                    if (strcmp(name, symbolName) == 0) {
                        void *page = (void *)((uintptr_t)&pointers[j] & ~(pageSize - 1));
                        if (mprotect(page, pageSize, PROT_READ | PROT_WRITE) == 0) {
                            if (original && !*original) *original = pointers[j];
                            pointers[j] = replacement;
                            totalPatched++;
                        }
                    }
                }
            }
        }
    }
    return totalPatched;
}

static void installSocketHooks(void) {
    orig_connect = NULL;
    orig_send = NULL;
    orig_recv = NULL;
    orig_recvfrom = NULL;
    orig_recvmsg = NULL;
    orig_write = NULL;
    orig_read = NULL;
    orig_close = NULL;
    orig_getsockopt = NULL;
    
    int c = rebindSymbol("_connect", (void *)hook_connect, (void **)&orig_connect);
    int s = rebindSymbol("_send", (void *)hook_send, (void **)&orig_send);
    int r = rebindSymbol("_recv", (void *)hook_recv, (void **)&orig_recv);
    int rf = rebindSymbol("_recvfrom", (void *)hook_recvfrom, (void **)&orig_recvfrom);
    int rm = rebindSymbol("_recvmsg", (void *)hook_recvmsg, (void **)&orig_recvmsg);
    int w = rebindSymbol("_write", (void *)hook_write, (void **)&orig_write);
    int rd = rebindSymbol("_read", (void *)hook_read, (void **)&orig_read);
    int cl = rebindSymbol("_close", (void *)hook_close, (void **)&orig_close);
    int gs = rebindSymbol("_getsockopt", (void *)hook_getsockopt, (void **)&orig_getsockopt);
    int p = rebindSymbol("_poll", (void *)hook_poll, (void **)&orig_poll);
    int sel = rebindSymbol("_select", (void *)hook_select, (void **)&orig_select);
    
    if (!orig_connect) orig_connect = (ConnectFunc)dlsym(RTLD_NEXT, "connect");
    if (!orig_send) orig_send = (SendFunc)dlsym(RTLD_NEXT, "send");
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_write) orig_write = (WriteFunc)dlsym(RTLD_NEXT, "write");
    if (!orig_read) orig_read = (ReadFunc)dlsym(RTLD_NEXT, "read");
    if (!orig_close) orig_close = (CloseFunc)dlsym(RTLD_NEXT, "close");
    if (!orig_getsockopt) orig_getsockopt = (GetsockoptFunc)dlsym(RTLD_NEXT, "getsockopt");
    if (!orig_poll) orig_poll = (PollFunc)dlsym(RTLD_NEXT, "poll");
    if (!orig_select) orig_select = (SelectFunc)dlsym(RTLD_NEXT, "select");
    
    DLOG(@"[SOCK] Hooks: connect=%d send=%d recv=%d recvfrom=%d recvmsg=%d write=%d read=%d close=%d getsockopt=%d poll=%d select=%d", c, s, r, rf, rm, w, rd, cl, gs, p, sel);
    DLOG(@"[SOCK] Original: connect=%p send=%p recv=%p recvfrom=%p recvmsg=%p write=%p read=%p close=%p getsockopt=%p poll=%p select=%p", 
         orig_connect, orig_send, orig_recv, orig_recvfrom, orig_recvmsg, orig_write, orig_read, orig_close, orig_getsockopt, orig_poll, orig_select);
    
    if (!orig_connect) DLOG(@"[SOCK-ERROR] connect hook failed - network monitoring disabled!");
    if (!orig_send) DLOG(@"[SOCK-ERROR] send hook failed - outgoing data monitoring disabled!");
    if (!orig_recv) DLOG(@"[SOCK-ERROR] recv hook failed - incoming data monitoring disabled!");
}

// ============================================================
#pragma mark - DYLD API Hooking (hide injected dylibs from detection)
// ============================================================

static const char *g_hiddenDylibs[] = {
    "WangXianHook", "lnSignature", "libSupport", "liblnSignature", "substrate", "frida", NULL
};

static BOOL shouldHideDylib(const char *name) {
    if (!name) return NO;
    for (int i = 0; g_hiddenDylibs[i]; i++) {
        if (strstr(name, g_hiddenDylibs[i])) return YES;
    }
    return NO;
}

// Store original dyld functions
static uint32_t (*orig_dyld_image_count)(void) = NULL;
static const char *(*orig_dyld_get_image_name)(uint32_t) = NULL;
static const struct mach_header *(*orig_dyld_get_image_header)(uint32_t) = NULL;

// Count of hidden images (computed at init)
static uint32_t g_hiddenCount = 0;
static uint32_t g_hiddenIndices[32] = {0};

// Hooked dyld_image_count - return reduced count
static uint32_t hook_dyld_image_count(void) {
    uint32_t realCount = orig_dyld_image_count ? orig_dyld_image_count() : 0;
    uint32_t fakeCount = realCount - g_hiddenCount;
    DLOG(@"[DYLD-HOOK] image_count: real=%u fake=%u", realCount, fakeCount);
    return fakeCount;
}

// Hooked dyld_get_image_name - filter out hidden libraries
static const char *hook_dyld_get_image_name(uint32_t index) {
    if (!orig_dyld_get_image_name) return "";
    
    uint32_t fakeCount = orig_dyld_image_count() - g_hiddenCount;
    if (index >= fakeCount) {
        DLOG(@"[DYLD-HOOK] get_image_name(%u): index out of range (fakeCount=%u)", index, fakeCount);
        return "";
    }
    
    // Map fake index to real index (skip hidden ones)
    uint32_t realIndex = index;
    for (uint32_t i = 0; i < g_hiddenCount; i++) {
        if (g_hiddenIndices[i] <= realIndex) {
            realIndex++;
        }
    }
    
    const char *name = orig_dyld_get_image_name(realIndex);
    if (shouldHideDylib(name)) {
        DLOG(@"[DYLD-HOOK] get_image_name(%u->%u): STILL hidden '%s', skipping", index, realIndex, name);
        // Find next non-hidden
        while (shouldHideDylib(name) && realIndex < orig_dyld_image_count()) {
            realIndex++;
            name = orig_dyld_get_image_name(realIndex);
        }
    }
    
    DLOG(@"[DYLD-HOOK] get_image_name(%u->%u): '%s'", index, realIndex, name ?: "");
    return name ?: "";
}

// Hooked dyld_get_image_header - return header for mapped index
static const struct mach_header *hook_dyld_get_image_header(uint32_t index) {
    if (!orig_dyld_get_image_header) return NULL;
    
    uint32_t fakeCount = orig_dyld_image_count() - g_hiddenCount;
    if (index >= fakeCount) return NULL;
    
    // Map fake index to real index
    uint32_t realIndex = index;
    for (uint32_t i = 0; i < g_hiddenCount; i++) {
        if (g_hiddenIndices[i] <= realIndex) {
            realIndex++;
        }
    }
    
    return orig_dyld_get_image_header(realIndex);
}

// Compute hidden indices at initialization
static void computeHiddenIndices(void) {
    g_hiddenCount = 0;
    uint32_t realCount = _dyld_image_count();
    for (uint32_t i = 0; i < realCount && g_hiddenCount < 32; i++) {
        const char *name = _dyld_get_image_name(i);
        if (shouldHideDylib(name)) {
            g_hiddenIndices[g_hiddenCount++] = i;
            DLOG(@"[DYLD-HIDE] Index %u: '%s' will be hidden", i, name);
        }
    }
    DLOG(@"[DYLD-HIDE] Total hidden: %u / %u", g_hiddenCount, realCount);
}

static void installDyldHooks(void) {
    // Compute hidden indices first
    computeHiddenIndices();
    
    // Get original functions
    orig_dyld_image_count = _dyld_image_count;
    orig_dyld_get_image_name = _dyld_get_image_name;
    orig_dyld_get_image_header = _dyld_get_image_header;
    
    // Try to rebind via fishhook (works for calls through PLT)
    rebindSymbol("_dyld_image_count", (void *)hook_dyld_image_count, (void **)&orig_dyld_image_count);
    rebindSymbol("_dyld_get_image_name", (void *)hook_dyld_get_image_name, (void **)&orig_dyld_get_image_name);
    rebindSymbol("_dyld_get_image_header", (void *)hook_dyld_get_image_header, (void **)&orig_dyld_get_image_header);
    
    DLOG(@"[DYLD-HOOK] Installed hooks for image_count/get_image_name/get_image_header");
}

// ============================================================
#pragma mark - dladdr Hook (hide hook function origin)
// ============================================================

typedef int (*DladdrFunc)(const void *, Dl_info *);
static DladdrFunc orig_dladdr = NULL;

static int hook_dladdr(const void *addr, Dl_info *info) {
    if (!orig_dladdr || !info) return 0;
    
    int ret = orig_dladdr(addr, info);
    if (ret && info->dli_fname) {
        // If the address belongs to our hidden dylib, return fake info
        if (shouldHideDylib(info->dli_fname)) {
            DLOG(@"[DLADDR-HOOK] Hiding origin of addr %p (was '%s')", addr, info->dli_fname);
            // Return libSystem.B.dylib as the origin
            info->dli_fname = "/usr/lib/libSystem.B.dylib";
            info->dli_fbase = (void *)0x19d500000;  // Fake base
            info->dli_sname = NULL;
            info->dli_saddr = NULL;
        }
    }
    return ret;
}

static void installDladdrHook(void) {
    void *libdyld = dlopen("/usr/lib/libdyld.dylib", RTLD_NOLOAD);
    if (libdyld) {
        orig_dladdr = (DladdrFunc)dlsym(libdyld, "dladdr");
        rebindSymbol("_dladdr", (void *)hook_dladdr, (void **)&orig_dladdr);
        DLOG(@"[DLADDR-HOOK] Installed, orig=%p", orig_dladdr);
    }
}

// ============================================================
#pragma mark - dlsym Hook (hide hook framework symbols)
// ============================================================

typedef void* (*DlsymFunc)(void *, const char *);
static DlsymFunc orig_dlsym = NULL;

static void* hook_dlsym(void *handle, const char *symbol) {
    if (!orig_dlsym) {
        void *libdyld = dlopen("/usr/lib/libdyld.dylib", RTLD_NOLOAD);
        if (libdyld) {
            orig_dlsym = (DlsymFunc)dlsym(libdyld, "dlsym");
        }
    }
    if (!orig_dlsym) return NULL;
    
    NSString *symStr = [NSString stringWithUTF8String:symbol];
    NSString *lowerSym = [symStr lowercaseString];
    
    const char *hiddenSymbols[] = {
        "substrate", "fishhook", "mshookfunction", "rebind_symbols",
        "mshookmsg", "mshookclass", "mshookselector",
        "cydia", "cydiasubstrate", "theos",
        NULL
    };
    
    for (int i = 0; hiddenSymbols[i]; i++) {
        if ([lowerSym containsString:[NSString stringWithUTF8String:hiddenSymbols[i]]]) {
            DLOG(@"[DLSYM-HIDE] Returning NULL for symbol: '%s'", symbol);
            return NULL;
        }
    }
    
    void *result = orig_dlsym(handle, symbol);
    if (result) {
        DLOG(@"[DLSYM-LOG] symbol='%s' -> %p", symbol, result);
    }
    return result;
}

static void installDlsymHook(void) {
    void *libdyld = dlopen("/usr/lib/libdyld.dylib", RTLD_NOLOAD);
    if (libdyld) {
        orig_dlsym = (DlsymFunc)dlsym(libdyld, "dlsym");
        rebindSymbol("_dlsym", (void *)hook_dlsym, (void **)&orig_dlsym);
        DLOG(@"[DLSYM-HOOK] Installed, orig=%p", orig_dlsym);
    }
}

// ============================================================
#pragma mark - /proc/self/maps filtering (Linux fallback)
// ============================================================

static BOOL shouldHideLine(const char *line) {
    return shouldHideDylib(line);
}

// Hook fopen to detect /proc/self/maps access
typedef FILE *(*FopenFunc)(const char *, const char *);
static FopenFunc orig_fopen = NULL;
static FILE *hook_fopen(const char *path, const char *mode) {
    FILE *f = orig_fopen ? orig_fopen(path, mode) : NULL;
    if (f && path && strstr(path, "/proc/self/maps")) {
        DLOG(@"[PROC] /proc/self/maps opened");
    }
    return f;
}

// Hook fgets to filter out our dylibs from /proc/self/maps
typedef char *(*FgetsFunc)(char *, int, FILE *);
static FgetsFunc orig_fgets = NULL;
static char *hook_fgets(char *buf, int size, FILE *stream) {
    char *result = orig_fgets ? orig_fgets(buf, size, stream) : NULL;
    if (result && shouldHideLine(result)) {
        buf[0] = '\n';
        buf[1] = '\0';
    }
    return result;
}

#pragma mark - CCCrypt / SecKey Hooks

// v37.26: Forward declaration for wrapper to avoid implicit declaration
static int hook_CCCrypt_v37_26(uint32_t op, uint32_t alg, uint32_t options,
                                  const void *key, size_t keyLen,
                                  const void *iv,
                                  const void *dataIn, size_t dataInLen,
                                  void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved);

static int hook_CCCrypt(uint32_t op, uint32_t alg, uint32_t options,
                        const void *key, size_t keyLen,
                        const void *iv,
                        const void *dataIn, size_t dataInLen,
                        void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    // v37.26: Redirect to the full implementation above. This wrapper exists
    // because installSecurityHooks rebinds by this function's symbol name.
    return hook_CCCrypt_v37_26(op, alg, options, key, keyLen, iv,
                               dataIn, dataInLen, dataOut, dataOutAvailable, dataOutMoved);
}

// ============================================================
// v37.51: CC_MD5 hook — replace modified binary hash with clean hash
// ============================================================
// Our binary hash (全能签 modified): 913a1d1a9b704107b7b607b13d53a094
// Clean binary hash (original):      ddcb91f42c5a612b492a2296a971a5af
// When CC_MD5 output matches our hash, replace with clean hash.
// This makes client compute hash1/hash3 using clean binary hash → all 3 hashes consistent.

typedef unsigned char *(*CC_MD5Func)(const void *data, uint32_t len, unsigned char *md);
static CC_MD5Func orig_CC_MD5 = NULL;

static const uint8_t g_our_binary_hash[16] = {
    0x91,0x3a,0x1d,0x1a,0x9b,0x70,0x41,0x07,
    0xb7,0xb6,0x07,0xb1,0x3d,0x53,0xa0,0x94
};
static const uint8_t g_clean_binary_hash[16] = {
    0xdd,0xcb,0x91,0xf4,0x2c,0x5a,0x61,0x2b,
    0x49,0x2a,0x22,0x96,0xa9,0x71,0xa5,0xaf
};
// g_md5_replace_count declared near top of file (line 589)

static unsigned char *hook_CC_MD5(const void *data, uint32_t len, unsigned char *md) {
    unsigned char *ret = orig_CC_MD5(data, len, md);
    if (ret && md) {
        if (memcmp(md, g_our_binary_hash, 16) == 0) {
            memcpy(md, g_clean_binary_hash, 16);
            g_md5_replace_count++;
            DLOG(@"[MD5-HOOK] v37.51: Replaced binary hash (#%d, inputLen=%u)", g_md5_replace_count, len);
        }
    }
    return ret;
}

// Also hook CC_MD5_Final for streaming MD5
typedef int (*CC_MD5_FinalFunc)(unsigned char *md, void *c);
static CC_MD5_FinalFunc orig_CC_MD5_Final = NULL;

static int hook_CC_MD5_Final(unsigned char *md, void *c) {
    int ret = orig_CC_MD5_Final(md, c);
    if (ret == 1 && md) {
        if (memcmp(md, g_our_binary_hash, 16) == 0) {
            memcpy(md, g_clean_binary_hash, 16);
            g_md5_replace_count++;
            DLOG(@"[MD5-HOOK] v37.51: Replaced binary hash via CC_MD5_Final (#%d)", g_md5_replace_count);
        }
    }
    return ret;
}

typedef OSStatus (*SecKeyEncryptFunc)(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen);
static SecKeyEncryptFunc orig_SecKeyEncrypt = NULL;

static OSStatus hook_SecKeyEncrypt(SecKeyRef key, SecPadding padding, const uint8_t *plainText, size_t plainTextLen, uint8_t *cipherText, size_t *cipherTextLen) {
    if (!orig_SecKeyEncrypt) orig_SecKeyEncrypt = (SecKeyEncryptFunc)dlsym(RTLD_NEXT, "SecKeyEncrypt");
    if (!orig_SecKeyEncrypt) return errSecParam;
    DLOG(@"[SEC] SecKeyEncrypt plainLen=%zu cipherLen=%zu", plainTextLen, cipherTextLen ? *cipherTextLen : 0);
    return orig_SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen);
}

typedef OSStatus (*SecKeyDecryptFunc)(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen);
static SecKeyDecryptFunc orig_SecKeyDecrypt = NULL;

static OSStatus hook_SecKeyDecrypt(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen) {
    if (!orig_SecKeyDecrypt) orig_SecKeyDecrypt = (SecKeyDecryptFunc)dlsym(RTLD_NEXT, "SecKeyDecrypt");
    if (!orig_SecKeyDecrypt) return errSecParam;
    
    // v36.126: Do NOT bypass here — SecKeyDecrypt is the low-level implementation
    // called internally by SecKeyCreateDecryptedData. Only SecKeyCreateDecryptedData
    // should bypass (it will clear forceValidDecrypt). If game uses SecKeyDecrypt
    // directly (pre-iOS 10), we handle via CCCrypt or add separate bypass later.
    
    OSStatus ret = orig_SecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, plainTextLen);
    DLOG(@"[SEC] SecKeyDecrypt cipherLen=%zu plainLen=%zu ret=%d", cipherTextLen, plainTextLen ? *plainTextLen : 0, (int)ret);
    return ret;
}

// SecKeyCreateDecryptedData hook (iOS 10+)
// CORRECT signature: CFDataRef SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error);
typedef CFDataRef (*SecKeyCreateDecryptedDataFunc)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error);
static SecKeyCreateDecryptedDataFunc orig_SecKeyCreateDecryptedData = NULL;

static CFDataRef hook_SecKeyCreateDecryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef ciphertext, CFErrorRef *error) {
    if (!orig_SecKeyCreateDecryptedData) {
        orig_SecKeyCreateDecryptedData = (SecKeyCreateDecryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateDecryptedData");
    }
    if (!orig_SecKeyCreateDecryptedData) return NULL;
    
    // v36.126: CRITICAL FIX — Skip real decryption entirely when forceValidDecrypt=YES
    // v36.125 bug: calling orig first → RSA decryption "succeeds" with garbage → bypass never triggered
    if (g_forceValidDecrypt && ciphertext) {
        CFIndex cipherLen = CFDataGetLength(ciphertext);
        DLOG(@"[SEC-BYPASS] v36.126: SKIPPING real decrypt (cipherLen=%ld), returning fake valid plaintext", cipherLen);
        
        // Return a valid plaintext directly — no real decryption attempted
        // Format: JSON with success indicator (proven pattern from other game protocols)
        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";
        CFDataRef fakeData = CFDataCreate(NULL, (const UInt8 *)fakePlaintext, strlen(fakePlaintext));
        
        // Dump the ORIGINAL ciphertext first 64 bytes for analysis
        NSMutableString *hexDump = [NSMutableString stringWithCapacity:128];
        const UInt8 *cipherBytes = CFDataGetBytePtr(ciphertext);
        CFIndex dumpLen = MIN((CFIndex)64, cipherLen);
        for (CFIndex i = 0; i < dumpLen; i++) {
            [hexDump appendFormat:@"%02X ", cipherBytes[i]];
        }
        DLOG(@"[SEC-BYPASS] v36.126: Ciphertext first %ld bytes: %@", dumpLen, hexDump);
        
        // Clear force flag — only bypass ONE decryption call
        g_forceValidDecrypt = NO;
        DLOG(@"[SEC-BYPASS] v36.126: Returned fake plaintext (%zu bytes), forceValidDecrypt=NO", strlen(fakePlaintext));
        return fakeData;
    }
    
    // Normal mode — real decryption
    CFErrorRef *errPtr = NULL;
    CFDataRef result = orig_SecKeyCreateDecryptedData(key, algorithm, ciphertext, errPtr);
    if (errPtr && *errPtr) {
        DLOG(@"[SEC] SecKeyCreateDecryptedData FAILED: %@", CFBridgingRelease(CFErrorCopyDescription(*errPtr)));
    } else if (result) {
        DLOG(@"[SEC] SecKeyCreateDecryptedData SUCCESS: cipherLen=%lu plainLen=%lu",
             ciphertext ? CFDataGetLength(ciphertext) : 0, CFDataGetLength(result));
        // v36.135: Dump decrypted plaintext to see what server returned
        CFIndex plainLen = CFDataGetLength(result);
        if (plainLen > 0 && plainLen <= 512) {
            const UInt8 *plainBytes = CFDataGetBytePtr(result);
            NSMutableString *plainHex = [NSMutableString stringWithCapacity:plainLen * 3];
            NSMutableString *plainAscii = [NSMutableString stringWithCapacity:plainLen];
            for (CFIndex i = 0; i < plainLen; i++) {
                [plainHex appendFormat:@"%02X ", plainBytes[i]];
                [plainAscii appendFormat:@"%c", (plainBytes[i] >= 0x20 && plainBytes[i] < 0x7F) ? plainBytes[i] : '.'];
            }
            DLOG(@"[SEC-PLAIN] v36.135: Decrypted plaintext (%ld bytes): HEX: %@", plainLen, plainHex);
            DLOG(@"[SEC-PLAIN] v36.135: Decrypted plaintext ASCII: %@", plainAscii);
        }
    } else {
        DLOG(@"[SEC] SecKeyCreateDecryptedData returned NULL");
    }
    return result;
}

// ============================================================
// v36.123: Hook [UIDevice identifierForVendor]
// Let client construct 0x000EE007 with UUID NATIVELY
// (Avoids send-level buffer modification per Experience 1423135)
// ============================================================
// v37.19-DIST: Hook [UIDevice identifierForVendor] — do NOT force a fixed UUID.
// Distributable build: each user must use their OWN native IDFV so that the
// challenge-response (0x00FFF495 → 0x80FFF495 status) signature matches their
// real device fingerprint registered on the login server (0x002EE121).
// A globally hard-coded UUID makes ALL injected users share the same fingerprint,
// causing 0x80FFF495 status=1 (challenge failure) and immediate server FIN after
// 0x00FFF493. This was the root cause of v37.18 "connection interrupted".
// We still swizzle so that we have a hook point for future per-user overrides,
// but just call the original implementation.
static NSUUID* hook_identifierForVendor(UIDevice *self, SEL _cmd) {
    // v37.19-DIST: Call original — each user's own native IDFV
    if (orig_identifierForVendor) {
        NSUUID *real = orig_identifierForVendor(self, _cmd);
        static BOOL logged = NO;
        if (!logged) {
            DLOG(@"[IDFV-HOOK] v37.27-DIST: Using native IDFV = %@ (NOT fixed, distributable safe)", real);
            logged = YES;
        }
        return real;
    }
    // Fallback (should not happen)
    return nil;
}

static void installIDFVHook(void) {
    // Use a fixed reproducible UUID (matches what injectUUIDIntoDeviceInfo uses)
    const char *fixedUUIDStr = "D4896737-1234-5678-ABCD-0123456789AB";
    @try {
        g_fixedIDFV = [[NSUUID alloc] initWithUUIDBytes:(const unsigned char *)"\xD4\x89\x67\x37\x12\x34\x56\x78\xAB\xCD\x01\x23\x45\x67\x89\xAB"];
    } @catch (NSException *e) {
        g_fixedIDFV = [[NSUUID alloc] initWithUUIDString:[NSString stringWithUTF8String:fixedUUIDStr]];
    }
    if (!g_fixedIDFV) {
        g_fixedIDFV = [NSUUID UUID];  // last resort: random
    }
    DLOG(@"[IDFV-HOOK] v36.123: Fixed UUID = %@", [g_fixedIDFV UUIDString]);

    // Now swizzle UIDevice's identifierForVendor
    Class uiDeviceCls = NSClassFromString(@"UIDevice");
    if (!uiDeviceCls) {
        DLOG(@"[IDFV-HOOK] v36.123: FAILED - UIDevice class not found");
        return;
    }
    Method m = class_getInstanceMethod(uiDeviceCls, @selector(identifierForVendor));
    if (!m) {
        DLOG(@"[IDFV-HOOK] v36.123: FAILED - method identifierForVendor not found");
        return;
    }
    orig_identifierForVendor = (NSUUID* (*)(UIDevice*, SEL))method_getImplementation(m);
    IMP newImp = (IMP)hook_identifierForVendor;
    method_setImplementation(m, newImp);
    DLOG(@"[IDFV-HOOK] v36.123: SUCCESS - [UIDevice identifierForVendor] now returns fixed UUID");
}

// SecKeyCreateEncryptedData hook (iOS 10+)
// CORRECT signature: CFDataRef SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error);
typedef CFDataRef (*SecKeyCreateEncryptedDataFunc)(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error);
static SecKeyCreateEncryptedDataFunc orig_SecKeyCreateEncryptedData = NULL;

static CFDataRef hook_SecKeyCreateEncryptedData(SecKeyRef key, SecKeyAlgorithm algorithm, CFDataRef plaintext, CFErrorRef *error) {
    if (!orig_SecKeyCreateEncryptedData) {
        orig_SecKeyCreateEncryptedData = (SecKeyCreateEncryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateEncryptedData");
    }
    if (!orig_SecKeyCreateEncryptedData) return NULL;
    CFErrorRef *errPtr = NULL;
    CFDataRef result = orig_SecKeyCreateEncryptedData(key, algorithm, plaintext, errPtr);
    if (errPtr && *errPtr) {
        DLOG(@"[SEC] SecKeyCreateEncryptedData FAILED: %@", CFBridgingRelease(CFErrorCopyDescription(*errPtr)));
    } else if (result) {
        DLOG(@"[SEC] SecKeyCreateEncryptedData SUCCESS: plainLen=%lu cipherLen=%lu", 
             plaintext ? CFDataGetLength(plaintext) : 0, CFDataGetLength(result));
    } else {
        DLOG(@"[SEC] SecKeyCreateEncryptedData returned NULL");
    }
    return result;
}

// ============================================================
#pragma mark - v37.3 SCNetworkReachabilityGetFlags hook
// Force return kSCNetworkReachabilityFlagsReachable so client's
// pre-connect network check passes for game server (port 12003)
// ============================================================

typedef int (*SCNetworkReachabilityGetFlagsFunc)(void *target, uint32_t *flags);
static SCNetworkReachabilityGetFlagsFunc orig_SCNetworkReachabilityGetFlags = NULL;

static int hook_SCNetworkReachabilityGetFlags(void *target, uint32_t *flags) {
    // v37.3: Force reachable — kSCNetworkReachabilityFlagsReachable = 0x02
    if (flags) *flags = 0x02;
    return 1;  // TRUE
}

static void installSCNetworkReachabilityHook(void) {
    void *scLib = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOLOAD);
    if (!scLib) {
        scLib = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_LAZY);
    }
    if (scLib) {
        orig_SCNetworkReachabilityGetFlags = (SCNetworkReachabilityGetFlagsFunc)dlsym(scLib, "SCNetworkReachabilityGetFlags");
        if (orig_SCNetworkReachabilityGetFlags) {
            int r = rebindSymbol("_SCNetworkReachabilityGetFlags",
                                 (void *)hook_SCNetworkReachabilityGetFlags,
                                 (void **)&orig_SCNetworkReachabilityGetFlags);
            DLOG(@"[SEC] SCNetworkReachabilityGetFlags hook: rebind=%d addr=%p", r, orig_SCNetworkReachabilityGetFlags);
        } else {
            DLOG(@"[SEC] SCNetworkReachabilityGetFlags NOT found in SystemConfiguration");
        }
    } else {
        DLOG(@"[SEC] SystemConfiguration framework NOT loaded");
    }
}

static void installSecurityHooks(void) {
    // Log all loaded dylibs for diagnosis (use original functions before hook)
    uint32_t count = _dyld_image_count();
    DLOG(@"[DYLD] Total loaded images: %u", count);
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name) {
            NSString *nsname = [NSString stringWithUTF8String:name];
            if ([nsname containsString:@".dylib"]) {
                DLOG(@"[DYLD] %u: %@", i, nsname.lastPathComponent);
            }
        }
    }
    
    // v37.8: RESTORED DYLD hiding — Frida diagnostic (hook.txt) confirmed client
    //        calls _dyld_image_count() 100+ times and detects lnSignature.dylib
    //        + libSupport.dylib → triggers '版本过低'. DYLD hiding is REQUIRED.
    //        capture_real.js worked because Frida agent is NOT in dyld list.
    installDyldHooks();
    installDladdrHook();
    installDlsymHook();  // KEEP: dlsym hook is in capture_real.js
    
    // Hook fopen/fgets for /proc/self/maps (Linux fallback)
    void *syslib = dlopen("/usr/lib/libSystem.B.dylib", RTLD_NOLOAD);
    if (syslib) {
        void *fp = dlsym(syslib, "fopen");
        void *fg = dlsym(syslib, "fgets");
        DLOG(@"[SEC] libSystem: fopen=%p fgets=%p", fp, fg);
    }
    
    // v37.30: Restore v37.28 CCCrypt gated hook. USER CONFIRMED v37.28 did NOT
    // crash — only disconnected. CCCrypt fishhook rebind is SAFE when gated
    // after 0x80FFF495 (game server phase). We need this to:
    //   (A) Dump FULL plaintext hex of FFF493 payload before AES encrypt
    //   (B) Replace DY_MIESHI → DYanyou0040_MIESHI in plaintext before encryption
    {
        orig_CCCrypt = (CCCryptFunc)dlsym(RTLD_NEXT, "CCCrypt");
        if (orig_CCCrypt) {
            int r1 = rebindSymbol("_CCCrypt", (void *)hook_CCCrypt, (void **)&orig_CCCrypt);
            DLOG(@"[SEC] CCCrypt hook v37.30: rebind=%d addr=%p (GATED after 0x80FFF495 per v37.28 safe)", r1, orig_CCCrypt);
        } else {
            DLOG(@"[SEC] CCCrypt not found via dlsym (L4 won't work!)");
        }
    }

    // v37.51: Hook CC_MD5 and CC_MD5_Final to replace modified binary hash
    // with clean (original) binary hash. This makes the client compute all
    // hash1/hash2/hash3 using the original binary hash → server accepts.
    {
        orig_CC_MD5 = (CC_MD5Func)dlsym(RTLD_NEXT, "CC_MD5");
        if (orig_CC_MD5) {
            int rm = rebindSymbol("_CC_MD5", (void *)hook_CC_MD5, (void **)&orig_CC_MD5);
            DLOG(@"[SEC] CC_MD5 hook v37.51: rebind=%d addr=%p", rm, orig_CC_MD5);
        } else {
            DLOG(@"[SEC] CC_MD5 not found via dlsym");
        }
        orig_CC_MD5_Final = (CC_MD5_FinalFunc)dlsym(RTLD_NEXT, "CC_MD5_Final");
        if (orig_CC_MD5_Final) {
            int rmf = rebindSymbol("_CC_MD5_Final", (void *)hook_CC_MD5_Final, (void **)&orig_CC_MD5_Final);
            DLOG(@"[SEC] CC_MD5_Final hook v37.51: rebind=%d addr=%p", rmf, orig_CC_MD5_Final);
        }
    }

#if !DISABLE_CRYPTO_HOOKS
    // Hook SecKeyEncrypt / SecKeyDecrypt for RSA logging
    orig_SecKeyEncrypt = (SecKeyEncryptFunc)dlsym(RTLD_NEXT, "SecKeyEncrypt");
    if (orig_SecKeyEncrypt) {
        int r2 = rebindSymbol("_SecKeyEncrypt", (void *)hook_SecKeyEncrypt, (void **)&orig_SecKeyEncrypt);
        DLOG(@"[SEC] SecKeyEncrypt hook: rebind=%d addr=%p", r2, orig_SecKeyEncrypt);
    }
    
    orig_SecKeyDecrypt = (SecKeyDecryptFunc)dlsym(RTLD_NEXT, "SecKeyDecrypt");
    if (orig_SecKeyDecrypt) {
        int r3 = rebindSymbol("_SecKeyDecrypt", (void *)hook_SecKeyDecrypt, (void **)&orig_SecKeyDecrypt);
        DLOG(@"[SEC] SecKeyDecrypt hook: rebind=%d addr=%p", r3, orig_SecKeyDecrypt);
    }
    
    // Hook SecKeyCreateDecryptedData (iOS 10+ decrypt API)
    orig_SecKeyCreateDecryptedData = (SecKeyCreateDecryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateDecryptedData");
    if (orig_SecKeyCreateDecryptedData) {
        int r4 = rebindSymbol("_SecKeyCreateDecryptedData", (void *)hook_SecKeyCreateDecryptedData, (void **)&orig_SecKeyCreateDecryptedData);
        DLOG(@"[SEC] SecKeyCreateDecryptedData hook: rebind=%d addr=%p", r4, orig_SecKeyCreateDecryptedData);
    }
    
    // Hook SecKeyCreateEncryptedData (iOS 10+ encrypt API)
    orig_SecKeyCreateEncryptedData = (SecKeyCreateEncryptedDataFunc)dlsym(RTLD_NEXT, "SecKeyCreateEncryptedData");
    if (orig_SecKeyCreateEncryptedData) {
        int r5 = rebindSymbol("_SecKeyCreateEncryptedData", (void *)hook_SecKeyCreateEncryptedData, (void **)&orig_SecKeyCreateEncryptedData);
        DLOG(@"[SEC] SecKeyCreateEncryptedData hook: rebind=%d addr=%p", r5, orig_SecKeyCreateEncryptedData);
    }
#else
    DLOG(@"[SEC] Crypto hooks DISABLED (v36.47 fix - avoid corrupting encryption data)");
#endif

    // v36.123: Hook [UIDevice identifierForVendor] so client builds UUID-natively
    installIDFVHook();
    
    // v37.3: Hook SCNetworkReachabilityGetFlags — force reachable for game server connection
    installSCNetworkReachabilityHook();
    
    DLOG(@"[SEC] Security hooks ready (with DYLD hiding)");
}

// ============================================================
#pragma mark - NSUserDefaults observation (log reads, set verify flags)
// ============================================================

typedef id (*ObjForKeyIMP)(id, SEL, NSString *);
static ObjForKeyIMP orig_objectForKey = NULL;
static int g_nsudCount = 0;
static id hook_objectForKey(id self, SEL _cmd, NSString *key) {
    id val = orig_objectForKey ? orig_objectForKey(self, _cmd, key) : nil;
    // Log first 50 NSUserDefaults reads to avoid spam
    if (g_nsudCount < 50) {
        DLOG(@"[NSUD] objectForKey: %@ = %@", key, val);
    }
    g_nsudCount++;
    return val;
}

typedef BOOL (*BoolForKeyIMP)(id, SEL, NSString *);
static BoolForKeyIMP orig_boolForKey = NULL;
static BOOL hook_boolForKey(id self, SEL _cmd, NSString *key) {
    BOOL val = orig_boolForKey ? orig_boolForKey(self, _cmd, key) : NO;
    if (g_nsudCount < 50) {
        DLOG(@"[NSUD] boolForKey: %@ = %d", key, val);
    }
    g_nsudCount++;
    return val;
}

// ============================================================
#pragma mark - Observation-only hooks (log, don't modify)
// ============================================================

// NSDictionary objectForKey: - trace server list parsing (minimal logging)
static id (*orig_dictObjectForKey)(id, SEL, id) = NULL;
static int g_dictLogCount = 0;
static id hook_dictObjectForKey(id self, SEL _cmd, id key) {
    id ret = orig_dictObjectForKey ? orig_dictObjectForKey(self, _cmd, key) : nil;
    // Limit logging to first 30 calls to avoid performance issues during keyboard input
    if (g_dictLogCount < 30) {
        NSString *keyStr = [key isKindOfClass:[NSString class]] ? key : @"<non-string>";
        if ([keyStr containsString:@"server"] || [keyStr containsString:@"Server"] ||
            [keyStr containsString:@"status"] || [keyStr containsString:@"Status"] ||
            [keyStr containsString:@"list"] || [keyStr containsString:@"List"]) {
            NSString *retCls = ret ? NSStringFromClass([ret class]) : @"nil";
            DLOG(@"[DICT] objectForKey:'%@' -> %@ (%@)", keyStr, ret ?: @"nil", retCls);
            g_dictLogCount++;
        }
    }
    return ret;
}

// NSArray arrayForKey: - for JSON parsing (minimal logging)
static id (*orig_arrayForKey)(id, SEL, id) = NULL;
static int g_arrayLogCount = 0;
static id hook_arrayForKey(id self, SEL _cmd, id key) {
    id ret = orig_arrayForKey ? orig_arrayForKey(self, _cmd, key) : nil;
    // Limit logging to first 20 calls to avoid performance issues during keyboard input
    if (g_arrayLogCount < 20) {
        NSString *keyStr = [key isKindOfClass:[NSString class]] ? key : @"<non-string>";
        if ([keyStr containsString:@"server"] || [keyStr containsString:@"Server"] ||
            [keyStr containsString:@"list"] || [keyStr containsString:@"List"]) {
            NSUInteger cnt = 0;
            if ([ret isKindOfClass:[NSArray class]]) cnt = [ret count];
            DLOG(@"[DICT] arrayForKey:'%@' -> count=%lu", keyStr, (unsigned long)cnt);
            g_arrayLogCount++;
        }
    }
    return ret;
}

// NSURLSession.dataTaskWithRequest:completionHandler: - intercept and modify responses
typedef NSURLSessionDataTask *(*DTReqCompIMP)(id, SEL, NSURLRequest *, void (^)(NSData *, NSURLResponse *, NSError *));
static DTReqCompIMP orig_dtwrc = NULL;
static NSURLSessionDataTask *hook_dtwrc(id self, SEL _cmd, NSURLRequest *req, void (^comp)(NSData *, NSURLResponse *, NSError *)) {
    NSString *url = req.URL.absoluteString;
    DLOG(@"[NET] URL: %@", url);
    
    // Wrap completion handler to intercept and modify response
    void (^wrappedComp)(NSData *, NSURLResponse *, NSError *) = comp;
    if (comp) {
        wrappedComp = [^(NSData *data, NSURLResponse *resp, NSError *err) {
            NSHTTPURLResponse *httpResp = [resp isKindOfClass:[NSHTTPURLResponse class]] ? (NSHTTPURLResponse *)resp : nil;
            DLOG(@"[NET] Response: status=%ld url=%@ err=%@ bodyLen=%lu",
                 httpResp ? (long)httpResp.statusCode : -1, url, err, (unsigned long)data.length);
            
            if (data && data.length > 0) {
                NSString *body = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                
                if (body) {
                    DLOG(@"[NET] Body: %@", body);
                    
                    // Check if this is a server list response
                    BOOL isServerList = ([body containsString:@"server"] || [body containsString:@"servers"] || 
                                        [body containsString:@"serverCount"] || [body containsString:@"serverid"]);
                    
                    // Check if response indicates empty/no servers
                    BOOL isEmptyList = ([body containsString:@"\"serverCount\":0"] || 
                                        [body containsString:@"\"servers\":[]"] ||
                                        [body containsString:@"\"status\":5"] ||
                                        [body containsString:@"\"result\":\"fail\""]);
                    
                    if (isServerList && isEmptyList) {
                        DLOG(@"[NET-PATCH] Server list is empty, replacing with fake data");
                        NSString *fakeServerList = @"{\"status\":0,\"serverCount\":1,\"servers\":[{\"serverid\":1,\"name\":\"测试一区\",\"realname\":\"测试一区\",\"category\":\"一区\",\"serverType\":1,\"ip\":\"127.0.0.1\",\"port\":5678,\"status\":1,\"clientid\":1,\"onlinePlayerNum\":100,\"description\":\"运行\"}]}";
                        data = [fakeServerList dataUsingEncoding:NSUTF8StringEncoding];
                        DLOG(@"[NET-PATCH] Replaced with fake server list, new len=%lu", (unsigned long)data.length);
                    }
                    
                    // Check for version error
                    if ([body containsString:@"版本"] || [body containsString:@"更新"] || 
                        [body containsString:@"升级"] || [body containsString:@"版本过低"]) {
                        DLOG(@"[NET-PATCH] Detected version error, modifying...");
                        body = [body stringByReplacingOccurrencesOfString:@"\"status\":5" withString:@"\"status\":0"];
                        body = [body stringByReplacingOccurrencesOfString:@"\"result\":\"fail\"" withString:@"\"result\":\"success\""];
                        body = [body stringByReplacingOccurrencesOfString:@"版本过低" withString:@""];
                        body = [body stringByReplacingOccurrencesOfString:@"请更新" withString:@""];
                        data = [body dataUsingEncoding:NSUTF8StringEncoding];
                    }
                    
                    // Patch judgeAppInfoApi response: extend ENDTIME to future date
                    if ([url containsString:@"judgeAppInfoApi"] || [body containsString:@"ENDTIME"]) {
                        DLOG(@"[NET-PATCH] Detected judgeAppInfoApi response, extending ENDTIME");
                        // Replace any ENDTIME value with a future date (2027-12-31)
                        NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"\"ENDTIME\":\"[^\"]*\"" options:0 error:nil];
                        body = [regex stringByReplacingMatchesInString:body options:0 range:NSMakeRange(0, body.length) withTemplate:@"\"ENDTIME\":\"2027-12-31 23:59:59\""];
                        // Ensure END=0 (not ended) and OPEN=1 (open)
                        body = [body stringByReplacingOccurrencesOfString:@"\"END\":1" withString:@"\"END\":0"];
                        body = [body stringByReplacingOccurrencesOfString:@"\"OPEN\":0" withString:@"\"OPEN\":1"];
                        // Ensure code=1 (success) instead of code=0
                        body = [body stringByReplacingOccurrencesOfString:@"\"code\":0" withString:@"\"code\":1"];
                        data = [body dataUsingEncoding:NSUTF8StringEncoding];
                        DLOG(@"[NET-PATCH] Patched judgeAppInfoApi: ENDTIME extended, END=0, OPEN=1, code=1");
                    }
                    
                    // Patch any sign/cert API response to success
                    if ([url containsString:@"judgeAppInfoSignApi"] || [url containsString:@"postAppInfoApi"] || [url containsString:@"getAppInfoApi"]) {
                        DLOG(@"[NET-PATCH] Detected cert/sign API response, ensuring success");
                        if ([body containsString:@"\"code\":0"]) {
                            body = [body stringByReplacingOccurrencesOfString:@"\"code\":0" withString:@"\"code\":1"];
                            data = [body dataUsingEncoding:NSUTF8StringEncoding];
                            DLOG(@"[NET-PATCH] Patched cert API code:0 -> 1");
                        }
                    }
                }
            }
            
            comp(data, resp, err);
        } copy];
    }
    
    if (orig_dtwrc) return orig_dtwrc(self, _cmd, req, wrappedComp);
    return nil;
}

// NSURLSession.dataTaskWithRequest: (delegate mode, no completion handler)
// OBSERVE ONLY - no interception (delegate injection causes crashes)
typedef NSURLSessionDataTask *(*DTReqIMP)(id, SEL, NSURLRequest *);
static DTReqIMP orig_dtr = NULL;
static NSURLSessionDataTask *hook_dtr(id self, SEL _cmd, NSURLRequest *req) {
    DLOG(@"[NET-D] delegate URL: %@", req.URL.absoluteString);
    if (orig_dtr) return orig_dtr(self, _cmd, req);
    return nil;
}

// NSURLConnection.sendAsynchronousRequest:queue:completionHandler:
typedef void (*AsyncReqIMP)(id, SEL, NSURLRequest *, NSOperationQueue *, void (^)(NSURLResponse *, NSData *, NSError *));
static AsyncReqIMP orig_asyncReq = NULL;
static void hook_async(id self, SEL _cmd, NSURLRequest *req, NSOperationQueue *q, void (^comp)(NSURLResponse *, NSData *, NSError *)) {
    DLOG(@"[NET-C] async URL: %@", req.URL.absoluteString);
    if (orig_asyncReq) orig_asyncReq(self, _cmd, req, q, comp);
}

// NSURLConnection.sendSynchronousRequest:returningResponse:error:
typedef NSData *(*SyncReqIMP)(id, SEL, NSURLRequest *, NSURLResponse **, NSError **);
static SyncReqIMP orig_syncReq = NULL;
static NSData *hook_sync(id self, SEL _cmd, NSURLRequest *req, NSURLResponse **resp, NSError **err) {
    DLOG(@"[NET-C] sync URL: %@", req.URL.absoluteString);
    if (orig_syncReq) return orig_syncReq(self, _cmd, req, resp, err);
    return nil;
}

// UIViewController.presentViewController - OBSERVE + VERSION ALERT BLOCKING
// NOTE: presentViewController:animated:completion: is called ON THE PRESENTING VC,
// NOT on the presented VC. So we must hook UIViewController's version, not UIAlertController's!
// The previous hook on UIAlertController was NEVER triggered, and had WRONG param order causing SIGSEGV.
typedef void (*PresentVC_IMP)(id, SEL, UIViewController *, BOOL, void (^)(void));
static PresentVC_IMP orig_presentVC = NULL;
static void hook_presentVC(id self, SEL _cmd, UIViewController *vc, BOOL animated, void (^completion)(void)) {
    @try {
        // Check if presented VC is UIAlertController - block version-related alerts HERE
        if (vc && [vc isKindOfClass:[UIAlertController class]]) {
            @try {
                UIAlertController *alert = (UIAlertController *)vc;
                NSString *title = [alert title];
                NSString *msg = [alert message];
                NSString *presenterClass = NSStringFromClass([self class]);
                DLOG(@"[UI] presentVC: UIAlertController title='%@' msg='%@' presenter=%@",
                     title ? title : @"<nil>", msg ? msg : @"<nil>", presenterClass);
                
                if (title || msg) {
                    NSString *lowerMsg = msg ? [[msg lowercaseString] copy] : @"";
                    NSString *lowerTitle = title ? [[title lowercaseString] copy] : @"";
                    if ([lowerMsg containsString:@"版本过低"] || [lowerMsg containsString:@"版本太旧"] ||
                        [lowerMsg containsString:@"更新"] || [lowerTitle containsString:@"版本"] ||
                        [lowerMsg containsString:@"升级"] || [lowerMsg containsString:@"version"] ||
                        [lowerMsg containsString:@"update"]) {
                        DLOG(@"[ALERT-BLOCK] Blocked version alert in hook_presentVC: title='%@' msg='%@'",
                             title ? title : @"", msg ? msg : @"");
                        return;  // Do NOT present!
                    }
                }
            } @catch (NSException *e) {
                DLOG(@"[UI] Exception checking alert: %@", e.reason);
                // Passthrough on error - don't lose the alert completely
            }
        } else {
            NSString *vcClass = vc ? NSStringFromClass([vc class]) : @"<nil>";
            DLOG(@"[UI] presentVC: %@ presenter=%@", vcClass, NSStringFromClass([self class]));
        }
    } @catch (NSException *e) {
        DLOG(@"[UI] Outer exception in hook_presentVC: %@", e.reason);
    }
    
    // Always call original (unless we returned early for blocked alerts)
    // Safe completion: copy to heap, fallback to empty block
    void (^safeCompletion)(void) = NULL;
    if (completion) {
        @try {
            safeCompletion = [completion copy];
        } @catch (...) {
            safeCompletion = NULL;
        }
    }
    if (!safeCompletion) {
        safeCompletion = ^{};
    }
    
    if (orig_presentVC) {
        orig_presentVC(self, _cmd, vc, animated, safeCompletion);
    }
}

// ============================================================
#pragma mark - EncryptUtils Hook (v36.130 - FIXED RECURSION BUG)
// ============================================================
// Client uses EncryptUtils (BoringSSL) for RSA/AES decryption.
// We hook these class methods to return valid plaintext when forceValidDecrypt=YES.
//
// v36.130 CRITICAL FIX:
//   v36.129 had infinite recursion bug: non-bypass path used method_getImplementation()
//   which returns the REPLACED implementation (our hook), causing infinite recursion → crash.
//   FIX: Save original IMPs at install time, use saved IMPs in non-bypass path.
//
// v36.130 IMPROVEMENT:
//   Use bypass counter (up to 5) instead of one-shot flag, to handle multi-step decryption.

static BOOL g_encryptUtilsHooksInstalled = NO;
// Note: g_bypassRemaining, g_orig_rsaDecryptData, g_orig_rsaDecryptLarge, g_orig_aesDecryptData
// are defined earlier (near g_forceValidDecrypt) for forward access in hook_recv logic.

// Forward declaration for C++ Crypto Hook flag (defined later in C++ Crypto Hook section)
static BOOL g_cppCryptoHooksInstalled;

// Hook for +rsaDecryptData:withKeyRef:
// v36.132: ENCRYPT-BYPASS only triggers when C++ Crypto Hook is NOT installed
//          If C++ Hook is active, bypass is handled at C++ level (returning std::string)
//          EncryptUtils bypass would return NSData which causes C++ type mismatch crash
static NSData* hooked_rsaDecryptData(Class self, SEL _cmd, NSData *data, id keyRef) {
    if (g_forceValidDecrypt && data && g_bypassRemaining > 0 && !g_cppCryptoHooksInstalled) {
        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";
        NSData *fakeData = [NSData dataWithBytes:fakePlaintext length:strlen(fakePlaintext)];
        g_bypassRemaining--;
        DLOG(@"[ENCRYPT-BYPASS] v36.132: rsaDecryptData: SKIP real decrypt, return fake (remaining=%d, cppHook=%d)", g_bypassRemaining, g_cppCryptoHooksInstalled);
        if (g_bypassRemaining <= 0) {
            g_forceValidDecrypt = NO;
            DLOG(@"[ENCRYPT-BYPASS] v36.132: bypass exhausted, forceValidDecrypt=NO");
        }
        return fakeData;
    }
    // Non-bypass: use saved original IMP (no recursion!)
    if (g_orig_rsaDecryptData) {
        typedef NSData* (*OriginalFunc)(Class, SEL, NSData*, id);
        return ((OriginalFunc)g_orig_rsaDecryptData)(self, _cmd, data, keyRef);
    }
    return nil;
}

// Hook for +rsaDecryptLarge:withPrivateKey:
// v36.132: CRITICAL CHANGE - DO NOT trigger bypass when C++ Hook is installed!
//   C++ code expects std::string, not NSData. Returning NSData causes:
//   -[_NSInlineData UTF8String]: unrecognized selector → SIGABRT crash
//   Bypass is now handled by cpp_stub_force in C++ layer
static NSData* hooked_rsaDecryptLarge(Class self, SEL _cmd, NSData *data, NSData *privateKey) {
    if (g_forceValidDecrypt && data && g_bypassRemaining > 0 && !g_cppCryptoHooksInstalled) {
        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";
        NSData *fakeData = [NSData dataWithBytes:fakePlaintext length:strlen(fakePlaintext)];
        g_bypassRemaining--;
        DLOG(@"[ENCRYPT-BYPASS] v36.132: rsaDecryptLarge: SKIP real decrypt, return fake (remaining=%d, cppHook=%d)", g_bypassRemaining, g_cppCryptoHooksInstalled);
        if (g_bypassRemaining <= 0) {
            g_forceValidDecrypt = NO;
            DLOG(@"[ENCRYPT-BYPASS] v36.132: bypass exhausted, forceValidDecrypt=NO");
        }
        return fakeData;
    }
    // C++ Hook is installed - always pass through to original (C++ layer handles bypass)
    if (g_cppCryptoHooksInstalled && g_forceValidDecrypt) {
        DLOG(@"[ENCRYPT-PASS] v36.132: rsaDecryptLarge: pass through to original (C++ hook active, cppHook=%d)", g_cppCryptoHooksInstalled);
    }
    if (g_orig_rsaDecryptLarge) {
        typedef NSData* (*OriginalFunc)(Class, SEL, NSData*, NSData*);
        return ((OriginalFunc)g_orig_rsaDecryptLarge)(self, _cmd, data, privateKey);
    }
    return nil;
}

// Hook for +aesDecryptData:key:iv:
static NSData* hooked_aesDecryptData(Class self, SEL _cmd, NSData *data, NSData *key, NSData *iv) {
    if (g_forceValidDecrypt && data && g_bypassRemaining > 0 && !g_cppCryptoHooksInstalled) {
        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";
        NSData *fakeData = [NSData dataWithBytes:fakePlaintext length:strlen(fakePlaintext)];
        g_bypassRemaining--;
        DLOG(@"[ENCRYPT-BYPASS] v36.132: aesDecryptData: SKIP real decrypt, return fake (remaining=%d, cppHook=%d)", g_bypassRemaining, g_cppCryptoHooksInstalled);
        if (g_bypassRemaining <= 0) {
            g_forceValidDecrypt = NO;
            DLOG(@"[ENCRYPT-BYPASS] v36.132: bypass exhausted, forceValidDecrypt=NO");
        }
        return fakeData;
    }
    if (g_orig_aesDecryptData) {
        typedef NSData* (*OriginalFunc)(Class, SEL, NSData*, NSData*, NSData*);
        return ((OriginalFunc)g_orig_aesDecryptData)(self, _cmd, data, key, iv);
    }
    return nil;
}

// Install EncryptUtils hooks
static void installEncryptUtilsHooks_v130(void) {
    @try {
        if (g_encryptUtilsHooksInstalled) return;
        
        Class encryptUtilsCls = NSClassFromString(@"EncryptUtils");
        if (!encryptUtilsCls) {
            DLOG(@"[ENCRYPT-HOOK] v36.130: EncryptUtils class NOT found");
            return;
        }
        
        Class metaCls = object_getClass(encryptUtilsCls);
        DLOG(@"[ENCRYPT-HOOK] v36.130: EncryptUtils found, metaCls=%p", metaCls);
        
        // Hook +rsaDecryptData:withKeyRef:
        SEL sel1 = NSSelectorFromString(@"rsaDecryptData:withKeyRef:");
        if ([metaCls instancesRespondToSelector:sel1]) {
            Method m = class_getInstanceMethod(metaCls, sel1);
            if (m) {
                g_orig_rsaDecryptData = method_getImplementation(m);
                method_setImplementation(m, (IMP)hooked_rsaDecryptData);
                DLOG(@"[ENCRYPT-HOOK] v36.130: OK - Hooked +rsaDecryptData:withKeyRef: (orig=%p)", g_orig_rsaDecryptData);
            }
        }
        
        // Hook +rsaDecryptLarge:withPrivateKey:
        SEL sel2 = NSSelectorFromString(@"rsaDecryptLarge:withPrivateKey:");
        if ([metaCls instancesRespondToSelector:sel2]) {
            Method m = class_getInstanceMethod(metaCls, sel2);
            if (m) {
                g_orig_rsaDecryptLarge = method_getImplementation(m);
                method_setImplementation(m, (IMP)hooked_rsaDecryptLarge);
                DLOG(@"[ENCRYPT-HOOK] v36.130: OK - Hooked +rsaDecryptLarge:withPrivateKey: (orig=%p)", g_orig_rsaDecryptLarge);
            }
        }
        
        // Hook +aesDecryptData:key:iv:
        SEL sel3 = NSSelectorFromString(@"aesDecryptData:key:iv:");
        if ([metaCls instancesRespondToSelector:sel3]) {
            Method m = class_getInstanceMethod(metaCls, sel3);
            if (m) {
                g_orig_aesDecryptData = method_getImplementation(m);
                method_setImplementation(m, (IMP)hooked_aesDecryptData);
                DLOG(@"[ENCRYPT-HOOK] v36.130: OK - Hooked +aesDecryptData:key:iv: (orig=%p)", g_orig_aesDecryptData);
            }
        }
        
        g_encryptUtilsHooksInstalled = YES;
        DLOG(@"[ENCRYPT-HOOK] v36.130: All EncryptUtils hooks installed (orig IMPs saved, non-bypass = safe)");
    } @catch (NSException *e) {
        DLOG(@"[ENCRYPT-HOOK] v36.130: Exception: %@", e.reason);
    }
}

// ============================================================
#pragma mark - C++ Crypto Hook (v36.131 - FIX CRASH)
// ============================================================
// CRITICAL FINDING (v36.130 crash analysis):
//   Client uses cocos2d::CCFileUtils::rsaDecryptLarge (C++), NOT EncryptUtils (ObjC).
//   EncryptUtils is called indirectly, but C++ code is the actual entry point.
//   Hook strategy:
//     1. Keep EncryptUtils hooks for ObjC path (login cert verification)
//     2. ADD C++ function hooks using rebind_symbols for CCFileUtils::rsaDecryptLarge
//     3. When forceValidDecrypt=YES, return empty string immediately
//
// The crash in v36.130:
//   -[_NSInlineData UTF8String]: unrecognized selector
//   C++ code got NSData back from EncryptUtils hook, tried UTF8String on it.
//   Fix: Hook at C++ level, return std::string directly.
//
// v36.131 CRITICAL FIX:
//   Previous cpp_stub_force had WRONG register handling:
//   - It constructed std::string on stack (sp+16), NOT in x0 output buffer
//   - ARM64 ABI: return value std::string is written to x0 (output buffer)
//   - Calling convention: x0=output_buf, x1=this, x2=arg1, x3=arg2
//   Fixed: Write empty string directly to x0 buffer, keep all args unchanged
//   For original call: restore frame, BR to original (not BL, no new frame)

// g_cppCryptoHooksInstalled is defined as static BOOL above (line ~6430), initialized to 0 (= NO)
// Saved original C++ function pointers
// NOTE: g_cppOrig must NOT be static because it's referenced from
// inline ARM64 assembly in cpp_stub_force()
typedef struct {
    void *orig_rsaDecryptLarge;
    void *orig_rsaDecryptData;
} CppCryptoOrig;

CppCryptoOrig g_cppOrig = {NULL, NULL};

// Empty string constant
static const char g_cppEmptyStr[] = "";

// Success response string for bypass
// NOTE: g_cppSuccessStr must NOT be static because it's referenced from
// inline ARM64 assembly in cpp_stub_force()
const char g_cppSuccessStr[] = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";

// ARM64 C stub for CCFileUtils::rsaDecryptLarge
// C++ member function ABI (ARM64) - CRITICAL for large return:
//   For functions returning objects > 16 bytes (like std::string):
//   x0 = output buffer pointer (caller-allocated, 24 bytes for std::string)
//   x1 = this pointer
//   x2 = first arg (std::string const&)
//   x3 = second arg (std::string const&)
// Return: std::string written to x0 buffer, x0 stays as buffer ptr
//
// v36.132 FIX: Pure C implementation (no inline assembly)
//   - Correct function signature matches ARM64 ABI
//   - Writes fake std::string to output_buf directly via pointer manipulation
//   - Calls original function via function pointer for non-bypass path
void cpp_stub_force(void* output_buf, void* self, void* data, void* key) {
    // Check forceValidDecrypt flag (now a non-static global variable)
    if (g_forceValidDecrypt) {
        // Bypass path: write fake success std::string to output_buf
        // std::string internal layout (for Apple's libc++):
        //   offset 0: char* data_ (pointer to string data)
        //   offset 8: size_t length_
        //   offset 16: size_t capacity_
        // Note: For strings <= 15 chars, libc++ uses SSO (small string optimization)
        // which stores data inline. But our 37-char string exceeds SSO threshold,
        // so it uses heap allocation with a pointer.
        const char* fakeStr = "{\"code\":0,\"msg\":\"success\",\"data\":{\"result\":true}}";
        size_t fakeLen = 37;  // strlen(fakeStr)
        
        // Write directly to the output buffer (caller's std::string storage)
        char** dataPtr = (char**)output_buf;
        *dataPtr = (char*)fakeStr;  // data_ = pointer to fake string
        
        size_t* lenPtr = (size_t*)((char*)output_buf + 8);
        *lenPtr = fakeLen;  // length_ = 37
        
        size_t* capPtr = (size_t*)((char*)output_buf + 16);
        *capPtr = fakeLen;  // capacity_ = 37 (must be >= length_)
        
        return;
    }
    
    // Normal path: call original function
    // Use function pointer stored in g_cppOrig.orig_rsaDecryptLarge
    typedef void (*OriginalFunc)(void* output_buf, void* self, void* data, void* key);
    OriginalFunc origFunc = (OriginalFunc)g_cppOrig.orig_rsaDecryptLarge;
    if (origFunc) {
        origFunc(output_buf, self, data, key);
    }
}

// Install C++ crypto hooks using rebind_symbols
static void installCppCryptoHooks_v131(void) {
    if (g_cppCryptoHooksInstalled) return;
    
    DLOG(@"[CPP-CRYPTO] v36.131: Installing C++ crypto hooks for CCFileUtils::rsaDecryptLarge...");
    
    // The mangled name for cocos2d::CCFileUtils::rsaDecryptLarge
    // std::string rsaDecryptLarge(std::string const&, std::string const&)
    const char* mangledName = "_ZN7cocos2d11CCFileUtils15rsaDecryptLargeENSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES7_";
    
    void* sym = NULL;
    int imageCount = (int)_dyld_image_count();
    
    // Search in game binary and dylibs
    for (int i = 0; i < imageCount; i++) {
        const char* imageName = _dyld_get_image_name(i);
        if (!imageName) continue;
        
        if (strstr(imageName, "wangxian") || 
            strstr(imageName, "WangXian") ||
            strstr(imageName, "lnSignature") ||
            strstr(imageName, "libSupport")) {
            
            DLOG(@"[CPP-CRYPTO] Searching in image %d: %s", i, imageName);
            
            void* handle = dlopen(imageName, RTLD_LAZY | RTLD_NOLOAD);
            if (handle) {
                void* sym2 = dlsym(handle, mangledName);
                if (sym2) {
                    sym = sym2;
                    DLOG(@"[CPP-CRYPTO] FOUND %s at %p in %s", mangledName, sym, imageName);
                    dlclose(handle);
                    break;
                }
                dlclose(handle);
            }
        }
    }
    
    // If not found, try alternative names
    if (!sym) {
        DLOG(@"[CPP-CRYPTO] First search failed, trying alternate mangled names...");
        
        const char* altNames[] = {
            "_ZN7cocos2d11CCFileUtils15rsaDecryptLargeENSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES7_",
            "_ZN7cocos2d11CCFileUtils15rsaDecryptLargeE",
            NULL
        };
        
        for (int j = 0; altNames[j]; j++) {
            for (int i = 0; i < imageCount; i++) {
                const char* imageName = _dyld_get_image_name(i);
                if (!imageName) continue;
                
                if (strstr(imageName, "wangxian") || 
                    strstr(imageName, "WangXian") ||
                    strstr(imageName, "lnSignature") ||
                    strstr(imageName, "libSupport")) {
                    
                    void* handle = dlopen(imageName, RTLD_LAZY | RTLD_NOLOAD);
                    if (handle) {
                        void* sym2 = dlsym(handle, altNames[j]);
                        if (sym2) {
                            sym = sym2;
                            DLOG(@"[CPP-CRYPTO] FOUND '%s' at %p in %s", altNames[j], sym, imageName);
                            dlclose(handle);
                            break;
                        }
                        dlclose(handle);
                    }
                }
                if (sym) break;
            }
            if (sym) break;
        }
    }
    
    if (sym) {
        g_cppOrig.orig_rsaDecryptLarge = sym;
        DLOG(@"[CPP-CRYPTO] Original rsaDecryptLarge at %p", sym);
        
        // Get the header of the main executable
        const mach_header* mainHeader = (const mach_header*)_dyld_get_image_header(0);
        if (mainHeader) {
            DLOG(@"[CPP-CRYPTO] Main header: %p, rebinding...", mainHeader);
            
            struct rebinding rebinds[] = {
                { mangledName, (void*)cpp_stub_force, NULL }
            };
            
            int result = rebind_symbols_image((void*)mainHeader, NULL, rebinds, 1);
            DLOG(@"[CPP-CRYPTO] rebind_symbols_image result: %d", result);
            
            if (result == 0) {
                DLOG(@"[CPP-CRYPTO] v36.131: C++ crypto hooks installed successfully!");
                g_cppCryptoHooksInstalled = YES;
            } else {
                DLOG(@"[CPP-CRYPTO] v36.131: rebind_symbols_image failed (result=%d). Trying dlopen approach...", result);
                
                // Alternative: dlopen and use rebind_symbols on that handle
                void* mainHandle = dlopen(NULL, RTLD_LAZY);
                if (mainHandle) {
                    struct rebinding rebinds2[] = {
                        { mangledName, (void*)cpp_stub_force, NULL }
                    };
                    int result2 = rebind_symbols_image(
                        (void*)_dyld_get_image_header(0),
                        NULL,
                        rebinds2,
                        1
                    );
                    DLOG(@"[CPP-CRYPTO] Second rebind attempt result: %d", result2);
                    if (result2 == 0) {
                        g_cppCryptoHooksInstalled = YES;
                        DLOG(@"[CPP-CRYPTO] v36.131: C++ crypto hooks installed via second attempt!");
                    }
                }
            }
        }
    } else {
        DLOG(@"[CPP-CRYPTO] FAILED to find rsaDecryptLarge symbol.");
        DLOG(@"[CPP-CRYPTO] Will dump all rsaDecrypt-related symbols for debugging...");
        
        // Dump symbols containing "rsaDecrypt" or "CCFileUtils"
        for (int i = 0; i < imageCount; i++) {
            const char* imageName = _dyld_get_image_name(i);
            if (!imageName) continue;
            
            if (strstr(imageName, "wangxian") || strstr(imageName, "WangXian")) {
                DLOG(@"[CPP-CRYPTO] Searching in: %s", imageName);
                
                void* handle = dlopen(imageName, RTLD_LAZY | RTLD_NOLOAD);
                if (handle) {
                    const char* patterns[] = {
                        "rsaDecryptLarge",
                        "rsaDecryptData",
                        "CCFileUtils",
                        "encryptData",
                        "decryptData",
                        NULL
                    };
                    
                    for (int p = 0; patterns[p]; p++) {
                        void* sym2 = dlsym(handle, patterns[p]);
                        if (sym2) {
                            DLOG(@"[CPP-CRYPTO] Found '%s' at %p", patterns[p], sym2);
                        }
                    }
                    dlclose(handle);
                }
                break;
            }
        }
    }
    
    DLOG(@"[CPP-CRYPTO] v36.131: installCppCryptoHooks completed (installed=%d)", g_cppCryptoHooksInstalled);
}

// ============================================================
#pragma mark - v37.0 Minimal Recv Hook (login server patches only)
// ============================================================

// v37.6: Patch login server response data in-place
// ONLY patches status byte for 0x802EE118/120/121 — NO string modifications
// v37.6 FIX: v37.1-v37.4 patched status + cleared strings, which corrupted
//            response body → '网络连接中断'. v37.5 disabled recv hook entirely
//            → '版本过低' returned. v37.6: ONLY patch status=4→0, leave body intact.
//            Client sees status=0 (success) + original body → parses server list correctly.
static void patchLoginServerData(uint8_t *data, ssize_t len) {
    if (len < 8) return;

    // v37.12: ONLY clear "版本过低" string — do NOT modify status, do NOT replace other strings
    // v37.6 showed status patch → '网络连接中断'. v37.1-v37.4 showed string patch → '网络连接中断'.
    // v37.12 tries: ONLY clear "版本过低" (12 bytes UTF-8 → 12 spaces), keep everything else intact.

    // Clear "版本过低" (UTF-8: E7 89 88 E6 9C AC E8 BF 87 E4 BD 8E) → 12 spaces
    static const uint8_t versionLow[] = {0xE7,0x89,0x88,0xE6,0x9C,0xAC,0xE8,0xBF,0x87,0xE4,0xBD,0x8E};
    for (ssize_t i = 0; i <= len - 12; i++) {
        if (memcmp(data + i, versionLow, 12) == 0) {
            memset(data + i, 0x20, 12);
            DLOG(@"[RECV-PATCH] v37.12: Cleared '版本过低' at offset %zd (status untouched)", i);
        }
    }

    // Also clear "当前版本" (UTF-8: E5 BD 93 E5 89 8D E7 89 88 E6 9C AC) → 12 spaces
    static const uint8_t curVersion[] = {0xE5,0xBD,0x93,0xE5,0x89,0x8D,0xE7,0x89,0x88,0xE6,0x9C,0xAC};
    for (ssize_t i = 0; i <= len - 12; i++) {
        if (memcmp(data + i, curVersion, 12) == 0) {
            memset(data + i, 0x20, 12);
            DLOG(@"[RECV-PATCH] v37.12: Cleared '当前版本' at offset %zd", i);
        }
    }
}

// v37.0: Minimal recv hook — patches login server responses ONLY
static ssize_t hook_recv_minimal(int fd, void *buf, size_t len, int flags) {
    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recv) return -1;

    ssize_t ret = orig_recv(fd, buf, len, flags);
    if (ret > 0) {
        patchLoginServerData((uint8_t *)buf, ret);
    }
    return ret;
}

// v37.0: Minimal recvfrom hook
static ssize_t hook_recvfrom_minimal(int fd, void *buf, size_t len, int flags,
                                     struct sockaddr *from, socklen_t *fromlen) {
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvfrom) return -1;

    ssize_t ret = orig_recvfrom(fd, buf, len, flags, from, fromlen);
    if (ret > 0) {
        patchLoginServerData((uint8_t *)buf, ret);
    }
    return ret;
}

// v37.0: Minimal recvmsg hook
static ssize_t hook_recvmsg_minimal(int fd, struct msghdr *msg, int flags) {
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");
    if (!orig_recvmsg) return -1;

    ssize_t ret = orig_recvmsg(fd, msg, flags);
    if (ret > 0 && msg && msg->msg_iov && msg->msg_iovlen > 0) {
        // Patch first iov buffer
        struct iovec *iov = &msg->msg_iov[0];
        if (iov->iov_base && iov->iov_len >= 8) {
            patchLoginServerData((uint8_t *)iov->iov_base, MIN((ssize_t)iov->iov_len, ret));
        }
    }
    return ret;
}

// v37.0: Install minimal recv hooks (login server patches only, no game server mods)
static void installMinimalSocketHooks(void) {
    DLOG(@"[SOCK-MINIMAL] v37.6: Installing minimal recv hooks (status-only patch)...");

    int r = rebindSymbol("_recv", (void *)hook_recv_minimal, (void **)&orig_recv);
    int rf = rebindSymbol("_recvfrom", (void *)hook_recvfrom_minimal, (void **)&orig_recvfrom);
    int rm = rebindSymbol("_recvmsg", (void *)hook_recvmsg_minimal, (void **)&orig_recvmsg);

    if (!orig_recv) orig_recv = (RecvFunc)dlsym(RTLD_NEXT, "recv");
    if (!orig_recvfrom) orig_recvfrom = (RecvfromFunc)dlsym(RTLD_NEXT, "recvfrom");
    if (!orig_recvmsg) orig_recvmsg = (RecvmsgFunc)dlsym(RTLD_NEXT, "recvmsg");

    DLOG(@"[SOCK-MINIMAL] recv=%d recvfrom=%d recvmsg=%d (orig: recv=%p recvfrom=%p recvmsg=%p)",
         r, rf, rm, orig_recv, orig_recvfrom, orig_recvmsg);
}

// ============================================================
#pragma mark - Constructor - MINIMAL + observer hooks
// ============================================================

__attribute__((constructor))
static void entry(void) {
    log_init();
    
    if (!g_isActivated) {
        DLOG(@"[ACT] Not activated, waiting for activation...");
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            if (!g_isActivated) {
                DLOG(@"[ACT] Still not activated after 3 seconds");
            }
        });
        return;
    }
    
    installAllHooks();
}

// v37.26: MULTI-LAYER channel name interception at ALL construction points.
//
// v37.25 FAILED: NSBundle hook found 0 replacements → Info.plist does NOT
// contain DY_MIESHI. The channel is a hardcoded C-string compiled into the
// client binary, propagated via memcpy/CFString/NSString/CCCrypt-plaintext.
//
// v37.24 MEM-PATCH conceptually worked but white-screened because we logged
// "DY_MIESHI at 0x..." which itself contained DY_MIESHI text → patch loop.
//
// v37.26 6-LAYER defense (no memory scan, NO recursive logging):
//   L1: CFStringCreateWithCString        → "DY_MIESHI" C-string → CFSTR
//   L2: +[NSString stringWithUTF8String:] / -[NSString initWithUTF8String:]
//                                           → ObjC string construction
//   L3: memcpy(dest, src, n)              → C structure copy DY_MIESHI
//         src matches exactly → use longer replacement
//   L4: CCCrypt (op=0 ENC)               → plaintext JSON/protobuf buffer
//                                           BEFORE AES encrypt, find/replace
//   L5: send() ALL cmd on login+game ports → find DY_MIESHI in send buffer
//         (skip signed packets: 0x0000E002, 0x002EE118, 0x0002A018, 0x002EE121
//          on port 5678 — v37.21 proved EE121 signature HASH check kills conn)
//   L6: cmd=0x000EE007 channel len patch  → legacy safety net
//
// NO LOGGING of DY_MIESHI text in layer hooks to avoid self-recursion.
// Only ONE final diagnostic log per unique call site using numeric tags.

// ===== L0: strlen / strcmp / strncmp hooks (INIT TIME propagation) =====
// v37.33: Channel is hardcoded as C-string literal "DY_MIESHI" in TEXT.__cstring.
// If client reads DY_MIESHI at init time, construct_NEW_USER_ENTER_SERVER_REQER
// builds ONLY 604B JSON (missing accountId/hasRole/serverInfo fields). If it reads
// "DYanyou0040_MIESHI" then it builds 1010B FULL JSON. Hence we need to propagate
// channel replacement BEFORE any ObjC / JSON builder code runs. So intercept
// strlen + strcmp + strncmp at libSystem level. Combined with L3 memcpy fix,
// EVERY call site (allocation, comparison, copy) sees the LONGER correct channel.

// Canonical long channel. We keep static storage; if strlen("DY_MIESHI") is called,
// return 18 instead of 9 → caller mallocs 19 bytes → then our memcpy L3 can fit.
static const char kLongChannel[20] = "DYanyou0040_MIESHI"; // 18 + NUL

static size_t (*orig_strlen)(const char *s) = NULL;
static size_t hook_strlen(const char *s) {
    if (!orig_strlen) orig_strlen = (size_t (*)(const char*))dlsym(RTLD_NEXT, "strlen");
    // Use memcmp (NOT strcmp — strcmp is hooked and will recurse!)
    if (s && memcmp(s, "DY_MIESHI", 10) == 0) { // 10 = 9 chars + NUL
        return 18;
    }
    return orig_strlen ? orig_strlen(s) : ((size_t(*)(const char*))strlen)(s);
}

static int (*orig_strcmp)(const char *a, const char *b) = NULL;
static int hook_strcmp(const char *a, const char *b) {
    if (!orig_strcmp) orig_strcmp = (int (*)(const char*, const char*))dlsym(RTLD_NEXT, "strcmp");
    // Check channel forms with memcmp (to avoid recursion into strcmp)
    int sa = 0, sb = 0;
    if (a) {
        if (memcmp(a, "DY_MIESHI", 10) == 0) sa = 1;
        else if (memcmp(a, "DYanyou0040_MIESHI", 19) == 0) sa = 2;
    }
    if (b) {
        if (memcmp(b, "DY_MIESHI", 10) == 0) sb = 1;
        else if (memcmp(b, "DYanyou0040_MIESHI", 19) == 0) sb = 2;
    }
    if (sa > 0 && sb > 0) return 0; // canonical equivalence
    if (sa > 0) a = kLongChannel;
    if (sb > 0) b = kLongChannel;
    return orig_strcmp ? orig_strcmp(a, b) : ((int (*)(const char*,const char*))strcmp)(a, b);
}

static int (*orig_strncmp)(const char *a, const char *b, size_t n) = NULL;
static int hook_strncmp(const char *a, const char *b, size_t n) {
    if (!orig_strncmp) orig_strncmp = (int (*)(const char*, const char*, size_t))dlsym(RTLD_NEXT, "strncmp");
    BOOL aCh = NO, bCh = NO;
    if (a && n >= 9 && memcmp(a, "DY_MIESHI", 9) == 0) aCh = YES;
    else if (a && n >= 18 && memcmp(a, "DYanyou0040_MIESHI", 18) == 0) aCh = YES;
    if (b && n >= 9 && memcmp(b, "DY_MIESHI", 9) == 0) bCh = YES;
    else if (b && n >= 18 && memcmp(b, "DYanyou0040_MIESHI", 18) == 0) bCh = YES;
    if (aCh && bCh) return 0;
    if (aCh && n >= 18) a = kLongChannel;
    if (bCh && n >= 18) b = kLongChannel;
    return orig_strncmp ? orig_strncmp(a, b, n) : ((int(*)(const char*,const char*,size_t))strncmp)(a, b, n);
}

// ===== L3: memcpy interception (v37.33 fixed) =====
typedef void *(*memcpyFunc)(void *dest, const void *src, size_t n);
static memcpyFunc orig_memcpy = NULL;
static void *hook_memcpy(void *dest, const void *src, size_t n) {
    // DY_MIESHI is 9 chars; if src starts with it, propagate replacement.
    // v37.33: because strlen hook already returns 18, callers who do
    //   char *buf = malloc(strlen(s)+1); memcpy(buf, s, strlen(s)+1);
    // now allocate 19 bytes and memcpy 19 bytes (n==19 or n>=18 since strlen→18).
    // Hence dest capacity is sufficient to fit replacement. We just copy.
    if (src && n >= 9 && memcmp(src, "DY_MIESHI", 9) == 0) {
        // Case A: exact 9-byte or 10-byte (9 + NUL) — handled if n>=18 (thanks to strlen hook).
        // If n >= 19 we can write full replacement + safety null term.
        if (n >= 19) {
            static int count = 0;
            if (count < 3) { DLOG(@"[CH-L3] memcpy_short→long n=%zu site=%d", n, count); count++; }
            size_t rlen = 18;
            if (orig_memcpy) orig_memcpy(dest, kLongChannel, rlen);
            // NUL fill remaining
            if (n > rlen) memset((char*)dest + rlen, 0, n - rlen);
            return dest;
        }
        // Case B: n is smaller (e.g. fixed struct copy of 10 bytes or less).
        // Can't expand → leave as-is; L4/network-layer patch later will correct.
    }
    return orig_memcpy ? orig_memcpy(dest, src, n) : memcpy(dest, src, n);
}

// ===== L1: CFStringCreateWithCString =====
typedef CFStringRef (*CFStringCreateWithCStringFunc)(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding);
static CFStringCreateWithCStringFunc orig_CFStringCreateWithCString = NULL;
static CFStringRef hook_CFStringCreateWithCString(CFAllocatorRef alloc, const char *cStr, CFStringEncoding encoding) {
    if (!orig_CFStringCreateWithCString) {
        orig_CFStringCreateWithCString = (CFStringCreateWithCStringFunc)dlsym(RTLD_NEXT, "CFStringCreateWithCString");
    }
    if (cStr && encoding == kCFStringEncodingUTF8 && memcmp(cStr, "DY_MIESHI", 10) == 0) {
        static int count = 0;
        if (count < 3) { DLOG(@"[CH-L1] tag=CFStringCreateWithCString site=%d", count); count++; }
        return CFStringCreateWithCString(alloc, kLongChannel, encoding);
    }
    return orig_CFStringCreateWithCString ? orig_CFStringCreateWithCString(alloc, cStr, encoding) : NULL;
}

// ===== L2: NSString UTF8 hooks =====
static id (*orig_stringWithUTF8String)(Class self, SEL _cmd, const char *cStr);
static id hook_stringWithUTF8String(Class self, SEL _cmd, const char *cStr) {
    if (cStr && memcmp(cStr, "DY_MIESHI", 10) == 0) {
        static int count = 0;
        if (count < 3) { DLOG(@"[CH-L2] tag=stringWithUTF8String site=%d", count); count++; }
        return orig_stringWithUTF8String(self, _cmd, kLongChannel);
    }
    return orig_stringWithUTF8String(self, _cmd, cStr);
}
static id (*orig_initWithUTF8String)(NSString *self, SEL _cmd, const char *cStr);
static id hook_initWithUTF8String(NSString *self, SEL _cmd, const char *cStr) {
    if (cStr && memcmp(cStr, "DY_MIESHI", 10) == 0) {
        static int count = 0;
        if (count < 3) { DLOG(@"[CH-L2] tag=initWithUTF8String site=%d", count); count++; }
        return orig_initWithUTF8String(self, _cmd, kLongChannel);
    }
    return orig_initWithUTF8String(self, _cmd, cStr);
}

// ===== L4: CCCrypt plaintext ENC replacement =====
// (replaces old hook_CCCrypt)
static int hook_CCCrypt_v37_26(uint32_t op, uint32_t alg, uint32_t options,
                                const void *key, size_t keyLen,
                                const void *iv,
                                const void *dataIn, size_t dataInLen,
                                void *dataOut, size_t dataOutAvailable, size_t *dataOutMoved) {
    if (!orig_CCCrypt) orig_CCCrypt = (CCCryptFunc)dlsym(RTLD_NEXT, "CCCrypt");
    if (!orig_CCCrypt) return -1;

    // v37.28: L4 gate — only active after game server challenge (0x80FFF495).
    // Before that, pass through unchanged to avoid crashing JudgeApp/SecKey.
    if (!g_cccrypt_l4_active) {
        return orig_CCCrypt(op, alg, options, key, keyLen, iv,
                            dataIn, dataInLen, dataOut, dataOutAvailable, dataOutMoved);
    }

    const char *opStr = (op == 0) ? "ENC" : "DEC";

    // v36.126: Skip real AES decryption when forceValidDecrypt=YES
    if (op == 1 && g_forceValidDecrypt) {
        DLOG(@"[SEC-BYPASS] v36.126: CCCrypt DEC SKIPPING real decrypt (inLen=%zu, keyLen=%zu)", dataInLen, keyLen);
        const char *fakePlaintext = "{\"code\":0,\"msg\":\"success\"}";
        size_t fakeLen = strlen(fakePlaintext);
        if (fakeLen <= dataOutAvailable) {
            memcpy(dataOut, fakePlaintext, fakeLen);
            if (dataOutMoved) *dataOutMoved = fakeLen;
            return 0;
        }
        return -1;
    }

    // L4: ENCRYPT only — scan plaintext dataIn for channel+deviceModel+GPU strings,
    // create patched buffer with canonical replacements.
    //
    // v37.31: Replaces 3 strings (not only channel):
    //   DY_MIESHI           (9)  → DYanyou0040_MIESHI (18)  +9B each
    //   iPhone 16 Pro Max   (17) → iPhone7Plus       (11)  -6B each
    //   Apple Inc. Apple A18 Pro GPU (28) → Apple Inc. Apple A10 GPU (24)  -4B each
    // Net per occurrence: +9 -6 -4 = -1B.
    // If all 3 found: -1B. If only channel: +9B.
    const void *realDataIn = dataIn;
    size_t  realDataInLen = dataInLen;
    void   *patchedBuf = NULL;
    int patchCount = 0;
    int chCount = 0, dmCount = 0, gpCount = 0;
    if (op == 0 && dataIn && dataInLen >= 9) {
        // First pass: count ALL replacements
        const char *scanP = (const char *)dataIn;
        const char *scanEnd = scanP + dataInLen;
        const char *pcur = scanP;
        chCount = dmCount = gpCount = 0;
        while (pcur < scanEnd) {
            size_t rem = (size_t)(scanEnd - pcur);
            if (rem >= 9 && memcmp(pcur, "DY_MIESHI", 9) == 0) {
                BOOL bounded = YES;
                // Only match when it's clearly the channel field (in JSON, between " or delimiters)
                // To avoid false positives, only match when surrounded by quotes/braces
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                char next = (pcur + 9 < scanEnd) ? *(pcur+9) : 0;
                bounded = (prev == '"' || prev == ':' || prev == ',' || prev == '{' || prev == '[' || prev == ' ') &&
                          (next == '"' || next == ',' || next == '}' || next == ']' || next == ' ' || next == '\0' || next == ':');
                if (bounded) chCount++;
                pcur += 9;
            } else if (rem >= 17 && memcmp(pcur, "iPhone 16 Pro Max", 17) == 0) {
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                char next = (pcur + 17 < scanEnd) ? *(pcur+17) : 0;
                BOOL bounded = (prev == '"' || prev == ':') && (next == '"' || next == ',');
                if (bounded) dmCount++;
                pcur += 17;
            } else if (rem >= 28 && memcmp(pcur, "Apple Inc. Apple A18 Pro GPU", 28) == 0) {
                char prev = (pcur > scanP) ? *(pcur-1) : 0;
                char next = (pcur + 28 < scanEnd) ? *(pcur+28) : 0;
                BOOL bounded = (prev == '"' || prev == ':') && (next == '"' || next == ',');
                if (bounded) gpCount++;
                pcur += 28;
            } else {
                pcur++;
            }
        }
        patchCount = chCount + dmCount + gpCount;
        // v37.35: Save AES key+iv+alg+options from ANY ENC call in FFF493 range.
        // v37.37 CRITICAL FIX: Must save from FFF493#2 (inLen 500-800B) NOT FFF493#1!
        // AES-CBC uses different IV per message. Using FFF493#1's IV to encrypt FFF493#2
        // produces wrong ciphertext → server can't decrypt → no response.
        // Always update to the LATEST ENC call's key+iv.
        if (op == 0 && keyLen <= 32 && dataInLen >= 200 && dataInLen <= 800) {
            memcpy(g_saved_aes_key, key, keyLen);
            memcpy(g_saved_aes_iv, iv, keyLen);
            g_saved_key_len = keyLen;
            g_saved_alg = alg;
            g_saved_options = options;
            g_aes_key_saved = YES;
            NSMutableString *ivHex = [NSMutableString string];
            for (size_t i = 0; i < keyLen && i < 16; i++) [ivHex appendFormat:@"%02X", ((uint8_t*)iv)[i]];
            DLOG(@"[FFF493-REPL] v37.37: Updated AES key(%zuB)+iv=%@ alg=%u opt=%u from ENC inLen=%zu", keyLen, ivHex, alg, options, dataInLen);
        }
        // v37.43: isFFF493_2_stub detection DISABLED. The detection (starts with
        // {"username" && no accountId) was wrong — real client FFF493#2 JSON also
        // matches this pattern (611B native, no accountId field). This led to saving
        // a forged "extended plaintext" (1350B with fake accountId/hasRole/serverInfo)
        // which the send-hook then used to replace the native 896B packet with 1880B
        // forged packet → server returned only heartbeats → stuck at "正在进入...".
        // isFFF493_2_stub is now always NO; the extended-plaintext save block below
        // is also disabled.
        if (patchCount > 0) {
            ssize_t delta = (ssize_t)chCount * 9 + (ssize_t)dmCount * (-6) + (ssize_t)gpCount * (-4);
            size_t newDataInLen = (size_t)((ssize_t)dataInLen + delta);
            patchedBuf = malloc(newDataInLen + 32);
            if (patchedBuf) {
                char *out = (char *)patchedBuf;
                const char *p = (const char *)dataIn;
                const char *e = p + dataInLen;
                while (p < e) {
                    size_t rem = (size_t)(e - p);
                    if (rem >= 9 && memcmp(p, "DY_MIESHI", 9) == 0) {
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        char next = (p + 9 < e) ? *(p+9) : 0;
                        BOOL bounded = (prev == '"' || prev == ':' || prev == ',' || prev == '{' || prev == '[' || prev == ' ') &&
                                      (next == '"' || next == ',' || next == '}' || next == ']' || next == ' ' || next == '\0' || next == ':');
                        if (bounded) {
                            memcpy(out, "DYanyou0040_MIESHI", 18);
                            out += 18; p += 9; continue;
                        }
                    } else if (rem >= 17 && memcmp(p, "iPhone 16 Pro Max", 17) == 0) {
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        char next = (p + 17 < e) ? *(p+17) : 0;
                        BOOL bounded = (prev == '"' || prev == ':') && (next == '"' || next == ',');
                        if (bounded) {
                            memcpy(out, "iPhone7Plus", 11);
                            out += 11; p += 17; continue;
                        }
                    } else if (rem >= 28 && memcmp(p, "Apple Inc. Apple A18 Pro GPU", 28) == 0) {
                        char prev = (p > (const char *)dataIn) ? *(p-1) : 0;
                        char next = (p + 28 < e) ? *(p+28) : 0;
                        BOOL bounded = (prev == '"' || prev == ':') && (next == '"' || next == ',');
                        if (bounded) {
                            memcpy(out, "Apple Inc. Apple A10 GPU", 24);
                            out += 24; p += 28; continue;
                        }
                    }
                    *out++ = *p++;
                }
                realDataIn = patchedBuf;
                realDataInLen = (size_t)(out - (char *)patchedBuf);
                static int logged = 0;
                if (logged < 4) {
                    DLOG(@"[CH-L4] v37.35 patchesTot=%d ch=%d dm=%d gp=%d origLen=%zu newLen=%zu delta=%lld",
                         patchCount, chCount, dmCount, gpCount, dataInLen, realDataInLen,
                         (long long)realDataInLen - (long long)dataInLen);
                    logged++;
                }
            }
        }
        // v37.43: Extended plaintext save block DISABLED. With isFFF493_2_stub always
        // NO, this block never executes. Kept as comment for reference. The forged
        // extended plaintext (1350B with fake accountId/hasRole/serverInfo) was the
        // root cause of "正在进入..." stuck — send-hook used it to replace native
        // 896B FFF493#2 with 1880B forged packet, server rejected and only returned
        // heartbeats (0x80000015). Now FFF493#2 passes through via orig_send.
        // (Original block: build ext from base+trimLen, save to g_ext_plaintext)
    }

    DLOG(@"[CC-AES] %s inLen=%zu (real=%zu) keyLen=%zu", opStr, dataInLen, realDataInLen, keyLen);

    // v37.34: Dump FULL plaintext (not only first 80B) for ENC calls whose size is in
    // FFF493 range (280-1200 bytes). This lets us see exactly which JSON fields are
    // present in our stub JSON (604B) vs the 1010B full JSON built by the canonical
    // channel. Short JSONs only contain username/password/clientId.
    if (op == 0 && realDataIn && realDataInLen > 0) {
        // Diagnostic dump — FFF493 always < 2048 bytes; cap at 2048.
        int dumpLen = (int)(realDataInLen < 2048 ? realDataInLen : 2048);
        // HEX + ASCII view
        NSMutableString *hexStr = [NSMutableString stringWithCapacity:dumpLen * 3 + 200];
        NSMutableString *ascStr = [NSMutableString stringWithCapacity:dumpLen + 50];
        for (int i = 0; i < dumpLen; i++) {
            unsigned char c = ((const unsigned char *)realDataIn)[i];
            [hexStr appendFormat:@"%02X ", c];
            [ascStr appendFormat:@"%c", (c >= 0x20 && c < 0x7F) ? c : '.'];
        }
        static int dumpCount = 0;
        if (dumpCount < 8) {
            DLOG(@"[CC-AES-PLAIN-FULL] v37.34 ENC #%d inLen=%zu realLen=%zu HEX: %@", dumpCount, dataInLen, realDataInLen, hexStr);
            DLOG(@"[CC-AES-PLAIN-FULL] v37.34 ENC #%d ASCII: %@", dumpCount, ascStr);
            dumpCount++;
        }
    }

    // v37.44: Save FFF493#2 native plaintext for send-hook field replacement.
    // Detection: ENC op + plaintext contains "NEW_USER_ENTER_SERVER_REQ" + len>500.
    // This is the client's native 619B JSON (with empty sessionId/ticket).
    // Send hook will replace sessionId/ticket/clientId/MACADDRESS/md5 with clean
    // client values, re-encrypt, and build a new 1432B packet.
    if (op == 0 && realDataIn && realDataInLen > 500 && realDataInLen < 2048) {
        if (memmem(realDataIn, realDataInLen, "NEW_USER_ENTER_SERVER_REQ", 25) != NULL) {
            if (g_fff493_2_native_plain) { free(g_fff493_2_native_plain); }
            g_fff493_2_native_len = realDataInLen;
            g_fff493_2_native_plain = (char *)malloc(realDataInLen + 1);
            if (g_fff493_2_native_plain) {
                memcpy(g_fff493_2_native_plain, realDataIn, realDataInLen);
                g_fff493_2_native_plain[realDataInLen] = '\0';
                DLOG(@"[FFF493-REPL] v37.44: Saved FFF493#2 native plaintext %zuB for send-hook replacement", realDataInLen);
            }
        }
    }

    // v37.31 CRITICAL FIX: If we expanded plaintext (patchedBuf != NULL), the
    // caller's dataOut buffer is sized for the ORIGINAL plaintext's AES output.
    // (CCFileUtils::aesEncryptData allocates a fixed stack/heap buffer based on
    // dataInLen passed to it, NOT our realDataInLen.  orig_CCCrypt will write
    // past dataOutAvailable → SIGSEGV.)
    // Workaround: allocate a HEAP dataOutTmp big enough for the expanded input,
    // run orig_CCCrypt into that, then memcpy the first dataOutAvailable bytes
    // back to caller's dataOut only if it fits, else return kCCBufferTooSmall.
    // Actually, to avoid breaking the caller, we MUST pass enough room:
    //   CCCrypt ENC: dataOutMoved <= dataOutAvailable
    //   Required: ceil((realDataInLen + blocksize) / blocksize) * blocksize
    //   AES blocksize=16, with padding (kCCOptionPKCS7Padding usually):
    //   Worst case: (realDataInLen + 16) & ~0xF
    // If caller's dataOutAvailable is not enough, use our own buffer.
    void *tmpOut = NULL;
    size_t tmpOutSize = 0;
    if (patchedBuf != NULL) {
        // v37.32: Correct AES PKCS7 padding output calculation:
        //   output = ceil((plainLen + 1) / 16) * 16
        // PKCS7 always adds at least 1 byte of padding (hence +1).
        // Verified with v37.31 data: real=307 → needed=320, caller 333 fits!
        size_t needed = ((realDataInLen + 1 + 15) / 16) * 16;
        // Use caller's buffer if STRICTLY enough room; otherwise fall back to tmpOut.
        // We use needed+1 as threshold so tight fits still succeed (320 <= 333).
        if (dataOutAvailable < needed) {
            tmpOutSize = needed + 32;
            tmpOut = malloc(tmpOutSize);
            DLOG(@"[CH-L4-BUF] v37.32: caller dataOutAvailable=%zu < needed=%zu → use heap tmpOut=%p (tmpOutSize=%zu)",
                 dataOutAvailable, needed, tmpOut, tmpOutSize);
        }
    }
    void *outBuf = tmpOut ? tmpOut : dataOut;
    size_t outBufAvail = tmpOut ? tmpOutSize : dataOutAvailable;
    size_t outMovedTmp = 0;
    int ret = orig_CCCrypt(op, alg, options, key, keyLen, iv,
                           realDataIn, realDataInLen,
                           outBuf, outBufAvail, tmpOut ? &outMovedTmp : dataOutMoved);

    if (tmpOut) {
        if (ret == 0 && outMovedTmp > 0) {
            // v37.32 FIX: tmpOut ENCRYPT SUCCESS → copy ciphertext to caller's dataOut IF it FITS.
            // CCCrypt output length follows: ciphertext ≤ plaintext + block alignment with PKCS7.
            // Caller's dataOutAvailable may be LARGER than outMovedTmp? Yes!
            // v37.31 buggy fallback was wrong — outMovedTmp=320 vs dataOutAvailable=333 fits!
            if (outMovedTmp <= dataOutAvailable) {
                memcpy(dataOut, tmpOut, outMovedTmp);
                if (dataOutMoved) *dataOutMoved = outMovedTmp;
                DLOG(@"[CH-L4-BUF] v37.32: PATCH APPLIED via tmpOut copy outMoved=%zu callerAvail=%zu (FIT perfectly!)",
                     outMovedTmp, dataOutAvailable);
            } else {
                // output does not fit! call orig WITHOUT patch (conservative safe fallback
                DLOG(@"[CH-L4-BUF] v37.32: tmpOut produced %zu bytes > caller %zu available → SAFE FALLBACK no patch",
                     outMovedTmp, dataOutAvailable);
                if (patchedBuf) { free(patchedBuf); patchedBuf = NULL; realDataIn = dataIn; realDataInLen = dataInLen; }
                free(tmpOut); tmpOut = NULL;
                ret = orig_CCCrypt(op, alg, options, key, keyLen, iv,
                                   dataIn, dataInLen,
                                   dataOut, dataOutAvailable, dataOutMoved);
            }
        }
        if (tmpOut) free(tmpOut);
    }

    if (patchedBuf) free(patchedBuf);

    if (dataOutMoved && *dataOutMoved > 0) {
        DLOG(@"[CC-AES-OUT] %s len=%zu", opStr, *dataOutMoved);
    }
    return ret;
}

// ===== Diagnostics only (logs once, no DY_MIESHI literal in format) =====
static void installChannelInterceptLayers(void) {
    int layersOK = 0;

    // ===== L0: strlen / strcmp / strncmp FISHHOOK (INIT TIME propagation) =====
    // v37.33 CRITICAL: These run BEFORE ObjC + CFString initialization, ensuring
    // every malloc(strlen+1), every strcmp branch, every strncmp prefix check
    // treats DY_MIESHI as the 18-char canonical channel. This ensures
    // construct_NEW_USER_ENTER_SERVER_REQER builds 1010B full JSON (accountId,
    // hasRole, serverInfo...) instead of truncated 604B stub JSON.
    if (dlsym(RTLD_NEXT, "strlen")) {
        orig_strlen = (size_t (*)(const char*))dlsym(RTLD_NEXT, "strlen");
        int r = rebindSymbol("strlen", (void *)hook_strlen, (void **)&orig_strlen);
        DLOG(@"[CH-L0] strlen rebind=%d orig=%p", r, orig_strlen);
        layersOK++;
    }
    if (dlsym(RTLD_NEXT, "strcmp")) {
        orig_strcmp = (int (*)(const char*, const char*))dlsym(RTLD_NEXT, "strcmp");
        int r = rebindSymbol("strcmp", (void *)hook_strcmp, (void **)&orig_strcmp);
        DLOG(@"[CH-L0] strcmp rebind=%d orig=%p", r, orig_strcmp);
        layersOK++;
    }
    if (dlsym(RTLD_NEXT, "strncmp")) {
        orig_strncmp = (int (*)(const char*, const char*, size_t))dlsym(RTLD_NEXT, "strncmp");
        int r = rebindSymbol("strncmp", (void *)hook_strncmp, (void **)&orig_strncmp);
        DLOG(@"[CH-L0] strncmp rebind=%d orig=%p", r, orig_strncmp);
        layersOK++;
    }

    // L1: CFString via fishhook
    if (dlsym(RTLD_NEXT, "CFStringCreateWithCString")) {
        int r = rebindSymbol("CFStringCreateWithCString",
                             (void *)hook_CFStringCreateWithCString,
                             (void **)&orig_CFStringCreateWithCString);
        DLOG(@"[CH-L1] CFStringCreateWithCString rebind=%d", r);
        layersOK++;
    }

    // L2: NSString class methods via method_setImplementation
    Method m1 = class_getClassMethod([NSString class], @selector(stringWithUTF8String:));
    if (m1) { orig_stringWithUTF8String = (id (*)(Class, SEL, const char*))method_getImplementation(m1); method_setImplementation(m1, (IMP)hook_stringWithUTF8String); DLOG(@"[CH-L2] stringWithUTF8String installed"); layersOK++; }
    Method m2 = class_getInstanceMethod([NSString class], @selector(initWithUTF8String:));
    if (m2) { orig_initWithUTF8String = (id (*)(NSString*, SEL, const char*))method_getImplementation(m2); method_setImplementation(m2, (IMP)hook_initWithUTF8String); DLOG(@"[CH-L2] initWithUTF8String installed"); layersOK++; }

    // L3: memcpy via fishhook
    if (dlsym(RTLD_NEXT, "memcpy")) {
        orig_memcpy = (memcpyFunc)dlsym(RTLD_NEXT, "memcpy"); // capture before rebind
        int r = rebindSymbol("memcpy", (void *)hook_memcpy, (void **)&orig_memcpy);
        DLOG(@"[CH-L3] memcpy rebind=%d orig=%p", r, orig_memcpy);
        layersOK++;
    }

    // L4: CCCrypt swap pointer (already hook installed later, override IMP here to v37.26 version)
    DLOG(@"[CH-L4] CCCrypt plaintext-ENC layer ready. installSecurityHooks will rebind CCCrypt next.");
    layersOK++;

    // L5/L6: send buffer scan — implemented inside custom_send directly, see below.
    DLOG(@"[CH-L5] send buffer scan + L6 EE007 len-patch: handled in custom_send().");
    layersOK++;

    DLOG(@"[CH-INIT] v37.56 %d layers active (L0=dead L1=dead L2=NSString L3=dead L4=CCCryptENC+SAVE-PLAIN L5=sendScan+FFF493-REPL-v2-ENABLED(sessionId+ticket-ONLY) L6=EE007-TLV+EE121-CLEAN-248B-seq-only+MD5-HOOK + CH-PATCH vm_protect)", layersOK);
}

// v37.52: Directly patch C-string literal "DY_MIESHI" → "DYanyou0040_MIESHI" in binary memory.
// L0-L3 fishhook hooks (strlen/strcmp/strncmp/memcpy) NEVER trigger because these
// functions are inlined by the compiler on modern iOS — fishhook only rebinds symbol
// pointers, not inlined call sites. So construct_NEW_USER_ENTER_SERVER_REQER still
// reads the short "DY_MIESHI" channel → builds truncated 621B JSON (missing accountId,
// hasRole, serverInfo, character data) → FFF493-REPL can't fix it → server returns only
// heartbeats → stuck at "正在进入...".
//
// Root fix: patch the C-string literal IN-PLACE in __TEXT. Original binary had
// "DYanyou0040_MIESHI\0" (19 bytes). 全能签 overwrote first 10 bytes with "DY_MIESHI\0",
// leaving 9 stale bytes after. We write back all 19 bytes — safe because the slot
// was originally 19 bytes. construct_NEW_USER_ENTER_SERVER_REQER then reads the correct
// long channel and builds the full ~994B JSON.
//
// v37.53: mprotect FAILS with EACCES on iOS (code signature protects __TEXT).
// Use vm_protect with VM_PROT_COPY instead — this forces kernel to create a private
// copy-on-write page, bypassing code signature restrictions. This is the standard
// technique used by jailbreak tweaks (substrate, cycript) to patch code pages.
// NOTE: Writing 19 bytes overwrites the first 9 bytes of the adjacent "DYquick_MI..."
// string. This is acceptable — user uses DYanyou0040 channel, not DYquick.
#ifndef VM_PROT_COPY
#define VM_PROT_COPY 0x10
#endif
static void patchChannelStringInBinary(void) {
    const char shortCh[10] = "DY_MIESHI";         // 9 chars + NUL = 10
    const char longCh[19]  = "DYanyou0040_MIESHI"; // 18 chars + NUL = 19

    DLOG(@"[CH-PATCH] v37.53: Scanning binary for channel string literal...");

    int imageCount = (int)_dyld_image_count();
    int patched = 0;

    for (int idx = 0; idx < imageCount && patched == 0; idx++) {
        const char *imageName = _dyld_get_image_name(idx);
        if (!imageName) continue;
        // Only search in main binary (wangxian), not dylibs/frameworks
        if (!strstr(imageName, "wangxian") && !strstr(imageName, "WangXian")) continue;

        const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(idx);
        intptr_t slide = _dyld_get_image_vmaddr_slide(idx);
        if (!header || header->magic != MH_MAGIC_64) continue;

        DLOG(@"[CH-PATCH] v37.53: Searching in %s (slide=0x%lx)", imageName, (unsigned long)slide);

        const struct load_command *lc = (const struct load_command *)((uintptr_t)header + sizeof(struct mach_header_64));
        for (uint32_t i = 0; i < header->ncmds && patched == 0; i++) {
            if (lc->cmd != LC_SEGMENT_64) { lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize); continue; }
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__TEXT") != 0) { lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize); continue; }

            const struct section_64 *sect = (const struct section_64 *)((uintptr_t)seg + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < seg->nsects && patched == 0; j++) {
                // Search all __TEXT sections (string literal may be in __cstring or __const)
                size_t sectSize = sect[j].size;
                if (sectSize < 19) continue;

                char *start = (char *)(sect[j].addr + slide);
                char *end = start + sectSize;
                for (char *p = start; p <= end - 19; p++) {
                    // Match first 9 bytes "DY_MIESHI" (not 10 — 全能签 may not have
                    // written a NUL terminator; p[9] could be stale original data).
                    if (memcmp(p, shortCh, 9) != 0) continue;
                    // Boundary check: char before must be NUL or non-alphanumeric
                    // (ensures "DY_MIESHI" is the start of a string, not a substring).
                    if (p > start) {
                        char prev = *(p - 1);
                        if ((prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') ||
                            (prev >= '0' && prev <= '9') || prev == '_') continue;
                    }
                    // Found "DY_MIESHI" at a string boundary. Dump context.
                    char beforeHex[64] = {0};
                    for (int k = 0; k < 20 && p + k < end; k++)
                        snprintf(beforeHex + k*3, 4, "%02X ", (unsigned char)p[k]);
                    DLOG(@"[CH-PATCH] v37.53: Found in sect=%s offset=%ld before: %s",
                         sect[j].sectname, (long)(p - start), beforeHex);

                    // v37.53: Use vm_protect with VM_PROT_COPY to bypass iOS code signature.
                    // mprotect returns EACCES on __TEXT pages; vm_protect with VM_PROT_COPY
                    // forces kernel to create a private COW copy that we can write to.
                    uintptr_t pageAddr = (uintptr_t)p & ~((uintptr_t)0xFFF);
                    uintptr_t pageEnd  = ((uintptr_t)p + 19 + 0xFFF) & ~((uintptr_t)0xFFF);
                    size_t protSize = pageEnd - pageAddr;

                    kern_return_t kr = vm_protect(mach_task_self(),
                                                   (vm_address_t)pageAddr, protSize,
                                                   FALSE,
                                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                    if (kr == KERN_SUCCESS) {
                        // Write long channel (19 bytes — may overwrite first 9B of adjacent
                        // "DYquick_MI..." string, acceptable since user uses DYanyou0040)
                        memcpy(p, longCh, 19);
                        // Restore to RX
                        vm_protect(mach_task_self(),
                                   (vm_address_t)pageAddr, protSize,
                                   FALSE,
                                   VM_PROT_READ | VM_PROT_EXECUTE);

                        char afterHex[64] = {0};
                        for (int k = 0; k < 20 && p + k < end; k++)
                            snprintf(afterHex + k*3, 4, "%02X ", (unsigned char)p[k]);
                        DLOG(@"[CH-PATCH] v37.53: PATCHED! after: %s", afterHex);
                        patched++;
                    } else {
                        DLOG(@"[CH-PATCH] v37.53: vm_protect FAILED kr=%d", (int)kr);
                        // Fallback: try mprotect (may work on some jailbreak setups)
                        if (mprotect((void *)pageAddr, protSize, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
                            memcpy(p, longCh, 19);
                            mprotect((void *)pageAddr, protSize, PROT_READ | PROT_EXEC);
                            DLOG(@"[CH-PATCH] v37.53: mprotect fallback PATCHED!");
                            patched++;
                        } else {
                            DLOG(@"[CH-PATCH] v37.53: mprotect also FAILED errno=%d", errno);
                        }
                    }
                    break;
                }
            }
            lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize);
        }
    }

    DLOG(@"[CH-PATCH] v37.53: Complete, patched=%d", patched);
}

static void installAllHooks(void) {
    DLOG(@"[VERSION] WangXianHook v37.56-DIST — v37.54/v37.55 sent native EE121 → server CLOSED (hash1/hash3 include channel, modified binary makes them WRONG). v37.56 RESTORES v37.51 behavior: send clean 248B EE121 (seq-only replace, hash1/3 unverifiable → status=4 ACCEPT). FFF493-REPL v2 RE-ENABLED but ONLY replaces sessionId+ticket (keeps clientId/MACADDRESS/md5 NATIVE to match current session). CH-PATCH vm_protect kept.");
    DLOG(@"[ACT] Installing hooks (restore v36.155 working configuration)...");

    // v37.52: Patch channel string literal in binary memory FIRST, before any
    // hook installation. This is the ROOT fix — L0-L3 fishhook hooks are dead
    // (inlined functions), so in-memory patch is the only way to ensure
    // construct_NEW_USER_ENTER_SERVER_REQER sees the correct long channel.
    patchChannelStringInBinary();

    // v37.26: Install ALL 6 channel intercept layers FIRST.
    // This runs before any network code so the replacement propagates through
    // the entire packet construction pipeline including AES-encrypted FFF493.
    installChannelInterceptLayers();

    // === v37.13: RESTORE v36.155 full hook configuration ===
    // v37.0-v37.12 minimal mode failed — injection detected → '版本过低'
    // Need full hooks to bypass injection detection.

    installSecurityHooks();
    installKeyboardProtection();

    // v37.13: RESTORE full socket hooks (not minimal)
    installSocketHooks();

    // v37.13: RESTORE C++ crypto hooks
    installCppCryptoHooks_v131();

    // v37.13: RESTORE proactive C++ function patches
    proactivePatchCppFunctions();

    // v37.13: RESTORE MSI retry
    tryHookMieshiServerInfo(0);

    // === KEEP: UIAlertView.show hook (in capture_real.js) ===
    Class alertCls = [UIAlertView class];
    if (alertCls) {
        Method m = class_getInstanceMethod(alertCls, @selector(show));
        if (m) { orig_alertViewShow = (void (*)(id, SEL))method_getImplementation(m); method_setImplementation(m, (IMP)hook_alertViewShow); _log(@"[INIT] UIAlertView.show: hook"); }
    }

    // === KEEP: SignatureKit hooks (in capture_real.js) ===
    Class skCls = NSClassFromString(@"SignatureKit");
    if (skCls) {
        Class metaCls = object_getClass(skCls);

        Method m = class_getClassMethod(skCls, @selector(showAlert:));
        if (m) { orig_showAlert = (ShowAlertIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showAlert); _log(@"[INIT] SK.showAlert: SUPPRESS"); }

        m = class_getClassMethod(skCls, @selector(exitApplication));
        if (m) { orig_exitApp = (ExitAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_exitApp); _log(@"[INIT] SK.exitApplication: BLOCK"); }

        m = class_getClassMethod(skCls, @selector(judgeAppInfoWithBaseUrl:));
        if (m) { orig_judgeBase = (JudgeBaseIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeBase); _log(@"[INIT] SK.judgeAppInfoWithBaseUrl: ORIG"); }

        m = class_getClassMethod(skCls, @selector(handleAppInfoResult:));
        if (m) { orig_handleResult = (HandleResultIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_handleResult); _log(@"[INIT] SK.handleAppInfoResult: LOG"); }

        m = class_getClassMethod(skCls, @selector(judgeNet));
        if (m) { orig_judgeNet = (JudgeNetIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeNet); _log(@"[INIT] SK.judgeNet: BLOCK"); }

        m = class_getClassMethod(skCls, @selector(verifySignatureFromParameters:));
        if (m) { orig_verifySig = (VerifySigIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_verifySig); _log(@"[INIT] SK.verifySignatureFromParameters: ORIG"); }

        m = class_getClassMethod(skCls, @selector(generateRequestParams));
        if (m) { orig_genParams = (GenParamsIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_genParams); _log(@"[INIT] SK.generateRequestParams: LOG"); }

        m = class_getClassMethod(skCls, @selector(createSignatureParams:));
        if (m) { orig_createSigParams = (CreateSigParamsIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_createSigParams); _log(@"[INIT] SK.createSignatureParams: LOG"); }

        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(metaCls, &mcount);
        for (unsigned int i = 0; i < mcount; i++) {
            DLOG(@"[SK] +[%@]", NSStringFromSelector(method_getName(methods[i])));
        }
        if (methods) free(methods);
    } else {
        _log(@"[INIT] WARNING: SignatureKit NOT found!");
    }

    // === KEEP: SignatureCheck hooks (in capture_real.js) ===
    Class scCls = NSClassFromString(@"SignatureCheck");
    if (scCls) {
        Class metaCls = object_getClass(scCls);

        Method m = class_getClassMethod(scCls, @selector(JudgeApp));
        if (m) { orig_judgeApp = (JudgeAppIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_judgeApp); _log(@"[INIT] SC.JudgeApp: BLOCK"); }

        m = class_getClassMethod(scCls, @selector(showTipViewEND:));
        if (m) { orig_showTip = (ShowTipIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_showTip); _log(@"[INIT] SC.showTipViewEND: SUPPRESS"); }

        m = class_getClassMethod(scCls, @selector(exitApplication));
        if (m) { orig_scExit = (SCExitIMP)method_getImplementation(m); method_setImplementation(m, (IMP)hook_scExit); _log(@"[INIT] SC.exitApplication: BLOCK"); }

        unsigned int mcount = 0;
        Method *methods = class_copyMethodList(metaCls, &mcount);
        for (unsigned int i = 0; i < mcount; i++) {
            DLOG(@"[SC] +[%@]", NSStringFromSelector(method_getName(methods[i])));
        }
        if (methods) free(methods);
    } else {
        _log(@"[INIT] WARNING: SignatureCheck NOT found!");
    }

    _log(@"[INIT] v37.14: Socket hooks + NETIMPL hooks (crypto hooks disabled to prevent crash)");

    // === DEFERRED: Create log button (keep for debugging) ===
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        UIWindow *w = nil;
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *s in [UIApplication sharedApplication].connectedScenes) {
                if (s.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *win in s.windows) {
                        if (win.isKeyWindow) { w = win; break; }
                        if (!w && win.rootViewController) w = win;
                    }
                }
            }
        }
        if (!w) w = [UIApplication sharedApplication].keyWindow;
        if (!w) w = [UIApplication sharedApplication].windows.firstObject;
        if (w) {
            createLogButton(w);
        }
    });

    DLOG(@"[ACT] v37.14: All hooks installed (socket + NETIMPL, crypto disabled)");
}


