This is a potential pathway for integrating Channel C (Control) into openclaw's subprocess handling logic.

Note: Pod delivers the brake signal via dual-path (unreliable datagram + reliable stream).
The Pod SDK exposes a single `AbortSignal` to the Gateway — the SDK handles deduplication internally.
The Gateway does not need to be aware of the dual-path mechanism.

```
// --- cli-runner.ts ---
import { killProcessTree } from './shell-utils';

// The Pod SDK's session context provides an AbortSignal that fires when a
// Channel C brake signal arrives (via either the datagram or stream path,
// whichever is first — the SDK deduplicates by signal ID).
const podSignal = params.sessionContext?.signal;

const managedRun = await supervisor.spawn({
  sessionId: params.sessionId,
  // ... (lines 243 to 253 remain untouched)
  input: stdinPayload,
});

// 1. THE POD BRIDGE: Wire Pod's network signal to OpenClaw's OS kill switch
const onBrakePressed = () => {
    // The brake signal arrived! Use the exact function you found in shell-utils.ts
    // to nuke this specific Process Group tree.
    if (managedRun.pid) {
        killProcessTree(managedRun.pid);
    }
};

// Listen for the brake signal from the Pod mobile app
if (podSignal) {
    podSignal.addEventListener('abort', onBrakePressed, { once: true });
}

try {
    // 2. Wait for the process to finish (Line 255 from your screenshot)
    const result = await managedRun.wait();

    // Check if it finished because we aborted it
    if (podSignal?.aborted) {
         throw new Error("AbortError");
    }

    return result;

} catch (error) {
    // 3. SEMANTIC RECOVERY
    // If the error was caused by the human hitting the Brake button:
    if (podSignal?.aborted || error.message === "AbortError") {
        return {
            // Return a string to the LLM's context window instead of crashing
            output: "[SYSTEM_INTERRUPT: Action explicitly halted by human override via Pod. Do not retry.]",
            exitCode: 130 // Standard POSIX code for Script Interrupted
        };
    }

    throw error; // Otherwise, it was a normal script crash

} finally {
    // 4. Clean up the listener so we don't leak memory
    if (podSignal) {
        podSignal.removeEventListener('abort', onBrakePressed);
    }
}

```
