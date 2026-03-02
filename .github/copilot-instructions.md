# Copilot Review Instructions

## Review Format

When reviewing pull requests, structure every issue you find using the following four-part format. Do **not** propose a fix — focus entirely on analysis and explanation.

### For each issue, provide:

**1. Purpose — What the code does and why**
Explain the intent of the code in question. What is it trying to accomplish? What role does it play in the broader system? Reference the surrounding context (caller, module, data flow) to make the purpose clear.

**2. Mechanism — How it works**
Describe the algorithm, logic, or control flow the code uses to achieve its purpose. Be specific about the steps, data transformations, state transitions, or protocol interactions involved.

**3. Edge Cases — Where it breaks**
Identify the specific scenario(s) where the current implementation behaves incorrectly, unsafely, or unexpectedly. Explain the conditions that trigger the issue and what actually happens (e.g., panic, data corruption, silent failure, race condition, resource leak).

**4. Expected Behavior — What should happen instead**
Describe the correct or expected behavior under those same conditions. Be precise about invariants that should hold, error handling that should occur, or guarantees that should be maintained.

## General Guidelines

- Prioritize correctness and safety issues over style nitpicks.
- For Rust code, pay close attention to ownership, lifetimes, error propagation, and `unsafe` usage.
- Consider concurrency and async edge cases (deadlocks, race conditions, cancelled futures).
- Consider protocol-level concerns: framing, endianness, backward compatibility.
- Do not flag issues you are not confident about — prefer fewer, higher-quality findings.
