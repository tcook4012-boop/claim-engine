/* ============================================================================
   vision-checks.js  —  editable config for the AI visual QA checks.

   Like fault-prompt.js, this file is meant to be edited without touching app code.
   It defines the Claude model, the file cap, and the prompt for each visual check.

   HOW TO TUNE SENSITIVITY (the important knob):
   The prompt below ships MODERATELY CONSERVATIVE — it flags clear problems (wrong
   file, obvious instruction violations, nonsense output) and passes close calls.
   This keeps the review bucket small enough for a 2-person team to actually use.

   - Too many false flags bogging you down?  Make VETO_GUIDANCE more lenient
     (emphasize "only flag if you are highly confident a client would be upset").
   - Things slipping through to clients?  Make it more aggressive
     (emphasize "flag anything a client might reasonably be unhappy with").

   Every flag lands in the review bucket WITH Claude's reason, so you can see why it
   fired and tune from real examples. Forward-only: only runs on new uploads.

   TO ADD A FUTURE CHECK (e.g. embroidery):  add a new entry to CHECKS with its own
   id + prompt. The engine already knows how to run any entry here.
   ============================================================================ */

const VISION_MODEL = process.env.VISION_MODEL || "claude-sonnet-4-6";

// Max client reference files sent per call. Most orders have 1-3; capping protects
// cost and latency on orders with many reference images. Tunable.
const MAX_CLIENT_FILES = Number(process.env.VISION_MAX_CLIENT_FILES || 4);

// Shared sensitivity guidance, injected into every check's prompt. EDIT THIS to tune
// the whole system's trigger-happiness at once.
const VETO_GUIDANCE = `
SENSITIVITY (very important):
You are the last line of defense before work reaches a paying client. But a two-person
team reviews every flag, so DO NOT flag borderline or subjective issues. Only flag when
you are confident a reasonable client would be unhappy. When it is a close call, a matter
of taste, or you are unsure, PASS it. Precision matters more than catching everything.
Concretely:
- FLAG: the output is clearly the wrong file or unrelated to what the client provided;
  a written instruction was plainly ignored; the output is garbled, blank, or nonsensical.
- PASS: minor stylistic differences, color shifts that could be intentional, cropping or
  scaling differences, anything you are not confident a client would object to.`;

// The checks. Each has an id (stored/logged) and a prompt builder. The engine passes in
// the vendor's output image + the client's reference images + any written instructions.
const CHECKS = {
  vector_visual: {
    id: "vector_visual",
    label: "Vector visual QA",
    // Built per order. `instructions` may be empty — the visual sanity check still runs.
    buildPrompt: (instructions) => `
You are reviewing a completed VECTOR ART order for a print shop (PrintReadyArt).

You will be shown:
1. The VENDOR'S FINISHED OUTPUT (first image).
2. One or more CLIENT-PROVIDED FILES (the remaining images). These may include the main
   artwork to reproduce AND reference images. Reason over the whole set — the output should
   correspond to what the client provided, even if reference images are also present.

${instructions && instructions.trim()
  ? `The client also gave these WRITTEN INSTRUCTIONS:\n"""\n${instructions.trim()}\n"""\nCheck whether the finished output follows them.`
  : `This order has NO written instructions. Only perform the visual sanity check: does the
output plausibly correspond to the client's files, or did the vendor clearly upload the
wrong file / something nonsensical?`}

${VETO_GUIDANCE}

Respond with ONLY a JSON object, no other text:
{
  "pass": true | false,
  "confidence": 0.0-1.0,
  "reasons": ["short, specific reason", ...]   // empty array if pass
}
"reasons" must be concise and concrete (e.g. "Client asked to remove the gray background but
it is still present", "Output appears to be a completely different logo than the client art").
If pass is true, reasons must be [].`,
  },
};

// Formats that are already viewable by Claude vision without conversion.
const NATIVE_IMAGE_EXT = ["png", "jpg", "jpeg", "gif", "webp"];
// Formats we will convert to PNG via CloudConvert before sending to Claude.
const CONVERTIBLE_EXT = ["svg", "ai", "eps", "pdf", "cdr", "tif", "tiff", "bmp"];

module.exports = {
  VISION_MODEL,
  MAX_CLIENT_FILES,
  CHECKS,
  NATIVE_IMAGE_EXT,
  CONVERTIBLE_EXT,
};
