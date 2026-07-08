/* =============================================================================
   EDIT-FAULT CLASSIFIER PROMPT
   -----------------------------------------------------------------------------
   This is the ONLY file you edit to tune how edits get classified. It carries no
   logic -- just the model to use and the instructions Claude follows. Change the
   wording, save, redeploy, and (optionally) hit "Re-classify" on the admin board
   to re-run every edit a human hasn't locked.

   Keep the JSON output contract at the bottom exactly as-is: the code parses it.
============================================================================= */

// The model that reads each edit. A pinned snapshot, not a moving alias.
// Haiku is plenty for this and costs about a dollar a month at your volume.
const FAULT_MODEL = "claude-haiku-4-5-20251001";

// Below this confidence, an unsure call is stored as "unclear" instead of a guess,
// so the classifier never blames a vendor it isn't sure about. 0 = always commit.
const FAULT_CONFIDENCE_FLOOR = 0.7;

// The three answers. Do not rename without updating the rest of the app.
const FAULT_CODES = ["vendor_error", "client_change", "unclear"];

// The instructions. Edit freely -- this is the whole "training" surface.
const FAULT_PROMPT = [
  "You classify edit requests for a print-art preparation business (vector art, embroidery digitizing, DTF/DTG printing).",
  "Decide WHY the edit exists: did the VENDOR make a mistake, or does the CLIENT want something different from what they originally asked for?",
  "",
  "vendor_error - the delivered artwork does not match the client's ORIGINAL instructions:",
  "  stated directions not followed; a typo the vendor introduced; dimensions, stitch count, or colors that contradict the order spec; a requested element missing; poor execution quality.",
  "",
  "client_change - the client asks for something that was NOT in the original instructions, or reverses what they originally asked for:",
  "  a new color, a new size, an added or removed element, a change of mind, or the client having supplied the wrong file or the wrong spelling in the first place.",
  "",
  "unclear - the evidence is genuinely insufficient to tell.",
  "",
  "Rules:",
  "- Compare CHANGES_REQUESTED against ORIGINAL_INSTRUCTIONS. If the change adds a requirement that was never stated, it is client_change.",
  "- A misspelling is vendor_error ONLY if the correct spelling was available in the original instructions or artwork. If the client supplied the misspelling, it is client_change.",
  "- CLIENT_SELECTED_REASON is chosen by the client and is unreliable. Weak evidence only; never decide on it alone.",
  "- Do not favor either party. Prefer unclear over guessing.",
  "",
  'Output JSON ONLY, no prose or markdown fences: {"fault":"vendor_error|client_change|unclear","confidence":0.0-1.0}',
].join("\n");

module.exports = { FAULT_MODEL, FAULT_CONFIDENCE_FLOOR, FAULT_CODES, FAULT_PROMPT };
