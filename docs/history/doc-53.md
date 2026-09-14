# Doc 52: A visible cue that the domain field is ready

Small front-end doc. The domain field is focused when the page
opens (Doc 50), but the cue that says so is weak in dark theme
and easy to miss in both. Two changes: one focus ring for both
themes, and a single soft pulse of it when the page opens.
Line numbers are from main at 59b6c59.

## 1. One focus ring

static/style.css:534 to 537: in dark theme .input-unified
.input-wrapper:focus-within sets a white border at 0.25 alpha
and a 3px shadow at 0.05 alpha, which is close to invisible on
the navy input. The light-theme rule at 6202 to 6205 uses
var(--primary) and var(--primary-subtle). Make the dark rule
the same two tokens so focus looks the same in both themes,
and delete the light-theme override since it no longer
differs.

## 2. One pulse when the page opens

Add a keyframe that runs once on .input-wrapper: box-shadow
from 0 0 0 0 var(--primary-border) to 0 0 0 10px transparent
over 900ms with ease-out, then the normal focus ring remains.
Trigger it from the existing DOMContentLoaded handler in
static/app.js (164): when document.activeElement is
#domain-input and the URL carries no d parameter (203 already
checks it; a shared-result link auto-runs an audit and must
not pulse), add a class such as input-wrapper-hello to
.input-wrapper and remove it on animationend. Fire it once per
page load, never on later focus. Inside the @media
(prefers-reduced-motion: reduce) block at 1373 set animation:
none for that class.

Keep the caret blink and everything else as it is. No colour
is introduced; the pulse uses the existing --primary-border
token.

## Tests

Extend tests/test_visual_system.py (or the header browser
test) with: at 1280 in both themes, after load, .input-wrapper
has the hello class within 100ms and loses it within 2s; with
the d parameter set, it never gets the class; with
prefers-reduced-motion emulated,
getComputedStyle(...).animationName is none. Assert the
computed focus-within border colour is the same value in both
themes.

## Repo rules

No em dashes and no double hyphens in any user-facing text.
Run python3 -m pytest tests/ -q. All must pass.
Cache-bust per CLAUDE.md since app.js and style.css change.
Commit to a branch, push, merge to main, then deploy per
CLAUDE.md and confirm /api/health reports the new SHA.
Save this doc as docs/history/doc-52.md in the same commit.

## Done when

Opening the home page in either theme shows the domain field
with the cursor in it, a blue ring, and one soft pulse that
settles within a second; a shared-result link and
reduced-motion users get no pulse; the suite passes.
