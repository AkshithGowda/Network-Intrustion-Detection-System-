# UI revamp prompt (non-slop)

Paste this into any AI coding assistant, with the file you want revamped.

---

Redesign this interface as a tool for one specific person doing one specific job, not as a "futuristic AI dashboard".

**Who and what.** The user is a security analyst on shift. Their loop is: notice something is wrong, work out what and where, act. Order the page the same way: (1) current threat state and the numbers that define it, (2) what is happening over time, (3) the evidence for each alert, (4) the controls. If a block does not serve that loop, remove it. Do not show the same fact twice (for example a gauge that repeats the threat badge).

**Look.** Pure black background and a silver neutral scale of four steps (primary text, secondary, muted, hairline). Muted text must still pass 4.5:1 contrast. One structural colour (silver). Red, amber and green mean attack, warning and healthy and are used for state only, never for decoration. Structure comes from 1 px hairlines and spacing on an 8 px grid, not from boxes inside boxes.

**Do not use:** gradient text, animated sheen or shimmer, glow or neon shadows, glassmorphism, decorative corner brackets, emoji or icon-in-a-circle, purple-to-blue gradients, rainbow chart palettes, cards with a coloured top stripe, wide letter-spaced uppercase on everything, placeholder hype copy ("AI-powered", "next-gen").

**Type.** One UI font (system sans) and one monospace for data. Tabular figures for every number so columns align. A fixed scale (12 / 13 / 14 / 20 / 28 px). Uppercase small caps only for column headers and stat labels. Numbers are the largest, brightest thing on the page; labels are quiet.

**Charts.** One chart language: thin 1.5 px lines, zero baseline, direct value labels, no legend where a label can sit on the line. Silver for normal traffic, red only for attack counts. If a chart is 3D, it has to earn it: static, no animation, muted colours, and the numbers still readable.

**Controls.** Real buttons with all states: hover, focus-visible ring (2 px, high contrast), active, disabled. One primary action per group (solid silver, black text). Destructive or maintenance actions are visually separate and never look like attack launchers. Group buttons under plain labels ("Launch an attack", "Scenario", "Maintenance").

**Motion.** Only functional: a new alert row fades from red to clear in about a second, the live dot pulses, state changes ease in 150 ms. Nothing animates while idle. Respect `prefers-reduced-motion`.

**Content.** Every number has a unit or a label. Empty states say what will appear and what to do. Timestamps are monospaced. Error and offline states are visible in the header.

**Accessibility and responsive.** Semantic landmarks and headings (`header`, `main`, one `h1`, `h2` per panel), `role="status"` on the threat badge, no information by colour alone (severity also has text), full keyboard use, a layout that works at 390 px without horizontal scroll.

**Deliverable.** Change only presentation and markup unless a change is needed to remove duplication. Keep all element ids that the script uses. Test at 1440 px and 390 px and report what you removed and why.
