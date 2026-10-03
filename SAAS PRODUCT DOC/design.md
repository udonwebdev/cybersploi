```markdown
# Design System Strategy: The Tactical Void

## 1. Overview & Creative North Star
The Creative North Star for this design system is **"The Kinetic Command."**

In high-stakes cybersecurity, a UI must feel like a living, breathing tactical environment—not a static webpage. We are moving away from the "flat dashboard" era into an "Orbital Interface" aesthetic. This system breaks the template look by embracing **intentional asymmetry** and **tonal depth**. Layouts should mimic head-up displays (HUDs), where information is layered in 3D space. By utilizing high-contrast typography scales (the precision of `Space Grotesk` against the utilitarian `Manrope`), we create a hierarchy that feels both professional and aggressive.

## 2. Color & Surface Architecture
This system operates in the shadows. We use a "Deep Space" palette to ensure the vibrant "offensive" cyan and "threat" crimson pops with maximum energy.

### The "No-Line" Rule
**Strict Mandate:** 1px solid borders for sectioning are prohibited. Boundaries must be defined solely through background color shifts or subtle tonal transitions.
* Instead of a border, use `surface-container-low` for a section sitting on a `surface` background.
* Use `surface-container-highest` to draw the eye to the most critical interactive panels.

### Surface Hierarchy & Nesting
Treat the UI as a series of physical layers—like stacked sheets of darkened, frosted glass.
* **Base:** `surface` (#111318)
* **Primary Containers:** `surface-container-low` (#1a1c20) for large layout blocks.
* **Active Modules:** `surface-container-high` (#282a2e) for cards and focused content.
* **Floating Elements:** `surface-container-highest` (#333539) for pop-overs or active selections.

### The Glass & Gradient Rule
To achieve a "Red Team" high-tech feel, main CTAs and hero backgrounds should utilize a linear gradient transitioning from `primary` (#dbfcff) to `primary_container` (#00f0ff). For floating glass elements, apply `surface-variant` at 40% opacity with a `backdrop-blur` of 12px-20px.

## 3. Typography: Precision Engineering
Our typography choice reflects the "Blue Team" stability and the "Red Team" speed.

* **Display & Headlines (Space Grotesk):** This is our "Technical Command" font. Use `display-lg` (3.5rem) and `headline-md` (1.75rem) with tight letter-spacing (-0.02em) to create an authoritative, editorial feel. It should feel like a readout from a high-altitude drone.
* **Body & Titles (Manrope):** Our "Operational" font. `body-md` (0.875rem) provides the legibility required for dense logs and threat reports.
* **Labels (Space Grotesk):** For data-heavy tags, use `label-md` (0.75rem) in all caps with increased letter-spacing (+0.05em) to mimic code-base annotations.

## 4. Elevation & Depth: Tonal Layering
Traditional drop shadows are too "web-standard." We use **Ambient Glows** and **Tonal Stacking**.

* **The Layering Principle:** Depth is achieved by stacking. Place a `surface-container-lowest` card inside a `surface-container-low` section to create a "recessed" look. Use `surface-container-highest` for "elevated" elements.
* **The Ghost Border Fallback:** If a border is required for accessibility, use the `outline-variant` token at 15% opacity. It should be felt, not seen.
* **Tactical Glow:** For "Offensive" states, apply a drop-shadow using the `primary_fixed` color (#7df4ff) with a 20px blur at only 10% opacity. This creates a "neon hum" effect.

## 5. Components: Modular Warfare

### Buttons (The Kinetic Trigger)
* **Primary:** Gradient of `primary` to `primary_container`. No border. `rounded-md` (0.375rem). Text in `on_primary_fixed` (#002022).
* **Secondary:** Ghost style. Transparent background, `outline` token border at 20% opacity. On hover, background shifts to `surface-container-highest`.
* **Tertiary:** Text-only in `primary_fixed_dim`. Use for low-priority system actions.

### Cards & Lists (Data Modules)
* **The Divider Ban:** Never use line dividers. Separate list items using the spacing scale (e.g., `spacing-4` or 0.9rem) or by alternating background tones between `surface-container-low` and `surface-container`.
* **Interactive Cards:** Use `surface-container-high`. Upon hover, transition to `surface-bright` and increase the `primary` glow.

### Input Fields (Command Entry)
* Background: `surface-container-lowest`.
* Border: `outline-variant` at 20%.
* Active State: Border shifts to `primary_container` with a subtle glow.
* Font: Must use `body-md` (Manrope) for input, but `label-sm` (Space Grotesk) for the field label.

### Terminal & Log Chips
* **Threat Chip:** Background: `on_secondary_container` (#5b000f). Text: `secondary_fixed` (#ffdad8). Use for high-risk vulnerabilities.
* **Neutral Chip:** Background: `surface-container-highest`. Text: `on_surface_variant`. Use for system status.

## 6. Do’s and Don’ts

### Do:
* **Do use asymmetrical grids.** Align a headline to the left but offset the body text to the right using `spacing-16` (3.5rem) to create visual tension.
* **Do use "Surface Tinting".** When an alert is active, overlay the entire container with a 5% opacity `secondary_container` (#ff525c) tint to signal danger visually before the user reads a word.
* **Do embrace monospace aesthetics.** While we use Manrope, ensure technical data (IP addresses, hash strings) is set with `0.05rem` extra letter-spacing to mimic a terminal.

### Don’t:
* **Don't use pure black (#000000).** Use `surface` (#111318) to allow for depth layering beneath it.
* **Don't use default "web" roundedness.** Stick strictly to the `md` (0.375rem) or `sm` (0.125rem) scale. Large `xl` curves feel too friendly for a cybersecurity tool.
* **Don't clutter with icons.** Use icons sparingly. Let the typography and color (Cyan vs. Crimson) do the heavy lifting of communication.