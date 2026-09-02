# PinkGlasses brand assets

The mark is a pair of glasses whose lenses are targeting reticles — eyewear for the
name, a scanner for what the tool actually does.

| File | Use |
|---|---|
| `logo.svg`, `logo-512.png`, `logo-1024.png` | The bare mark, transparent background. Wide (≈256×136). |
| `icon.svg`, `icon-{16,32,64,128,256,512}.png` | Square tile version — app icon, avatar, favicon. |
| `favicon.ico` | 16/32/48/64 multi-size, built from `icon-256.png`. |
| `lockup-dark.svg` / `-1880.png` | Mark + wordmark + tagline, for dark backgrounds. |
| `lockup-light.svg` / `-1880.png` | Same, for light backgrounds. |
| `og.svg`, `og.png` | 1200×630 social card for link previews. |

## Palette

| Role | Hex |
|---|---|
| Frame light | `#FFC2E0` |
| Frame | `#FF5CA5` |
| Glass light | `#F0348A` |
| Glass | `#C61068` |
| Glass deep | `#7E0844` |
| Reticle | `#FFD0E7` |
| Tile | `#1B2130` → `#0B0E14` (matches the app's `--bg`) |

## Notes

- Verified legible down to 16 px; below ~24 px prefer `icon-*.png` over `logo.svg`,
  since the bare mark is wide and short.
- The lockup SVGs use a live `<text>` element with a system font stack, so they may
  reflow slightly on machines without Inter. Use the PNGs where exact metrics matter.
- Clear space around the mark: at least the height of one lens.

## Where these are used

- `README.md` and the wiki `Home` page open with the lockup (`<picture>` picks the
  dark or light one from `prefers-color-scheme`).
- `web/public/` holds the copies the SPA serves: `favicon.ico`, `icon.svg`,
  `apple-touch-icon.png`, `icon-192.png`, `icon-512.png`, `og.png`, `logo.svg`
  (the sidebar mark) and `site.webmanifest`. Vite copies `public/` into `dist/`
  verbatim, and the api serves `web/dist`, so they need no build step of their own.
- Regenerate the rasters after editing any SVG:

  ```sh
  make brand
  ```
