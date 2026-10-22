# Wappalyzer Welcome Experience - Reconstructed Architecture

Production-grade reconstruction and reverse-engineering of the Wappalyzer onboarding experience (`https://www.wappalyzer.com/welcome/`), authored in accordance with the evidence-led methodologies established in `morluto/rea` (Reverse Engineer Anything).

## Architecture Overview

This project reconstructs Wappalyzer's client-side welcome and technographics onboarding interface, incorporating:
- Complete Wappalyzer visual design tokens (Deep Purple `#4608ad`, Dark Purple `#32067c`, Electric Blue `#2196f3`).
- Fully responsive navigation header with multi-tiered product and resource menus.
- Real-time Interactive Technology Profiler / Scanner supporting instant heuristic and signature detection for web domains.
- Complete Multi-State Authentication Suite (Sign In, Create Account, Reset Password, Google SSO simulation) with client-side input validation and feedback.
- Accessible Theme Engine supporting Dark Mode and Light Mode with system preference synchronization and persistent local storage.
- Bilingual Localization supporting English (`en`) and Bahasa Indonesia (`id`).
- Semantic HTML5 structure adhering to WCAG 2.1 AA accessibility guidelines (touch targets >= 44px, color contrast >= 4.5:1).

## Tech Stack

- **Build Engine:** Vite 6
- **Styling:** Vanilla CSS with centralized design tokens (`src/tokens.css`)
- **State & Logic:** Modern ES Modules (JavaScript)
- **Deployment Platform:** Vercel / GitHub Pages

## Project Structure

```
wappalyzer-welcome/
├── index.html                  # Semantic entry point with vector SVG assets
├── package.json                # Project dependencies and build scripts
├── vercel.json                 # Vercel deployment specification
├── src/
│   ├── main.js                 # Application state, theme controller, localization & scanner logic
│   ├── tokens.css              # Centralized design tokens (Light and Dark mode)
│   ├── styles.css              # Core component and layout styling
│   ├── locales/
│   │   ├── en.js               # English localization catalog
│   │   └── id.js               # Indonesian localization catalog
│   └── data/
│       └── techDatabase.js     # Technographic signatures and heuristic analysis engine
└── dist/                       # Optimized production bundle
```

## Running Locally

1. Install dependencies:
```bash
npm install
```

2. Start local development server:
```bash
npm run dev
```

3. Build production bundle:
```bash
npm run build
```

4. Preview production build:
```bash
npm run preview
```

## Deployment

### Vercel Deployment
This repository is configured with `vercel.json` for zero-configuration builds on Vercel:
```bash
vercel --prod
```
Or connect the GitHub repository directly to Vercel for continuous integration deployments.
