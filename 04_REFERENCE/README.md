# SOC Dashboard — original user visual reference

The user supplied the original screenshot again on 2026-11-11 and confirmed this as the primary visual direction. The binary is now preserved at `SOC_Dashboard_User_Reference.png`.

- Dimensions: **901 × 885 px**
- Size: **374,904 bytes**
- SHA-256: `53df69c6f4504b64b6bd513c0169ba87c9cbfaac85a0a2212c5f0b6219156ca2`
- The hash matches the original reference recorded in the V3.0 package exactly.
- The screenshot credits “Cyber Security Monitoring Dashboard by Delubemo™ Studio on Dribbble.” It is a visual reference, not a statement of ownership or a license for commercial redistribution of the original screenshot.

The implementation follows the slim left rail, tab navigation, charcoal/slate surfaces, orange selected controls, three metric cards, adjacent incident panel, score panel, eight tool cards, orange-red analytics panel and lower timeline. English uses the reference's reading order; Arabic uses RTL content with the navigation rail retained at the left. The interface is responsive.

Metrics are computed from available data. Unmeasured score, detection time and unconnected vulnerability scanner remain explicit. The reference's sample user, numbers and successful protection claims are not running product data.

Implementation: `public/dashboard.js`, `public/soc.css`, and shared UI `public/app.js`. Pixel-identical reproduction across arbitrary viewports is not claimed; browser comparison is recorded in `docs/engineering/BROWSER_QA_AR.md`.
