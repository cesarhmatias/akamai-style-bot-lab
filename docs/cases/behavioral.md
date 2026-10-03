# `behavioral`: interaction telemetry (mouse, keyboard, touch, motion)

Category: behavioral · Module: `api/app/modules/behavioral.py` · Protected URL: `/protected/behavioral`
· Default: on · Module tier: **HIGH** for the concept; every threshold is lab-defined

## What it is

The module judges the interaction telemetry the client captured: how the pointer moved, how keys were typed, whether touch
and device-motion data look like a person. It reads standard telemetry from `sensor:{sid}` and, on transactional endpoints,
preferably the inline telemetry captured while the form was filled.

## How real Akamai uses it

Akamai's behavioral detection evaluates "movement patterns and other interaction details unique to humans" and is a Bot
Manager Premier feature (detection-methods page, report §1.2 case 9, [P]). Content Protector analyses user interaction
(touchscreen, keyboard, mouse) and behaviour across the site ([P], 2024-02-06); the mobile SDK docs, as quoted in 2019,
list device characteristics, orientation and accelerometer data ([S]). Results feed the Bot Score (0-100) and its
response segments. Akamai's models and thresholds are not public.

## Confidence

| Sub-feature | Tier |
|---|---|
| The concept: multi-modal behavioral signals feeding the Bot Score | HIGH |
| All thresholds and weights below | LAB-defined (not Akamai's) |

No flag.

## How the lab simulates it

Modalities are scored independently; a session needs **one** modality with enough data that looks human, and a robotic
modality always wins (a bot cannot offset a scripted keyboard with a pretty mouse path). Mouse-only and keyboard-only
humans both pass; zero interaction fails.

- **Mouse**: strokes split at 120 ms pauses. Fewer than 8 points overall 60; 80% or more of strokes straight (max deviation
  max(1.5 px, 1% of the chord)) 50; median inter-event time below 0.2 ms (burst) 40, else a cadence CV below 0.08 35; speed
  CV below 0.05 25; direction entropy below 0.5 bits 20; turn entropy below 0.2 bits 20; first event to submit under
  150 ms 30; no mouse events 70.
- **Keyboard** (timings only, key identities never collected): at least 8 completed key presses and 5 usable gaps. Median
  inter-key gap below 8 ms 55, else gap CV below 0.10 45; median dwell below 5 ms or dwell CV below 0.05 40.
- **Touch**: touchmove strokes go through the same path analysis as the mouse (at least 8 move points).
- **Form fill** (inline telemetry only): 8 or more characters filled with no key events and no paste 45.
- **Soft signals** (added on top, never enough alone): constant scroll cadence 20, mobile UA without DeviceMotion or touch
  points 25, static motion readings 20, interaction without window focus 10.

Score: 50 and above fails, 20-49 warns, below 20 passes ("human-like behavior"). No sensor at all is fail 90 ("no
sensor_data posted (no behavioral telemetry)"). On `transactional` requests the inline payload is used when its MAC
verifies (`details["telemetry_type"] = "inline"`), otherwise the standard sensor. `details["segment_hint"]` maps the score
onto the report's example Bot Score bands; the real segment is decided by the response policy (see `bot_score`).

## How a scraper passes it

Produce human-like timing for at least one modality before the telemetry is sent: a patient mouse path with varying speed
and direction, or typing with variable intervals and dwell.

## Observed results

| Client | Cell | Verdict and reason |
|---|---|---|
| naive | fail | fail 90, "no sensor_data posted (no behavioral telemetry)" |
| curl_cffi | fail | fail 90, same reason |
| Playwright (seeded Bezier path with jitter) | pass | pass 0, "human-like behavior" |

## Limits and caveats

- Synthetic Bezier paths with jitter, or replayed recordings, can pass: this is a lab teaching model, not a research-grade
  classifier (and the Playwright case shows it).
- Akamai's 2026 interactive behavioral challenge is a separate case: [`interactive_challenge`](interactive_challenge.md).
