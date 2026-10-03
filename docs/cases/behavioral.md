# Case 9: `behavioral` (mouse biometrics)

Category: behavioral. Module: `api/app/modules/behavioral.py`. Protected URL: `/protected/behavioral`.

## Mechanism
Even when a script runs, the way a pointer moves distinguishes people from scripts: smooth curves, varying
speed, pauses, changing direction, versus teleports, straight lines and constant timing.

## How real Akamai uses it
Public knowledge: the sensor payload includes mouse/touch/keyboard event data and timing, scored
server-side as part of the telemetry. The lab's thresholds are its own, made up for demonstration.

## How THIS server detects it
It reads `sensor:{sid}` (written by `sensor_data`, so it needs that flow) and analyses `[x, y, t_ms]` points
split into strokes at gaps > 120 ms. Penalties are additive (cap 100); `>= 50` fail, `>= 20` warn.

| rule | penalty |
|---|---|
| no mouse events | 70 (returned immediately) |
| fewer than 8 points | 60 |
| >= 80% of shaped strokes (>= 4 points, >= 30 px) are straight (deviation <= max(1.5 px, 1% of chord)) | 50 |
| median inter-event dt < 0.2 ms (burst injection) | 40 |
| otherwise dt coefficient of variation < 0.08 | 35 |
| speed CV < 0.05 | 25 |
| direction entropy < 0.5 bits (16 bins) | 20 |
| turn entropy < 0.2 bits (24 bins) | 20 |
| first event to submit < 150 ms | 30 |

No sensor at all: fail 90 "no sensor_data posted (no behavioral telemetry)". `details` carries the
computed metrics.

## How a client passes here
Drive a real browser and emit many separate `mouse.move` calls along curved, eased, jittered paths with
small random delays (`bezier_path` / `human_mouse` in `clients/playwright_client.py`: 3 strokes of 70
points, 8-25 ms apart, seeded RNG 1337).

## Observed (real run)
- naive / curl_cffi: fail 90, "no sensor_data posted (no behavioral telemetry)".
- Playwright: pass 0, "human-like behavior"; metrics: 102 points, 2 strokes, straight_fraction 0.0,
  median dt 19.55 ms, cadence CV 0.337, speed CV 0.574, direction entropy 2.699, turn entropy 3.022,
  dwell 2298.8 ms. (The sensor caps at the first 2 s window after the first move.)

## Caveats
- A scripted Bezier is a synthetic human; a better model would pass. The lab shows the cat-and-mouse
  dynamic, not a robust biometric system.
- Only mouse data is judged; key/scroll/touch counts are recorded but unscored.
