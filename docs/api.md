# API overview

## Event bus

`RadarEventBus` provides a thread-safe callback registry for publishing radar events.

```python
from ass_radar.events import RadarEvent, RadarEventBus

bus = RadarEventBus()

bus.publish(RadarEvent(kind="example", code=1))
```

## Typed package metadata

The package is marked as typed through `ass_radar/py.typed`, allowing type checkers to understand the public API surface.

## Relay and protocol helpers

The `ass_radar.photon` and `ass_radar.relay` modules handle deserialization, payload rewriting, and event bridging between runtime streams.
