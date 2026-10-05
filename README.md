# ass_radar

ass_radar is a Python package for working with Albion-style Radar event capture, relay processing, and Photon packet parsing.

## Features

- event bus and runtime source tracking
- relay and mobile-state processing helpers
- Photon packet parsing utilities
- explicit type annotations and typed-package metadata

## Installation

```bash
pip install .
```

For local development:

```bash
python -m pip install -e .
```

## Quick start

```python
from ass_radar.events import RadarEvent, RadarEventBus

bus = RadarEventBus()


def on_event(event: RadarEvent) -> None:
    print(event.kind, event.code)

sub = bus.subscribe(on_event)

bus.publish(RadarEvent(kind="player", code=42, parameters={"x": 1, "y": 2}))
sub.unsubscribe()
```

## Package layout

- `ass_radar.events`: event bus and runtime metadata
- `ass_radar.mobile_core`: mobile radar state and routing
- `ass_radar.player_positions`: position trust and validation helpers
- `ass_radar.product_events`: product event definitions
- `ass_radar.photon`: Photon protocol parsing and encryption helpers
- `ass_radar.relay`: relay/processor support

## Type checking

The package includes a `py.typed` marker so type checkers can treat it as a typed library. The project is configured for Python 3.11+ and can be checked with `mypy` or `pyright`.

## License

This project is currently distributed as source code for local use and modification. Update the license metadata in `pyproject.toml` before redistributing publicly.
