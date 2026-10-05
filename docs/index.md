# Project documentation

This project provides a collection of helpers for radar event processing, Photon packet analysis, and relay support.

## Main modules

- `ass_radar.events`: event bus primitives and runtime source tracking
- `ass_radar.mobile_core`: mobile marker state and domain routing
- `ass_radar.player_positions`: trust and plausibility checks for position data
- `ass_radar.product_events`: product-specific event types and wrappers
- `ass_radar.photon`: packet, encryption, rewriting, and protocol handlers
- `ass_radar.relay`: bridge and relay processing components

## Development notes

- The package is designed for Python 3.10+
- Type support is exposed through the `py.typed` marker
- Source files include docstrings and type annotations in the main runtime paths

See the project README for installation and quick-start examples.
