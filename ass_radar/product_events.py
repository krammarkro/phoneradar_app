"""Event-route classification helpers for radar product telemetry.

The route tables in this module are used to normalize observed Photon event and
operation codes into a consistent product-specific classification. This helps
higher-level consumers decide which protocol messages should be considered core,
relay, or evidence traffic.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal, TypeAlias

from ass_radar.events import RadarEvent
from ass_radar.photon.keysync import KEY_SYNC_EVENT_CODES

RadarEventKind: TypeAlias = Literal['event', 'request', 'response']
ProductEventSetName: TypeAlias = Literal['radar-core', 'dungeon-intel', 'relay', 'evidence']

EVENT_LEAVE = 1
EVENT_MOVE = 3
EVENT_HEALTH_UPDATE = 6
EVENT_HEALTH_UPDATES = 7
EVENT_NEW_CHARACTER = 29
EVENT_NEW_SIMPLE_HARVESTABLE_OBJECT_LIST = 39
EVENT_NEW_HARVESTABLE_OBJECT = 40
EVENT_HARVESTABLE_CHANGE_STATE = 46
EVENT_MOB_CHANGE_STATE = 47
EVENT_HARVEST_FINISHED = 61
EVENT_CHARACTER_EQUIPMENT_CHANGED = 90
EVENT_REGENERATION_HEALTH_CHANGED = 91
EVENT_NEW_MOB = 123
EVENT_MOUNTED = 211
EVENT_LOCAL_TREASURES_UPDATE = 285
EVENT_NEW_RANDOM_DUNGEON_EXIT = 325
EVENT_FISHING_FINISHED = 358
EVENT_NEW_FISHING_ZONE_OBJECT = 361
EVENT_CHANGE_FLAGGING_FINISHED = 365
EVENT_NEW_LOOT_CHEST = 393
EVENT_LOOT_CHEST_OPENED = 395
EVENT_NEW_MISTS_IMMEDIATE_RETURN_EXIT = 520
EVENT_MISTS_PLAYER_JOINED_INFO = 521
EVENT_NEW_MISTS_STATIC_ENTRANCE = 522
EVENT_NEW_MISTS_OPEN_WORLD_EXIT = 523
EVENT_NEW_MISTS_WISP_SPAWN = 525
EVENT_MISTS_ENTRANCE_DATA_CHANGED = 531
EVENT_NEW_CAGED_OBJECT = 532
EVENT_CAGED_OBJECT_STATE_UPDATED = 533
EVENT_NEW_HUNT_TRACK = 558
EVENT_HUNT_QUEST_MISSION_PROGRESS_UPDATE = 560
EVENT_HELL_DUNGEONS_PLAYER_JOINED_INFO = 620

OP_JOIN = 2
OP_MOVE = 22
OP_CHANGE_CLUSTER = 41
OP_GET_CHARACTER_EQUIPMENT = 143
OP_MISTS_USE_STATIC_ENTRANCE = 473


@dataclass(frozen=True, order=True, slots=True)
class EventRoute:
    """A normalized event or operation route description."""

    kind: RadarEventKind
    code: int

    def __post_init__(self) -> None:
        if type(self.kind) is not str or self.kind not in frozenset({'event', 'request', 'response'}):
            raise ValueError('invalid_event_route')
        if type(self.code) is not int or not 0 <= self.code <= 65535:
            raise ValueError('invalid_event_route')


@dataclass(frozen=True, slots=True)
class RouteResolution:
    """Result of resolving an observed message into a canonical route."""

    observed: EventRoute
    routed: EventRoute
    from_parameter: bool


RADAR_CORE_ROUTES: Final[frozenset[EventRoute]] = frozenset({
    EventRoute('event', EVENT_LEAVE),
    EventRoute('event', EVENT_MOVE),
    EventRoute('event', EVENT_HEALTH_UPDATE),
    EventRoute('event', EVENT_HEALTH_UPDATES),
    EventRoute('event', EVENT_NEW_CHARACTER),
    EventRoute('event', EVENT_NEW_SIMPLE_HARVESTABLE_OBJECT_LIST),
    EventRoute('event', EVENT_NEW_HARVESTABLE_OBJECT),
    EventRoute('event', EVENT_HARVESTABLE_CHANGE_STATE),
    EventRoute('event', EVENT_MOB_CHANGE_STATE),
    EventRoute('event', EVENT_HARVEST_FINISHED),
    EventRoute('event', EVENT_CHARACTER_EQUIPMENT_CHANGED),
    EventRoute('event', EVENT_REGENERATION_HEALTH_CHANGED),
    EventRoute('event', EVENT_NEW_MOB),
    EventRoute('event', EVENT_MOUNTED),
    EventRoute('event', EVENT_NEW_RANDOM_DUNGEON_EXIT),
    EventRoute('event', EVENT_FISHING_FINISHED),
    EventRoute('event', EVENT_NEW_FISHING_ZONE_OBJECT),
    EventRoute('event', EVENT_CHANGE_FLAGGING_FINISHED),
    EventRoute('event', EVENT_NEW_LOOT_CHEST),
    EventRoute('event', EVENT_MISTS_PLAYER_JOINED_INFO),
    EventRoute('event', EVENT_NEW_CAGED_OBJECT),
    EventRoute('event', EVENT_CAGED_OBJECT_STATE_UPDATED),
    EventRoute('request', OP_MOVE),
    EventRoute('request', OP_GET_CHARACTER_EQUIPMENT),
    EventRoute('request', OP_MISTS_USE_STATIC_ENTRANCE),
    EventRoute('response', OP_JOIN),
    EventRoute('response', OP_CHANGE_CLUSTER),
    EventRoute('response', OP_GET_CHARACTER_EQUIPMENT),
})

DUNGEON_INTEL_ROUTES: Final[frozenset[EventRoute]] = frozenset({
    EventRoute('request', OP_MISTS_USE_STATIC_ENTRANCE),
    EventRoute('response', OP_JOIN),
    EventRoute('response', OP_CHANGE_CLUSTER),
    EventRoute('event', EVENT_MISTS_PLAYER_JOINED_INFO),
})

OPENRADAR_REGISTRY_ONLY_ROUTES: Final[frozenset[EventRoute]] = frozenset({
    EventRoute('event', EVENT_LOCAL_TREASURES_UPDATE),
    EventRoute('event', EVENT_LOOT_CHEST_OPENED),
    EventRoute('event', EVENT_NEW_MISTS_IMMEDIATE_RETURN_EXIT),
    EventRoute('event', EVENT_NEW_MISTS_STATIC_ENTRANCE),
    EventRoute('event', EVENT_NEW_MISTS_OPEN_WORLD_EXIT),
    EventRoute('event', EVENT_NEW_MISTS_WISP_SPAWN),
    EventRoute('event', EVENT_MISTS_ENTRANCE_DATA_CHANGED),
    EventRoute('event', EVENT_NEW_HUNT_TRACK),
    EventRoute('event', EVENT_HUNT_QUEST_MISSION_PROGRESS_UPDATE),
    EventRoute('event', EVENT_HELL_DUNGEONS_PLAYER_JOINED_INFO),
})

RELAY_ROUTES: Final[frozenset[EventRoute]] = RADAR_CORE_ROUTES | OPENRADAR_REGISTRY_ONLY_ROUTES

EVIDENCE_ROUTES: Final[frozenset[EventRoute]] = frozenset({
    EventRoute('event', 1),
    EventRoute('event', 3),
    EventRoute('event', 6),
    EventRoute('event', 11),
    EventRoute('event', 29),
    EventRoute('event', 39),
    EventRoute('event', 40),
    EventRoute('event', 46),
    EventRoute('event', 59),
    EventRoute('event', 61),
    EventRoute('event', 90),
    EventRoute('event', 123),
    EventRoute('event', 285),
    EventRoute('event', 323),
    EventRoute('event', 325),
    EventRoute('event', 391),
    EventRoute('event', 393),
    EventRoute('event', 518),
    EventRoute('event', 519),
    EventRoute('event', 520),
    EventRoute('event', 521),
    EventRoute('event', 529),
    EventRoute('event', 530),
    EventRoute('event', 531),
    EventRoute('event', 532),
    EventRoute('event', 556),
    EventRoute('event', 558),
    EventRoute('event', 598),
    EventRoute('event', 600),
    EventRoute('request', 21),
    EventRoute('request', 22),
    EventRoute('response', 2),
    EventRoute('response', 35),
    EventRoute('response', 41),
    EventRoute('response', 137),
})

POSITION_SENSITIVE_ROUTES: Final[frozenset[EventRoute]] = frozenset({
    EventRoute('event', EVENT_MOVE),
})

DIAGNOSTIC_ONLY_ROUTES: Final[frozenset[EventRoute]] = frozenset(
    EventRoute('event', code) for code in KEY_SYNC_EVENT_CODES
)

FIXTURE_SENSITIVE_ROUTES: Final[frozenset[EventRoute]] = frozenset({
    EventRoute('event', 598),
    EventRoute('event', 600),
})

PRODUCT_EVENT_SET_NAMES: Final[tuple[ProductEventSetName, ...]] = ('radar-core', 'dungeon-intel', 'relay', 'evidence')

PRODUCT_EVENT_SETS: Final[Mapping[ProductEventSetName, frozenset[EventRoute]]] = MappingProxyType({
    'radar-core': RADAR_CORE_ROUTES,
    'dungeon-intel': DUNGEON_INTEL_ROUTES,
    'relay': RELAY_ROUTES,
    'evidence': EVIDENCE_ROUTES,
})


def resolve_event_route(*, kind: object, observed_code: object, parameters: object) -> RouteResolution | None:
    """Resolve an observed message into a canonical route.

    Photon payloads may provide an alternate route code in a metadata parameter,
    such as the routing fields used by some relay transports. This helper normalizes
    both the observed and routed values into a single deterministic route record.
    """
    if type(kind) is not str or kind not in frozenset({'event', 'request', 'response'}):
        return None
    if type(observed_code) is not int or not 0 <= observed_code <= 65535:
        return None
    if not isinstance(parameters, Mapping):
        return None
    routed_number_key = 252 if kind == 'event' else 253
    routed_string_key = str(routed_number_key)
    integer_value = _MISSING
    string_value = _MISSING
    try:
        for key, value in parameters.items():
            if type(key) is int and key == routed_number_key:
                integer_value = value
            elif type(key) is str and key == routed_string_key:
                string_value = value
    except Exception:
        return None
    observed = EventRoute(kind, observed_code)  # type: ignore[arg-type]
    if integer_value is _MISSING and string_value is _MISSING:
        return RouteResolution(observed=observed, routed=observed, from_parameter=False)
    routed_codes: list[int] = []
    for value in (integer_value, string_value):
        if value is _MISSING:
            continue
        routed_code = _canonical_code(value)
        if routed_code is None:
            return None
        routed_codes.append(routed_code)
    if len(set(routed_codes)) != 1:
        return None
    return RouteResolution(
        observed=observed,
        routed=EventRoute(kind, routed_codes[0]),  # type: ignore[arg-type]
        from_parameter=True,
    )


def resolve_radar_event_route(event: RadarEvent) -> RouteResolution | None:
    try:
        return resolve_event_route(kind=event.kind, observed_code=event.code, parameters=event.parameters)
    except Exception:
        return None


def get_product_event_routes(name: object) -> frozenset[EventRoute]:
    if type(name) is not str:
        raise ValueError('invalid_product_event_set')
    try:
        return PRODUCT_EVENT_SETS[name]  # type: ignore[index]
    except (KeyError, TypeError):
        raise ValueError('invalid_product_event_set') from None


def event_parts_in_product_set(*, kind: object, observed_code: object, parameters: object, event_set: object) -> bool:
    resolution = resolve_event_route(kind=kind, observed_code=observed_code, parameters=parameters)
    if resolution is None:
        return False
    try:
        routes = get_product_event_routes(event_set)
    except ValueError:
        return False
    return resolution.routed in routes


def radar_event_in_product_set(event: RadarEvent, event_set: object) -> bool:
    resolution = resolve_radar_event_route(event)
    if resolution is None:
        return False
    try:
        routes = get_product_event_routes(event_set)
    except ValueError:
        return False
    return resolution.routed in routes


def _canonical_code(value: object) -> int | None:
    if type(value) is int:
        if 0 <= value <= 65535:
            return value
        return None
    if type(value) is not str:
        return None
    if value == '0':
        return 0
    if not value:
        return None
    if len(value) > 5:
        return None
    if value[0] not in '123456789':
        return None
    if any(character not in '0123456789' for character in value[1:]):
        return None
    code = int(value)
    if code <= 65535:
        return code
    return None


def is_valid_product_event_set(name: object) -> bool:
    try:
        get_product_event_routes(name)
        return True
    except ValueError:
        return False


_MISSING = object()

if not DUNGEON_INTEL_ROUTES <= RADAR_CORE_ROUTES:
    raise RuntimeError('invalid_product_event_policy')
if not RADAR_CORE_ROUTES <= RELAY_ROUTES:
    raise RuntimeError('invalid_product_event_policy')
if not OPENRADAR_REGISTRY_ONLY_ROUTES.isdisjoint(RADAR_CORE_ROUTES):
    raise RuntimeError('invalid_product_event_policy')
if not DIAGNOSTIC_ONLY_ROUTES <= EVIDENCE_ROUTES:
    raise RuntimeError('invalid_product_event_policy')
if not DIAGNOSTIC_ONLY_ROUTES.isdisjoint(RELAY_ROUTES):
    raise RuntimeError('invalid_product_event_policy')
if not DIAGNOSTIC_ONLY_ROUTES <= FIXTURE_SENSITIVE_ROUTES <= EVIDENCE_ROUTES:
    raise RuntimeError('invalid_product_event_policy')
