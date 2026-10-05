"""Platform-neutral, bounded marker state for the Phone Radar bridge."""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ass_radar.events import RadarEvent
from ass_radar.player_positions import is_plausible_player_position, is_trusted_player_position_source, is_trusted_player_spawn_position_source
from ass_radar.relay.processor import RelayPhotonProcessor

_MAX_ENTITIES = 512
_MAX_TEXT_LENGTH = 128
_MAX_ENTITY_ID = 9007199254740991
_MAX_ABSOLUTE_POSITION = 100000
_PLAYER_MOB_TTL_MS = 3000
_OBJECT_TTL_MS = 40000
_RESOURCE_TTL_MS = 180000
_EQUIPMENT_RESPONSE_TTL_MS = 5000
_BUCKET_NAMES = ('players', 'resources', 'mobs', 'chests', 'objects')
_MAX_BUFFER_LENGTH = 512
_MAX_MOBILE_FLOWS = 512
_MAX_MOBILE_PAYLOAD_BYTES = 65536
_MOBILE_FLOW_DIRECTIONS = frozenset({'client_to_upstream', 'upstream_to_client'})
_MAX_MOBILE_CATALOG_BYTES = 524288
_MAX_MOBILE_CATALOG_MAPS = 1024
_MAX_MOBILE_MOB_AVATARS = 16384
_MAX_MOBILE_ITEM_ICONS = 65536
_MAX_EQUIPMENT_ICON_SLOTS = 9
_MAX_CLEANUP_INTERVAL_MS = 60000
_FALLBACK_ZONE_BOUNDS = {'minX': -412.5, 'minY': -412.5, 'maxX': 412.5, 'maxY': 412.5}
_MOBILE_CATALOG_ASSET = re.compile(r'^maps/[A-Za-z0-9#-]+\.webp$')
_MOBILE_CATALOG_IMAGE_STEM = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_@-]{0,127}$')
_MOBILE_RESOURCE_TYPES = ((0, 5, 'log'), (6, 10, 'rock'), (11, 15, 'fiber'), (16, 22, 'hide'), (23, 27, 'ore'))
_MOBILE_RESOURCE_FAMILIES = ('fiber', 'hide', 'log', 'ore', 'rock')
_MOBILE_MARKER_STYLES = {
    'caged': 'cage',
    'chest:blue': 'blue',
    'chest:green': 'green',
    'chest:legendary': 'legendary',
    'chest:rare': 'rare',
    'fishing': 'fish',
    'localPlayer': 'local-player-glyph',
    'mob': 'mob-glyph',
    'player': 'player-glyph',
}


@dataclass(frozen=True, slots=True)
class MobileCatalog:
    """Validated, bounded lookup data staged with the Android package."""
    maps: dict[str, dict[str, Any]]
    resource_types: tuple[tuple[int, int, str], ...]
    mob_avatars: tuple[str | None, ...]
    item_icons: tuple[str | None, ...]


@dataclass(slots=True)
class MobileRadarState:
    """Python-owned state whose snapshot is the sole mobile UI boundary."""
    clock_ms: Callable[[], int] = field(default_factory=lambda: int(time.time() * 1000))
    revision: int = 0
    zone_session_id: int = 0
    map_id: str | None = None
    zone_name: str = ""
    map_asset: str | None = None
    bounds: dict[str, float] = field(default_factory=lambda: {'minX': 0.0, 'minY': 0.0, 'maxX': 1.0, 'maxY': 1.0})
    local_player: dict[str, float] = field(default_factory=lambda: {'x': 0.0, 'y': 0.0})
    players: dict[int, dict[str, Any]] = field(default_factory=dict)
    resources: dict[int, dict[str, Any]] = field(default_factory=dict)
    mobs: dict[int, dict[str, Any]] = field(default_factory=dict)
    chests: dict[int, dict[str, Any]] = field(default_factory=dict)
    objects: dict[int, dict[str, Any]] = field(default_factory=dict)

    def snapshot(self) -> dict[str, Any]:
        """Return independent JSON-safe marker data without packet-derived internals."""
        return {
            'schema': 'marker_snapshot_v1',
            'revision': self.revision,
            'capturedAtMs': _safe_clock_value(self.clock_ms) or 0,
            'zone': {
                'mapId': self.map_id,
                'name': self.zone_name,
                'sessionId': self.zone_session_id,
                'mapAsset': self.map_asset,
                'bounds': dict(self.bounds),
            },
            'localPlayer': dict(self.local_player),
            'players': _snapshot_bucket(self.players, 'player'),
            'resources': _snapshot_bucket(self.resources, 'resource'),
            'mobs': _snapshot_bucket(self.mobs, 'mob'),
            'chests': _snapshot_bucket(self.chests, 'chest'),
            'objects': _snapshot_objects(self.objects),
        }


class MobileDomainRouter:
    """Routes the small Android-safe event subset into :class:`MobileRadarState`."""

    def __init__(self, state: MobileRadarState | None = None, *, clock_ms: Callable[[], int] | None = None, catalog_json: str | None = None) -> None:
        self._clock_ms = clock_ms if clock_ms else _system_clock_ms
        self.state = state if state else MobileRadarState(clock_ms=self._clock_ms)
        catalog = _parse_mobile_catalog(catalog_json)
        self._catalog_maps = catalog.maps
        self._resource_types = catalog.resource_types
        self._mob_avatars = catalog.mob_avatars
        self._item_icons = catalog.item_icons
        self._player_guid_keys: dict[str, int] = {}
        self._pending_equipment: tuple[str, int, int] | None = None

    def dispatch(self, event: RadarEvent) -> bool:
        before = self.state.revision
        if self._route_normalized(event):
            self.state.revision += 1
        return self.state.revision != before

    def cleanup(self, *, now_ms: int | None = None) -> bool:
        before = self.state.revision
        if now_ms is None:
            now = _safe_clock_value(self._clock_ms)
        else:
            now = _safe_timestamp(now_ms)
        if now is None:
            return False
        if self._expire_entities(now):
            self.state.revision += 1
        return self.state.revision != before

    def _route_normalized(self, event: RadarEvent) -> bool:
        if not isinstance(event, RadarEvent):
            return False
        parameters = _normalize_parameters(event.parameters)
        if parameters is None:
            return False
        routed_code = _resolved_code(event.kind, event.code, parameters)
        if routed_code is None:
            return False
        now = _safe_clock_value(self._clock_ms)
        if now is None:
            self._pending_equipment = None
            return False
        if event.kind == 'response':
            if routed_code == 2:
                return self._join(parameters)
            if routed_code == 41:
                return self._transition(parameters.get(0))
            if routed_code == 143:
                return self._equipment_response(parameters, event.metadata, now)
            return False
        if event.kind == 'request':
            if routed_code == 22:
                return self._set_local_position(parameters.get(1))
            if routed_code == 143:
                self._equipment_request(parameters, now)
            return False
        if event.kind != 'event':
            return False
        entity_id = _entity_id(parameters.get(0))
        if routed_code == 1:
            return self._remove_everywhere(entity_id)
        if routed_code == 3:
            return self._move(entity_id, parameters, event.metadata, now)
        if routed_code in frozenset({6, 7, 91}):
            return self._health(routed_code, entity_id, parameters, now)
        if routed_code == 29:
            return self._player_spawn(entity_id, parameters, event.metadata, now)
        if routed_code == 90:
            return self._equipment(entity_id, parameters, now)
        if routed_code == 211:
            return self._mounted(entity_id, parameters, now)
        if routed_code == 39:
            return self._resource_list(parameters, now)
        if routed_code == 40:
            return self._resource(entity_id, parameters, now)
        if routed_code == 46:
            return self._resource_state(entity_id, parameters, now)
        if routed_code == 123:
            return self._mob(entity_id, parameters, now)
        if routed_code == 47:
            return self._touch_bucket('mobs', entity_id, now)
        if routed_code == 361:
            return self._object(entity_id, parameters.get(1), parameters.get(4), 'fishing', now)
        if routed_code == 358:
            return self._remove_object_kind(entity_id, 'fishing')
        if routed_code == 393:
            return self._chest(entity_id, parameters, now)
        if routed_code == 532:
            return self._object(entity_id, parameters.get(2), parameters.get(4), 'caged', now)
        if routed_code == 533:
            return self._remove_object_kind(entity_id, 'caged')
        return False

    def _join(self, parameters: Mapping[int, Any]) -> bool:
        changed = False
        map_id = _text(parameters.get(8))
        position = _position(parameters.get(9))
        if map_id is not None:
            changed = self._set_zone(map_id)
        if position is not None:
            # _set_local_values returns bool, use call with unpacked position
            result = self._set_local_values(*position)
            changed = result or changed
        return changed

    def _transition(self, map_id: Any) -> bool:
        normalized = _text(map_id)
        if normalized is not None:
            return self._set_zone(normalized)
        return False

    def _set_zone(self, map_id: str) -> bool:
        if self.state.map_id == map_id:
            return False
        self.state.map_id = map_id
        catalog_entry = self._catalog_maps.get(map_id)
        if catalog_entry is not None:
            name = catalog_entry['name']
        else:
            name = map_id
        self.state.zone_name = name
        if catalog_entry is not None:
            asset = catalog_entry['asset']
        else:
            asset = None
        self.state.map_asset = asset
        bounds = dict(catalog_entry['bounds']) if catalog_entry is not None else dict(_FALLBACK_ZONE_BOUNDS)
        self.state.bounds = bounds
        self.state.zone_session_id += 1
        for name in _BUCKET_NAMES:
            getattr(self.state, name).clear()
        self._player_guid_keys.clear()
        self._pending_equipment = None
        return True

    def _set_local_position(self, value: Any) -> bool:
        position = _position(value)
        if position is not None:
            return self._set_local_values(*position)
        return False

    def _set_local_values(self, x: float, y: float) -> bool:
        if self.state.local_player == {'x': x, 'y': y}:
            return False
        self.state.local_player = {'x': x, 'y': y}
        return True

    def _move(self, entity_id: int | None, parameters: Mapping[int, Any], metadata: Mapping[str, Any], now: int) -> bool:
        if entity_id is None:
            return False
        x = parameters.get(4)
        y = parameters.get(5)
        position = _position((x, y))
        if position is None:
            return False
        changed = False
        for bucket_name in ('mobs', 'resources', 'chests', 'objects'):
            bucket = getattr(self.state, bucket_name)
            if entity_id in bucket:
                if self._upsert(bucket_name, entity_id, {**bucket[entity_id], 'x': position[0], 'y': position[1], 'last_seen_ms': now}):
                    changed = True
        source = _metadata_value(metadata, 'position_source')
        if is_trusted_player_position_source(source) and is_plausible_player_position(x, y):
            old = self.state.players.get(entity_id, {})
            entity = {**old, 'id': entity_id, 'x': position[0], 'y': position[1], 'last_seen_ms': now}
            if self._upsert('players', entity_id, entity):
                changed = True
        return changed

    def _player_spawn(self, entity_id: int | None, parameters: Mapping[int, Any], metadata: Mapping[str, Any], now: int) -> bool:
        if entity_id is None:
            return False
        old = self.state.players.get(entity_id, {})
        entity = {**old, 'id': entity_id, 'last_seen_ms': now}
        label = _text(parameters.get(1))
        if label is not None:
            entity['label'] = label
        guild = _text(parameters.get(8))
        if guild is not None:
            entity['guild'] = guild
        equipment = _equipment_values(parameters.get(40))
        if equipment is None:
            equipment = _equipment_values(parameters.get(38))
        if equipment is not None:
            entity['equipment'] = equipment
            entity['equipment_icons'] = self._equipment_icons(equipment)
        source = _metadata_value(metadata, 'position_source')
        spawn = _metadata_value(metadata, 'spawn_position')
        if is_trusted_player_spawn_position_source(source):
            position = _position_from_mapping(spawn)
            if position is not None and is_plausible_player_position(*position):
                entity['x'], entity['y'] = position
        changed = self._upsert('players', entity_id, entity)
        guid_key = _guid_key(parameters.get(7))
        if guid_key is not None and entity_id in self.state.players:
            # prune old guid keys mapping to this entity_id? Actually keep only one per entity
            self._player_guid_keys = {k: v for k, v in self._player_guid_keys.items() if v != entity_id}
            self._player_guid_keys[guid_key] = entity_id
        return changed

    def _equipment_request(self, parameters: Mapping[int, Any], now: int) -> None:
        self._pending_equipment = None
        if now is None:
            return None
        guid_key = _guid_key(parameters.get(0))
        if guid_key is None:
            return None
        if not isinstance(parameters.get(1), bool):
            return None
        entity_id = self._player_guid_keys.get(guid_key)
        if entity_id is None:
            return None
        if entity_id not in self.state.players:
            return None
        self._pending_equipment = (guid_key, self.state.zone_session_id, now)
        return None

    def _equipment_response(self, parameters: Mapping[int, Any], metadata: Mapping[str, Any], now: int) -> bool:
        pending = self._pending_equipment
        self._pending_equipment = None
        return_code = _metadata_value(metadata, 'return_code')
        if pending is None or now is None or not isinstance(return_code, int) or return_code != 0:
            return False
        guid_key, session_id, requested_at = pending
        if session_id != self.state.zone_session_id:
            return False
        if now < requested_at:
            return False
        if now - requested_at > _EQUIPMENT_RESPONSE_TTL_MS:
            return False
        if _guid_key(parameters.get(0)) != guid_key:
            return False
        if not _inspect_equipment_ids(parameters.get(1)):
            return False
        item_power = _item_power(parameters.get(3))
        entity_id = self._player_guid_keys.get(guid_key)
        if item_power is None or entity_id is None or entity_id not in self.state.players:
            return False
        return self._upsert('players', entity_id, {**self.state.players[entity_id], 'item_power': item_power, 'last_seen_ms': now})

    def _health(self, code: int, entity_id: int | None, parameters: Mapping[int, Any], now: int) -> bool:
        if entity_id is None:
            return False
        values = None
        health = None
        normalized = None
        max_health = None
        if code == 7:
            values = parameters.get(3)
            if isinstance(values, list) and values:
                health = values[0]
            else:
                health = None
        elif code == 91:
            health = parameters.get(2)
        else:
            health = parameters.get(3)
        normalized = _health(health)
        if normalized is None:
            return False
        if code == 91:
            max_health = _health(parameters.get(3))
        else:
            max_health = None
        changed = False
        for bucket_name in ('players', 'mobs'):
            bucket = getattr(self.state, bucket_name)
            if entity_id not in bucket:
                continue
            if bucket_name == 'mobs' and normalized <= 0:
                if self._remove_from(bucket_name, entity_id):
                    changed = True
                continue
            entity = {**bucket[entity_id], 'health': normalized, 'last_seen_ms': now}
            if bucket_name == 'players' and max_health is not None:
                entity['max_health'] = max_health
            if self._upsert(bucket_name, entity_id, entity):
                changed = True
        return changed

    def _equipment(self, entity_id: int | None, parameters: Mapping[int, Any], now: int) -> bool:
        values = _equipment_values(parameters.get(2))
        if entity_id is None or values is None or entity_id not in self.state.players:
            return False
        return self._upsert('players', entity_id, {**self.state.players[entity_id], 'equipment': values, 'equipment_icons': self._equipment_icons(values), 'last_seen_ms': now})

    def _mounted(self, entity_id: int | None, parameters: Mapping[int, Any], now: int) -> bool:
        mounted = parameters.get(11)
        if entity_id is None or not isinstance(mounted, bool) or entity_id not in self.state.players:
            return False
        return self._upsert('players', entity_id, {**self.state.players[entity_id], 'mounted': mounted, 'last_seen_ms': now})

    def _resource_list(self, parameters: Mapping[int, Any], now: int) -> bool:
        values = parameters.get(0)
        if all(key in parameters for key in (0, 1, 2, 3, 4)):
            ids = _bounded_number_array(values, maximum=_MAX_ENTITY_ID)
            types = _bounded_number_array(parameters.get(1), maximum=_MAX_ENTITY_ID)
            tiers = _bounded_number_array(parameters.get(2), maximum=12)
            sizes = _bounded_number_array(parameters.get(4), maximum=1000000)
            positions = parameters.get(3)
            if ids is not None and types is not None and tiers is not None and sizes is not None and type(positions) is list:
                return self._store_batch_resources(ids, types, tiers, sizes, positions, now)
        if type(values) is not list:
            return False
        if not all(type(v) is dict for v in values):
            return False
        changed = False
        for value in values[:_MAX_ENTITIES]:
            normalized = _normalize_parameters(value)
            if normalized is None:
                continue
            if self._resource(_entity_id(normalized.get(0)), normalized, now):
                changed = True
        return changed

    def _store_batch_resources(self, ids: list[int], types: list[int], tiers: list[int], sizes: list[int], positions: list[Any], now: int) -> bool:
        changed = False
        for index, entity_id in enumerate(ids[:_MAX_ENTITIES]):
            position_index = index * 2
            if position_index + 1 >= len(positions):
                continue
            type_id = types[index] if index < len(types) else None
            tier = tiers[index] if index < len(tiers) else None
            x = positions[position_index]
            y = positions[position_index + 1]
            size = sizes[index] if index < len(sizes) else None
            resource_parameters = {0: entity_id, 5: type_id, 7: tier, 8: [x, y], 10: size, 11: 0}
            if self._resource(entity_id, resource_parameters, now):
                changed = True
        return changed

    def _resource(self, entity_id: int | None, parameters: Mapping[int, Any], now: int) -> bool:
        position = _position(parameters.get(8))
        if entity_id is None or position is None:
            return False
        entity = {'id': entity_id, 'x': position[0], 'y': position[1], 'last_seen_ms': now}
        tier = _bounded_int(parameters.get(7), 0, 12)
        enchantment = _bounded_int(parameters.get(11), 0, 4)
        resource_type_id = _bounded_int(parameters.get(5), 0, _MAX_ENTITY_ID)
        family = self._resource_family(resource_type_id)
        if family is not None:
            entity['type'] = family
        if tier is not None:
            entity['tier'] = tier
        if enchantment is not None:
            entity['enchantment'] = enchantment
        return self._upsert('resources', entity_id, entity)

    def _resource_state(self, entity_id: int | None, parameters: Mapping[int, Any], now: int) -> bool:
        if entity_id is None or entity_id not in self.state.resources:
            return False
        size = _bounded_int(parameters.get(1), 0, 1000000)
        if size is None:
            return False
        if size == 0:
            return self._remove_from('resources', entity_id)
        entity = {**self.state.resources[entity_id], 'last_seen_ms': now}
        enchantment = _bounded_int(parameters.get(2), 0, 4)
        if enchantment is not None:
            entity['enchantment'] = enchantment
        return self._upsert('resources', entity_id, entity)

    def _mob(self, entity_id: int | None, parameters: Mapping[int, Any], now: int) -> bool:
        if entity_id is None:
            return False
        position = _position(parameters.get(7))
        entity = {**self.state.mobs.get(entity_id, {}), 'id': entity_id, 'last_seen_ms': now}
        if position is not None:
            entity['x'], entity['y'] = position
        type_id = _bounded_int(parameters.get(1), 0, _MAX_ENTITY_ID)
        if type_id is not None:
            entity['type'] = f'mob:{type_id}'
            entity.pop('icon', None)
            avatar_index = type_id - 16
            if 0 <= avatar_index < len(self._mob_avatars):
                icon = self._mob_avatars[avatar_index]
                if icon is not None:
                    entity['icon'] = icon
        label = _text(parameters.get(32)) or _text(parameters.get(31))
        if label is not None:
            entity['label'] = label
        health = _health(parameters.get(2))
        if health is not None:
            entity['health'] = health
        enchantment = _bounded_int(parameters.get(33), 0, 4)
        if enchantment is not None:
            entity['enchantment'] = enchantment
        return self._upsert('mobs', entity_id, entity)

    def _resource_family(self, type_id: int | None) -> str | None:
        if type_id is None:
            return None
        for first, last, family in self._resource_types:
            if first <= type_id <= last:
                return family
        return None

    def _equipment_icons(self, equipment: list[int]) -> list[str | None]:
        return [self._item_icons[item_id] if item_id < len(self._item_icons) else None for item_id in equipment[:_MAX_EQUIPMENT_ICON_SLOTS]]

    def _chest(self, entity_id: int | None, parameters: Mapping[int, Any], now: int) -> bool:
        position = _position(parameters.get(1))
        label = _text(parameters.get(4)) or _text(parameters.get(3))
        if entity_id is None or position is None or label is None:
            return False
        entity = {'id': entity_id, 'x': position[0], 'y': position[1], 'type': label, 'last_seen_ms': now}
        rarity = _bounded_int(parameters.get(5), 0, 10)
        if rarity is not None:
            entity['rarity'] = rarity
        return self._upsert('chests', entity_id, entity)

    def _object(self, entity_id: int | None, raw_position: Any, raw_type: Any, kind: str, now: int) -> bool:
        position = _position(raw_position)
        object_type = _text(raw_type)
        if entity_id is None or position is None or object_type is None:
            return False
        return self._upsert('objects', entity_id, {'id': entity_id, 'kind': kind, 'type': object_type, 'x': position[0], 'y': position[1], 'last_seen_ms': now})

    def _touch_bucket(self, bucket_name: str, entity_id: int | None, now: int) -> bool:
        if entity_id is None:
            return False
        bucket = getattr(self.state, bucket_name)
        if entity_id not in bucket:
            return False
        return self._upsert(bucket_name, entity_id, {**bucket[entity_id], 'last_seen_ms': now})

    def _remove_everywhere(self, entity_id: int | None) -> bool:
        if entity_id is None:
            return False
        changed = False
        for bucket_name in _BUCKET_NAMES:
            if self._remove_from(bucket_name, entity_id):
                changed = True
        self._player_guid_keys = {k: v for k, v in self._player_guid_keys.items() if v != entity_id}
        self._prune_player_references()
        return changed

    def _remove_object_kind(self, entity_id: int | None, kind: str) -> bool:
        if entity_id is None:
            return False
        entity = self.state.objects.get(entity_id)
        if entity is None:
            return False
        if entity.get('kind') != kind:
            return False
        return self._remove_from('objects', entity_id)

    def _remove_from(self, bucket_name: str, entity_id: int | None) -> bool:
        if entity_id is None:
            return False
        bucket = getattr(self.state, bucket_name)
        if entity_id not in bucket:
            return False
        del bucket[entity_id]
        return True

    def _upsert(self, bucket_name: str, entity_id: int, entity: dict[str, Any]) -> bool:
        bucket = getattr(self.state, bucket_name)
        candidate = _bounded_entity(entity)
        if candidate is None:
            return False
        previous = bucket.get(entity_id)
        if previous == candidate:
            return False
        if previous is None and len(bucket) >= _MAX_ENTITIES and entity_id > max(bucket):
            return False
        bucket[entity_id] = candidate
        if len(bucket) > _MAX_ENTITIES:
            del bucket[max(bucket)]
        if bucket_name == 'players':
            self._prune_player_references()
        return True

    def _expire_entities(self, now: int) -> bool:
        changed = False
        for bucket_name, ttl_ms in (('players', _PLAYER_MOB_TTL_MS), ('mobs', _PLAYER_MOB_TTL_MS), ('chests', _OBJECT_TTL_MS), ('objects', _OBJECT_TTL_MS), ('resources', _RESOURCE_TTL_MS)):
            bucket = getattr(self.state, bucket_name)
            stale = [entity_id for entity_id, entity in bucket.items() if now - entity['last_seen_ms'] > ttl_ms]
            for entity_id in stale:
                del bucket[entity_id]
            if stale:
                changed = True
        self._prune_player_references()
        return changed

    def _prune_player_references(self) -> None:
        active_ids = set(self.state.players)
        self._player_guid_keys = {k: v for k, v in self._player_guid_keys.items() if v in active_ids}
        if self._pending_equipment is not None and self._pending_equipment[0] not in self._player_guid_keys:
            self._pending_equipment = None


class AndroidPhotonAdapter:
    """Own per-flow Photon processors and expose safe marker snapshots to Android."""

    def __init__(self, processor_factory: Callable[..., RelayPhotonProcessor] = RelayPhotonProcessor, *, clock_ms: Callable[[], int] | None = None, catalog_json: str | None = None, cleanup_interval_ms: int = 1000) -> None:
        if not isinstance(cleanup_interval_ms, int) or not 1 <= cleanup_interval_ms <= _MAX_CLEANUP_INTERVAL_MS:
            raise ValueError('invalid cleanup interval')
        self._clock_ms = clock_ms if clock_ms else _system_clock_ms
        self._router = MobileDomainRouter(clock_ms=self._clock_ms, catalog_json=catalog_json)
        self._processor_factory = processor_factory
        self._processors: dict[str, RelayPhotonProcessor] = {}
        self._snapshot_revision = self._router.state.revision
        self._cleanup_interval_ms = cleanup_interval_ms
        self._last_cleanup_ms: int | None = None

    def open_flow(self, flow_id: str) -> None:
        self._validate_flow_id(flow_id)
        if flow_id in self._processors:
            raise ValueError('duplicate flow_id')
        if len(self._processors) >= _MAX_MOBILE_FLOWS:
            raise ValueError('flow capacity exceeded')
        def on_event(event: dict[str, Any]) -> None:
            self._on_event(event)
        def on_diagnostic(diagnostic: dict[str, Any]) -> None:
            self._on_diagnostic(diagnostic)
        processor = self._processor_factory(on_event=on_event, on_diagnostic=on_diagnostic, strict_transport=True, event_source='local_relay')
        self._processors[flow_id] = processor

    def process(self, flow_id: str, direction: str, payload: bytes | bytearray) -> dict[str, list[bytes] | str | None]:
        self._validate_flow_id(flow_id)
        if not isinstance(direction, str) or direction not in _MOBILE_FLOW_DIRECTIONS:
            raise ValueError('invalid direction')
        if type(payload) not in (bytes, bytearray):
            raise TypeError('payload must be bytes or bytearray')
        if len(payload) > _MAX_MOBILE_PAYLOAD_BYTES:
            raise ValueError('payload exceeds maximum size')
        processor = self._processors.get(flow_id)
        if processor is None:
            raise KeyError('unknown flow_id')
        try:
            outputs = processor.process_packets(direction=direction, payload=bytes(payload))
        except Exception:
            self._finalize_flow(flow_id, processor)
            raise
        if not isinstance(outputs, list) or any(type(item) is not bytes for item in outputs):
            raise TypeError('processor returned invalid payloads')
        self._cleanup_if_due()
        snapshot = self._snapshot_if_advanced()
        return {'payloads': outputs, 'snapshot': snapshot}

    def close_flow(self, flow_id: str) -> bool:
        self._validate_flow_id(flow_id)
        processor = self._processors.get(flow_id)
        if processor is None:
            return False
        self._finalize_flow(flow_id, processor)
        return True

    def _finalize_flow(self, flow_id: str, processor: RelayPhotonProcessor) -> None:
        if self._processors.get(flow_id) is not processor:
            return None
        del self._processors[flow_id]
        try:
            processor.finalize()
        except Exception:
            pass
        return None

    def _on_event(self, event: object) -> None:
        if not isinstance(event, dict):
            return None
        kind = event.get('kind')
        code = event.get('code')
        parameters = event.get('parameters')
        metadata = event.get('metadata', {})
        source = event.get('source', 'local_relay')
        if not isinstance(kind, str) or not isinstance(code, int) or not isinstance(parameters, dict) or not isinstance(metadata, dict) or not isinstance(source, str):
            return None
        safe_metadata = _safe_mobile_metadata(metadata)
        self._router.dispatch(RadarEvent(kind=kind, code=code, parameters=dict(parameters), source=source[:_MAX_TEXT_LENGTH], metadata=safe_metadata))

    def _on_diagnostic(self, _diagnostic: object) -> None:
        """Discard diagnostics which may contain sensitive transport state."""
        return None

    def _cleanup_if_due(self) -> None:
        now = _safe_clock_value(self._clock_ms)
        if now is None:
            return None
        last_cleanup = self._last_cleanup_ms
        if last_cleanup is not None and now >= last_cleanup and now - last_cleanup < self._cleanup_interval_ms:
            return None
        self._last_cleanup_ms = now
        self._router.cleanup(now_ms=now)

    def _snapshot_if_advanced(self) -> str | None:
        revision = self._router.state.revision
        if revision <= self._snapshot_revision:
            return None
        self._snapshot_revision = revision
        return json.dumps(self._router.state.snapshot(), allow_nan=False, separators=(',', ':'), sort_keys=True)

    @staticmethod
    def _validate_flow_id(flow_id: object) -> None:
        if not isinstance(flow_id, str):
            raise TypeError('flow_id must be a string')
        if not flow_id or len(flow_id) > _MAX_TEXT_LENGTH:
            raise ValueError('invalid flow_id')


def _parse_mobile_catalog(catalog_json: str | None) -> MobileCatalog:
    if catalog_json is None:
        return MobileCatalog(maps={}, resource_types=_MOBILE_RESOURCE_TYPES, mob_avatars=(), item_icons=())
    if not isinstance(catalog_json, str) or not catalog_json or len(catalog_json.encode('utf-8')) > _MAX_MOBILE_CATALOG_BYTES:
        raise ValueError('invalid mobile catalog size')

    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate mobile catalog key')
            result[key] = value
        return result

    try:
        raw = json.loads(catalog_json, object_pairs_hook=reject_duplicate_pairs, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('non-finite mobile catalog number')))
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise ValueError('invalid mobile catalog JSON') from exc
    expected_keys = {'maps', 'schema', 'itemIcons', 'mobAvatars', 'markerStyles', 'resourceTiers', 'resourceTypes', 'resourceFamilies', 'resourceEnchantments'}
    if not isinstance(raw, dict) or set(raw) != expected_keys or raw.get('schema') != 'phone_radar_catalog_v2':
        raise ValueError('invalid mobile catalog schema')
    if raw.get('markerStyles') != _MOBILE_MARKER_STYLES:
        raise ValueError('invalid mobile catalog marker styles')
    if list(raw.get('resourceFamilies')) != list(_MOBILE_RESOURCE_FAMILIES):
        raise ValueError('invalid mobile catalog resource families')
    if raw.get('resourceTiers') != [1, 8] or raw.get('resourceEnchantments') != [0, 4]:
        raise ValueError('invalid mobile catalog resource bounds')
    expected_resource_types = [{'family': f, 'first': a, 'last': b} for a, b, f in _MOBILE_RESOURCE_TYPES]
    if raw.get('resourceTypes') != expected_resource_types:
        raise ValueError('invalid mobile catalog resource types')
    mob_avatars = _parse_catalog_image_stems(raw.get('mobAvatars'), maximum=_MAX_MOBILE_MOB_AVATARS, label='mob avatars')
    item_icons = _parse_catalog_image_stems(raw.get('itemIcons'), maximum=_MAX_MOBILE_ITEM_ICONS, label='item icons')
    maps = raw.get('maps')
    if not isinstance(maps, list) or not maps or len(maps) > _MAX_MOBILE_CATALOG_MAPS:
        raise ValueError('invalid mobile catalog maps')
    catalog_maps: dict[str, dict[str, Any]] = {}
    previous_map_id: str | None = None
    for entry in maps:
        if not isinstance(entry, dict) or set(entry) != {'name', 'asset', 'mapId', 'bounds'}:
            raise ValueError('invalid mobile catalog map')
        map_id, name, asset, bounds = entry['mapId'], entry['name'], entry['asset'], entry['bounds']
        if not isinstance(map_id, str) or not map_id or len(map_id) > _MAX_TEXT_LENGTH or map_id in catalog_maps or (previous_map_id is not None and map_id <= previous_map_id):
            raise ValueError('invalid mobile catalog map identity')
        if not isinstance(name, str) or not name or len(name) > _MAX_TEXT_LENGTH:
            raise ValueError('invalid mobile catalog map identity')
        if asset is not None:
            if not isinstance(asset, str) or len(asset) > 160 or _MOBILE_CATALOG_ASSET.fullmatch(asset) is None:
                raise ValueError('invalid mobile catalog map asset')
        if not isinstance(bounds, list) or len(bounds) != 4 or any(not isinstance(v, (int, float)) or not math.isfinite(v) for v in bounds) or bounds[0] >= bounds[2] or bounds[1] >= bounds[3] or any(abs(float(v)) > _MAX_ABSOLUTE_POSITION for v in bounds):
            raise ValueError('invalid mobile catalog map bounds')
        catalog_maps[map_id] = {'name': name, 'asset': asset, 'bounds': {'minX': float(bounds[0]), 'minY': float(bounds[1]), 'maxX': float(bounds[2]), 'maxY': float(bounds[3])}}
        previous_map_id = map_id
    return MobileCatalog(maps=catalog_maps, resource_types=_MOBILE_RESOURCE_TYPES, mob_avatars=mob_avatars, item_icons=item_icons)


def _parse_catalog_image_stems(value: Any, *, maximum: int, label: str) -> tuple[str | None, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f'invalid mobile catalog {label}')
    for stem in value:
        if stem is None:
            continue
        if not isinstance(stem, str) or _MOBILE_CATALOG_IMAGE_STEM.fullmatch(stem) is None:
            raise ValueError(f'invalid mobile catalog {label}')
    return tuple(value)


def _normalize_parameters(parameters: object) -> dict[int, Any] | None:
    if not isinstance(parameters, dict):
        return None
    normalized: dict[int, Any] = {}
    try:
        items = parameters.items()
        for key, value in items:
            if isinstance(key, int):
                normalized_key = key
            elif isinstance(key, str) and key.isdecimal():
                normalized_key = int(key)
            else:
                continue
            if normalized_key in normalized and normalized[normalized_key] != value:
                return None
            normalized[normalized_key] = value
    except Exception:
        return None
    return normalized


def _safe_mobile_metadata(metadata: dict[object, object]) -> dict[str, object]:
    safe: dict[str, object] = {}
    position_source = metadata.get('position_source')
    if isinstance(position_source, str) and 0 < len(position_source) <= _MAX_TEXT_LENGTH:
        safe['position_source'] = position_source
    spawn_position = metadata.get('spawn_position')
    if isinstance(spawn_position, dict):
        position = _position_pair(spawn_position.get('x'), spawn_position.get('y'))
        if position is not None:
            safe['spawn_position'] = {'x': position[0], 'y': position[1]}
    return_code = metadata.get('return_code')
    if isinstance(return_code, int) and 0 <= return_code <= 65535:
        safe['return_code'] = return_code
    return safe


def _metadata_value(metadata: object, key: str) -> Any:
    if isinstance(metadata, dict):
        return metadata.get(key)
    return None


def _resolved_code(kind: object, observed: object, parameters: Mapping[int, Any]) -> int | None:
    if not isinstance(kind, str) or kind not in frozenset({'event', 'request', 'response'}):
        return None
    if not isinstance(observed, int) or not 0 <= observed <= 65535:
        return None
    # If parameters contains mapping for kind-specific key 252/253 use that else observed
    parameter_code = parameters.get(252 if kind == 'event' else 253)
    if parameter_code is None:
        return observed
    return _bounded_int(parameter_code, 0, 65535)


def _entity_id(value: Any) -> int | None:
    if isinstance(value, int) and 0 <= value <= _MAX_ENTITY_ID:
        return value
    if isinstance(value, str) and value.isdecimal():
        normalized = int(value)
        if normalized <= _MAX_ENTITY_ID:
            return normalized
    return None


def _position(value: Any) -> tuple[float, float] | None:
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return _position_pair(value[0], value[1])
    return None


def _position_from_mapping(value: Any) -> tuple[float, float] | None:
    if not isinstance(value, dict):
        return None
    return _position_pair(value.get('x'), value.get('y'))


def _position_pair(x: Any, y: Any) -> tuple[float, float] | None:
    if type(x) not in (int, float) or type(y) not in (int, float):
        return None
    x_value = float(x)
    y_value = float(y)
    if not math.isfinite(x_value) or not math.isfinite(y_value):
        return None
    if abs(x_value) > _MAX_ABSOLUTE_POSITION or abs(y_value) > _MAX_ABSOLUTE_POSITION:
        return None
    return (x_value, y_value)


def _text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return normalized[:_MAX_TEXT_LENGTH]


def _bounded_int(value: Any, minimum: int, maximum: int) -> int | None:
    if not isinstance(value, int):
        return None
    if not minimum <= value <= maximum:
        return None
    return value


def _health(value: Any) -> float | None:
    if type(value) not in (int, float):
        return None
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 <= normalized <= 1000000.0:
        return None
    return normalized


def _equipment_values(value: Any) -> list[int] | None:
    if not isinstance(value, list) or len(value) > 32:
        return None
    values = [_bounded_int(item, 0, 10000000) for item in value]
    if not all(v is not None for v in values):
        return None
    return values  # type: ignore


def _catalog_image_stem(value: Any) -> str | None:
    if not isinstance(value, str) or _MOBILE_CATALOG_IMAGE_STEM.fullmatch(value) is None:
        return None
    return value


def _equipment_icon_values(value: Any) -> list[str | None] | None:
    if not isinstance(value, list) or len(value) > _MAX_EQUIPMENT_ICON_SLOTS:
        return None
    values: list[str | None] = []
    for item in value:
        if item is None:
            values.append(None)
            continue
        stem = _catalog_image_stem(item)
        if stem is None:
            return None
        values.append(stem)
    return values


def _guid_key(value: Any) -> str | None:
    payload = _strict_byte_array(value)
    if payload is None or len(payload) != 16 or not any(payload):
        return None
    return hashlib.sha256(bytes(payload)).hexdigest()


def _strict_byte_array(value: Any) -> list[int] | None:
    if isinstance(value, (bytes, bytearray)):
        payload = list(value)
    elif isinstance(value, dict) and set(value) == {'type', 'data'} and value.get('type') == 'Buffer' and isinstance(value.get('data'), list):
        payload = value.get('data')
    else:
        return None
    if len(payload) > _MAX_BUFFER_LENGTH or any(not isinstance(item, int) or not 0 <= item <= 255 for item in payload):
        return None
    return list(payload)


def _bounded_number_array(value: Any, *, maximum: int) -> list[int] | None:
    byte_payload = _strict_byte_array(value)
    if byte_payload is not None:
        return byte_payload
    if not isinstance(value, list) or len(value) > _MAX_ENTITIES:
        return None
    if not all(isinstance(item, int) and 0 <= item <= maximum for item in value):
        return None
    return list(value)


def _inspect_equipment_ids(value: Any) -> bool:
    if not isinstance(value, list) or len(value) != 10:
        return False
    return all(_entity_id(item) is not None for item in value)


def _item_power(value: Any) -> float | None:
    if type(value) not in (int, float):
        return None
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 <= normalized <= 10000.0:
        return None
    return normalized


def _bounded_entity(entity: Mapping[str, Any]) -> dict[str, Any] | None:
    entity_id = _entity_id(entity.get('id'))
    if 'x' in entity and 'y' in entity:
        position = _position_pair(entity.get('x'), entity.get('y'))
        if position is None:
            return None
        x, y = position
    else:
        x, y = None, None
    last_seen = _safe_timestamp(entity.get('last_seen_ms'))
    if entity_id is None or last_seen is None:
        return None
    result: dict[str, Any] = {'id': entity_id, 'last_seen_ms': last_seen}
    if x is not None and y is not None:
        result.update({'x': x, 'y': y})
    for key in ('label', 'type', 'guild'):
        text = _text(entity.get(key))
        if text is not None:
            result[key] = text
    icon = _catalog_image_stem(entity.get('icon'))
    if icon is not None:
        result['icon'] = icon
    for key, maximum in (('tier', 12), ('enchantment', 4), ('rarity', 10)):
        value = _bounded_int(entity.get(key), 0, maximum)
        if value is not None:
            result[key] = value
    health = _health(entity.get('health'))
    if health is not None:
        result['health'] = health
    max_health = _health(entity.get('max_health'))
    if max_health is not None:
        result['max_health'] = max_health
    item_power = _item_power(entity.get('item_power'))
    if item_power is not None:
        result['item_power'] = item_power
    if isinstance(entity.get('mounted'), bool):
        result['mounted'] = entity['mounted']
    equipment = _equipment_values(entity.get('equipment'))
    if equipment is not None:
        result['equipment'] = equipment
    equipment_icons = _equipment_icon_values(entity.get('equipment_icons'))
    if equipment_icons is not None:
        result['equipment_icons'] = equipment_icons
    kind = entity.get('kind')
    if kind in frozenset({'caged', 'fishing'}):
        result['kind'] = kind
    return result


def _snapshot_bucket(bucket: Mapping[int, Mapping[str, Any]], kind: str) -> list[dict[str, Any]]:
    markers: list[dict[str, Any]] = []
    for entity_id in sorted(bucket):
        entity = bucket[entity_id]
        if 'x' not in entity or 'y' not in entity:
            continue
        marker = {'id': entity['id'], 'kind': kind, 'x': entity['x'], 'y': entity['y']}
        for source, target in (('label', 'label'), ('type', 'type'), ('icon', 'icon'), ('guild', 'guild'), ('tier', 'tier'), ('enchantment', 'enchantment'), ('rarity', 'rarity'), ('health', 'health'), ('max_health', 'maxHealth'), ('item_power', 'itemPower'), ('mounted', 'mounted'), ('equipment', 'equipment'), ('equipment_icons', 'equipmentIcons')):
            if source in entity:
                if source in ('equipment', 'equipment_icons'):
                    marker[target] = list(entity[source])
                else:
                    marker[target] = entity[source]
        marker['lastSeenMs'] = entity['last_seen_ms']
        markers.append(marker)
    return markers


def _snapshot_objects(bucket: Mapping[int, Mapping[str, Any]]) -> list[dict[str, Any]]:
    markers: list[dict[str, Any]] = []
    for entity_id in sorted(bucket):
        entity = bucket[entity_id]
        marker = {'id': entity['id'], 'kind': entity['kind'], 'type': entity['type'], 'x': entity['x'], 'y': entity['y'], 'lastSeenMs': entity['last_seen_ms']}
        markers.append(marker)
    return markers


def _safe_timestamp(value: Any) -> int | None:
    if isinstance(value, int) and 0 <= value <= _MAX_ENTITY_ID:
        return value
    return None


def _safe_clock_value(clock: Callable[[], object]) -> int | None:
    try:
        return _safe_timestamp(clock())
    except Exception:
        return None


def _system_clock_ms() -> int:
    return int(time.time() * 1000)

