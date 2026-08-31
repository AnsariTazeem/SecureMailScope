"""Safe bounded YAML policy pack loader (Commit 4).

Loads a PolicyPack from a YAML file with strict safety constraints:
- Bounded input size (65,536 bytes)
- Strict UTF-8 decoding
- SafeLoader-derived loader only (no unsafe constructs)
- Rejects duplicate keys, merge keys, aliases/anchors, executable tags
- Bounded depth and node count before model validation
- All failures converted to PolicyPackLoadError with bounded messages
"""

from __future__ import annotations

import hashlib
import importlib.resources
import json
from pathlib import Path

import yaml
from pydantic import ValidationError
from yaml.nodes import MappingNode, SequenceNode

from securemailscope.chain.errors import PolicyPackLoadError
from securemailscope.chain.policy.models import PolicyPack

_MAX_YAML_BYTES = 65_536
_MAX_NESTING_DEPTH = 20
_MAX_PARSED_NODES = 2_048


class _SafeLoader(yaml.SafeLoader):
    """SafeLoader with additional restrictions."""

    def __init__(self, stream):
        super().__init__(stream)
        self._node_count = 0
        self._max_depth = 0
        self._anchor_seen = False

    def get_single_data(self):
        data = super().get_single_data()
        if self._anchor_seen:
            raise PolicyPackLoadError(
                "policy_load",
                "YAML aliases and anchors are not allowed",
            )
        return data

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            if getattr(index, "value", None) == "<<":
                raise PolicyPackLoadError(
                    "policy_load",
                    "YAML merge keys (<<) are not allowed",
                )
            raise PolicyPackLoadError(
                "policy_load",
                "YAML aliases and anchors are not allowed",
            )
        if getattr(self.peek_event(), "anchor", None) is not None:
            self._anchor_seen = True

        self._node_count += 1
        if self._node_count > _MAX_PARSED_NODES:
            raise PolicyPackLoadError(
                "policy_load",
                "YAML node count exceeds maximum",
                f"max_nodes={_MAX_PARSED_NODES}",
            )
        node = super().compose_node(parent, index)
        depth = self._calculate_depth(node)
        if depth > _MAX_NESTING_DEPTH:
            raise PolicyPackLoadError(
                "policy_load",
                "YAML nesting depth exceeds maximum",
                f"max_depth={_MAX_NESTING_DEPTH}",
            )
        return node

    def _calculate_depth(self, node, current=0):
        if isinstance(node, MappingNode):
            children = (
                child for key_node, value_node in node.value for child in (key_node, value_node)
            )
        elif isinstance(node, SequenceNode):
            children = iter(node.value)
        else:
            return current

        max_child = current
        for child in children:
            child_depth = self._calculate_depth(child, current + 1)
            if child_depth > max_child:
                max_child = child_depth
        return max_child

    def construct_mapping(self, node, deep=False):
        # Reject duplicate keys
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise PolicyPackLoadError(
                    "policy_load",
                    "duplicate mapping key in YAML",
                    f"key={str(key)[:100]}",
                )
            seen.add(key)
        # Reject merge keys (<<)
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key == "<<":
                raise PolicyPackLoadError(
                    "policy_load",
                    "YAML merge keys (<<) are not allowed",
                )
        return super().construct_mapping(node, deep=deep)

    def ignore_alias(self, node):
        # Reject aliases/anchors
        raise PolicyPackLoadError(
            "policy_load",
            "YAML aliases and anchors are not allowed",
        )


# Register the tag handlers to reject executable/custom tags
def _reject_executable_tag(loader, node):
    raise PolicyPackLoadError(
        "policy_load",
        "executable or custom YAML tags are not allowed",
        f"tag={getattr(node, 'tag', 'unknown')[:100]}",
    )


for tag in (
    "!!python/object/apply",
    "!!python/object/new",
    "!!python/object",
    "!!python/name",
    "!!python/module",
    "!!python/function",
    "!!python/class",
):
    yaml.add_constructor(tag, _reject_executable_tag, Loader=_SafeLoader)
_SafeLoader.add_constructor(None, _reject_executable_tag)


def _read_bounded_yaml(path: Path) -> str:
    """Read YAML file with size and encoding bounds."""
    if not path.exists():
        raise PolicyPackLoadError(
            "policy_load",
            "policy pack file not found",
            f"path={str(path)[:256]}",
        )
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PolicyPackLoadError(
            "policy_load",
            "failed to read policy pack file",
            str(exc)[:256],
        ) from exc

    if len(data) > _MAX_YAML_BYTES:
        raise PolicyPackLoadError(
            "policy_load",
            "policy pack exceeds maximum size",
            f"max_bytes={_MAX_YAML_BYTES}",
        )
    if not data:
        raise PolicyPackLoadError("policy_load", "policy pack is empty")

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyPackLoadError(
            "policy_load",
            "policy pack is not valid UTF-8",
            str(exc)[:256],
        ) from exc


def load_policy_pack(path: Path) -> PolicyPack:
    """Load and validate a PolicyPack from a YAML file."""
    text = _read_bounded_yaml(path)

    try:
        data = yaml.load(text, Loader=_SafeLoader)
    except PolicyPackLoadError:
        raise
    except yaml.YAMLError as exc:
        raise PolicyPackLoadError(
            "policy_load",
            "YAML parse error",
            str(exc)[:256],
        ) from exc
    except Exception as exc:
        raise PolicyPackLoadError(
            "policy_load",
            "unexpected YAML error",
            str(exc)[:256],
        ) from exc

    if data is None:
        raise PolicyPackLoadError("policy_load", "empty YAML document")

    try:
        return PolicyPack.model_validate(data)
    except ValidationError as exc:
        raise PolicyPackLoadError(
            "policy_load",
            "policy pack validation failed",
            str(exc)[:512],
        ) from exc


def load_default_policy_pack() -> PolicyPack:
    """Load the checked-in default policy pack using importlib.resources."""
    try:
        ref = importlib.resources.files("securemailscope.chain.policy.rules").joinpath(
            "smtp-starttls-1.0.0.yaml"
        )
        text = ref.read_text(encoding="utf-8")
    except Exception as exc:
        raise PolicyPackLoadError(
            "policy_load",
            "default policy pack resource not found",
            str(exc)[:256],
        ) from exc

    if len(text.encode("utf-8")) > _MAX_YAML_BYTES:
        raise PolicyPackLoadError(
            "policy_load",
            "default policy pack exceeds maximum size",
        )

    try:
        data = yaml.load(text, Loader=_SafeLoader)
    except PolicyPackLoadError:
        raise
    except yaml.YAMLError as exc:
        raise PolicyPackLoadError(
            "policy_load",
            "default policy pack YAML parse error",
            str(exc)[:256],
        ) from exc
    except Exception as exc:
        raise PolicyPackLoadError(
            "policy_load",
            "unexpected YAML error in default pack",
            str(exc)[:256],
        ) from exc

    if data is None:
        raise PolicyPackLoadError("policy_load", "default policy pack is empty")

    try:
        return PolicyPack.model_validate(data)
    except ValidationError as exc:
        raise PolicyPackLoadError(
            "policy_load",
            "default policy pack validation failed",
            str(exc)[:512],
        ) from exc


def canonical_policy_pack_digest(pack: PolicyPack) -> str:
    """SHA-256 over canonical JSON of pack.model_dump(mode='json')."""
    dumped = pack.model_dump(mode="json")
    # Use the same canonical JSON as the chain
    canonical = json.dumps(dumped, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
