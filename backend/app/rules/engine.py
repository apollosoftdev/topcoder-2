"""Rule engine for configurable policy enforcement."""

import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)


class EnforcementMode(str, Enum):
    """Policy enforcement modes."""

    ADVISORY = "advisory"  # Comments only, no blocking
    WARNING = "warning"  # Annotations + alerts
    BLOCKING = "blocking"  # Prevent merge via check runs


class RuleSeverity(str, Enum):
    """Rule severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Rule:
    """Individual rule definition."""

    id: str
    name: str
    description: str
    severity: RuleSeverity
    enabled: bool = True
    pattern: Optional[str] = None
    message: str = ""
    suggestion: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    languages: list[str] = field(default_factory=lambda: ["*"])
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RulePack:
    """Collection of rules for a specific domain."""

    id: str
    name: str
    description: str
    version: str
    rules: list[Rule]
    enforcement_mode: EnforcementMode = EnforcementMode.WARNING
    metadata: dict[str, Any] = field(default_factory=dict)


class RuleEngine:
    """Engine for loading and applying rules."""

    def __init__(self, rules_dir: Optional[str] = None):
        """Initialize the rule engine.

        Args:
            rules_dir: Directory containing rule YAML files
        """
        if rules_dir:
            self.rules_dir = Path(rules_dir)
        else:
            # Default to the defaults directory
            self.rules_dir = Path(__file__).parent / "defaults"

        self.rule_packs: dict[str, RulePack] = {}
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        """Load all rule packs from the rules directory."""
        if not self.rules_dir.exists():
            logger.warning(f"Rules directory not found: {self.rules_dir}")
            return

        for yaml_file in self.rules_dir.glob("*.yaml"):
            try:
                rule_pack = self._load_rule_pack(yaml_file)
                self.rule_packs[rule_pack.id] = rule_pack
                logger.info(f"Loaded rule pack: {rule_pack.id} ({len(rule_pack.rules)} rules)")
            except Exception as e:
                logger.error(f"Failed to load rule pack {yaml_file}: {e}")

    def _load_rule_pack(self, filepath: Path) -> RulePack:
        """Load a rule pack from a YAML file."""
        with open(filepath, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        rules = []
        for rule_data in data.get("rules", []):
            rule = Rule(
                id=rule_data["id"],
                name=rule_data["name"],
                description=rule_data.get("description", ""),
                severity=RuleSeverity(rule_data.get("severity", "medium")),
                enabled=rule_data.get("enabled", True),
                pattern=rule_data.get("pattern"),
                message=rule_data.get("message", ""),
                suggestion=rule_data.get("suggestion", ""),
                cwe=rule_data.get("cwe"),
                owasp=rule_data.get("owasp"),
                languages=rule_data.get("languages", ["*"]),
                tags=rule_data.get("tags", []),
                metadata=rule_data.get("metadata", {}),
            )
            rules.append(rule)

        return RulePack(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            rules=rules,
            enforcement_mode=EnforcementMode(
                data.get("enforcement_mode", "warning")
            ),
            metadata=data.get("metadata", {}),
        )

    def get_rule_pack(self, pack_id: str) -> Optional[RulePack]:
        """Get a rule pack by ID."""
        return self.rule_packs.get(pack_id)

    def get_all_packs(self) -> list[RulePack]:
        """Get all loaded rule packs."""
        return list(self.rule_packs.values())

    def get_rules_for_packs(self, pack_ids: list[str]) -> list[Rule]:
        """Get all enabled rules from specified rule packs.

        Args:
            pack_ids: List of rule pack IDs to include

        Returns:
            List of enabled rules from the specified packs
        """
        rules = []
        for pack_id in pack_ids:
            pack = self.rule_packs.get(pack_id)
            if pack:
                rules.extend(rule for rule in pack.rules if rule.enabled)
        return rules

    def get_enforcement_mode(self, pack_ids: list[str]) -> EnforcementMode:
        """Determine the strictest enforcement mode from specified packs.

        Args:
            pack_ids: List of rule pack IDs

        Returns:
            The strictest enforcement mode among the packs
        """
        mode_priority = {
            EnforcementMode.ADVISORY: 0,
            EnforcementMode.WARNING: 1,
            EnforcementMode.BLOCKING: 2,
        }

        strictest = EnforcementMode.ADVISORY
        for pack_id in pack_ids:
            pack = self.rule_packs.get(pack_id)
            if pack and mode_priority[pack.enforcement_mode] > mode_priority[strictest]:
                strictest = pack.enforcement_mode

        return strictest

    def load_custom_rules(self, yaml_content: str) -> RulePack:
        """Load custom rules from YAML content.

        Args:
            yaml_content: YAML string containing rule definitions

        Returns:
            Loaded RulePack
        """
        data = yaml.safe_load(yaml_content)

        rules = []
        for rule_data in data.get("rules", []):
            rule = Rule(
                id=rule_data["id"],
                name=rule_data["name"],
                description=rule_data.get("description", ""),
                severity=RuleSeverity(rule_data.get("severity", "medium")),
                enabled=rule_data.get("enabled", True),
                pattern=rule_data.get("pattern"),
                message=rule_data.get("message", ""),
                suggestion=rule_data.get("suggestion", ""),
                cwe=rule_data.get("cwe"),
                owasp=rule_data.get("owasp"),
                languages=rule_data.get("languages", ["*"]),
                tags=rule_data.get("tags", []),
            )
            rules.append(rule)

        pack = RulePack(
            id=data.get("id", "custom"),
            name=data.get("name", "Custom Rules"),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            rules=rules,
            enforcement_mode=EnforcementMode(
                data.get("enforcement_mode", "warning")
            ),
        )

        # Add to loaded packs
        self.rule_packs[pack.id] = pack
        return pack
