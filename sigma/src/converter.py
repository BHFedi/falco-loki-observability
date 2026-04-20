"""
converter.py — pySigma Loki backend wrapper.

Converts a normalized Sigma rule dict into either:
  - ruler YAML            (SIGMA_OUTPUT_FORMAT=ruler)
  - grafana_alerting YAML (SIGMA_OUTPUT_FORMAT=grafana_alerting)
  - both                  (SIGMA_OUTPUT_FORMAT=both)

The pySigma LogQLBackend only accepts two __init__ kwargs:
  - add_line_filters (bool)
  - case_sensitive   (bool)

Grafana-specific options (datasource_uid, folder, org_id, interval,
contact_point, group_by_field) are passed as custom_attributes on the
backend instance AFTER construction, which is how the sigma CLI's -O
flags work internally.
"""

import inspect
import logging
from typing import Any

import yaml

from config import Config

log = logging.getLogger(__name__)


def _sigma_rule_to_yaml_str(rule: dict) -> str:
    """Serialise a cleaned rule dict back to YAML string for pySigma ingestion."""
    clean = {k: v for k, v in rule.items() if not k.startswith("_")}
    return yaml.dump(clean, default_flow_style=False, allow_unicode=True)


def _build_backend(config: Config, output_format: str):
    """
    Instantiate LogQLBackend with only the kwargs it actually accepts,
    then inject Grafana options via custom_attributes / direct attributes.

    The real LogQLBackend.__init__ signature (all versions) only accepts:
      add_line_filters: bool = False
      case_sensitive:   bool = False

    Everything else (grafana_*, loki_group_by_field) is set post-construction
    because that is how the sigma CLI passes -O options to the backend.
    """
    from sigma.backends.loki import LogQLBackend

    # ── Determine which kwargs __init__ actually accepts ──────────────────────
    try:
        valid_params = set(inspect.signature(LogQLBackend.__init__).parameters.keys())
        valid_params.discard("self")
    except Exception:
        valid_params = {"add_line_filters", "case_sensitive"}

    log.debug("LogQLBackend accepts init params: %s", valid_params)

    # ── Build safe kwargs — only pass what __init__ actually accepts ───────────
    candidate_kwargs: dict[str, Any] = {
        "add_line_filters": config.add_line_filters,
        "case_sensitive": config.case_sensitive,
    }
    init_kwargs = {k: v for k, v in candidate_kwargs.items() if k in valid_params}

    backend = LogQLBackend(**init_kwargs)

    # ── Inject Grafana options post-construction ───────────────────────────────
    # The backend stores these in self.custom_attributes (a dict) or as direct
    # instance attributes depending on the version. We try custom_attributes
    # first (newer versions), then fall back to setattr (older versions).
    if output_format == "grafana_alerting":
        grafana_opts: dict[str, Any] = {
            "grafana_datasource_uid": config.grafana_datasource_uid,
            "grafana_folder": config.grafana_folder,
            "grafana_org_id": config.grafana_org_id,
            "grafana_interval": config.grafana_interval,
            "grafana_contact_point": config.grafana_contact_point,
        }
        if config.loki_group_by_field:
            grafana_opts["loki_group_by_field"] = config.loki_group_by_field

        if hasattr(backend, "custom_attributes") and isinstance(backend.custom_attributes, dict):
            backend.custom_attributes.update(grafana_opts)
            log.debug("Injected Grafana opts via custom_attributes: %s", grafana_opts)
        else:
            for k, v in grafana_opts.items():
                setattr(backend, k, v)
            log.debug("Injected Grafana opts via setattr: %s", grafana_opts)

    return backend


class ConversionResult:
    def __init__(
        self,
        ruler_yaml: str | None = None,
        grafana_yaml: str | None = None,
        logql: str | None = None,
    ):
        self.ruler_yaml = ruler_yaml
        self.grafana_yaml = grafana_yaml
        self.logql = logql

    def has_output(self) -> bool:
        return bool(self.ruler_yaml or self.grafana_yaml or self.logql)

    def __repr__(self):
        parts = []
        if self.ruler_yaml:
            parts.append("ruler")
        if self.grafana_yaml:
            parts.append("grafana_alerting")
        if self.logql:
            parts.append("logql")
        return f"<ConversionResult formats={parts}>"


class RuleConverter:
    """
    Wraps the pySigma Loki backend.
    Takes a normalized rule dict; returns a ConversionResult.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._output_format = config.output_format  # ruler | grafana_alerting | both

        # Log the actual backend signature once at startup for diagnostics
        try:
            from sigma.backends.loki import LogQLBackend
            sig = inspect.signature(LogQLBackend.__init__)
            params = [
                f"{n}={p.default!r}" if p.default is not inspect.Parameter.empty else n
                for n, p in sig.parameters.items()
                if n != "self"
            ]
            log.info("LogQLBackend.__init__ signature: (%s)", ", ".join(params))
        except Exception as exc:
            log.warning("Could not inspect LogQLBackend signature: %s", exc)

    def convert(self, rule: dict) -> ConversionResult:
        """
        Convert a (normalized) Sigma rule dict to the configured output format(s).
        Returns ConversionResult. Raises ValueError on unsupported constructs.
        """
        sigma_yaml = _sigma_rule_to_yaml_str(rule)
        result = ConversionResult()

        try:
            if self._output_format in ("ruler", "both"):
                result.ruler_yaml = self._convert_format(sigma_yaml, "ruler")

            if self._output_format in ("grafana_alerting", "both"):
                result.grafana_yaml = self._convert_format(sigma_yaml, "grafana_alerting")

            # Always generate plain LogQL as a diagnostic / audit artifact
            result.logql = self._convert_format(sigma_yaml, "default")

        except Exception as exc:
            raise ValueError(f"pySigma conversion error: {exc}") from exc

        log.info("Converted rule '%s' → %r", rule.get("title", "?"), result)
        return result

    def _convert_format(self, sigma_yaml: str, output_format: str) -> str:
        """Run pySigma for a single output format and return the string output."""
        from sigma.collection import SigmaCollection

        backend = _build_backend(self._config, output_format)
        collection = SigmaCollection.from_yaml(sigma_yaml)
        queries = backend.convert(collection, output_format=output_format)

        if isinstance(queries, list):
            return "\n---\n".join(str(q) for q in queries)
        return str(queries)
