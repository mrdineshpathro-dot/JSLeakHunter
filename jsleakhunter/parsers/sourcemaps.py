"""Static source-map helpers; never executes JavaScript."""
import json

def embedded_sources(payload):
    try:
        data = json.loads(payload) if isinstance(payload, str) else payload
        return [(name, source or '') for name, source in zip(data.get('sources', []), data.get('sourcesContent', [])) if source]
    except (TypeError, ValueError, AttributeError):
        return []
