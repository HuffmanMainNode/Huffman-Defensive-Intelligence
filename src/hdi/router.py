from hdi.adapters import ALL_ADAPTERS


class Router:
    """Classifies validated events against local adapter contracts only."""

    def __init__(self):
        self.adapters = [adapter() for adapter in ALL_ADAPTERS]

    def matching_adapters(self, event):
        event.validate()
        return [adapter.project_id for adapter in self.adapters if adapter.accepts(event)]
