from hdi.adapters.base import Adapter
from hdi.model import HDIEvent, EventValidationError


class OpenSwarmAdapter(Adapter):
    project_id = "open_swarm"

    def accepts(self, event):
        return event.source_project == self.project_id

    def normalize(self, raw):
        event = HDIEvent.from_dict(raw)
        if not self.accepts(event):
            raise EventValidationError("Open-Swarm adapter received another project's event")
        return event
