from hdi.adapters.base import Adapter
from hdi.model import HDIEvent, EventValidationError


class OIXAdapter(Adapter):
    project_id = "oix"

    def accepts(self, event):
        return event.source_project == self.project_id

    def normalize(self, raw):
        event = HDIEvent.from_dict(raw)
        if not self.accepts(event):
            raise EventValidationError("OIX adapter received another project's event")
        return event
