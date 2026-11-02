from hdi.adapters.base import Adapter
from hdi.model import HDIEvent, EventValidationError


class HalloweenOSINTAdapter(Adapter):
    project_id = "halloween_osint"

    def accepts(self, event):
        return event.source_project == self.project_id

    def normalize(self, raw):
        event = HDIEvent.from_dict(raw)
        if not self.accepts(event):
            raise EventValidationError("OSINT adapter received another project's event")
        return event
