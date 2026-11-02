from abc import ABC, abstractmethod

from hdi.model import HDIEvent


class Adapter(ABC):
    project_id: str

    @abstractmethod
    def accepts(self, event: HDIEvent) -> bool:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw: dict) -> HDIEvent:
        raise NotImplementedError
