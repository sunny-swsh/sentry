from __future__ import absolute_import

import six

from collections import Iterable
from itertools import chain

from sentry.mediators import Mediator, Param
from sentry.models import ServiceHook

# Subscribing to these events via the UI is done in a resource-centric way.
# This means you subscribe to "Issue" events. There are many types of Issue
# events - this maps those resource-centric values to the actual events
# emitted.
EVENT_EXPANSION = {
    'issue': ['issue.created'],
}


def expand_events(events):
    return set(chain.from_iterable(
        [EVENT_EXPANSION.get(event, [event]) for event in events]
    ))


class Creator(Mediator):
    application = Param('sentry.models.ApiApplication', required=False)
    actor = Param('sentry.db.models.BaseModel')
    project = Param('sentry.models.Project')
    events = Param(Iterable)
    url = Param(six.string_types)

    def call(self):
        self.hook = self._create_service_hook()
        return self.hook

    def _create_service_hook(self):
        return ServiceHook.objects.create(
            application=self.application,
            actor_id=self.actor.id,
            project_id=self.project.id,
            events=expand_events(self.events),
            url=self.url,
        )
