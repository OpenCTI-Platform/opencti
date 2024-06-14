# coding: utf-8

from pycti.entities.stixCyberObservables.opencti_stix_cyber_observable_deprecated import StixCyberObservableDeprecated
from pycti.entities.stixCyberObservables.opencti_stix_cyber_observable_latest import StixCyberObservableLatest
from pycti.entities.stixCyberObservables.opencti_stix_cyber_observable_properties import (
    SCO_PROPERTIES,
    SCO_PROPERTIES_WITH_FILES
)


class StixCyberObservable(StixCyberObservableLatest, StixCyberObservableDeprecated):
    def __init__(self, opencti, file):
        self.opencti = opencti
        self.file = file
        self.properties = SCO_PROPERTIES
        self.properties_with_files = SCO_PROPERTIES_WITH_FILES

        StixCyberObservableLatest.__init__(self)
        StixCyberObservableDeprecated.__init__(self)
