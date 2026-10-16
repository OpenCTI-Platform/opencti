import { useMemo, useState } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import Drawer from '../../../common/drawer/Drawer';
import { Investigation, InvestigationEnrichmentWork, InvestigationWorkSorted } from './investigation-enrichment.types';
import InvestigationEnrichmentLaunch from './InvestigationEnrichmentLaunch';
import InvestigationEnrichmentDrawerTabs, { TabList } from './InvestigationEnrichmentDrawerTabs';
import InvestigationEnrichmentWorkList from './InvestigationEnrichmentWorkList';

const addInMap = (
  map: Map<string, InvestigationEnrichmentWork[]>,
  work?: InvestigationEnrichmentWork,
) => {
  if (work && work.event_source_id) {
    if (map.has(work.event_source_id)) {
      map.get(work.event_source_id)?.push(work);
    } else {
      map.set(work.event_source_id, [work]);
    }
  }
};

interface InvestigationEnrichmentDrawerProps {
  open: boolean;
  onClose: () => void;
  onLaunchCompleted: () => void;
  investigation: Investigation;
}

const InvestigationEnrichmentDrawer = ({
  open,
  onClose,
  onLaunchCompleted,
  investigation,
}: InvestigationEnrichmentDrawerProps) => {
  const { t_i18n } = useFormatter();
  const [tab, setTab] = useState<TabList>('done');

  const works: InvestigationWorkSorted = useMemo(() => {
    const done = new Map<string, InvestigationEnrichmentWork[]>();
    const ongoing = new Map<string, InvestigationEnrichmentWork[]>();
    const toreview = new Map<string, InvestigationEnrichmentWork[]>(); // TODO
    if (investigation) {
      investigation.enrichmentWorks?.edges?.forEach((work) => {
        if (work?.node.status === 'complete' || work?.node.status === 'timeout') {
          addInMap(done, work?.node);
        } else {
          addInMap(ongoing, work?.node);
        }
      });
    }
    return { ongoing, done, toreview };
  }, [investigation]);

  return (
    <Drawer
      title={t_i18n('Enrichment')}
      open={open}
      onClose={onClose}
    >
      <>
        <InvestigationEnrichmentLaunch
          onCompleted={onLaunchCompleted}
          investigationId={investigation.id}
        />

        <InvestigationEnrichmentDrawerTabs
          current={tab}
          onChange={setTab}
          works={works}
        />

        <InvestigationEnrichmentWorkList
          works={works[tab]}
        />
      </>
    </Drawer>
  );
};

export default InvestigationEnrichmentDrawer;
