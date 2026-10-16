import { useMemo } from 'react';
import { useFormatter } from '../../../../../components/i18n';
import Drawer from '../../../common/drawer/Drawer';
import { Investigation, InvestigationEnrichmentWork } from './investigation-enrichment.types';
import InvestigationEnrichmentLaunch from './InvestigationEnrichmentLaunch';

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

  const works = useMemo(() => {
    const worksMap = new Map<string, InvestigationEnrichmentWork[]>();
    if (investigation) {
      investigation.enrichmentWorks?.edges?.forEach((work) => {
        if (work && work.node && work.node.event_source_id) {
          if (worksMap.has(work.node.event_source_id)) {
            worksMap.get(work.node.event_source_id)?.push(work.node);
          } else {
            worksMap.set(work.node.event_source_id, [work.node]);
          }
        }
      });
    }
    return worksMap;
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

        <div>
          Number of works: {investigation.enrichmentWorks?.edges?.length}
        </div>
      </>
    </Drawer>
  );
};

export default InvestigationEnrichmentDrawer;
