import { useFormatter } from '../../../../../components/i18n';
import Drawer from '../../../common/drawer/Drawer';
import InvestigationEnrichmentLaunch from './InvestigationEnrichmentLaunch';

interface InvestigationEnrichmentDrawerProps {
  open: boolean;
  onClose: () => void;
  enrichmentType?: string;
}

const InvestigationEnrichmentDrawer = ({
  open,
  onClose,
  enrichmentType,
}: InvestigationEnrichmentDrawerProps) => {
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      title={t_i18n('Enrichment')}
      open={open}
      onClose={onClose}
    >
      <InvestigationEnrichmentLaunch
        enrichmentType={enrichmentType}
      />
    </Drawer>
  );
};

export default InvestigationEnrichmentDrawer;
