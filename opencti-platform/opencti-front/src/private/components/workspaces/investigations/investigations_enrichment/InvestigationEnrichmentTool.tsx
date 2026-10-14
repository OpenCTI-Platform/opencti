import { useState } from 'react';
import { CloudRefreshOutline } from 'mdi-material-ui';
import GraphToolbarItem from '../../../../../components/graph/components/GraphToolbarItem';
import { useFormatter } from '../../../../../components/i18n';
import { GraphEntity } from '../../../../../components/graph/graph.types';
import { useGetCurrentUserAccessRight } from '../../../../../utils/authorizedMembers';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import useGranted, { INVESTIGATION_INUPDATE } from '../../../../../utils/hooks/useGranted';
import InvestigationEnrichmentDrawer from './InvestigationEnrichmentDrawer';

interface InvestigationEnrichmentToolProps {
  entity: GraphEntity;
}

const InvestigationEnrichmentTool = ({
  entity,
}: InvestigationEnrichmentToolProps) => {
  const { t_i18n } = useFormatter();
  const { canEdit } = useGetCurrentUserAccessRight(entity.currentUserAccessRight);
  const canUpdate = useGranted([INVESTIGATION_INUPDATE]);

  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;
  const selection = [...selectedNodes, ...selectedLinks];
  const hasSelection = selection.length > 0;

  // Enrichment available only if elements are all of same type.
  const selectedEntityTypes = new Set(selection.map((el) => el.entity_type));
  const enrichmentType = selectedEntityTypes.size === 1 ? [...selectedEntityTypes][0] : undefined;

  const [openEnrichment, setOpenEnrichment] = useState(false);

  return (
    <>
      <GraphToolbarItem
        color="primary"
        title={t_i18n('Enrichment')}
        Icon={<CloudRefreshOutline />}
        disabled={!canEdit || !canUpdate || !hasSelection}
        onClick={() => setOpenEnrichment(true)}
      />

      <InvestigationEnrichmentDrawer
        open={openEnrichment}
        enrichmentType={enrichmentType}
        onClose={() => setOpenEnrichment(false)}
      />
    </>
  );
};

export default InvestigationEnrichmentTool;
