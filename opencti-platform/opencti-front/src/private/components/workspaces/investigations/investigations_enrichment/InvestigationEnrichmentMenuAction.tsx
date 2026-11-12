import { useEffect, useMemo, useState } from 'react';
import { CloudRefreshOutline } from 'mdi-material-ui';
import BackgroundTaskLaunch from '../../../common/background_task/BackgroundTaskLaunch';
import { useGraphContext } from '../../../../../components/graph/GraphContext';
import { registerGraphSelectionAction } from '../../../../../components/graph/badges';
import { fetchQuery } from '../../../../../relay/environment';
import { EnrichmentConnector, enrichmentConnectorsQuery } from '../../../data/connectors/EnrichmentConnectorSelection';
import { EnrichmentConnectorSelectionQuery } from '../../../data/connectors/__generated__/EnrichmentConnectorSelectionQuery.graphql';
import { toEnrichmentSelection, toEnrichmentTaskActions } from './investigation-enrichment.utils';

export const INVESTIGATION_ENRICHMENT_MENU_ACTION_ID = 'investigation-enrichment';

interface InvestigationEnrichmentMenuActionProps {
  investigationId: string;
  canLaunch: boolean;
  onLaunched: () => void;
}

/**
 * The "Enrichment" action of the Selection section of the graph context menu: a submenu of the
 * connectors that can enrich the selection, the same as the enrichment drawer lists. Picking one
 * launches the enrichment with that connector only, asking for a confirmation only above the
 * background task limit. Not registered for a user who cannot launch an enrichment from the drawer.
 */
const InvestigationEnrichmentMenuAction = ({
  investigationId,
  canLaunch,
  onLaunched,
}: InvestigationEnrichmentMenuActionProps) => {
  const { graphState } = useGraphContext();
  const { selectedNodes, selectedLinks } = graphState;

  const { selectionMap, selectionSize, enrichmentType } = useMemo(
    () => toEnrichmentSelection([...selectedNodes, ...selectedLinks]),
    [selectedLinks, selectedNodes],
  );

  // The connectors of the last entity type loaded: while another type is selected, its connectors are loading.
  const [loaded, setLoaded] = useState<{ type: string; connectors: EnrichmentConnector[] }>();
  const connectors = loaded && loaded.type === enrichmentType ? loaded.connectors : undefined;
  const [connector, setConnector] = useState<EnrichmentConnector>();
  const [processing, setProcessing] = useState(false);

  // Loaded when the selection changes, so that the menu does not wait for them when it opens.
  useEffect(() => {
    if (!canLaunch || !enrichmentType) return undefined;
    let current = true;
    fetchQuery<EnrichmentConnectorSelectionQuery>(enrichmentConnectorsQuery, { type: enrichmentType })
      .toPromise()
      .then((data) => (data?.enrichmentConnectors ?? []).flatMap((c) => (c ? [{ id: c.id, name: c.name }] : [])))
      .catch(() => [])
      .then((list) => {
        if (current) setLoaded({ type: enrichmentType, connectors: list });
      });
    return () => {
      current = false;
    };
  }, [canLaunch, enrichmentType]);

  // Registered again when the connectors change, so that an open menu shows them.
  useEffect(() => {
    if (!canLaunch) return undefined;
    return registerGraphSelectionAction({
      id: INVESTIGATION_ENRICHMENT_MENU_ACTION_ID,
      icon: CloudRefreshOutline,
      label: (t_i18n) => t_i18n('Enrichment'),
      isAvailable: (_, context) => context === 'investigation',
      disabledReason: (_, t_i18n) => {
        if (enrichmentType && !connectors) return t_i18n('Loading');
        if (!connectors || connectors.length === 0) return t_i18n('No connector available for the selected entities.');
        return undefined;
      },
      options: () => ({
        items: (connectors ?? []).map((c) => ({ key: c.id, label: c.name })),
        onSelect: (key) => setConnector(connectors?.find((c) => c.id === key)),
      }),
    });
  }, [canLaunch, enrichmentType, connectors]);

  return (
    <BackgroundTaskLaunch
      display={!!connector}
      processing={processing}
      selectedElements={selectionMap}
      numberOfSelectedElements={selectionSize}
      taskScope="KNOWLEDGE"
      actions={toEnrichmentTaskActions(connector ? [connector] : [], investigationId)}
      confirmOnlyAboveLimit
      onClose={() => {
        setConnector(undefined);
        // A launch the API rejected never completes: closing the launcher must not leave it busy for the next one.
        setProcessing(false);
      }}
      onLaunch={() => setProcessing(true)}
      onCompleted={() => {
        setConnector(undefined);
        setProcessing(false);
        onLaunched();
      }}
    />
  );
};

export default InvestigationEnrichmentMenuAction;
