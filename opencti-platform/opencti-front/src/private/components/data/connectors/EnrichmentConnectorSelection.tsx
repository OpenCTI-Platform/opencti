import { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { EnrichmentConnectorSelectionQuery } from './__generated__/EnrichmentConnectorSelectionQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { Box, Typography } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { Alert, Checkbox } from '@filigran/design-system';

export const enrichmentConnectorsQuery = graphql`
  query EnrichmentConnectorSelectionQuery($type: String!) {
    enrichmentConnectors(type: $type) {
      id
      name
    }
  }
`;

export interface EnrichmentConnector {
  id: string;
  name: string;
}

interface EnrichmentConnectorSelectionComponentProps {
  value: EnrichmentConnector[];
  onChange: (value: EnrichmentConnector[]) => void;
  queryRef: PreloadedQuery<EnrichmentConnectorSelectionQuery>;
}

const EnrichmentConnectorSelectionComponent = ({
  onChange,
  queryRef,
  value,
}: EnrichmentConnectorSelectionComponentProps) => {
  const { t_i18n } = useFormatter();

  const { enrichmentConnectors } = usePreloadedQuery(enrichmentConnectorsQuery, queryRef);
  const connectors = (enrichmentConnectors ?? []).flatMap((c) => {
    // Filter out undefined, it's more a TS fix than a real scenario.
    if (!c) return [];
    return c;
  });

  const isSelected = (connectorId: string) => value.some((c) => c.id === connectorId);

  const toggleConnector = (connector: EnrichmentConnector) => {
    const newValue = isSelected(connector.id)
      ? value.filter((c) => c.id !== connector.id)
      : [...value, { id: connector.id, name: connector.name }];
    onChange(newValue);
  };

  return (
    <div>
      <Typography variant="h4">
        {t_i18n('Selected connectors')}
      </Typography>
      {connectors.length === 0 && (
        <Alert
          severity="warning"
          title={t_i18n('No connector available for the selected entities.')}
        />
      )}
      {connectors.map((connector) => (
        <Box key={connector.id} sx={{ mb: 1 }}>
          <Checkbox
            label={connector.name}
            checked={isSelected(connector.id)}
            onCheckedChange={() => toggleConnector(connector)}
          />
        </Box>
      ))}
    </div>
  );
};

interface EnrichmentConnectorSelectionProps {
  type: string;
  value: EnrichmentConnector[];
  onChange: (value: EnrichmentConnector[]) => void;
}

const EnrichmentConnectorSelection = ({
  type,
  value,
  onChange,
}: EnrichmentConnectorSelectionProps) => {
  const queryRef = useQueryLoading<EnrichmentConnectorSelectionQuery>(
    enrichmentConnectorsQuery,
    { type },
  );

  return (
    <Suspense fallback={<Loader />}>
      {queryRef && (
        <EnrichmentConnectorSelectionComponent
          value={value}
          onChange={onChange}
          queryRef={queryRef}
        />
      )}
    </Suspense>
  );
};

export default EnrichmentConnectorSelection;
