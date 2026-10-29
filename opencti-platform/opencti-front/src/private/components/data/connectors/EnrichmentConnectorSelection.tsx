import { Suspense } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { EnrichmentConnectorSelectionQuery } from './__generated__/EnrichmentConnectorSelectionQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { Box, Typography } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { Alert, Checkbox } from '@filigran/design-system';

const enrichmentConnectorsQuery = graphql`
  query EnrichmentConnectorSelectionQuery($type: String!) {
    enrichmentConnectors(type: $type) {
      id
      name
    }
  }
`;

interface EnrichmentConnectorSelectionComponentProps {
  value: string[];
  onChange: (value: string[]) => void;
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

  const toggleConnector = (connectorId: string) => {
    const newValue = value.includes(connectorId)
      ? value.filter((c) => c !== connectorId)
      : [...value, connectorId];
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
            checked={value.includes(connector.id)}
            onCheckedChange={() => toggleConnector(connector.id)}
          />
        </Box>
      ))}
    </div>
  );
};

interface EnrichmentConnectorSelectionProps {
  type: string;
  value: string[];
  onChange: (value: string[]) => void;
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
