import { Suspense, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { EnrichmentConnectorsSelectionQuery } from './__generated__/EnrichmentConnectorsSelectionQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader from '../../../../components/Loader';
import { Box, Typography } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { Alert, Checkbox } from '@filigran/design-system';

const enrichmentConnectorsQuery = graphql`
  query EnrichmentConnectorsSelectionQuery($type: String!) {
    enrichmentConnectors(type: $type) {
      id
      name
    }
  }
`;

interface EnrichmentConnectorSelectionComponentProps {
  onChange: (value: string[]) => void;
  queryRef: PreloadedQuery<EnrichmentConnectorsSelectionQuery>;
}

const EnrichmentConnectorSelectionComponent = ({
  onChange,
  queryRef,
}: EnrichmentConnectorSelectionComponentProps) => {
  const { t_i18n } = useFormatter();
  const [selectedConnectors, setSelectedConnectors] = useState<string[]>([]);

  const { enrichmentConnectors } = usePreloadedQuery(enrichmentConnectorsQuery, queryRef);
  const connectors = (enrichmentConnectors ?? []).flatMap((c) => {
    // Filter out undefined, it's more a TS fix than a real scenario.
    if (!c) return [];
    return c;
  });

  const toggleConnector = (connectorId: string) => {
    setSelectedConnectors((old) => {
      const newValue = old.includes(connectorId)
        ? old.filter((c) => c !== connectorId)
        : [...old, connectorId];
      onChange(newValue);
      return newValue;
    });
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
            checked={selectedConnectors.includes(connector.id)}
            onCheckedChange={() => toggleConnector(connector.id)}
          />
        </Box>
      ))}
    </div>
  );
};

interface EnrichmentConnectorSelectionProps {
  type: string;
  onChange: (value: string[]) => void;
}

const EnrichmentConnectorSelection = ({
  type,
  onChange,
}: EnrichmentConnectorSelectionProps) => {
  const queryRef = useQueryLoading<EnrichmentConnectorsSelectionQuery>(
    enrichmentConnectorsQuery,
    { type },
  );

  return (
    <Suspense fallback={<Loader />}>
      {queryRef && (
        <EnrichmentConnectorSelectionComponent
          onChange={onChange}
          queryRef={queryRef}
        />
      )}
    </Suspense>
  );
};

export default EnrichmentConnectorSelection;
