import React from 'react';
import SyncCreation from '@components/data/sync/SyncCreation';
import IngestionTaxiiCreation from '@components/data/ingestionTaxii/IngestionTaxiiCreation';
import IngestionTaxiiCollectionCreation from '@components/data/ingestionTaxiiCollection/IngestionTaxiiCollectionCreation';
import IngestionRssCreation from '@components/data/ingestionRss/IngestionRssCreation';
import { IngestionCsvCreationContainer } from '@components/data/ingestionCsv/IngestionCsvCreation';
import { IngestionJsonCreationContainer } from '@components/data/ingestionJson/IngestionJsonCreation';
import FormCreationContainer from '@components/data/forms/FormCreationContainer';
import { IngestionRssLinesDataTableQuery$variables } from '@components/data/ingestionRss/__generated__/IngestionRssLinesDataTableQuery.graphql';
import { BuiltInIntegrationKind } from '@components/integrations/available/builtInIntegrations';

interface BuiltInIntegrationCreationProps {
  kind: BuiltInIntegrationKind | null;
  onClose: () => void;
}

// Hosts the existing per-kind creation drawers, driven from the catalog cards.
const BuiltInIntegrationCreation = ({ kind, onClose }: BuiltInIntegrationCreationProps) => {
  if (!kind) return null;
  switch (kind) {
    case 'sync':
      return <SyncCreation open={true} handleClose={onClose} />;
    case 'taxii':
      return <IngestionTaxiiCreation triggerButton={false} open={true} handleClose={onClose} />;
    case 'taxii-push':
      return <IngestionTaxiiCollectionCreation open={true} handleClose={onClose} />;
    case 'rss':
      return (
        <IngestionRssCreation
          triggerButton={false}
          open={true}
          handleClose={onClose}
          paginationOptions={{ count: 25 } as IngestionRssLinesDataTableQuery$variables}
        />
      );
    case 'csv':
      return <IngestionCsvCreationContainer triggerButton={false} open={true} handleClose={onClose} />;
    case 'json':
      return <IngestionJsonCreationContainer open={true} handleClose={onClose} isDuplicated={false} />;
    case 'form':
    default:
      return <FormCreationContainer triggerButton={false} open={true} handleClose={onClose} />;
  }
};

export default BuiltInIntegrationCreation;
