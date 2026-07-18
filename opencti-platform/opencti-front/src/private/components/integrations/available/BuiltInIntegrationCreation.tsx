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
  activeKind: BuiltInIntegrationKind | null;
  onClose: () => void;
}

// Hosts the existing per-kind creation drawers, driven from the catalog cards.
// Every drawer stays mounted (closed) so opening one plays the standard
// slide-in transition instead of appearing already open.
const BuiltInIntegrationCreation = ({ activeKind, onClose }: BuiltInIntegrationCreationProps) => {
  return (
    <>
      <SyncCreation
        open={activeKind === 'sync'}
        handleClose={onClose}
      />
      <IngestionTaxiiCreation
        triggerButton={false}
        open={activeKind === 'taxii'}
        handleClose={onClose}
      />
      <IngestionTaxiiCollectionCreation
        open={activeKind === 'taxii-push'}
        handleClose={onClose}
      />
      <IngestionRssCreation
        triggerButton={false}
        open={activeKind === 'rss'}
        handleClose={onClose}
        paginationOptions={{ count: 25 } as IngestionRssLinesDataTableQuery$variables}
      />
      <IngestionCsvCreationContainer
        triggerButton={false}
        open={activeKind === 'csv'}
        handleClose={onClose}
      />
      <IngestionJsonCreationContainer
        open={activeKind === 'json'}
        handleClose={onClose}
        isDuplicated={false}
      />
      <FormCreationContainer
        triggerButton={false}
        open={activeKind === 'form'}
        handleClose={onClose}
      />
    </>
  );
};

export default BuiltInIntegrationCreation;
