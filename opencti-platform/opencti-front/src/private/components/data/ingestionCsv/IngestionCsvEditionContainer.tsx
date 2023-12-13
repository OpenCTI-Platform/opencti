import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import IngestionCsvEdition from '@components/data/ingestionCsv/IngestionCsvEdition';
import { IngestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

export const ingestionCsvEditionContainerQuery = graphql`
  query IngestionCsvEditionContainerQuery($id: String!) {
    ingestionCsv(id: $id) {
      ...IngestionCsvEditionFragment_ingestionCsv
    }
  }
`;

interface IngestionCsvEditionContainerProps {
  queryRef: PreloadedQuery<IngestionCsvEditionContainerQuery>;
  open: boolean;
  handleClose?: () => void;
}

const IngestionCsvEditionContainer: FunctionComponent<IngestionCsvEditionContainerProps> = ({
  queryRef,
  open,
  handleClose,
}) => {
  const { t } = useFormatter();

  const { ingestionCsv } = usePreloadedQuery(ingestionCsvEditionContainerQuery, queryRef);

  if (!ingestionCsv) {
    return <Loader variant={LoaderVariant.inElement} />;
  }
  return (
    <Drawer
      title={t('Update a CSV Ingester')}
      variant={open == null ? DrawerVariant.update : undefined}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <IngestionCsvEdition
          ingestionCsv={ingestionCsv}
          enableReferences={useIsEnforceReference('IngestionCsv')}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default IngestionCsvEditionContainer;
