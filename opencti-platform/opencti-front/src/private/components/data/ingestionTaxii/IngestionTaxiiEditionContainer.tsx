import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import IngestionTaxiiEdition from '@components/data/ingestionTaxii/IngestionTaxiiEdition';
import { IngestionTaxiiEditionContainerQuery } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

export const ingestionTaxiiEditionContainerQuery = graphql`
  query IngestionTaxiiEditionContainerQuery($id: String!) {
    ingestionTaxii(id: $id) {
      ...IngestionTaxiiEditionFragment_ingestionTaxii
    }
  }
`;

interface IngestionTaxiiEditionContainerProps {
  queryRef: PreloadedQuery<IngestionTaxiiEditionContainerQuery>;
  open: boolean;
  handleClose?: () => void;
}

const IngestionTaxiiEditionContainer: FunctionComponent<IngestionTaxiiEditionContainerProps> = ({
  queryRef,
  open,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();

  const { ingestionTaxii } = usePreloadedQuery(ingestionTaxiiEditionContainerQuery, queryRef);

  if (!ingestionTaxii) {
    return <div />;
  }
  return (
    <Drawer
      title={t_i18n('Update a TAXII ingester')}
      open={open}
      onClose={handleClose}
    >
      {({ onClose }) => (
        <IngestionTaxiiEdition
          ingestionTaxii={ingestionTaxii}
          enableReferences={useIsEnforceReference('IngestionTaxii')}
          handleClose={onClose}
        />
      )
      }
    </Drawer>
  );
};

export default IngestionTaxiiEditionContainer;
