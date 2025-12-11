import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import IngestionJsonEdition from '@components/data/ingestionJson/IngestionJsonEdition';
import { IngestionJsonEditionContainerQuery } from '@components/data/ingestionJson/__generated__/IngestionJsonEditionContainerQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

export const ingestionJsonEditionContainerQuery = graphql`
  query IngestionJsonEditionContainerQuery($id: String!) {
    ingestionJson(id: $id) {
      ...IngestionJsonEditionFragment_ingestionJson
    }
  }
`;

interface IngestionJsonEditionContainerProps {
  queryRef: PreloadedQuery<IngestionJsonEditionContainerQuery>;
  open: boolean;
  handleClose?: () => void;
}

const IngestionJsonEditionContainer: FunctionComponent<IngestionJsonEditionContainerProps> = ({
  queryRef,
  open,
  handleClose,
}) => {
  const { t_i18n } = useFormatter();

  const { ingestionJson } = usePreloadedQuery(ingestionJsonEditionContainerQuery, queryRef);

  if (!ingestionJson) {
    return <Loader variant={LoaderVariant.inline} />;
  }
  return (
    <Drawer
      title={t_i18n('Update a JSON feed')}
      variant={open == null ? DrawerVariant.update : undefined}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <IngestionJsonEdition
          ingestionJson={ingestionJson}
          enableReferences={useIsEnforceReference('IngestionJson')}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default IngestionJsonEditionContainer;
