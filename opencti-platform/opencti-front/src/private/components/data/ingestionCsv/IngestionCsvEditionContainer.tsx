import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { FunctionComponent } from 'react';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import IngestionCsvEdition from '@components/data/ingestionCsv/IngestionCsvEdition';
import { IngestionCsvEditionContainerQuery } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionContainerQuery.graphql';
import IngestionCsvEditionDeprecated from '@components/data/ingestionCsv/IngestionCsvEditionDeprecated';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useHelper from '../../../../utils/hooks/useHelper';

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
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();

  const { ingestionCsv } = usePreloadedQuery(ingestionCsvEditionContainerQuery, queryRef);

  if (!ingestionCsv) {
    return <Loader variant={LoaderVariant.inline} />;
  }
  return (
    <Drawer
      title={t_i18n('Update a CSV Feed')}
      variant={open == null ? DrawerVariant.update : undefined}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => {
        return isFeatureEnable('CSV_FEED')
          ? <IngestionCsvEdition
              ingestionCsv={ingestionCsv}
              enableReferences={useIsEnforceReference('IngestionCsv')}
              handleClose={onClose}
            />
          : <IngestionCsvEditionDeprecated
              ingestionCsv={ingestionCsv}
              enableReferences={useIsEnforceReference('IngestionCsv')}
              handleClose={onClose}
            />;
      }}
    </Drawer>
  );
};

export default IngestionCsvEditionContainer;
