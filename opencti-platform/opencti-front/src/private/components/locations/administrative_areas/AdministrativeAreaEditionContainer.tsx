import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import AdministrativeAreaEditionOverview from './AdministrativeAreaEditionOverview';
import { useFormatter } from '../../../../components/i18n';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { AdministrativeAreaEditionContainerQuery } from './__generated__/AdministrativeAreaEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

interface AdministrativeAreaEditionContainerProps {
  queryRef: PreloadedQuery<AdministrativeAreaEditionContainerQuery>
  handleClose: () => void
  open?: boolean
}

export const administrativeAreaEditionQuery = graphql`
  query AdministrativeAreaEditionContainerQuery($id: String!) {
    administrativeArea(id: $id) {
      ...AdministrativeAreaEditionOverview_administrativeArea
      editContext {
        name
        focusOn
      }
    }
  }
`;
const AdministrativeAreaEditionContainer: FunctionComponent<AdministrativeAreaEditionContainerProps> = ({ queryRef, handleClose, open }) => {
  const { t } = useFormatter();
  const { administrativeArea } = usePreloadedQuery(administrativeAreaEditionQuery, queryRef);
  if (administrativeArea === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t('Update an area')}
      variant={open == null ? DrawerVariant.update : undefined}
      context={administrativeArea.editContext}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <AdministrativeAreaEditionOverview
          administrativeAreaRef={administrativeArea}
          context={administrativeArea.editContext}
          handleClose={onClose}
          enableReferences={useIsEnforceReference('Administrative-Area')}
        />
      )}
    </Drawer>
  );
};

export default AdministrativeAreaEditionContainer;
