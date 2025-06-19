import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import {
  AdministrativeAreaEditionOverview_administrativeArea$key,
} from '@components/locations/administrative_areas/__generated__/AdministrativeAreaEditionOverview_administrativeArea.graphql';
import AdministrativeAreaEditionOverview from './AdministrativeAreaEditionOverview';
import { useFormatter } from '../../../../components/i18n';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { AdministrativeAreaEditionContainerQuery } from './__generated__/AdministrativeAreaEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

interface AdministrativeAreaEditionContainerProps {
  queryRef: PreloadedQuery<AdministrativeAreaEditionContainerQuery>
  handleClose: () => void
  open?: boolean
  controlledDial?: DrawerControlledDialType
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
const AdministrativeAreaEditionContainer: FunctionComponent<AdministrativeAreaEditionContainerProps> = ({
  queryRef,
  handleClose,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { administrativeArea } = usePreloadedQuery(administrativeAreaEditionQuery, queryRef);
  if (administrativeArea === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update an area')}
      context={administrativeArea?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={controlledDial}
    >
      {({ onClose }) => (
        <AdministrativeAreaEditionOverview
          administrativeAreaRef={administrativeArea as AdministrativeAreaEditionOverview_administrativeArea$key}
          context={administrativeArea?.editContext}
          handleClose={onClose}
          enableReferences={useIsEnforceReference('Administrative-Area')}
        />
      )}
    </Drawer>
  );
};

export default AdministrativeAreaEditionContainer;
