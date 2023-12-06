import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import {
  AdministrativeAreaEditionOverview_administrativeArea$key,
} from '@components/locations/administrative_areas/__generated__/AdministrativeAreaEditionOverview_administrativeArea.graphql';
import Drawer from '@components/common/drawer/Drawer';
import EditEntityControlledDial from '@components/common/menus/EditEntityControlledDial';
import AdministrativeAreaEditionOverview from './AdministrativeAreaEditionOverview';
import { useFormatter } from '../../../../components/i18n';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { AdministrativeAreaEditionContainerQuery } from './__generated__/AdministrativeAreaEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import AdministrativeAreaDelete from './AdministrativeAreaDelete';

interface AdministrativeAreaEditionContainerProps {
  queryRef: PreloadedQuery<AdministrativeAreaEditionContainerQuery>
  handleClose: () => void
  open?: boolean
}

export const administrativeAreaEditionQuery = graphql`
  query AdministrativeAreaEditionContainerQuery($id: String!) {
    administrativeArea(id: $id) {
      id
      ...AdministrativeAreaEditionOverview_administrativeArea
      editContext {
        name
        focusOn
      }
    }
  }
`;
const AdministrativeAreaEditionContainer: FunctionComponent<AdministrativeAreaEditionContainerProps> = ({ queryRef, handleClose, open }) => {
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
      controlledDial={EditEntityControlledDial()}
    >
      {({ onClose }) => (<>
        <AdministrativeAreaEditionOverview
          administrativeAreaRef={administrativeArea as AdministrativeAreaEditionOverview_administrativeArea$key}
          context={administrativeArea?.editContext}
          handleClose={onClose}
          enableReferences={useIsEnforceReference('Administrative-Area')}
        />
        {!useIsEnforceReference('Administrative-Area') && administrativeArea?.id
          && <AdministrativeAreaDelete id={administrativeArea.id} />
        }
      </>)}
    </Drawer>
  );
};

export default AdministrativeAreaEditionContainer;
