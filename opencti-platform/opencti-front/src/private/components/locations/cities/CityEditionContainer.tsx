import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CityEditionOverview_city$key } from '@components/locations/cities/__generated__/CityEditionOverview_city.graphql';
import Drawer from '@components/common/drawer/Drawer';
import EditEntityControlledDial from '@components/common/menus/EditEntityControlledDial';
import CityEditionOverview from './CityEditionOverview';
import { useFormatter } from '../../../../components/i18n';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { CityEditionContainerQuery } from './__generated__/CityEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import CityDelete from './CityDelete';

interface CityEditionContainerProps {
  queryRef: PreloadedQuery<CityEditionContainerQuery>
  handleClose: () => void
  open?: boolean
}

export const cityEditionQuery = graphql`
  query CityEditionContainerQuery($id: String!) {
    city(id: $id) {
      id
      ...CityEditionOverview_city
      editContext {
        name
        focusOn
      }
    }
  }
`;
const CityEditionContainer: FunctionComponent<CityEditionContainerProps> = ({
  queryRef,
  handleClose,
  open,
}) => {
  const { t_i18n } = useFormatter();
  const { city } = usePreloadedQuery(cityEditionQuery, queryRef);
  if (city === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update a city')}
      context={city?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={EditEntityControlledDial()}
    >
      {({ onClose }) => (<>
        <CityEditionOverview
          cityRef={city as CityEditionOverview_city$key}
          enableReferences={useIsEnforceReference('City')}
          context={city?.editContext}
          handleClose={onClose}
        />
        {!useIsEnforceReference('City') && city?.id
          && <CityDelete id={city.id} />
        }
      </>)}
    </Drawer>
  );
};

export default CityEditionContainer;
