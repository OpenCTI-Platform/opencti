import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { CityEditionOverview_city$key } from '@components/locations/cities/__generated__/CityEditionOverview_city.graphql';
import CityEditionOverview from './CityEditionOverview';
import { useFormatter } from '../../../../components/i18n';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { CityEditionContainerQuery } from './__generated__/CityEditionContainerQuery.graphql';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

interface CityEditionContainerProps {
  queryRef: PreloadedQuery<CityEditionContainerQuery>
  handleClose: () => void
  open?: boolean
  controlledDial?: DrawerControlledDialType
}

export const cityEditionQuery = graphql`
  query CityEditionContainerQuery($id: String!) {
    city(id: $id) {
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
  controlledDial,
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
      controlledDial={controlledDial}
    >
      {({ onClose }) => (
        <CityEditionOverview
          cityRef={city as CityEditionOverview_city$key}
          enableReferences={useIsEnforceReference('City')}
          context={city?.editContext}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default CityEditionContainer;
