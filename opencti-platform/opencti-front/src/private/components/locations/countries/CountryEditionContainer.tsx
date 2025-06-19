import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import CountryEditionOverview from './CountryEditionOverview';
import { CountryEditionContainerQuery } from './__generated__/CountryEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

interface CountryEditionContainerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<CountryEditionContainerQuery>
  open?: boolean
  controlledDial?: DrawerControlledDialType
}

export const countryEditionQuery = graphql`
  query CountryEditionContainerQuery($id: String!) {
    country(id: $id) {
      ...CountryEditionOverview_country
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CountryEditionContainer: FunctionComponent<CountryEditionContainerProps> = ({
  handleClose,
  queryRef,
  open,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { country } = usePreloadedQuery(countryEditionQuery, queryRef);
  if (country) {
    return (
      <Drawer
        title={t_i18n('Update a country')}
        context={country.editContext}
        onClose={handleClose}
        open={open}
        controlledDial={controlledDial}
      >
        {({ onClose }) => (
          <CountryEditionOverview
            countryRef={country}
            enableReferences={useIsEnforceReference('Country')}
            context={country.editContext}
            handleClose={onClose}
          />
        )}
      </Drawer>
    );
  }
  return <Loader variant={LoaderVariant.inline} />;
};

export default CountryEditionContainer;
