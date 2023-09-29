import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import CountryEditionOverview from './CountryEditionOverview';
import { CountryEditionContainerQuery } from './__generated__/CountryEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';

interface CountryEditionContainerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<CountryEditionContainerQuery>
  open?: boolean
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

const CountryEditionContainer: FunctionComponent<CountryEditionContainerProps> = ({ handleClose, queryRef, open }) => {
  const { t } = useFormatter();
  const { country } = usePreloadedQuery(countryEditionQuery, queryRef);
  if (country) {
    return (
      <Drawer
        title={t('Update an country')}
        variant={open == null ? DrawerVariant.update : undefined}
        context={country.editContext}
        onClose={handleClose}
        open={open}
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
  return <Loader variant={LoaderVariant.inElement} />;
};

export default CountryEditionContainer;
