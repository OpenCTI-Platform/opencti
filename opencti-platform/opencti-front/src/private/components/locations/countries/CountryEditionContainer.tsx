import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType, DrawerVariant } from '@components/common/drawer/Drawer';
import { CountryEditionOverview_country$key } from '@components/locations/countries/__generated__/CountryEditionOverview_country.graphql';
import useHelper from 'src/utils/hooks/useHelper';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { CountryEditionContainerQuery } from './__generated__/CountryEditionContainerQuery.graphql';
import CountryEditionOverview from './CountryEditionOverview';

interface CountryEditionContainerProps {
  queryRef: PreloadedQuery<CountryEditionContainerQuery>
  handleClose: () => void
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

const CountryEditionContainer: FunctionComponent<
CountryEditionContainerProps
> = ({ handleClose, queryRef, open, controlledDial }) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { country } = usePreloadedQuery(countryEditionQuery, queryRef);
  if (country === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update an country')}
      variant={open == null ? DrawerVariant.update : undefined}
      context={country?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={FABReplaced ? controlledDial : undefined}
    >
      {({ onClose }) => (
        <CountryEditionOverview
          countryRef={country as CountryEditionOverview_country$key}
          enableReferences={useIsEnforceReference('Country')}
          context={country?.editContext}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default CountryEditionContainer;
