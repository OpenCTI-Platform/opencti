import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import EditEntityControlledDial from '@components/common/menus/EditEntityControlledDial';
import { useFormatter } from '../../../../components/i18n';
import CountryEditionOverview from './CountryEditionOverview';
import { CountryEditionContainerQuery } from './__generated__/CountryEditionContainerQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import CountryDelete from './CountryDelete';

interface CountryEditionContainerProps {
  handleClose: () => void
  queryRef: PreloadedQuery<CountryEditionContainerQuery>
  open?: boolean
}

export const countryEditionQuery = graphql`
  query CountryEditionContainerQuery($id: String!) {
    country(id: $id) {
      id
      ...CountryEditionOverview_country
      editContext {
        name
        focusOn
      }
    }
  }
`;

const CountryEditionContainer: FunctionComponent<CountryEditionContainerProps> = ({ handleClose, queryRef, open }) => {
  const { t_i18n } = useFormatter();
  const { country } = usePreloadedQuery(countryEditionQuery, queryRef);
  if (country) {
    return (
      <Drawer
        title={t_i18n('Update an country')}
        context={country.editContext}
        onClose={handleClose}
        open={open}
        controlledDial={EditEntityControlledDial()}
      >
        {({ onClose }) => (<>
          <CountryEditionOverview
            countryRef={country}
            enableReferences={useIsEnforceReference('Country')}
            context={country.editContext}
            handleClose={onClose}
          />
          {!useIsEnforceReference('Country')
            && <CountryDelete id={country.id} />
          }
        </>)}
      </Drawer>
    );
  }
  return <Loader variant={LoaderVariant.inElement} />;
};

export default CountryEditionContainer;
