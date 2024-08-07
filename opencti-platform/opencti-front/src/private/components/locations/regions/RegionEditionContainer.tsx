import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerControlledDialType, DrawerVariant } from '@components/common/drawer/Drawer';
import { RegionEditionOverview_region$key } from '@components/locations/regions/__generated__/RegionEditionOverview_region.graphql';
import useHelper from 'src/utils/hooks/useHelper';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { RegionEditionContainerQuery } from './__generated__/RegionEditionContainerQuery.graphql';
import RegionEditionOverview from './RegionEditionOverview';

interface RegionEditionContainerProps {
  queryRef: PreloadedQuery<RegionEditionContainerQuery>
  handleClose: () => void
  open?: boolean
  controlledDial?: DrawerControlledDialType
}

export const regionEditionQuery = graphql`
  query RegionEditionContainerQuery($id: String!) {
    region(id: $id) {
      ...RegionEditionOverview_region
      editContext {
        name
        focusOn
      }
    }
  }
`;

const RegionEditionContainer: FunctionComponent<
RegionEditionContainerProps
> = ({ handleClose, queryRef, open, controlledDial }) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { region } = usePreloadedQuery(regionEditionQuery, queryRef);
  if (region === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t_i18n('Update a region')}
      variant={open == null ? DrawerVariant.update : undefined}
      context={region?.editContext}
      onClose={handleClose}
      open={open}
      controlledDial={FABReplaced ? controlledDial : undefined}
    >
      {({ onClose }) => (
        <RegionEditionOverview
          regionRef={region as RegionEditionOverview_region$key}
          enableReferences={useIsEnforceReference('Region')}
          context={region?.editContext}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default RegionEditionContainer;
