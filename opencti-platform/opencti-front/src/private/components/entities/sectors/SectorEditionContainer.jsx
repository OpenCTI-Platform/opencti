import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import SectorEditionOverview from './SectorEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const SectorEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, sector, open } = props;
  const { editContext } = sector;

  return (
    <Drawer
      title={t('Update a sector')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <SectorEditionOverview
        sector={sector}
        enableReferences={useIsEnforceReference('Sector')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const SectorEditionFragment = createFragmentContainer(SectorEditionContainer, {
  sector: graphql`
    fragment SectorEditionContainer_sector on Sector {
      id
      ...SectorEditionOverview_sector
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default SectorEditionFragment;
