import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import SectorEditionOverview from './SectorEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';

const SectorEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const entityTypeDisplayName = useEntityTypeDisplayName();

  const { handleClose, sector, open, controlledDial } = props;
  const { editContext } = sector;

  return (
    <Drawer
      title={t_i18n('', { id: 'Update ...', values: { entity_type: entityTypeDisplayName('Sector') } })}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
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
