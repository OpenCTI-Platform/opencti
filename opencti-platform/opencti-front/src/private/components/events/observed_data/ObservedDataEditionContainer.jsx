import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ObservedDataEditionOverview from './ObservedDataEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const ObservedDataEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, observedData, open } = props;
  const { editContext } = observedData;

  return (
    <Drawer
      title={t('Update an observed data')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
    >
      <ObservedDataEditionOverview
        observedData={observedData}
        enableReferences={useIsEnforceReference('Observed-Data')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const ObservedDataEditionFragment = createFragmentContainer(
  ObservedDataEditionContainer,
  {
    observedData: graphql`
      fragment ObservedDataEditionContainer_observedData on ObservedData {
        id
        ...ObservedDataEditionOverview_observedData
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default ObservedDataEditionFragment;
