import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import useHelper from '../../../../utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';
import IndicatorEditionOverview from './IndicatorEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const IndicatorEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { handleClose, indicator, open, controlledDial } = props;
  const { editContext } = indicator;

  return (
    <Drawer
      title={t_i18n('Update an indicator')}
      open={open}
      onClose={handleClose}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={isFABReplaced ? controlledDial : undefined}
    >
      <IndicatorEditionOverview
        indicator={indicator}
        enableReferences={useIsEnforceReference('Indicator')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const IndicatorEditionFragment = createFragmentContainer(
  IndicatorEditionContainer,
  {
    indicator: graphql`
      fragment IndicatorEditionContainer_indicator on Indicator {
        id
        ...IndicatorEditionOverview_indicator
        editContext {
          name
          focusOn
        }
      }
    `,
  },
);

export default IndicatorEditionFragment;
