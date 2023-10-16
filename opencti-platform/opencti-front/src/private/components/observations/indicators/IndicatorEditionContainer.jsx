import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import IndicatorEditionOverview from './IndicatorEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const IndicatorEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, indicator, open } = props;
  const { editContext } = indicator;

  return (
    <Drawer
      title={t('Update an indicator')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
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
