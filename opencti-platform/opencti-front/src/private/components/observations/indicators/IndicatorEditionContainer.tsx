import React, { FunctionComponent } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import IndicatorEditionOverview from './IndicatorEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerControlledDialType } from '../../common/drawer/Drawer';
import { IndicatorEditionContainer_indicator$data } from '@components/observations/indicators/__generated__/IndicatorEditionContainer_indicator.graphql';

interface IndicatorEditionContainerProps {
  handleClose: () => void;
  indicator: IndicatorEditionContainer_indicator$data;
  controlledDial?: DrawerControlledDialType;
}

const IndicatorEditionContainer: FunctionComponent<IndicatorEditionContainerProps> = ({
  handleClose,
  indicator,
  controlledDial,
}) => {
  const { t_i18n } = useFormatter();
  const { editContext } = indicator;

  return (
    <Drawer
      title={t_i18n('Update an indicator')}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
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
