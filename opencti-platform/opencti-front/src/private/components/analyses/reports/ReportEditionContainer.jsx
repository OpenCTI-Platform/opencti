import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import useHelper from '../../../../utils/hooks/useHelper';
import { useFormatter } from '../../../../components/i18n';
import ReportEditionOverview from './ReportEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const ReportEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { handleClose, report, open, controlledDial } = props;
  const { editContext } = report;

  return (
    <Drawer
      title={t_i18n('Update a report')}
      open={open}
      onClose={handleClose}
      variant={!isFABReplaced && open == null ? DrawerVariant.update : undefined}
      context={editContext}
      controlledDial={isFABReplaced ? controlledDial : undefined}
    >
      <ReportEditionOverview
        report={report}
        enableReferences={useIsEnforceReference('Report')}
        context={editContext}
        handleClose={handleClose}
      />
    </Drawer>
  );
};

const ReportEditionFragment = createFragmentContainer(ReportEditionContainer, {
  report: graphql`
    fragment ReportEditionContainer_report on Report {
      id
      ...ReportEditionOverview_report
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default ReportEditionFragment;
