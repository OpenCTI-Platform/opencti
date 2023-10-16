import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ReportEditionOverview from './ReportEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer, { DrawerVariant } from '../../common/drawer/Drawer';

const ReportEditionContainer = (props) => {
  const { t } = useFormatter();

  const { handleClose, report, open } = props;
  const { editContext } = report;

  return (
    <Drawer
      title={t('Update a report')}
      open={open}
      onClose={handleClose}
      variant={open == null ? DrawerVariant.update : undefined}
      context={editContext}
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
