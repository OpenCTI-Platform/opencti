import React from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import ReportEditionOverview from './ReportEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';

const ReportEditionContainer = (props) => {
  const { t_i18n } = useFormatter();

  const { handleClose, report, open, controlledDial } = props;
  const { editContext } = report;

  return (
    <Drawer
      title={t_i18n('Update a report')}
      open={open}
      onClose={handleClose}
      context={editContext}
      controlledDial={controlledDial}
    >
      <>
        <ReportEditionOverview
          report={report}
          enableReferences={useIsEnforceReference('Report')}
          context={editContext}
          handleClose={handleClose}
        />
      </>
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
