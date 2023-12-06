import React, { useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import { Button } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import ReportEditionOverview from './ReportEditionOverview';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import Drawer from '../../common/drawer/Drawer';
import ReportPopoverDeletion from './ReportPopoverDeletion';

const ReportEditionContainer = (props) => {
  const { t_i18n } = useFormatter();
  const [displayDelete, setDisplayDelete] = useState(false);

  const { handleClose, report, open, controlledDial } = props;
  const { editContext } = report;

  const handleOpenDelete = () => {
    setDisplayDelete(true);
  };
  const handleCloseDelete = () => {
    setDisplayDelete(false);
  };

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
        {!useIsEnforceReference('Report')
          && <>
            <Button
              onClick={handleOpenDelete}
              variant='contained'
              color='error'
            >
              {t_i18n('Delete')}
            </Button>
            <ReportPopoverDeletion
              reportId={report.id}
              displayDelete={displayDelete}
              handleClose={handleClose}
              handleCloseDelete={handleCloseDelete}
            />
          </>
        }
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
