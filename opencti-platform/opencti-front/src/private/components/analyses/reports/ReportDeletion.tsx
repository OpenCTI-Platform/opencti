import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { Alert, AlertTitle, Checkbox, Dialog, DialogActions, DialogContent, DialogContentText, FormControlLabel, FormGroup } from '@mui/material';
import Button from '@common/button/Button';
import { useTheme } from '@mui/styles';
import DialogTitle from '@mui/material/DialogTitle';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Transition from '../../../../components/Transition';
import { QueryRenderer } from '../../../../relay/environment';
import type { Theme } from '../../../../components/Theme';
import { ReportDeletionQuery$data } from './__generated__/ReportDeletionQuery.graphql';

const reportDeletionQuery = graphql`
  query ReportDeletionQuery($id: String) {
    report(id: $id) {
      deleteWithElementsCount
    }
  }
`;

const reportDeletionMutation = graphql`
  mutation ReportDeletionMutation($id: ID!, $purgeElements: Boolean) {
    reportEdit(id: $id) {
      delete(purgeElements: $purgeElements)
    }
  }
`;

interface ReportDeletionProps {
  reportId: string;
  handleClose: () => void;
  isOpen: boolean;
}

const ReportDeletion: FunctionComponent<ReportDeletionProps> = ({
  reportId,
  handleClose,
  isOpen,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const [purgeElements, setPurgeElements] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_Report') },
  });
  const [commitMutation] = useApiMutation(
    reportDeletionMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );

  const handleCloseDelete = () => {
    setDeleting(false);
    handleClose();
  };

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: { id: reportId, purgeElements },
      onCompleted: () => {
        handleCloseDelete();
        navigate('/dashboard/analyses/reports');
      },
      onError: () => {
        handleCloseDelete();
      },
    });
  };

  return (
    <Dialog
      open={isOpen}
      slots={{ transition: Transition }}
      slotProps={{ paper: { elevation: 1 } }}
      onClose={handleCloseDelete}
    >
      <DialogTitle>
        {t_i18n('Are you sure?')}
      </DialogTitle>
      <DialogContent>
        <DialogContentText>
          {t_i18n('Do you want to delete this report?')}
        </DialogContentText>
        <QueryRenderer
          query={reportDeletionQuery}
          variables={{ id: reportId }}
          render={(result: { props: ReportDeletionQuery$data }) => {
            const numberOfDeletions = result.props?.report?.deleteWithElementsCount ?? 0;
            if (numberOfDeletions === 0) return <div />;
            return (
              <Alert
                severity="warning"
                variant="outlined"
                style={{ marginTop: 20 }}
              >
                <AlertTitle>{t_i18n('Cascade delete')}</AlertTitle>
                {t_i18n('In this report, ')}&nbsp;
                <strong style={{ color: theme.palette.error.main }}>
                  {numberOfDeletions}
                </strong>
                  &nbsp;
                {t_i18n(
                  'element(s) are not linked to any other reports and will be orphan after the deletion.',
                )}
                <FormGroup>
                  <FormControlLabel
                    control={(
                      <Checkbox
                        disableRipple={true}
                        checked={purgeElements}
                        onChange={() => setPurgeElements(!purgeElements)}
                      />
                    )}
                    label={t_i18n('Also delete these elements')}
                  />
                </FormGroup>
              </Alert>
            );
          }}
        >
        </QueryRenderer>
      </DialogContent>
      <DialogActions>
        <Button variant="secondary" onClick={handleCloseDelete} disabled={deleting}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={submitDelete} disabled={deleting}>
          {t_i18n('Confirm')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ReportDeletion;
