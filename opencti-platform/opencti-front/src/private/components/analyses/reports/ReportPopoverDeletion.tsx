import { graphql, useMutation } from 'react-relay';
import DialogContent from '@mui/material/DialogContent';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import Checkbox from '@mui/material/Checkbox';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React, { FunctionComponent, useState } from 'react';
import { useTheme } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import DialogContentText from '@mui/material/DialogContentText';
import { MESSAGING$, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { ReportPopoverDeletionQuery$data } from './__generated__/ReportPopoverDeletionQuery.graphql';
import type { Theme } from '../../../../components/Theme';
import Transition from '../../../../components/Transition';

const reportPopoverDeletionQuery = graphql`
  query ReportPopoverDeletionQuery($id: String) {
    report(id: $id) {
      deleteWithElementsCount
    }
  }
`;

const reportPopoverDeletionMutation = graphql`
  mutation ReportPopoverDeletionMutation($id: ID!, $purgeElements: Boolean) {
    reportEdit(id: $id) {
      delete(purgeElements: $purgeElements)
    }
  }
`;

interface ReportPopoverDeletionProps {
  reportId: string;
  displayDelete: boolean;
  handleClose: () => void;
  handleCloseDelete: () => void;
}

const ReportPopoverDeletion: FunctionComponent<ReportPopoverDeletionProps> = ({
  reportId,
  displayDelete,
  handleClose,
  handleCloseDelete,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const navigate = useNavigate();
  const [purgeElements, setPurgeElements] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [commitMutation] = useMutation(reportPopoverDeletionMutation);
  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      variables: { id: reportId, purgeElements },
      onError: (error: Error) => {
        MESSAGING$.notifyError(`${error}`);
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        MESSAGING$.notifySuccess(`${t_i18n('entity_Report')} ${t_i18n('successfully deleted')}`);
        navigate('/dashboard/analyses/reports');
      },
    });
  };
  return (
    <Dialog
      open={displayDelete}
      TransitionComponent={Transition}
      PaperProps={{ elevation: 1 }}
      onClose={handleCloseDelete}
    >
      <DialogContent>
        <DialogContentText>
          {t_i18n('Do you want to delete this report?')}
        </DialogContentText>
        <QueryRenderer
          query={reportPopoverDeletionQuery}
          variables={{ id: reportId }}
          render={(result: { props: ReportPopoverDeletionQuery$data }) => {
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
                    control={
                      <Checkbox
                        disableRipple={true}
                        checked={purgeElements}
                        onChange={() => setPurgeElements(!purgeElements)}
                      />
                    }
                    label={t_i18n('Also delete these elements')}
                  />
                </FormGroup>
              </Alert>
            );
          }}
        ></QueryRenderer>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCloseDelete} disabled={deleting}>
          {t_i18n('Cancel')}
        </Button>
        <Button color="secondary" onClick={submitDelete} disabled={deleting}>
          {t_i18n('Delete')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ReportPopoverDeletion;
