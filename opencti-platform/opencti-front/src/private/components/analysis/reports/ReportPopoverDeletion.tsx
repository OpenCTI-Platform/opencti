import { graphql } from 'react-relay';
import DialogContent from '@mui/material/DialogContent';
import Typography from '@mui/material/Typography';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import FormGroup from '@mui/material/FormGroup';
import FormControlLabel from '@mui/material/FormControlLabel';
import { useHistory } from 'react-router-dom';
import Checkbox from '@mui/material/Checkbox';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import React, { FunctionComponent, useState } from 'react';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { ReportPopoverDeletionQuery$data } from './__generated__/ReportPopoverDeletionQuery.graphql';

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
  reportId: string,
  displayDelete: boolean,
  handleClose: () => void
  handleCloseDelete: () => void
}

const ReportPopoverDeletion: FunctionComponent<ReportPopoverDeletionProps> = ({
  reportId,
  displayDelete,
  handleClose,
  handleCloseDelete,
}) => {
  const { t } = useFormatter();
  const history = useHistory();
  const [purgeElements, setPurgeElements] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const submitDelete = () => {
    setDeleting(true);
    commitMutation({
      mutation: reportPopoverDeletionMutation,
      variables: { id: reportId, purgeElements },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        history.push('/dashboard/analysis/reports');
      },
      updater: undefined,
      optimisticUpdater: undefined,
      optimisticResponse: undefined,
      onError: undefined,
      setSubmitting: undefined,
    });
  };

  return <Dialog open={displayDelete} PaperProps={{ elevation: 1 }} onClose={handleCloseDelete}>
    <DialogContent>
      <Typography variant="body1">
        {t('Do you want to delete this report?')}
      </Typography>
      <QueryRenderer
        query={reportPopoverDeletionQuery}
        variables={{ id: reportId }}
        render={(result: { props: ReportPopoverDeletionQuery$data }) => {
          const numberOfDeletions = result.props?.report?.deleteWithElementsCount ?? '-';
          if (numberOfDeletions === 0) return <div />;
          return <Alert severity="warning" variant="outlined" style={{ marginTop: 20 }}>
            <AlertTitle>
              {t('Cascade delete')}<br/>
              <b style={{ color: 'red' }}>{numberOfDeletions}</b>&nbsp;{t('element(s) which are only in this report')}
            </AlertTitle>
            <FormGroup>
              <FormControlLabel
                control={<Checkbox checked={purgeElements} onChange={() => setPurgeElements(!purgeElements)} />}
                label={t('Delete the element if no other containers contain it')}
              />
            </FormGroup>
          </Alert>;
        }}
      />
    </DialogContent>
    <DialogActions>
      <Button onClick={handleCloseDelete} disabled={deleting}>
        {t('Cancel')}
      </Button>
      <Button color="secondary" onClick={submitDelete} disabled={deleting}>
        {t('Delete')}
      </Button>
    </DialogActions>
  </Dialog>;
};

export default ReportPopoverDeletion;
