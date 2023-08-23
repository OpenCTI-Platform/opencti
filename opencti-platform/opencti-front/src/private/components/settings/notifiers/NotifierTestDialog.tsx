import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { Theme } from '../../../../components/Theme';
import { NotifierTestDialogQuery } from './__generated__/NotifierTestDialogQuery.graphql';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    width: 400,
    marginBottom: 10,
  },
  success: {
    backgroundColor: theme.palette.success.main,
    borderColor: theme.palette.success.main,
    color: theme.palette.common.white,
  },
  error: {
    backgroundColor: theme.palette.error.main,
    borderColor: theme.palette.error.main,
    color: theme.palette.common.white,
  },
}));

export const notifierTestQuery = graphql`
  query NotifierTestDialogQuery($input: NotifierTestInput!) {
    notifierTest(input: $input)
  }
`;

const NotifierTestResult = ({
  queryRef,
}: {
  queryRef: PreloadedQuery<NotifierTestDialogQuery>;
}) => {
  const { notifierTest } = usePreloadedQuery<NotifierTestDialogQuery>(
    notifierTestQuery,
    queryRef,
  );
  const { t } = useFormatter();
  const classes = useStyles();
  return (
    <>
      <Typography>
        Result{' '}
        <Chip
          className={notifierTest ? classes.error : classes.success}
          label={t(notifierTest ? 'Error' : 'OK')}
        />
      </Typography>
      {notifierTest && <code>{notifierTest}</code>}
    </>
  );
};

interface NotifierTestDialogProps {
  open: boolean;
  onClose: () => void;
  queryRef?: PreloadedQuery<NotifierTestDialogQuery> | null;
  onTest: (target: string) => void;
}

const NotifierTestDialog: FunctionComponent<NotifierTestDialogProps> = ({
  open,
  onClose,
  queryRef,
  onTest,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const [target, setTarget] = useState('default_notification');
  return (
    <Dialog open={open} onClose={onClose} PaperProps={{ elevation: 1 }}>
      <DialogTitle>{t('Testing notifier')}</DialogTitle>
      <DialogContent>
        <div className={classes.container}>
          <Typography>Choose target</Typography>
          <Select
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            fullWidth={true}
          >
            <MenuItem value={'default_notification'}>
              {t('Sample Notification')}
            </MenuItem>
            <MenuItem value={'default_digest'}>{t('Sample Digest')}</MenuItem>
            <MenuItem value={'default_activity'}>
              {t('Sample Activity Alert')}
            </MenuItem>
          </Select>
        </div>
        <div className={classes.container}>
          {!queryRef && <Typography>Result</Typography>}
          <React.Suspense
            fallback={
              <>
                <Typography>Result</Typography>
                <Loader variant={LoaderVariant.inElement} />
              </>
            }
          >
            {queryRef && <NotifierTestResult queryRef={queryRef} />}
          </React.Suspense>
        </div>
        <Button
          variant="contained"
          color="secondary"
          onClick={() => onTest(target)}
        >
          {t('Test')}
        </Button>
      </DialogContent>
    </Dialog>
  );
};

export default NotifierTestDialog;
