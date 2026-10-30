import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { DialogActions } from '@mui/material';
import { Chip, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import Typography from '@mui/material/Typography';
import { styled } from '@mui/material/styles';
import React, { FunctionComponent, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { NotifierTestDialogQuery } from './__generated__/NotifierTestDialogQuery.graphql';

const Container = styled('div')({
  width: 400,
  marginBottom: 10,
});

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
  const { t_i18n } = useFormatter();
  return (
    <>
      <Typography>
        Result{' '}
        <Chip
          severity={notifierTest ? 'critical' : 'low'}
          label={t_i18n(notifierTest ? 'Error' : 'OK')}
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
  const { t_i18n } = useFormatter();
  const [target, setTarget] = useState('default_notification');
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={t_i18n('Testing notifier')}
    >
      <Container>
        {/* The bare `Typography` label becomes `SelectLabel`, so the visible text is actually ASSOCIATED with the
            field instead of merely sitting above it. */}
        <Select value={target} onValueChange={setTarget}>
          <SelectLabel>{t_i18n('Choose target')}</SelectLabel>
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent aria-label={t_i18n('Choose target')}>
            <SelectItem value="default_notification">
              {t_i18n('Sample Notification')}
            </SelectItem>
            <SelectItem value="default_digest">{t_i18n('Sample Digest')}</SelectItem>
            <SelectItem value="default_activity">
              {t_i18n('Sample Activity Alert')}
            </SelectItem>
          </SelectContent>
        </Select>
      </Container>
      <Container>
        {!queryRef && <Typography>Result</Typography>}
        <React.Suspense
          fallback={(
            <>
              <Typography>Result</Typography>
              <Loader variant={LoaderVariant.inElement} />
            </>
          )}
        >
          {queryRef && <NotifierTestResult queryRef={queryRef} />}
        </React.Suspense>
      </Container>
      <DialogActions>
        <Button
          onClick={() => onTest(target)}
        >
          {t_i18n('Test')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default NotifierTestDialog;
