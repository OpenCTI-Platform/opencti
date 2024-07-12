import React, { useEffect, useRef, useState } from 'react';
import { MutationParameters, SelectorStoreUpdater } from 'relay-runtime';
import { UseMutationConfig } from 'react-relay';
import { Alert, Typography, List, ListItem, Tooltip } from '@mui/material';
import { useFormatter } from '../../components/i18n';

interface UseBulkCommitArgs<M extends MutationParameters> {
  commit: (args: UseMutationConfig<M>) => void
  relayUpdater?: SelectorStoreUpdater<M['response']>
}

interface UseBulkCommit_commits<I> {
  inputs: I[]
  onStepError?: (err: Error) => void
  onStepCompleted?: () => void
  onCompleted?: (total: number) => void
}

interface BulkResultProps<I> {
  inputToString: (input: I) => string
}

function useBulkCommit<I, M extends MutationParameters>({
  commit,
  relayUpdater,
}: UseBulkCommitArgs<M>) {
  const { t_i18n } = useFormatter();

  const [count, setCount] = useState(0);
  const [currentCount, setCurrentCount] = useState(0);
  const [inError, setInError] = useState<[I, Error][]>([]);

  const onBulkCompleted = useRef<UseBulkCommit_commits<I>['onCompleted']>();

  useEffect(() => {
    if (currentCount === count && count !== 0) {
      onBulkCompleted.current?.(count);
    }
  }, [count, currentCount, setCurrentCount, setCount]);

  const bulkCommit = ({
    inputs,
    onStepCompleted,
    onStepError,
    onCompleted,
  }: UseBulkCommit_commits<I>) => {
    onBulkCompleted.current = onCompleted;
    setCount(inputs.length);
    setCurrentCount(0);
    setInError([]);

    inputs.forEach((input) => {
      commit({
        variables: { input },
        updater: relayUpdater,
        onError: (error) => {
          setCurrentCount((c) => c + 1);
          setInError((err) => [...err, [input, error]]);
          onStepError?.(error);
        },
        onCompleted: () => {
          setCurrentCount((c) => c + 1);
          onStepCompleted?.();
        },
      });
    });
  };

  const BulkResult = ({ inputToString }: BulkResultProps<I>) => (
    <>
      {currentCount === count && (
        <Alert variant="outlined" sx={{ marginTop: 2 }}>
          <Typography>
            {currentCount - inError.length} {t_i18n('entities created')}
          </Typography>
        </Alert>
      )}
      {inError.length > 0 && (
        <Alert
          variant="outlined"
          severity="error"
          sx={{
            marginTop: 2,
            '.MuiAlert-message': {
              width: '100%',
            },
          }}
        >
          <Typography>
            {inError.length} {t_i18n('entities not created')}
          </Typography>
          <List dense>
            {inError.map(([input, error], index) => (
              <Tooltip key={index} title={error.message}>
                <ListItem divider>
                  {inputToString(input)}
                </ListItem>
              </Tooltip>
            ))}
          </List>
        </Alert>
      )}
    </>
  );

  return {
    bulkCommit,
    bulkCount: count,
    bulkCurrentCount: currentCount,
    BulkResult,
  };
}

export default useBulkCommit;
