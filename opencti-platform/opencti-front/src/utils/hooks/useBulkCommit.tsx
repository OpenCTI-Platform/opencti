import React, { useEffect, useRef, useState } from 'react';
import { MutationParameters, SelectorStoreUpdater } from 'relay-runtime';
import { UseMutationConfig, VariablesOf } from 'react-relay';
import { Alert, Typography, List, ListItem, Tooltip } from '@mui/material';
import { useFormatter } from '../../components/i18n';

interface UseBulkCommitArgs<M extends MutationParameters> {
  commit: (args: UseMutationConfig<M>) => void
  relayUpdater?: SelectorStoreUpdater<M['response']>
  type?: 'entities' | 'observables'
}

interface UseBulkCommit_commits<M extends MutationParameters> {
  variables: VariablesOf<M>[]
  onStepError?: (err: Error) => void
  onStepCompleted?: () => void
  onCompleted?: (total: number) => void
}

interface BulkResultProps<M extends MutationParameters> {
  variablesToString: (variables: VariablesOf<M>) => string
}

function useBulkCommit<M extends MutationParameters>({
  commit,
  relayUpdater,
  type = 'entities',
}: UseBulkCommitArgs<M>) {
  const { t_i18n } = useFormatter();

  const [count, setCount] = useState(0);
  const [currentCount, setCurrentCount] = useState(0);
  const [inError, setInError] = useState<[VariablesOf<M>, Error][]>([]);

  const onBulkCompleted = useRef<UseBulkCommit_commits<M>['onCompleted']>();

  const resetBulk = () => {
    setCount(0);
    setCurrentCount(0);
    setInError([]);
  };

  useEffect(() => {
    if (currentCount === count && count !== 0) {
      onBulkCompleted.current?.(count);
    }
  }, [count, currentCount, setCurrentCount, setCount]);

  const bulkCommit = ({
    variables,
    onStepCompleted,
    onStepError,
    onCompleted,
  }: UseBulkCommit_commits<M>) => {
    onBulkCompleted.current = onCompleted;
    setCount(variables.length);
    setCurrentCount(0);
    setInError([]);
    variables.forEach((variable) => {
      commit({
        variables: variable,
        updater: relayUpdater,
        onError: (error) => {
          setCurrentCount((c) => c + 1);
          setInError((err) => [...err, [variable, error]]);
          onStepError?.(error);
        },
        onCompleted: () => {
          setCurrentCount((c) => c + 1);
          onStepCompleted?.();
        },
      });
    });
  };

  const createdLabel = type === 'entities'
    ? t_i18n('entities created')
    : t_i18n('observables created');

  const notCreatedLabel = type === 'entities'
    ? t_i18n('entities not created')
    : t_i18n('observables not created');

  const BulkResult = ({ variablesToString }: BulkResultProps<M>) => (
    <>
      {currentCount === count && (
        <Alert variant="outlined" sx={{ marginTop: 2 }}>
          <Typography>
            {currentCount - inError.length} {createdLabel}
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
            {inError.length} {notCreatedLabel}
          </Typography>
          <List dense>
            {inError.map(([variables, error], index) => {
              return (
                <Tooltip key={index} title={error.message}>
                  <ListItem divider>
                    {variablesToString(variables)}
                  </ListItem>
                </Tooltip>
              );
            })}
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
    resetBulk,
  };
}

export default useBulkCommit;
