import React, { useEffect, useRef, useState } from 'react';
import { MutationParameters, SelectorStoreUpdater } from 'relay-runtime';
import { UseMutationConfig, VariablesOf } from 'react-relay';
import { Alert, Typography, List, ListItem, Tooltip } from '@mui/material';
import { useFormatter } from '../../components/i18n';

type ObjectType = 'entities' | 'observables' | 'files';

interface UseBulkCommitArgs<M extends MutationParameters> {
  commit: (args: UseMutationConfig<M>) => void
  relayUpdater?: SelectorStoreUpdater<M['response']>
  type?: ObjectType
}

interface UseBulkCommit_commits<M extends MutationParameters> {
  variables: VariablesOf<M>[]
  onStepError?: (err: Error, v: VariablesOf<M>) => void
  onStepCompleted?: (v: VariablesOf<M>) => void
  onCompleted?: (total: number) => void
  commit?: (args: UseMutationConfig<M>) => void
}

interface BulkResultProps<M extends MutationParameters> {
  variablesToString: (variables: VariablesOf<M>) => string
}

function useBulkCommit<M extends MutationParameters>({
  commit: defaultCommit, // Default commit function
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
  }, [count, currentCount]);

  // Accepts an optional `commit` function override
  const bulkCommit = ({
    commit = defaultCommit, // Fallback to default commit
    variables,
    onStepCompleted,
    onStepError,
    onCompleted,
  }: UseBulkCommit_commits<M> & { commit?: (args: UseMutationConfig<M>) => void }) => {
    if (!commit) {
      throw new Error('bulkCommit: No commit function provided.');
    }

    onBulkCompleted.current = onCompleted;
    setCount(variables.length);
    setCurrentCount(0);
    setInError([]);

    variables.forEach((variable) => {
      commit({
        variables: variable as VariablesOf<M>, // Explicitly cast variables
        updater: relayUpdater,
        onError: (error) => {
          setCurrentCount((c) => c + 1);
          setInError((err) => [...err, [variable as VariablesOf<M>, error]]);
          onStepError?.(error, variable);
        },
        onCompleted: () => {
          setCurrentCount((c) => c + 1);
          onStepCompleted?.(variable);
        },
      });
    });
  };

  const successLabel: Record<ObjectType, string> = {
    entities: t_i18n('entities created'),
    observables: t_i18n('observables created'),
    files: t_i18n('files imported'),
  };

  const errorLabel: Record<ObjectType, string> = {
    entities: t_i18n('entities not created'),
    observables: t_i18n('observables not created'),
    files: t_i18n('files not imported'),
  };

  const BulkResult = ({ variablesToString }: BulkResultProps<M>) => (
    <>
      {currentCount === count && (
        <Alert variant="outlined" sx={{ marginTop: 2 }}>
          <Typography>
            {currentCount - inError.length} {successLabel[type]}
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
            {inError.length} {errorLabel[type]}
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
