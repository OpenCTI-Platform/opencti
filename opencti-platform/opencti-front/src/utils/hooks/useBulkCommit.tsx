import React, { useContext, useEffect, useRef, useState } from 'react';
import { MutationParameters, SelectorStoreUpdater } from 'relay-runtime';
import { UseMutationConfig, VariablesOf } from 'react-relay';
import { Alert, Box, Typography, List, ListItem, LinearProgress } from '@mui/material';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../components/i18n';
import type { Theme } from '../../components/Theme';
import { CreationFeedbackContext } from './useCreationFeedback';
import { getGraphQLResponseErrorsMessage } from '../../relay/graphQLResponseErrors';

type ObjectType = 'entities' | 'observables' | 'files';

interface UseBulkCommitArgs<M extends MutationParameters> {
  commit: (args: UseMutationConfig<M>) => void;
  relayUpdater?: SelectorStoreUpdater<M['response']>;
  type?: ObjectType;
}

interface UseBulkCommit_commits<M extends MutationParameters> {
  variables: VariablesOf<M>[];
  onStepError?: (err: Error, v: VariablesOf<M>) => void;
  onStepCompleted?: (v: VariablesOf<M>, response: M['response']) => void;
  onCompleted?: (total: number) => void;
  commit?: (args: UseMutationConfig<M>) => void;
}

interface BulkResultProps<M extends MutationParameters> {
  variablesToString: (variables: VariablesOf<M>) => string;
  // Other objects the creation made, e.g. "2 indicators created": shown once all are created
  extraResults?: string[];
}

function useBulkCommit<M extends MutationParameters>({
  commit: defaultCommit, // Default commit function
  relayUpdater,
  type = 'entities',
}: UseBulkCommitArgs<M>) {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const { bulkCreation } = useContext(CreationFeedbackContext);

  const [count, setCount] = useState(0);
  const [currentCount, setCurrentCount] = useState(0);
  const [inError, setInError] = useState<[VariablesOf<M>, Error][]>([]);

  const onBulkCompleted = useRef<UseBulkCommit_commits<M>['onCompleted']>(undefined);

  const resetBulk = () => {
    setCount(0);
    setCurrentCount(0);
    setInError([]);
    bulkCreation?.onBulkEnd();
  };

  useEffect(() => {
    if (currentCount === count && count !== 0) {
      onBulkCompleted.current?.(count);
      if (count > 1) bulkCreation?.onBulkCompleted();
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
    // A single object is not a bulk creation: it has no result dialog
    const isBulk = variables.length > 1;
    if (isBulk) bulkCreation?.onBulkStart();
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
        onCompleted: (response) => {
          setCurrentCount((c) => c + 1);
          onStepCompleted?.(variable, response);
        },
      });
    });
  };

  const successLabel: Record<ObjectType, string> = {
    entities: t_i18n('entities created'),
    observables: t_i18n('observables created'),
    files: t_i18n('files imported'),
  };

  // Shown while the created objects are added to the surrounding container (files are never added to one)
  const addingLabel = (containerType: string) => (type === 'observables'
    ? t_i18n('Observables added to the {containerType}', { values: { containerType } })
    : t_i18n('Entities added to the {containerType}', { values: { containerType } }));

  const errorLabel: Record<ObjectType, string> = {
    entities: t_i18n('entities not created'),
    observables: t_i18n('observables not created'),
    files: t_i18n('files not imported'),
  };

  const BulkResult = ({ variablesToString, extraResults = [] }: BulkResultProps<M>) => (
    <>
      {currentCount === count && currentCount - inError.length > 0 && (
        <Alert variant="outlined" sx={{ marginTop: 2 }}>
          <Typography>
            {currentCount - inError.length} {successLabel[type]}
          </Typography>
        </Alert>
      )}
      {count > 0 && currentCount === count && extraResults.map((result) => (
        <Alert key={result} variant="outlined" sx={{ marginTop: 2 }}>
          <Typography>{result}</Typography>
        </Alert>
      ))}
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
              const message = getGraphQLResponseErrorsMessage(error);
              return (
                <ListItem key={index} divider sx={{ gap: theme.spacing(2) }}>
                  <Typography sx={{ flexShrink: 0 }}>{variablesToString(variables)}</Typography>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Typography noWrap tabIndex={0} sx={{ color: 'error.main', minWidth: 0, marginLeft: 'auto' }}>{message}</Typography>
                    </TooltipTrigger>
                    <TooltipContent>{message}</TooltipContent>
                  </Tooltip>
                </ListItem>
              );
            })}
          </List>
        </Alert>
      )}
      {/* After the creation's own result: the created objects are then added to the container */}
      {bulkCreation?.progress && (bulkCreation.progress.inProgress || bulkCreation.progress.total > 0) && (
        <Box sx={{ marginTop: theme.spacing(2) }}>
          {bulkCreation.progress.inProgress && (
            <Typography sx={{ color: 'text.disabled' }}>
              {addingLabel(bulkCreation.containerType)}
            </Typography>
          )}
          <Box sx={{ display: 'flex', gap: theme.spacing(1.5), alignItems: 'center' }}>
            <LinearProgress
              style={{ flex: 1 }}
              variant="determinate"
              value={bulkCreation.progress.total > 0 ? (bulkCreation.progress.done / bulkCreation.progress.total) * 100 : 0}
            />
            <Typography style={{ flexShrink: 0 }}>{`${bulkCreation.progress.done}/${bulkCreation.progress.total}`}</Typography>
          </Box>
        </Box>
      )}
      {bulkCreation?.resultMessage && !bulkCreation.progress?.inProgress && (
        <Alert variant="outlined" sx={{ marginTop: 2 }}>
          <Typography>{bulkCreation.resultMessage}</Typography>
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
