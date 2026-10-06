import { useState } from 'react';
import { graphql } from 'react-relay';
import { Box, DialogActions, Typography } from '@mui/material';
import { RemoveCircleOutlineOutlined, ReplayOutlined } from '@mui/icons-material';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import { PayloadError } from 'relay-runtime';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import { DeployedOnActionsRetryMutation } from './__generated__/DeployedOnActionsRetryMutation.graphql';
import { DeployedOnActionsRemoveMutation } from './__generated__/DeployedOnActionsRemoveMutation.graphql';
import { canRemoveDeployment, canRetryDeployment } from './disseminationAssuranceUtils';

const deployedOnRetryMutation = graphql`
  mutation DeployedOnActionsRetryMutation($id: ID!) {
    indicatorDeploymentRetry(id: $id) {
      id
      ...DeployedOnRelationships_node
    }
  }
`;

const deployedOnRemoveMutation = graphql`
  mutation DeployedOnActionsRemoveMutation($id: ID!) {
    indicatorDeploymentRemove(id: $id) {
      id
      ...DeployedOnRelationships_node
    }
  }
`;

/** Two md icon buttons (36 px) and their 4 px gap, so that a row with both actions shows both. */
export const DEPLOYMENT_ACTIONS_COLUMN_WIDTH = 76;

interface DeployedOnActionsProps {
  id: string;
  deploymentStatus: string | null | undefined;
  revoked: boolean | null | undefined;
  indicatorName?: string | null;
  platformName?: string | null;
}

/** Analyst actions on one deployment: ask the connector to deploy again, or withdraw it from this platform only. */
const DeployedOnActions = ({ id, deploymentStatus, revoked, indicatorName, platformName }: DeployedOnActionsProps) => {
  const { t_i18n } = useFormatter();
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [commitRetry, retrying] = useApiMutation<DeployedOnActionsRetryMutation>(deployedOnRetryMutation);
  const [commitRemove, removing] = useApiMutation<DeployedOnActionsRemoveMutation>(deployedOnRemoveMutation);

  // Payload errors reach onCompleted: only a returned deployment confirms the action.
  const succeeded = (deployment: { id: string } | null | undefined, errors: PayloadError[] | null) => {
    if (errors && errors.length > 0) {
      MESSAGING$.notifyError(errors[0].message);
      return false;
    }
    return !!deployment;
  };
  const retryable = canRetryDeployment(deploymentStatus);
  const removable = canRemoveDeployment(deploymentStatus, revoked);

  const stop = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
  };

  // Each action keeps its own slot, so that "Deploy again" and "Remove" line up on every row of the table.
  return (
    <Box
      sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', columnGap: 0.5, width: '100%' }}
      onClick={stop}
    >
      {retryable && (
        <Box sx={{ gridColumn: 1 }}>
          <Tooltip>
            <TooltipTrigger asChild>
              <IconButton
                variant="default"
                priority="tertiary"
                size="md"
                aria-label={t_i18n('Deploy again')}
                disabled={retrying}
                onClick={(event: React.MouseEvent) => {
                  stop(event);
                  commitRetry({
                    variables: { id },
                    onCompleted: (response, errors) => {
                      if (succeeded(response.indicatorDeploymentRetry, errors)) {
                        MESSAGING$.notifySuccess(t_i18n('The connector will deploy the indicator again'));
                      }
                    },
                  });
                }}
                icon={<ReplayOutlined fontSize="small" />}
                data-testid="deployment-retry"
              />
            </TooltipTrigger>
            <TooltipContent>{t_i18n('Deploy again')}</TooltipContent>
          </Tooltip>
        </Box>
      )}
      {removable && (
        <Box sx={{ gridColumn: 2 }}>
          <Tooltip>
            <TooltipTrigger asChild>
              <IconButton
                variant="default"
                priority="tertiary"
                size="md"
                aria-label={t_i18n('Remove from this platform')}
                disabled={removing}
                onClick={(event: React.MouseEvent) => {
                  stop(event);
                  setConfirmRemove(true);
                }}
                icon={<RemoveCircleOutlineOutlined fontSize="small" />}
                data-testid="deployment-remove"
              />
            </TooltipTrigger>
            <TooltipContent>{t_i18n('Remove from this platform')}</TooltipContent>
          </Tooltip>
        </Box>
      )}
      <Dialog
        open={confirmRemove}
        onClose={() => setConfirmRemove(false)}
        title={indicatorName && platformName
          ? t_i18n('Remove {indicator} from {platform}', { values: { indicator: indicatorName, platform: platformName } })
          : t_i18n('Remove from this platform')}
        size="small"
      >
        <Typography>
          {t_i18n('The stream connector removes the indicator from this security platform and reports it as removed. Without confirmation, the deployment is flagged as expired after the grace period.')}
        </Typography>
        <DialogActions>
          <Button variant="secondary" onClick={() => setConfirmRemove(false)} disabled={removing}>
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={() => commitRemove({
              variables: { id },
              onCompleted: (response, errors) => {
                if (succeeded(response.indicatorDeploymentRemove, errors)) {
                  setConfirmRemove(false);
                  MESSAGING$.notifySuccess(t_i18n('The connector will remove the indicator from the platform'));
                }
              },
            })}
            disabled={removing}
          >
            {t_i18n('Remove')}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default DeployedOnActions;
