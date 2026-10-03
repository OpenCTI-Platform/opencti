import { useState } from 'react';
import { graphql } from 'react-relay';
import { DialogActions, Stack, Typography } from '@mui/material';
import { RemoveCircleOutlineOutlined, ReplayOutlined } from '@mui/icons-material';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
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

interface DeployedOnActionsProps {
  id: string;
  deploymentStatus: string | null | undefined;
  revoked: boolean | null | undefined;
}

/** Analyst actions on one deployment: ask the connector to deploy again, or withdraw it from this platform only. */
const DeployedOnActions = ({ id, deploymentStatus, revoked }: DeployedOnActionsProps) => {
  const { t_i18n } = useFormatter();
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [commitRetry, retrying] = useApiMutation(deployedOnRetryMutation, undefined, {
    successMessage: t_i18n('The connector will deploy the indicator again'),
  });
  const [commitRemove, removing] = useApiMutation(deployedOnRemoveMutation, undefined, {
    successMessage: t_i18n('The connector will remove the indicator from the platform'),
  });
  const retryable = canRetryDeployment(deploymentStatus);
  const removable = canRemoveDeployment(deploymentStatus, revoked);

  const stop = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
  };

  return (
    <Stack direction="row" gap={0.5} onClick={stop}>
      {retryable && (
        <Tooltip>
          <TooltipTrigger asChild>
            <IconButton
              variant="default"
              priority="tertiary"
              size="md"
              aria-label={t_i18n('Retry deployment')}
              disabled={retrying}
              onClick={(event: React.MouseEvent) => {
                stop(event);
                commitRetry({ variables: { id } });
              }}
              icon={<ReplayOutlined fontSize="small" />}
              data-testid="deployment-retry"
            />
          </TooltipTrigger>
          <TooltipContent>{t_i18n('Retry deployment')}</TooltipContent>
        </Tooltip>
      )}
      {removable && (
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
      )}
      <Dialog
        open={confirmRemove}
        onClose={() => setConfirmRemove(false)}
        title={t_i18n('Remove from this platform')}
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
              onCompleted: () => setConfirmRemove(false),
              onError: () => setConfirmRemove(false),
            })}
            disabled={removing}
          >
            {t_i18n('Remove')}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
};

export default DeployedOnActions;
