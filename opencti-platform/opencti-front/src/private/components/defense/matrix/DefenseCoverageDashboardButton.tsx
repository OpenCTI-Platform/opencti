import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import { InsertChartOutlinedOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { buildDashboardTemplateExport } from '../../../../components/dashboard/templates/dashboardTemplates';
import { defenseCoverageDashboardTemplate } from '../../../../components/dashboard/templates/defenseCoverageDashboardTemplate';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Security from '../../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import { resolveLink } from '../../../../utils/Entity';
import { MESSAGING$ } from '../../../../relay/environment';
import { notifyPayloadErrors } from './defenseMutation-utils';
import { DefenseCoverageDashboardButtonMutation } from './__generated__/DefenseCoverageDashboardButtonMutation.graphql';
const defenseCoverageDashboardButtonMutation = graphql`
  mutation DefenseCoverageDashboardButtonMutation($input: WorkspaceDuplicateInput!) {
    workspaceDuplicate(input: $input) {
      id
    }
  }
`;

/**
 * Creates a custom dashboard from the built-in "Defense coverage" template and opens it.
 */
const DefenseCoverageDashboardButton = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [commit, creating] = useApiMutation<DefenseCoverageDashboardButtonMutation>(defenseCoverageDashboardButtonMutation);
  const create = () => {
    commit({
      variables: {
        input: {
          type: 'dashboard',
          name: t_i18n('Defense coverage'),
          description: t_i18n('Threat-informed defense: coverage by tactic, uncovered techniques used by threats and detection rules.'),
          manifest: buildDashboardTemplateExport(defenseCoverageDashboardTemplate, t_i18n).configuration.manifest,
        },
      },
      onCompleted: (response, errors) => {
        if (notifyPayloadErrors(errors)) return;
        if (response.workspaceDuplicate?.id) {
          MESSAGING$.notifySuccess(t_i18n('Defense coverage dashboard created'));
          navigate(`${resolveLink('Dashboard')}/${response.workspaceDuplicate.id}`);
        }
      },
    });
  };
  return (
    <Security needs={[EXPLORE_EXUPDATE]}>
      <Button
        variant="secondary"
        size="small"
        startIcon={<InsertChartOutlinedOutlined fontSize="small" />}
        onClick={create}
        disabled={creating}
        data-testid="defense-coverage-dashboard-create"
      >
        {t_i18n('Create the defense coverage dashboard')}
      </Button>
    </Security>
  );
};

export default DefenseCoverageDashboardButton;
