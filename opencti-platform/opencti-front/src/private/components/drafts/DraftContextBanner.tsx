import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import DraftBlock from '@components/common/draft/DraftBlock';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useAuth from '../../../utils/hooks/useAuth';
import { truncate } from '../../../utils/String';

export const draftContextBannerMutation = graphql`
    mutation DraftContextBannerMutation(
        $input: [EditInput]!
    ) {
        meEdit(input: $input) {
            name
            draftContext {
              id
              name
            }
        }
    }
`;

const DraftContextBanner = () => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(draftContextBannerMutation);
  const { me } = useAuth();
  const navigate = useNavigate();
  const currentDraftContextName = me.draftContext ? me.draftContext.name : '';

  const handleExitDraft = () => {
    commit({
      variables: {
        input: { key: 'draft_context', value: '' },
      },
      onCompleted: () => {
        navigate('/');
      },
    });
  };

  return (
    <div style={{ padding: '0 12px' }}>
      <div style={{ display: 'flex', width: '100%', alignItems: 'center' }}>
        <div style={{ padding: '0 12px' }}>
          <DraftBlock body={truncate(currentDraftContextName, 40)} />
        </div>
        <div>
          <Button
            variant="contained"
            color="primary"
            style={{ width: '100%' }}
            onClick={handleExitDraft}
          >
            {t_i18n('Approve draft')}
          </Button>
        </div>
        <div style={{ padding: '0 12px' }}>
          <Button
            color="primary"
            variant="outlined"
            style={{ width: '100%' }}
            onClick={handleExitDraft}
          >
            {t_i18n('Exit draft')}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default DraftContextBanner;
