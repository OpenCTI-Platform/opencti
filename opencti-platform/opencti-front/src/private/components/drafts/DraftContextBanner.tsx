import React from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import { SimplePaletteColorOptions } from '@mui/material';
import { useTheme } from '@mui/styles';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
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

export const getDraftModeColor = (theme: Theme) => {
  const draftModeColor = (theme.palette.warning as SimplePaletteColorOptions)?.main ?? theme.palette.primary.main;
  return draftModeColor;
};

const DraftContextBanner = () => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(draftContextBannerMutation);
  const theme = useTheme<Theme>();
  const { me } = useAuth();
  const navigate = useNavigate();
  const currentDraftContextName = me.draftContext ? me.draftContext.name : '';

  const draftModeColor = getDraftModeColor(theme);

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
          <Chip
            style={{
              color: draftModeColor,
              borderColor: draftModeColor,
              textTransform: 'uppercase',
              borderRadius: theme.borderRadius,
            }}
            variant="outlined"
            label={`${t_i18n('Draft Mode')} - ${truncate(currentDraftContextName, 20)}`}
          />
        </div>
        <div>
          <Button
            variant="contained"
            color="primary"
            style={{ width: '100%', height: 32 }}
            onClick={handleExitDraft}
          >
            {t_i18n('Approve draft')}
          </Button>
        </div>
        <div style={{ padding: '0 12px' }}>
          <Button
            color="primary"
            style={{ width: '100%', height: 32 }}
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
