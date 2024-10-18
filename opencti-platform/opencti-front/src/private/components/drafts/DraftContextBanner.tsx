import React from 'react';
import { Form, Formik } from 'formik';
import DraftContextField from '@components/drafts/DraftContextField';
import { graphql } from 'react-relay';
import Button from '@mui/material/Button';
import { useNavigate } from 'react-router-dom';
import Chip from '@mui/material/Chip';
import { useTheme } from '@mui/styles';
import { SimplePaletteColorOptions } from '@mui/material';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import useAuth from '../../../utils/hooks/useAuth';

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
  const theme = useTheme<Theme>();
  const { me } = useAuth();
  const navigate = useNavigate();
  const currentDraftContext = me.draftContext ? { label: me.draftContext.name, value: me.draftContext.id } : {};

  const initialValues = { draft_context: currentDraftContext };
  const draftModeColor = (theme.palette.warning as SimplePaletteColorOptions)?.main ?? theme.palette.primary.main;

  const handleSubmitField = (
    name: string,
    value: string | null,
  ) => {
    if (value) {
      commit({
        variables: {
          input: { key: name, value, operation: 'replace' },
        },
        onCompleted: () => {
          navigate(`/dashboard/drafts/${value}`);
        },
      });
    }
  };

  const handleSwitchToLive = () => {
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
      <Formik
        onSubmit={() => {}}
        enableReinitialize={true}
        initialValues={initialValues}
      >
        <Form style={{ display: 'flex', width: '100%', alignItems: 'center' }}>
          <div style={{ padding: '0 12px' }}>
            <Chip
              style={{
                color: draftModeColor,
                borderColor: draftModeColor,
                textTransform: 'uppercase',
                borderRadius: theme.borderRadius,
              }}
              variant="outlined"
              label={t_i18n('Draft Mode')}
            />
          </div>
          <div style={{ marginRight: '10px', minWidth: 160 }}>
            <DraftContextField onChange={handleSubmitField}/>
          </div>
          <div>
            <Button
              variant="contained"
              color="primary"
              style={{ width: '100%' }}
              onClick={handleSwitchToLive}
            >
              {t_i18n('Exit draft')}
            </Button>
          </div>
        </Form>
      </Formik>
    </div>
  );
};

export default DraftContextBanner;
