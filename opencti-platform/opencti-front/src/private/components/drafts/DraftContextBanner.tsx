import React from 'react';
import { Form, Formik } from 'formik';
import DraftField from '@components/drafts/DraftContextField';
import { graphql } from 'react-relay';
import Button from '@mui/material/Button';
import { useNavigate } from 'react-router-dom';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../components/i18n';
import useAuth from '../../../utils/hooks/useAuth';

export const draftContextBannerMutation = graphql`
    mutation DraftContextBannerMutation(
        $input: [EditInput]!
    ) {
        meEdit(input: $input) {
            name
            draft_context
        }
    }
`;

const DraftContextBanner = () => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(draftContextBannerMutation);
  const { me } = useAuth();
  const navigate = useNavigate();
  const currentDraftContext = me.draft_context ?? '';

  const handleSubmitField = (
    name: string,
    value: string | null,
  ) => {
    commit({
      variables: {
        input: { key: name, value, operation: 'replace' },
      },
      onCompleted: () => {
        navigate(`/dashboard/drafts/${value}`);
      },
    });
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
        initialValues={{ draft_context: currentDraftContext }}
      >
        <Form style={{ display: 'flex', width: '100%', alignItems: 'center' }}>
          <div style={{ marginRight: '10px', minWidth: 160 }}>
            <DraftField onChange={handleSubmitField}/>
          </div>
          <div>
            <Button
              variant="contained"
              color="secondary"
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
