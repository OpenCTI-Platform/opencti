import React from 'react';
import { Form, Formik } from 'formik';
import DraftField from '@components/drafts/DraftContextField';
import { graphql } from 'react-relay';
import Button from '@mui/material/Button';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../components/i18n';

export const draftContextBannerMutation = graphql`
  mutation DraftContextBannerMutation(
      $input: [EditInput]!
  ) {
      meEdit(input: $input) {
        name
        workspace_context
      }
  }
`;

const DraftContextBanner = () => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation(draftContextBannerMutation);

  const handleSubmitField = (
    name: string,
    value: string | null,
  ) => {
    commit({
      variables: {
        input: { key: name, value, operation: 'replace' },
      },
    });
  };

  const handleSwitchToLive = () => {
    commit({
      variables: {
        input: { key: 'workspace_context', value: '' },
      },
    });
  };

  return (
    <div style={{
      position: 'relative',
      display: 'flex',
      zIndex: 2000,
      width: '100%',
    }}
    >
      <Formik
        onSubmit={() => {}}
        initialValues={{ workspace_context: '' }}
      >
        <Form style={{ display: 'flex', width: '100%', alignItems: 'center' }}>
          <div style={{ flex: 1, marginRight: '10px' }}>
            <DraftField onChange={handleSubmitField}/>
          </div>
          <div style={{ flex: 1, alignItems: 'right' }}>
            <Button
              style={{ width: '100%' }}
              onClick={handleSwitchToLive}
            >
              {t_i18n('Switch to live')}
            </Button>
          </div>
        </Form>
      </Formik>
    </div>
  );
};

export default DraftContextBanner;
