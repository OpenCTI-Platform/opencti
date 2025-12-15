import { graphql } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Button from '@common/button/Button';
import Box from '@mui/material/Box';
import CodeBlock from '@components/common/CodeBlock';
import Alert from '@mui/material/Alert';
import { IngestionJsonMapperTestDialogMutation$data } from '@components/data/ingestionJson/__generated__/IngestionJsonMapperTestDialogMutation.graphql';
import { IngestionJsonAddInput } from '@components/data/ingestionJson/IngestionJsonCreation';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { getAuthenticationValue } from '../../../../utils/ingestionAuthentificationUtils';

const ingestionJsonMapperTestMutation = graphql`
  mutation IngestionJsonMapperTestDialogMutation($input: IngestionJsonAddInput!) {
    ingestionJsonTester(input: $input) {
      nbEntities
      nbRelationships
      objects
      state
    }
  }
`;

interface IngestionJsonMapperTestDialogProps {
  open: boolean;
  onClose: () => void;
  values: IngestionJsonAddInput;
  setIsCreateDisabled?: React.Dispatch<React.SetStateAction<boolean>>;
}

const IngestionJsonMapperTestDialog: FunctionComponent<IngestionJsonMapperTestDialogProps> = ({
  open,
  onClose,
  values,
  setIsCreateDisabled,
}) => {
  const { t_i18n } = useFormatter();
  const [result, setResult] = useState<IngestionJsonMapperTestDialogMutation$data | undefined>(undefined);
  const [commitTest] = useApiMutation(ingestionJsonMapperTestMutation, undefined, { errorMessage: 'Something went wrong. Please check the configuration.' });
  const [loading, setLoading] = useState<boolean>(false);

  const handleClose = () => {
    setResult(undefined);
    onClose();
  };

  const authenticationValueResolved = getAuthenticationValue(values);

  const onTest = () => {
    setLoading(true);
    commitTest({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          authentication_type: values.authentication_type,
          authentication_value: authenticationValueResolved,
          uri: values.uri,
          verb: values.verb,
          body: values.body,
          headers: values.headers,
          query_attributes: values.query_attributes,
          pagination_with_sub_page: values.pagination_with_sub_page,
          pagination_with_sub_page_query_verb: values.pagination_with_sub_page_query_verb,
          pagination_with_sub_page_attribute_path: values.pagination_with_sub_page_attribute_path,
          user_id: typeof values.user_id === 'string' ? values.user_id : values.user_id.value,
          json_mapper_id: typeof values.json_mapper_id === 'string' ? values.json_mapper_id : values.json_mapper_id.value,
          markings: values.markings.map((marking) => marking.value),
        },
      },
      onCompleted: (data) => {
        const resultTest = data as IngestionJsonMapperTestDialogMutation$data;
        if (resultTest) {
          setResult(resultTest);
          if (setIsCreateDisabled) {
            setIsCreateDisabled(resultTest.ingestionJsonTester?.nbEntities === 0);
          }
        }
        setLoading(false);
      },
      onError: (error) => {
        handleError(error);
        setLoading(false);
      },
    });
  };

  return (
    <Dialog open={open} onClose={handleClose} slotProps={{ paper: { elevation: 1 } }}>
      <DialogTitle>{t_i18n('Testing JSON feed')}</DialogTitle>
      <DialogContent>
        <Box>
          <div style={{ width: '100%', marginTop: 10 }}>
            <Alert
              severity="info"
              variant="outlined"
              style={{ padding: '0px 10px 0px 10px' }}
            >
              {t_i18n('Please, note that the test will be run on the 50 first lines')}
            </Alert>
          </div>
        </Box>
        <Box
          sx={{ display: 'inline-flex', textAlign: 'center', marginTop: '8px', alignItems: 'baseline' }}
        >
          <Button
            color={result?.ingestionJsonTester?.nbEntities ? 'primary' : 'secondary'}
            onClick={() => onTest()}
          >
            {t_i18n('Test')}
          </Button>
          {loading && (
            <Box sx={{ marginLeft: '8px' }}>
              <Loader variant={LoaderVariant.inElement} />
            </Box>
          )}
          {result
            && (
              <Box
                sx={{
                  paddingTop: '8px',
                  marginLeft: '12px',
                  fontSize: '1rem',
                  gap: '8px',
                  justifyContent: 'center',
                  display: 'flex',
                }}
              >
                <span>{t_i18n('Objects found')} : </span>
                <span><strong>{result?.ingestionJsonTester?.nbEntities} </strong> {t_i18n('Entities')}</span>
                <span><strong>{result?.ingestionJsonTester?.nbRelationships}</strong> {t_i18n('Relationships')}</span>
              </Box>
            )
          }
        </Box>
        <Box sx={{ marginTop: '8px' }}>
          <h3>State</h3>
          <CodeBlock
            customHeight="50px"
            code={result?.ingestionJsonTester?.state || t_i18n('You will find here the computed state.')}
            language="json"
          />
        </Box>
        <Box sx={{ marginTop: '8px' }}>
          <h3>Objects</h3>
          <CodeBlock
            code={result?.ingestionJsonTester?.objects || t_i18n('You will find here the result in JSON format.')}
            language="json"
          />
        </Box>
      </DialogContent>
    </Dialog>
  );
};

export default IngestionJsonMapperTestDialog;
