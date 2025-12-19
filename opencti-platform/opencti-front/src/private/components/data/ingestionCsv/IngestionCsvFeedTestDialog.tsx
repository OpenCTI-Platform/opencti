import { graphql } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Button from '@common/button/Button';
import Box from '@mui/material/Box';
import CodeBlock from '@components/common/CodeBlock';
import Alert from '@mui/material/Alert';
import { IngestionCsvFeedTestDialogMutation$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvFeedTestDialogMutation.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { getAuthenticationValue } from '../../../../utils/ingestionAuthentificationUtils';
import { FieldOption } from '../../../../utils/field';
import { CsvMapperAddInput } from '../csvMapper/CsvMapperUtils';

const ingestionCsvFeedTestMutation = graphql`
  mutation IngestionCsvFeedTestDialogMutation($input: IngestionCsvAddInput!) {
    ingestionCsvTester(input: $input) {
      nbEntities
      nbRelationships
      objects
    }
  }
`;

interface ingestionCsvFeedTestDialogProps {
  open: boolean;
  onClose: () => void;
  values: {
    name: string;
    description?: string | null;
    authentication_type: string;
    csv_mapper?: CsvMapperAddInput;
    csv_mapper_type?: string;
    authentication_value?: string | null;
    uri: string;
    ingestion_running?: boolean | null;
    csv_mapper_id?: string | FieldOption | null;
    user_id: string | FieldOption;
    markings: FieldOption[];
  };
  setIsCreateDisabled?: React.Dispatch<React.SetStateAction<boolean>>;
}

const IngestionCsvFeedTestDialog: FunctionComponent<ingestionCsvFeedTestDialogProps> = ({
  open,
  onClose,
  values,
  setIsCreateDisabled,
}) => {
  const { t_i18n } = useFormatter();
  const [result, setResult] = useState<IngestionCsvFeedTestDialogMutation$data | undefined>(undefined);
  const [commitTest] = useApiMutation(ingestionCsvFeedTestMutation, undefined, { errorMessage: 'Something went wrong. Please check the configuration.' });
  const [loading, setLoading] = useState<boolean>(false);

  const handleClose = () => {
    setResult(undefined);
    onClose();
  };

  const authentifcationValueResolved = getAuthenticationValue(values);

  const onTest = () => {
    setLoading(true);
    commitTest({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          authentication_type: values.authentication_type,
          authentication_value: authentifcationValueResolved,
          uri: values.uri,
          ingestion_running: values.ingestion_running,
          user_id: typeof values.user_id === 'string' ? values.user_id : values.user_id.value,
          csv_mapper_id: typeof values.csv_mapper_id === 'string' ? values.csv_mapper_id : values.csv_mapper_id?.value,
          csv_mapper: values.csv_mapper ? JSON.stringify((values.csv_mapper)) : undefined,
          csv_mapper_type: values.csv_mapper_type,
          markings: values.markings.map((marking) => marking.value),
        },
      },
      onCompleted: (data) => {
        const resultTest = data as IngestionCsvFeedTestDialogMutation$data;
        if (resultTest) {
          setResult(resultTest);
          if (setIsCreateDisabled) {
            setIsCreateDisabled(resultTest.ingestionCsvTester?.nbEntities === 0);
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
      <DialogTitle>{t_i18n('Testing CSV Feed')}</DialogTitle>
      <DialogContent>
        <Box>
          <div style={{ width: '100%', marginTop: 10 }}>
            <Alert
              severity="info"
              variant="outlined"
              style={{ padding: '0px 10px 0px 10px' }}
            >
              {t_i18n('Please, note that the test will be run on the 10 first lines')}
            </Alert>
          </div>
        </Box>
        <Box
          sx={{ display: 'inline-flex', textAlign: 'center', marginTop: '8px', alignItems: 'baseline' }}
        >
          <Button
            color={result?.ingestionCsvTester?.nbEntities ? 'primary' : 'secondary'}
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
                <span><strong>{result?.ingestionCsvTester?.nbEntities} </strong> {t_i18n('Entities')}</span>
                <span><strong>{result?.ingestionCsvTester?.nbRelationships}</strong> {t_i18n('Relationships')}</span>
              </Box>
            )
          }
        </Box>
        <Box sx={{ marginTop: '8px' }}>
          <CodeBlock
            code={result?.ingestionCsvTester?.objects || t_i18n('You will find here the result in JSON format.')}
            language="json"
          />
        </Box>
      </DialogContent>
    </Dialog>
  );
};

export default IngestionCsvFeedTestDialog;
