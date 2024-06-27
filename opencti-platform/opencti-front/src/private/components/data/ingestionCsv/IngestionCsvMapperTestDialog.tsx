import { graphql } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import CodeBlock from '@components/common/CodeBlock';
import Alert from '@mui/material/Alert';
import { Option } from '@components/common/form/ReferenceField';
import { IngestionCsvMapperTestDialogMutation$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvMapperTestDialogMutation.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const ingestionCsvMapperTestMutation = graphql`
  mutation IngestionCsvMapperTestDialogMutation($input: IngestionCsvAddInput!) {
    ingestionCsvTester(input: $input) {
      nbEntities
      nbRelationships
      objects
    }
  }
`;

interface IngestionCsvMapperTestDialogProps {
  open: boolean
  onClose: () => void
  values: {
    name: string,
    description?: string | null,
    authentication_type: string,
    authentication_value?: string | null,
    current_state_date: Date | null,
    uri: string,
    ingestion_running?: boolean | null,
    csv_mapper_id: string | Option,
    user_id: string | Option
    markings: Option[]
  }
  setIsCreateDisabled?: React.Dispatch<React.SetStateAction<boolean>>
}

const IngestionCsvMapperTestDialog: FunctionComponent<IngestionCsvMapperTestDialogProps> = ({
  open,
  onClose,
  values,
  setIsCreateDisabled,
}) => {
  const { t_i18n } = useFormatter();
  const [result, setResult] = useState<IngestionCsvMapperTestDialogMutation$data | undefined>(undefined);
  const [commitTest] = useApiMutation(ingestionCsvMapperTestMutation, undefined, { errorMessage: 'Something went wrong. Please check the configuration.' });
  const [loading, setLoading] = useState<boolean>(false);

  const handleClose = () => {
    setResult(undefined);
    onClose();
  };

  const onTest = () => {
    setLoading(true);
    commitTest({
      variables: {
        input: {
          name: values.name,
          description: values.description,
          authentication_type: values.authentication_type,
          authentication_value: values.authentication_value,
          current_state_date: values.current_state_date,
          uri: values.uri,
          ingestion_running: values.ingestion_running,
          user_id: typeof values.user_id === 'string' ? values.user_id : values.user_id.value,
          csv_mapper_id: typeof values.csv_mapper_id === 'string' ? values.csv_mapper_id : values.csv_mapper_id.value,
          markings: values.markings.map((marking) => marking.value),
        },
      },
      onCompleted: (data) => {
        const resultTest = (data as IngestionCsvMapperTestDialogMutation$data);
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
    <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
      <DialogTitle>{t_i18n('Testing csv mapper')}</DialogTitle>
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
            variant="contained"
            color={result?.ingestionCsvTester?.nbEntities ? 'primary' : 'secondary'}
            onClick={() => onTest()}
          >
            {t_i18n('Test')}
          </Button>
          {loading && (
            <Box sx={{ marginLeft: '8px' }}>
              <Loader variant={LoaderVariant.inElement}/>
            </Box>
          )}
          {result
            && <Box
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
          }
        </Box>
        <Box sx={{ marginTop: '8px' }}>
          <CodeBlock
            code={result?.ingestionCsvTester?.objects || t_i18n('You will find here the result in JSON format.')}
            language={'json'}
          />
        </Box>
      </DialogContent>
    </Dialog>
  );
};

export default IngestionCsvMapperTestDialog;
