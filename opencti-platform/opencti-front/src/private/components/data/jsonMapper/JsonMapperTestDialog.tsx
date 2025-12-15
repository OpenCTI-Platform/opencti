import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import React, { FunctionComponent, useState } from 'react';
import DialogContent from '@mui/material/DialogContent';
import Button from '@common/button/Button';
import Tooltip from '@mui/material/Tooltip';
import { graphql } from 'react-relay';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import CodeBlock from '@components/common/CodeBlock';
import { InformationOutline } from 'mdi-material-ui';
import Box from '@mui/material/Box';
import { JsonMapperTestDialogMutation$data } from '@components/data/jsonMapper/__generated__/JsonMapperTestDialogMutation.graphql';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, handleError } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const jsonMapperTestQuery = graphql`
  mutation JsonMapperTestDialogMutation($configuration: String!, $file: Upload!) {
    jsonMapperTest(configuration: $configuration, file: $file) {
      objects
      nbRelationships
      nbEntities
    }
  }
`;

interface JsonMapperTestDialogProps {
  open: boolean;
  onClose: () => void;
  configuration: string;
}

const JsonMapperTestDialog: FunctionComponent<JsonMapperTestDialogProps> = ({
  open,
  onClose,
  configuration,
}) => {
  const { t_i18n } = useFormatter();

  const [value, setValue] = useState<File | undefined>(undefined);
  const [result, setResult] = useState<JsonMapperTestDialogMutation$data | undefined>(undefined);
  const [loading, setLoading] = useState<boolean>(false);

  const onChange = async (field: string, v: string | File | undefined | null) => {
    if (field === 'file' && v instanceof File) {
      if (v.type === 'text/json' || v.type === 'application/json') {
        setValue(v);
      } else {
        setValue(undefined);
        setResult(undefined);
      }
    }
  };

  const onTest = () => {
    setLoading(true);

    commitMutation({
      mutation: jsonMapperTestQuery,
      variables: { file: value, configuration },
      onCompleted: (data: JsonMapperTestDialogMutation$data) => {
        const resultTest = data.jsonMapperTest;
        if (resultTest) {
          setResult({ jsonMapperTest: { ...resultTest } });
        }
        setLoading(false);
      },
      onError: (error: Error) => {
        handleError(error);
        setLoading(false);
      },
      setSubmitting: undefined,
      optimisticResponse: undefined,
      optimisticUpdater: undefined,
      updater: undefined,
    });
  };

  const handleClose = () => {
    setValue(undefined);
    setResult(undefined);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} slotProps={{ paper: { elevation: 1 } }}>
      <DialogTitle>{t_i18n('Testing json mapper')}</DialogTitle>
      <DialogContent>
        <Box
          sx={{
            display: 'flex',
            flexDirection: 'row',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <CustomFileUploader
            setFieldValue={(field, v) => onChange(field, v)}
            label="Your testing file limited to 50 lines (JSON only, max 1MB)"
            // we also accept application/vnd.ms-excel type because that's how json's seem to be seen as under WindowsOS + Firefox browser
            acceptMimeTypes="text/json,application/json"
            // we limit the file size so the upload does not take too long for a simple test
            sizeLimit={1000000}
          />
          <Tooltip
            title={t_i18n(
              'Select a sample file in JSON format, with a maximum size of 1MB to limit the processing time.',
            )}
          >
            <InformationOutline
              fontSize="small"
              color="primary"
              style={{ cursor: 'default' }}
            />
          </Tooltip>
        </Box>
        <Box
          sx={{ display: 'inline-flex', textAlign: 'center', marginTop: '8px' }}
        >
          <Button
            color="secondary"
            disabled={!value || loading}
            onClick={onTest}
          >
            {t_i18n('Test')}
          </Button>
          {loading && (
            <Box sx={{ marginLeft: '8px' }}>
              <Loader variant={LoaderVariant.inElement} />
            </Box>
          )}
        </Box>
        {result
          && (
            <Box
              sx={{
                paddingTop: '8px',
                fontSize: '1rem',
                gap: '8px',
                justifyContent: 'center',
                display: 'flex',
              }}
            >
              <span>{t_i18n('Objects found')} : </span>
              <span><strong>{result?.jsonMapperTest?.nbEntities} </strong> {t_i18n('Entities')}</span>
              <span><strong>{result?.jsonMapperTest?.nbRelationships}</strong> {t_i18n('Relationships')}</span>
            </Box>
          )
        }
        <Box sx={{ marginTop: '8px' }}>
          <CodeBlock
            code={result?.jsonMapperTest?.objects || t_i18n('You will find here the result in JSON format.')}
            language="json"
          />
        </Box>
      </DialogContent>
    </Dialog>
  );
};

export default JsonMapperTestDialog;
