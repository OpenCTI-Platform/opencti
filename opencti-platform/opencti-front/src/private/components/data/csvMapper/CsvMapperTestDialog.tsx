import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import React, { FunctionComponent, useState } from 'react';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import { graphql } from 'react-relay';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import CodeBlock from '@components/common/CodeBlock';
import { CsvMapperTestDialogQuery$data } from '@components/data/csvMapper/__generated__/CsvMapperTestDialogQuery.graphql';
import { InformationOutline } from 'mdi-material-ui';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery, handleError } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const csvMapperTestQuery = graphql`
    query CsvMapperTestDialogQuery($configuration: String!, $content: String!) {
        csvMapperTest(configuration: $configuration, content: $content) {
            objects
            nbRelationships
            nbEntities
        }
    }
`;

interface CsvMapperTestDialogProps {
  open: boolean;
  onClose: () => void;
  configuration: string;
}

const CsvMapperTestDialog: FunctionComponent<CsvMapperTestDialogProps> = ({
  open,
  onClose,
  configuration,
}) => {
  const { t } = useFormatter();

  const [value, setValue] = useState<string>('');
  const [result, setResult] = useState<CsvMapperTestDialogQuery$data | undefined>(undefined);
  const [loading, setLoading] = useState<boolean>(false);

  const onChange = async (field: string, v: string | File | undefined) => {
    if (field === 'file' && v instanceof File) {
      if (v.type === 'text/csv') {
        const fileValue = await v.text();
        setValue(fileValue);
      } else {
        setValue('');
        setResult(undefined);
      }
    }
  };

  const onTest = () => {
    setLoading(true);
    fetchQuery(csvMapperTestQuery, {
      configuration,
      content: value,
    })
      .toPromise()
      .then((data) => {
        const resultTest = (data as CsvMapperTestDialogQuery$data)
          .csvMapperTest;
        if (resultTest) {
          setResult({
            csvMapperTest: {
              ...resultTest,
            },
          });
        }
        setLoading(false);
      }).catch((error) => {
        handleError(error);
        setLoading(false);
      });
  };

  const handleClose = () => {
    setValue('');
    setResult(undefined);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
      <DialogTitle>{t('Testing csv mapper')}</DialogTitle>
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
            label={'Your testing file (csv only, max 5MB)'}
            acceptMimeTypes={'text/csv'}
            // we limit the file size so the upload does not take too long for a simple test
            sizeLimit={5000000}
          />
          <Tooltip
            title={t(
              'Select a sample file in CSV format, with a maximum size of 5MB to limit the processing time.',
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
            variant="contained"
            color="secondary"
            disabled={!value || loading}
            onClick={onTest}
          >
            {t('Test')}
          </Button>
          {loading && (
            <Box sx={{ marginLeft: '8px' }}>
              <Loader variant={LoaderVariant.inElement}/>
            </Box>
          )}
        </Box>
        {result
          && <Box
            sx={{
              paddingTop: '8px',
              fontSize: '1rem',
              gap: '8px',
              justifyContent: 'center',
              display: 'flex',
            }}>
            <span>{t('Objects found')} : </span>
            <span><strong>{result?.csvMapperTest?.nbEntities} </strong> {t('Entities')}</span>
            <span><strong>{result?.csvMapperTest?.nbRelationships}</strong> {t('Relationships')}</span>
          </Box>
        }
        <Box sx={{ marginTop: '8px' }}>
          <CodeBlock
            code={result?.csvMapperTest?.objects || t('You will find here the result in JSON format')}
            language={'json'}
          />
        </Box>
      </DialogContent>
    </Dialog>
  );
};

export default CsvMapperTestDialog;
