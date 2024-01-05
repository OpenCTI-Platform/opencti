import { graphql } from 'react-relay';
import React, { FunctionComponent, useState } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import Box from '@mui/material/Box';
import CodeBlock from '@components/common/CodeBlock';
import { IngestionCsvMapperTestDialogQuery$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvMapperTestDialogQuery.graphql';
import { Option } from '@components/common/form/ReferenceField';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery, handleError } from '../../../../relay/environment';

const ingestionCsvMapperTestQuery = graphql`
  query IngestionCsvMapperTestDialogQuery($uri: String!, $csvMapper_id: String!) {
    test_mapper(uri: $uri, csvMapper_id: $csvMapper_id) {
      nbEntities
      nbRelationships
      objects
    }
  }
`;

interface IngestionCsvMapperTestDialogProps {
  open: boolean
  onClose: () => void
  uri: string
  csvMapperId: string | Option
}

const IngestionCsvMapperTestDialog: FunctionComponent<IngestionCsvMapperTestDialogProps> = ({
  open,
  onClose,
  uri,
  csvMapperId,
}) => {
  const { t } = useFormatter();
  const [result, setResult] = useState<IngestionCsvMapperTestDialogQuery$data | undefined>(undefined);
  const [loading, setLoading] = useState<boolean>(false);

  const handleClose = () => {
    setResult(undefined);
    onClose();
  };

  const onTest = (url: string, csvMapper_id: string) => {
    setLoading(true);
    fetchQuery(ingestionCsvMapperTestQuery, { uri: url, csvMapper_id })
      .toPromise()
      .then((data) => {
        const resultTest = (data as IngestionCsvMapperTestDialogQuery$data)
          .test_mapper;
        if (resultTest) {
          setResult({
            test_mapper: {
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

  return (
    <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
      <DialogTitle>{t('Testing csv mapper')}</DialogTitle>
      <DialogContent>
        <Box>

        </Box>
        <Box
          sx={{ display: 'inline-flex', textAlign: 'center', marginTop: '8px' }}
        >
          <Button
            variant="contained"
            color="secondary"
            onClick={() => onTest(uri, typeof csvMapperId === 'string' ? csvMapperId : csvMapperId.value)}
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
            }}
             >
            <span>{t('Objects found')} : </span>
            <span><strong>{result?.test_mapper?.nbEntities} </strong> {t('Entities')}</span>
            <span><strong>{result?.test_mapper?.nbRelationships}</strong> {t('Relationships')}</span>
          </Box>
        }
        <Box sx={{ marginTop: '8px' }}>
          <CodeBlock
            code={result?.test_mapper?.objects || t('You will find here the result in JSON format')}
            language={'json'}
          />
        </Box>
      </DialogContent>
    </Dialog>
  );
};

export default IngestionCsvMapperTestDialog;
