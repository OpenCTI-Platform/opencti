import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import React, { FunctionComponent, useState } from 'react';
import DialogContent from '@mui/material/DialogContent';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import CustomFileUploader from '@components/common/files/CustomFileUploader';
import CodeBlock from '@components/common/CodeBlock';
import {
  CsvMapperTestDialogQuery$data,
} from '@components/data/csvMapper/__generated__/CsvMapperTestDialogQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery } from '../../../../relay/environment';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const csvMapperTestQuery = graphql`
  query CsvMapperTestDialogQuery($configuration: String!, $content: String!) {
    csvMapperTest(configuration: $configuration, content:$content)
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
  const [result, setResult] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);

  const onChange = async (field: string, v: string | File | undefined) => {
    if (field === 'file' && v instanceof File) {
      if (v.type === 'text/csv') {
        const fileValue = await v.text();
        setValue(fileValue);
      } else {
        setValue('');
        setResult('');
      }
    }
  };

  const onTest = () => {
    setLoading(true);
    fetchQuery(csvMapperTestQuery, {
      configuration,
      content: value,
    }).toPromise()
      .then((data) => {
        const resultTest = (data as CsvMapperTestDialogQuery$data).csvMapperTest;
        setResult(JSON.stringify(resultTest, null, '  '));
        setLoading(false);
      });
  };

  const handleClose = () => {
    setValue('');
    setResult('');
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
      <DialogTitle>{t('Testing csv mapper')}</DialogTitle>
      <DialogContent>
        <CustomFileUploader
            setFieldValue={(field, v) => onChange(field, v)}
            label={'Your testing file (csv only)'}/>
        <div style={{ display: 'inline-flex', textAlign: 'center', marginTop: 20 }}>
          <Button
            variant="contained"
            color="secondary"
            disabled={!value || loading}
            onClick={onTest}
          >
            {t('Test')}
          </Button>
          {loading && <div style={{ marginLeft: 10 }}><Loader variant={LoaderVariant.inElement} /></div> }
        </div>
        <div style={{ marginTop: 20 }}>
          <CodeBlock code={result || t('You will find here your test json result')} language={'json'} />
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default CsvMapperTestDialog;
