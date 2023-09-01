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

  const onChange = async (field: string, v: string | File | undefined) => {
    if (field === 'file' && v instanceof File) {
      const fileValue = await v.text();
      setValue(fileValue);
    }
  };

  const onTest = () => {
    fetchQuery(csvMapperTestQuery, {
      configuration,
      content: value,
    }).toPromise()
      .then((data) => {
        const resultTest = (data as CsvMapperTestDialogQuery$data).csvMapperTest;
        setResult(JSON.stringify(resultTest, null, '  '));
      });
  };

  const handleClose = () => {
    setResult('');
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleClose} PaperProps={{ elevation: 1 }}>
      <DialogTitle>{t('Testing csv mapper')}</DialogTitle>
      <DialogContent>
        <CustomFileUploader
            setFieldValue={(field, v) => onChange(field, v)}
            label={'Your testing file'}/>
        <Button
          variant="contained"
          color="secondary"
          disabled={!value}
          onClick={onTest}
          style={{ marginTop: 20 }}
        >
          {t('Test')}
        </Button>
        <div style={{ marginTop: 20 }}>
          <CodeBlock code={result || 'You will find here your test json result'} language={'json'} />
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default CsvMapperTestDialog;
