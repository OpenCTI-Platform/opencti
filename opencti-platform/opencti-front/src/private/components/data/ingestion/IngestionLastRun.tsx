import React, { FunctionComponent } from 'react';
import { useFormatter } from '../../../../components/i18n';
import { useTheme } from '@mui/styles';
import { Theme } from '../../../../components/Theme';

type LastRun = {
  ingestion_id: string;
  onOpenHistory: (ingestionId: string) => void;
  last_execution_status?: string | null;
  last_execution_date?: string | null;
};
const IngestionLastRun: FunctionComponent<LastRun> = (props) => {
  const { nsdt } = useFormatter();
  const theme = useTheme<Theme>();
  const { last_execution_status, last_execution_date } = props;
  const backgroundColor = last_execution_status === 'error' ? theme.palette.error.main : theme.palette.success.main;
  return (
    <>
      {last_execution_date && (
        <div
          onClick={() => props.onOpenHistory(props.ingestion_id)}
          style={{
            cursor: 'pointer',
            backgroundColor,
            height: 12,
            width: 12,
            display: 'inline-flex',
            borderRadius: 20,
            marginRight: 5,
          }}
        />
      )}
      <span>{nsdt(last_execution_date)}</span>
    </>
  );
};

export default IngestionLastRun;
