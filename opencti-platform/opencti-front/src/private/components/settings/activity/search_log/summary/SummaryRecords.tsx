import React from 'react';
import type { Theme } from '../../../../../../components/Theme';
import makeStyles from '@mui/styles/makeStyles';
import WidgetNoData from '../../../../../../components/dashboard/WidgetNoData';

const useStyles = makeStyles<Theme>((theme) => ({
  recordsList: {
    margin: 0,
    display: 'flex',
    flexFlow: 'column',
    gap: theme.spacing(1),
    columnGap: theme.spacing(5),
    paddingLeft: theme.spacing(3),
    height: '100%',
  },
  record: {
    fontSize: 14,
    fontWeight: 500,
    color: theme.palette.text?.primary,
  },
  filler: {
    borderBottom: '1px dotted #333',
    height: 4,
  },
  recordValue: {
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
}));

interface SummaryRecord {
  value: string;
  count: number;
}

interface SummaryRecordsProps {
  records: SummaryRecord[];
}

const SummaryRecords = ({ records }: SummaryRecordsProps) => {
  const classes = useStyles();

  const renderContent = () => {
    if (records.length === 0) {
      return <WidgetNoData />;
    } else {
      return (
        <ol className={classes.recordsList}>
          {records.map((r) => {
            return (
              <li key={r.value} className={classes.record}>
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingRight: 8, paddingLeft: 2, alignItems: 'center' }}>
                  <div className={classes.recordValue}>{r.value} </div>
                  <div style={{ flex: 1, padding: 4, minWidth: 16 }}>
                    <div className={classes.filler}></div>
                  </div>
                  <div>{`(${r.count})`}</div>
                </div>
              </li>
            );
          })}
        </ol>
      );
    }
  };

  return (
    <div style={{ flex: 1, overflowY: 'auto', height: '100%' }}>
      {renderContent()}
    </div>
  );
};

export default SummaryRecords;
