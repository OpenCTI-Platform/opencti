import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import ListItemIcon from '@mui/material/ListItemIcon';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { toPairs } from 'ramda';
import { useFormatter } from './i18n';
import { DataColumns } from './list_lines';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  item: {
    paddingLeft: 10,
    textTransform: 'uppercase',
  },
  headerItem: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
  },
  sortIcon: {
    position: 'absolute',
    margin: '7px 0 0 5px',
    padding: 0,
  },
  sortableHeaderItem: {
    float: 'left',
    fontSize: 12,
    fontWeight: '700',
    cursor: 'pointer',
  },
}));

interface TriggerLineTitlesProps {
  dataColumns: DataColumns;
  sortBy?: string;
  orderAsc?: boolean;
  handleSort?: (field: string, orderAsc: boolean) => void;
  secondaryAction?: boolean;
}

const ColumnsLinesTitles: FunctionComponent<TriggerLineTitlesProps> = ({
  dataColumns,
  sortBy,
  orderAsc,
  handleSort,
  secondaryAction,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const reverseBy = (field: string) => {
    if (handleSort) {
      handleSort(field, !orderAsc);
    }
  };
  const renderHeaderElement = (
    field: string,
    label: string,
    width: number | string | undefined,
    isSortable = true,
  ) => {
    if (isSortable) {
      const orderComponent = orderAsc ? (
        <ArrowDropDown
          classes={{ root: classes.sortIcon }}
          style={{ top: 0 }}
        />
      ) : (
        <ArrowDropUp classes={{ root: classes.sortIcon }} style={{ top: 0 }} />
      );
      return (
        <div
          key={field}
          className={classes.sortableHeaderItem}
          style={{ width }}
          onClick={() => reverseBy(field)}
        >
          <span>{t_i18n(label)}</span>
          {sortBy === field ? orderComponent : ''}
        </div>
      );
    }
    return (
      <div className={classes.headerItem} style={{ width }} key={field}>
        <span>{t_i18n(label)}</span>
      </div>
    );
  };
  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={false}
      secondaryAction={secondaryAction && (
        <> &nbsp; </>
      )}
    >
      <ListItemIcon> &nbsp; </ListItemIcon>
      <ListItemText
        primary={
          <>
            {toPairs(dataColumns).map((dataColumn) => renderHeaderElement(
              dataColumn[0],
              dataColumn[1].label,
              dataColumn[1].width,
              dataColumn[1].isSortable,
            ))}
          </>
        }
      />
    </ListItem>
  );
};

export default ColumnsLinesTitles;
