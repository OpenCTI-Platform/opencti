import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import { styled } from '@mui/material/styles';
import ListItemIcon from '@mui/material/ListItemIcon';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import { toPairs } from 'ramda';
import { useFormatter } from './i18n';
import { DataColumns } from './list_lines';
import { onActivationKey } from '../utils/domEvent';

const HeaderItem = styled('div')({
  float: 'left',
  fontSize: 12,
  fontWeight: '700',
});

const SortableHeaderItem = styled('div')({
  float: 'left',
  fontSize: 12,
  fontWeight: '700',
  cursor: 'pointer',
});

const sortIconSx = {
  position: 'absolute',
  margin: '7px 0 0 5px',
  padding: 0,
} as const;

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
          sx={sortIconSx}
          style={{ top: 0 }}
        />
      ) : (
        <ArrowDropUp sx={sortIconSx} style={{ top: 0 }} />
      );
      return (
        <SortableHeaderItem
          key={field}
          style={{ width }}
          onClick={() => reverseBy(field)}
          role="button"
          tabIndex={0}
          onKeyDown={onActivationKey(() => reverseBy(field))}
        >
          <span>{t_i18n(label)}</span>
          {sortBy === field ? orderComponent : ''}
        </SortableHeaderItem>
      );
    }
    return (
      <HeaderItem style={{ width }} key={field}>
        <span>{t_i18n(label)}</span>
      </HeaderItem>
    );
  };
  return (
    <ListItem
      sx={{
        paddingLeft: '10px',
        textTransform: 'uppercase',
      }}
      divider={false}
      secondaryAction={secondaryAction && (
        <> &nbsp; </>
      )}
    >
      <ListItemIcon> &nbsp; </ListItemIcon>
      <ListItemText
        primary={(
          <>
            {toPairs(dataColumns).map((dataColumn) => renderHeaderElement(
              dataColumn[0],
              dataColumn[1].label,
              dataColumn[1].width,
              dataColumn[1].isSortable,
            ))}
          </>
        )}
      />
    </ListItem>
  );
};

export default ColumnsLinesTitles;
