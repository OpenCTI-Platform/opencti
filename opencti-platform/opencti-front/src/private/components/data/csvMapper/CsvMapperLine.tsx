import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import TableViewIcon from '@mui/icons-material/TableView';
import { CsvMapperLine_csvMapper$key } from '@components/data/csvMapper/__generated__/CsvMapperLine_csvMapper.graphql';
import CsvMapperPopover from '@components/data/csvMapper/CsvMapperPopover';
import {
  CsvMapperLinesPaginationQuery$variables,
} from '@components/data/csvMapper/__generated__/CsvMapperLinesPaginationQuery.graphql';
import { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary?.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
}));

const csvMapperFragment = graphql`
    fragment CsvMapperLine_csvMapper on CsvMapper {
        id
        name
        errors
    }
`;

interface CsvMapperLineProps {
  node: CsvMapperLine_csvMapper$key;
  dataColumns: DataColumns;
  paginationOptions: CsvMapperLinesPaginationQuery$variables;
}

const CsvMapperLine: FunctionComponent<CsvMapperLineProps> = ({
  node,
  dataColumns,
  paginationOptions,
}) => {
  const classes = useStyles();
  const csvMapper = useFragment(csvMapperFragment, node);

  if (!csvMapper) {
    return <ErrorNotFound />;
  }

  return (
        <ListItem key={csvMapper.id} classes={{ root: classes.item }} divider={true}>
            <ListItemIcon classes={{ root: classes.itemIcon }}>
                <TableViewIcon />
            </ListItemIcon>
            <ListItemText
                primary={
                    <div>
                        {Object.values(dataColumns).map((value) => (
                            <div
                                key={value.label}
                                className={classes.bodyItem}
                                style={{ width: value.width }}
                            >
                                {value.render?.(csvMapper)}
                            </div>
                        ))}
                    </div>
                }
            />
            <ListItemSecondaryAction>
                 <CsvMapperPopover
                    csvMapperId={csvMapper.id}
                    paginationOptions={paginationOptions}
                 />
            </ListItemSecondaryAction>
        </ListItem>
  );
};

export default CsvMapperLine;
