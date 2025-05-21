import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment } from 'react-relay';
import TableViewIcon from '@mui/icons-material/TableView';
import JsonMapperPopover from '@components/data/jsonMapper/JsonMapperPopover';
import { JsonMapperLine_jsonMapper$key } from '@components/data/jsonMapper/__generated__/JsonMapperLine_jsonMapper.graphql';
import { jsonMappers_MappersQuery$variables } from '@components/data/jsonMapper/__generated__/jsonMappers_MappersQuery.graphql';
import type { Theme } from '../../../../components/Theme';
import { DataColumns } from '../../../../components/list_lines';
import ErrorNotFound from '../../../../components/ErrorNotFound';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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

const jsonMapperFragment = graphql`
  fragment JsonMapperLine_jsonMapper on JsonMapper {
    id
    name
    errors
  }
`;

interface JsonMapperLineProps {
  node: JsonMapperLine_jsonMapper$key;
  dataColumns: DataColumns;
  paginationOptions: jsonMappers_MappersQuery$variables;
}

const JsonMapperLine: FunctionComponent<JsonMapperLineProps> = ({
  node,
  dataColumns,
  paginationOptions,
}) => {
  const classes = useStyles();
  const jsonMapper = useFragment(jsonMapperFragment, node);

  if (!jsonMapper) {
    return <ErrorNotFound />;
  }

  return (
    <ListItem
      key={jsonMapper.id}
      classes={{ root: classes.item }}
      divider={true}
      secondaryAction={
        <JsonMapperPopover
          jsonMapperId={jsonMapper.id}
          paginationOptions={paginationOptions}
        />
      }
    >
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
                {value.render?.(jsonMapper)}
              </div>
            ))}
          </div>
        }
      />
    </ListItem>
  );
};

export default JsonMapperLine;
