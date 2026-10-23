import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { styled } from '@mui/material/styles';
import { graphql, useFragment } from 'react-relay';
import TableViewIcon from '@mui/icons-material/TableView';
import JsonMapperPopover from '@components/data/jsonMapper/JsonMapperPopover';
import { JsonMapperLine_jsonMapper$key } from '@components/data/jsonMapper/__generated__/JsonMapperLine_jsonMapper.graphql';
import { jsonMappers_MappersQuery$variables } from '@components/data/jsonMapper/__generated__/jsonMappers_MappersQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

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
  const jsonMapper = useFragment(jsonMapperFragment, node);

  if (!jsonMapper) {
    return <ErrorNotFound />;
  }

  return (
    <ListItem
      key={jsonMapper.id}
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={(
        <JsonMapperPopover
          jsonMapperId={jsonMapper.id}
          paginationOptions={paginationOptions}
        />
      )}
    >
      <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
        <TableViewIcon />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            {Object.values(dataColumns).map((value) => (
              <BodyItem
                key={value.label}
                style={{ width: value.width }}
              >
                {value.render?.(jsonMapper)}
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};

export default JsonMapperLine;
