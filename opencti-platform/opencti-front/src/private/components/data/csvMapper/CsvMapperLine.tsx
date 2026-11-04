import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { styled } from '@mui/material/styles';
import { graphql, useFragment } from 'react-relay';
import TableViewIcon from '@mui/icons-material/TableView';
import { CsvMapperLine_csvMapper$key } from '@components/data/csvMapper/__generated__/CsvMapperLine_csvMapper.graphql';
import CsvMapperPopover from '@components/data/csvMapper/CsvMapperPopover';
import { csvMappers_MappersQuery$variables } from '@components/data/csvMapper/__generated__/csvMappers_MappersQuery.graphql';
import { DataColumns } from '../../../../components/list_lines';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

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
  paginationOptions: csvMappers_MappersQuery$variables;
}

const CsvMapperLine: FunctionComponent<CsvMapperLineProps> = ({
  node,
  dataColumns,
  paginationOptions,
}) => {
  const csvMapper = useFragment(csvMapperFragment, node);

  if (!csvMapper) {
    return <ErrorNotFound />;
  }

  return (
    <ListItem
      key={csvMapper.id}
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={(
        <CsvMapperPopover
          csvMapperId={csvMapper.id}
          paginationOptions={paginationOptions}
        />
      )}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
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
                {value.render?.(csvMapper)}
              </BodyItem>
            ))}
          </div>
        )}
      />
    </ListItem>
  );
};

export default CsvMapperLine;
