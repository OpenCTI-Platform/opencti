import { styled } from '@mui/material/styles';
import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent, ReactNode, useState } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import Tooltip from '@mui/material/Tooltip';
import { MoreVert } from '@mui/icons-material';
import IngestionCsvPopover from '@components/data/ingestionCsv/IngestionCsvPopover';
import { IngestionCsvLinesPaginationQuery$variables } from '@components/data/ingestionCsv/__generated__/IngestionCsvLinesPaginationQuery.graphql';
import { IngestionCsvLine_node$key } from '@components/data/ingestionCsv/__generated__/IngestionCsvLine_node.graphql';
import TableViewIcon from '@mui/icons-material/TableView';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface IngestionCsvLineProps {
  node: IngestionCsvLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  paginationOptions?: IngestionCsvLinesPaginationQuery$variables;
}

const ingestionCsvLineFragment = graphql`
  fragment IngestionCsvLine_node on IngestionCsv {
    id
    name
    uri
    ingestion_running
    current_state_hash
    last_execution_date
  }
`;

interface CellProps {
  width: number | string | undefined;
  children: ReactNode;
  withTooltip?: boolean;
}
const Cell = ({ width, children, withTooltip = true }: CellProps) => {
  return withTooltip ? (
    <Tooltip title={children}>
      <BodyItem style={{ width }}>
        {children}
      </BodyItem>
    </Tooltip>
  ) : (
    <BodyItem style={{ width }}>
      {children}
    </BodyItem>
  );
};

export const IngestionCsvLineComponent: FunctionComponent<IngestionCsvLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const { t_i18n, fldt } = useFormatter();
  const data = useFragment(ingestionCsvLineFragment, node);
  const [stateHash, setStateHash] = useState(data.current_state_hash ? data.current_state_hash : EMPTY_VALUE);
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={(
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <IngestionCsvPopover
            ingestionCsvId={data.id}
            paginationOptions={paginationOptions}
            running={data.ingestion_running}
            setStateHash={setStateHash}
          />
        </Security>
      )}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <TableViewIcon />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <Cell width={dataColumns.name.width}>
              {data.name}
            </Cell>
            <Cell width={dataColumns.uri.width}>
              {data.uri}
            </Cell>
            <Cell width={dataColumns.ingestion_running.width} withTooltip={false}>
              <ItemBoolean
                label={data.ingestion_running ? t_i18n('Active') : t_i18n('Inactive')}
                status={!!data.ingestion_running}
              />
            </Cell>
            <Cell width={dataColumns.last_execution_date.width}>
              {fldt(data.last_execution_date) || EMPTY_VALUE}
            </Cell>
            <Cell width={dataColumns.current_state_hash.width}>
              {stateHash}
            </Cell>
          </div>
        )}
      />
    </ListItem>
  );
};

export const IngestionCsvLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={<MoreVert />}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.uri.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.ingestion_running.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.current_state_hash.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={100}
                height="100%"
              />
            </BodyItem>
            <BodyItem>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={100}
                height="100%"
              />
            </BodyItem>
          </div>
        )}
      />
    </ListItem>
  );
};
