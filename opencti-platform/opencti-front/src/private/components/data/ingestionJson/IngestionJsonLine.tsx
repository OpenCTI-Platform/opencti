import { styled } from '@mui/material/styles';
import { graphql, useFragment } from 'react-relay';
import React, { FunctionComponent } from 'react';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Skeleton from '@mui/material/Skeleton';
import { MoreVert } from '@mui/icons-material';
import IngestionJsonPopover from '@components/data/ingestionJson/IngestionJsonPopover';
import TableViewIcon from '@mui/icons-material/TableView';
import { IngestionJsonLine_node$key } from '@components/data/ingestionJson/__generated__/IngestionJsonLine_node.graphql';
import { IngestionJsonLinesPaginationQuery$variables } from '@components/data/ingestionJson/__generated__/IngestionJsonLinesPaginationQuery.graphql';
import { Link } from 'react-router';
import ItemBoolean from '../../../../components/ItemBoolean';
import { useFormatter } from '../../../../components/i18n';
import { DataColumns } from '../../../../components/list_lines';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface IngestionJsonLineProps {
  node: IngestionJsonLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  paginationOptions?: IngestionJsonLinesPaginationQuery$variables;
}

const ingestionJsonLineFragment = graphql`
  fragment IngestionJsonLine_node on IngestionJson {
    id
    name
    uri
    connector_id
    ingestion_running
    last_execution_date
  }
`;

export const IngestionJsonLineComponent: FunctionComponent<IngestionJsonLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const { t_i18n, fldt } = useFormatter();
  const data = useFragment(ingestionJsonLineFragment, node);
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={(
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <IngestionJsonPopover
            ingestionJsonId={data.id}
            paginationOptions={paginationOptions}
            running={data.ingestion_running}
          />
        </Security>
      )}
    >
      <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
        <TableViewIcon />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.uri.width }}
            >
              {data.uri}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.ingestion_running.width }}
            >
              <ItemBoolean
                label={data.ingestion_running ? t_i18n('Active') : t_i18n('Inactive')}
                status={!!data.ingestion_running}
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.connector.width }}
            >
              {fldt(data.last_execution_date) || EMPTY_VALUE}
            </BodyItem>
            <BodyItem>
              <Link to={`/dashboard/integrations/connectors/${data.connector_id}`}>VIEW</Link>
            </BodyItem>
          </div>
        )}
      />
    </ListItem>
  );
};

export const IngestionJsonLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={<MoreVert />}
    >
      <ListItemIcon sx={{ color: (theme) => theme.palette.primary.main }}>
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
              style={{ width: dataColumns.connector.width }}
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
