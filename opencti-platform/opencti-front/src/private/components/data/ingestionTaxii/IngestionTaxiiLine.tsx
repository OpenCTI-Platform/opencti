import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import { AccessPoint } from 'mdi-material-ui';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { IngestionTaxiiLine_node$key } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiLine_node.graphql';
import { IngestionTaxiiLinesPaginationQuery$variables } from '@components/data/ingestionTaxii/__generated__/IngestionTaxiiLinesPaginationQuery.graphql';
import IngestionTaxiiPopover from './IngestionTaxiiPopover';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import Security from '../../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import ItemCopy from '../../../../components/ItemCopy';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { EMPTY_VALUE } from '../../../../utils/String';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface IngestionTaxiiLineProps {
  node: IngestionTaxiiLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  paginationOptions?: IngestionTaxiiLinesPaginationQuery$variables;
}

const ingestionTaxiiLineFragment = graphql`
    fragment IngestionTaxiiLine_node on IngestionTaxii {
        id
        name
        description
        uri
        version
        ingestion_running
        added_after_start
        current_state_cursor
        last_execution_date
        confidence_to_score
    }
`;

export const IngestionTaxiiLineLineComponent: FunctionComponent<IngestionTaxiiLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const { t_i18n, fldt } = useFormatter();
  const data = useFragment(ingestionTaxiiLineFragment, node);
  const [stateValue, setStateValue] = useState(data.current_state_cursor ? data.current_state_cursor : EMPTY_VALUE);
  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={(
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <IngestionTaxiiPopover
            ingestionTaxiiId={data.id}
            paginationOptions={paginationOptions}
            running={data.ingestion_running}
            setStateValue={setStateValue}
          />
        </Security>
      )}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <AccessPoint />
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
              style={{ width: dataColumns.last_execution_date.width }}
            >
              {fldt(data.last_execution_date) || EMPTY_VALUE}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.added_after_start.width }}
            >
              <ItemCopy content={data.added_after_start || EMPTY_VALUE} variant="inLine" />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.current_state_cursor.width }}
            >
              <ItemCopy content={stateValue} variant="inLine" />
            </BodyItem>
          </div>
        )}
      />
    </ListItem>
  );
};

export const IngestionTaxiiLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
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
              style={{ width: dataColumns.last_execution_date.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.added_after_start.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={100}
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.current_state_cursor.width }}
            >
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
