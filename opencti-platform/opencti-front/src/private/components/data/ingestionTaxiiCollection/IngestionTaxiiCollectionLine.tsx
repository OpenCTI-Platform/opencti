import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { MoreVert } from '@mui/icons-material';
import { AccessPoint } from 'mdi-material-ui';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { IngestionTaxiiCollectionLine_node$key } from '@components/data/ingestionTaxiiCollection/__generated__/IngestionTaxiiCollectionLine_node.graphql';
import {
  IngestionTaxiiCollectionLinesPaginationQuery$variables,
} from '@components/data/ingestionTaxiiCollection/__generated__/IngestionTaxiiCollectionLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import Security from '../../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import ItemCopy from '../../../../components/ItemCopy';
import { DataColumns } from '../../../../components/list_lines';
import IngestionTaxiiCollectionPopover from './IngestionTaxiiCollectionPopover';
import { APP_BASE_PATH } from '../../../../relay/environment';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { bodyItemStyle } from '../../../../components/list_lines/listLineStyles';

const BodyItem = styled('div')(bodyItemStyle);

interface IngestionTaxiiCollectionLineProps {
  node: IngestionTaxiiCollectionLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  paginationOptions?: IngestionTaxiiCollectionLinesPaginationQuery$variables;
}

const ingestionTaxiiCollectionLineFragment = graphql`
    fragment IngestionTaxiiCollectionLine_node on IngestionTaxiiCollection {
        id
        name
        description
        ingestion_running
    }
`;

export const IngestionTaxiiCollectionLineLineComponent: FunctionComponent<IngestionTaxiiCollectionLineProps> = ({
  dataColumns,
  node,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const data = useFragment(ingestionTaxiiCollectionLineFragment, node);

  return (
    <ListItem
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      secondaryAction={(
        <Security needs={[INGESTION_SETINGESTIONS]}>
          <IngestionTaxiiCollectionPopover
            ingestionTaxiiId={data.id}
            paginationOptions={paginationOptions}
            running={data.ingestion_running}
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
              style={{ width: dataColumns.id.width, paddingRight: 10 }}
            >
              <ItemCopy content={`${window.location.origin}${APP_BASE_PATH}/taxii2/root/collections/${data.id}/objects/`} variant="inLine" />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.ingestion_running.width }}
            >
              <ItemBoolean
                label={data.ingestion_running ? t_i18n('Active') : t_i18n('Inactive')}
                status={!!data.ingestion_running}
              />
            </BodyItem>
          </div>
        )}
      />
    </ListItem>
  );
};

export const IngestionTaxiiCollectionLineDummy = ({ dataColumns }: { dataColumns: DataColumns }) => {
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
            <BodyItem style={{ width: dataColumns.name.width }}>
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
          </div>
        )}
      />
    </ListItem>
  );
};
