import React, { FunctionComponent } from 'react';
import { Link } from 'react-router';
import { graphql, useFragment } from 'react-relay';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';
import { IndividualLine_node$key } from '@components/entities/individuals/__generated__/IndividualLine_node.graphql';
import { DraftChip } from '@components/common/draft/DraftChip';
import { ListItemButton } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';

const BodyItem = styled('div')({
  height: 25,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 10,
  display: 'flex',
  alignItems: 'center',
});

interface IndividualLineProps {
  node: IndividualLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
}

const individualLineFragment = graphql`
    fragment IndividualLine_node on Individual {
        id
        name
        created
        modified
        draftVersion {
            draft_id
            draft_operation
        }
        objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
        }
        objectLabel {
            id
            value
            color
        }
    }
`;

export const IndividualLine: FunctionComponent<IndividualLineProps> = ({
  dataColumns,
  node,
  onLabelClick,
}) => {
  const { ftd } = useFormatter();
  const data = useFragment(individualLineFragment, node);
  return (
    <ListItemButton
      sx={{ paddingLeft: '10px', height: 50 }}
      divider={true}
      component={Link}
      to={`/dashboard/entities/individuals/${data.id}`}
    >
      <ListItemIcon sx={{ color: 'primary.main' }}>
        <ItemIcon type="Individual" />
      </ListItemIcon>
      <ListItemText
        primary={(
          <div>
            <BodyItem
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
              {data.draftVersion && (<DraftChip />)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={data.objectLabel}
                onClick={onLabelClick.bind(this)}
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created.width }}
            >
              {ftd(data.created)}
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.modified.width }}
            >
              {ftd(data.modified)}
            </BodyItem>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItemButton>
  );
};

export const IndividualLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  return (
    <ListItem sx={{ paddingLeft: '10px', height: 50 }} divider={true}>
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
              style={{ width: dataColumns.objectLabel.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.created.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </BodyItem>
            <BodyItem
              style={{ width: dataColumns.modified.width }}
            >
              <Skeleton
                animation="wave"
                variant="rectangular"
                width={140}
                height="100%"
              />
            </BodyItem>
          </div>
        )}
      />
      <ListItemIcon sx={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};
