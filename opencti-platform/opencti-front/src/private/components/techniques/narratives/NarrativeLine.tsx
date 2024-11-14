import React, { FunctionComponent, CSSProperties } from 'react';
import { Link } from 'react-router-dom';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import Skeleton from '@mui/material/Skeleton';
import { useTheme } from '@mui/material/styles';
import StixCoreObjectLabels from '@components/common/stix_core_objects/StixCoreObjectLabels';
import Tooltip from '@mui/material/Tooltip';
import Checkbox from '@mui/material/Checkbox';
import { graphql, useFragment } from 'react-relay';
import { Theme } from '@mui/material/styles/createTheme';
import { NarrativeLine_node$data, NarrativeLine_node$key } from './__generated__/NarrativeLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilled } from '../../../../utils/String';

interface NarrativeLineProps {
  node: NarrativeLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: HandleAddFilter;
  selectedElements: Record<string, NarrativeLine_node$data>;
  deSelectedElements: Record<string, NarrativeLine_node$data>;
  onToggleEntity: (
    entity: NarrativeLine_node$data,
    event?: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onToggleShiftEntity: (
    index: number,
    entity: NarrativeLine_node$data,
    event?: React.SyntheticEvent
  ) => void;
  index: number;
  redirectionMode: string;
}

export const narrativeLineFragment = graphql`
  fragment NarrativeLine_node on Narrative {
    id
    name
    description
    created
    modified
    entity_type
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
    isSubNarrative
    parentNarratives {
      edges {
        node {
          id
          name
          description
        }
      }
    }
    subNarratives {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

const commonBodyItemStyle: CSSProperties = {
  height: 20,
  fontSize: 13,
  float: 'left',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  paddingRight: 10,
};

const commonTextStyle = (theme: Theme, width?: string | number): CSSProperties => ({
  ...commonBodyItemStyle,
  color: theme.palette.text.primary,
  width,
});

export const NarrativeLine: FunctionComponent<NarrativeLineProps> = ({
  dataColumns,
  node,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleShiftEntity,
  index,
}) => {
  const theme = useTheme();
  const { fd } = useFormatter();
  const data = useFragment(narrativeLineFragment, node);
  return (
    <ListItem
      style={{ paddingLeft: 10, height: 50 }}
      divider={true}
      component={Link}
      to={`/dashboard/techniques/narratives/${data.id}`}
    >
      <ListItemIcon
        style={{ color: theme.palette.primary.main, minWidth: 40 }}
        onClick={(event) => (event.shiftKey
          ? onToggleShiftEntity(index, data, event)
          : onToggleEntity(data, event))
          }
      >
        <Checkbox
          edge="start"
          checked={
            (selectAll && !(data.id in (deSelectedElements || {})))
            || data.id in (selectedElements || {})
          }
          disableRipple={true}
        />
      </ListItemIcon>
      <ListItemIcon style={{ color: theme.palette.primary.main }}>
        <ItemIcon type="Narrative" />
      </ListItemIcon>
      <ListItemText
        primary={
          <>
            <Tooltip title={data.name}>
              <div style={commonTextStyle(theme, dataColumns.name.width)}>
                {data.name}
              </div>
            </Tooltip>
            <div style={commonTextStyle(theme, dataColumns.description.width)}>
              {emptyFilled(data.description)}
            </div>
            <div style={commonTextStyle(theme, dataColumns.objectLabel.width)}>
              <StixCoreObjectLabels
                variant="inList"
                labels={data.objectLabel}
                onClick={onLabelClick}
              />
            </div>
            <div style={commonTextStyle(theme, dataColumns.created.width)}>
              {fd(data.created)}
            </div>
            <div style={commonTextStyle(theme, dataColumns.modified.width)}>
              {fd(data.modified)}
            </div>
          </>
            }
      />
      <ListItemIcon style={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined />
      </ListItemIcon>
    </ListItem>
  );
};

export const NarrativeLineDummy = ({
  dataColumns,
}: {
  dataColumns: DataColumns;
}) => {
  const theme = useTheme();

  return (
    <ListItem style={{ paddingLeft: 10, height: 50 }} divider={true}>
      <ListItemIcon style={{ color: theme.palette.primary.main }}>
        <Skeleton
          animation="wave"
          variant="circular"
          width={30}
          height={30}
        />
      </ListItemIcon>
      <ListItemText
        primary={
          <>
            <div style={commonTextStyle(theme, dataColumns.name.width)}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div style={commonTextStyle(theme, dataColumns.description.width)}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div style={commonTextStyle(theme, dataColumns.objectLabel.width)}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
            <div style={commonTextStyle(theme, dataColumns.created.width)}>
              <Skeleton
                animation="wave"
                variant="rectangular"
                width="90%"
                height="100%"
              />
            </div>
          </>
        }
      />
      <ListItemIcon style={{ position: 'absolute', right: -10 }}>
        <KeyboardArrowRightOutlined color="disabled" />
      </ListItemIcon>
    </ListItem>
  );
};
