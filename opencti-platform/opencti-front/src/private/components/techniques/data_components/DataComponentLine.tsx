import React, { FunctionComponent } from 'react';
import { Link } from 'react-router-dom';
import makeStyles from '@mui/styles/makeStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRight, SourceOutlined } from '@mui/icons-material';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { DataComponentLine_node$key } from './__generated__/DataComponentLine_node.graphql';
import { Theme } from '../../../../components/Theme';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import { DataColumns } from '../../../../components/list_lines';

const useStyles = makeStyles<Theme>((theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 5,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey?.[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey?.[700],
  },
}));

interface DataComponentLineProps {
  node: DataComponentLine_node$key;
  dataColumns: DataColumns;
  onLabelClick: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent
  ) => void;
}

const dataComponentFragment = graphql`
  fragment DataComponentLine_node on DataComponent {
    id
    name
    description
    created
    modified
    objectLabel {
      edges {
        node {
          id
          value
          color
        }
      }
    }
  }
`;

const DataComponentLine: FunctionComponent<DataComponentLineProps> = ({
  dataColumns,
  node,
  onLabelClick,
}) => {
  const classes = useStyles();
  const { fd } = useFormatter();

  const data = useFragment(dataComponentFragment, node);

  return (
    <ListItem
      classes={{ root: classes.item }}
      divider={true}
      button={true}
      component={Link}
      to={`/dashboard/techniques/data_components/${data.id}`}
    >
      <ListItemIcon classes={{ root: classes.itemIcon }}>
        <SourceOutlined />
      </ListItemIcon>
      <ListItemText
        primary={
          <div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.name.width }}
            >
              {data.name}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.objectLabel.width }}
            >
              <StixCoreObjectLabels
                variant="inList"
                labels={data.objectLabel}
                onClick={onLabelClick}
              />
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.created.width }}
            >
              {fd(data.created)}
            </div>
            <div
              className={classes.bodyItem}
              style={{ width: dataColumns.modified?.width }}
            >
              {fd(data.modified)}
            </div>
          </div>
        }
      />
      <ListItemIcon classes={{ root: classes.goIcon }}>
        <KeyboardArrowRight />
      </ListItemIcon>
    </ListItem>
  );
};

export default DataComponentLine;
