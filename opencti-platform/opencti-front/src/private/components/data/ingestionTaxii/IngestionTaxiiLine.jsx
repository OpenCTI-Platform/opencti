import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import { AccessPoint } from 'mdi-material-ui';
import { compose } from 'ramda';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import IngestionTaxiiPopover from './IngestionTaxiiPopover';
import inject18n from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import Security from '../../../../utils/Security';
import { INGESTION_SETINGESTIONS } from '../../../../utils/hooks/useGranted';
import ItemCopy from '../../../../components/ItemCopy';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
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
    paddingRight: 10,
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  filter: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    marginRight: 7,
    borderRadius: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    height: 20,
    marginRight: 10,
  },
});

class IngestionTaxiiLineLineComponent extends Component {
  render() {
    const { classes, node, dataColumns, paginationOptions, t, fldt } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <AccessPoint />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.uri.width }}
              >
                {node.uri}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.ingestion_running.width }}
              >
                <ItemBoolean
                  variant="inList"
                  label={node.ingestion_running ? t('Active') : t('Inactive')}
                  status={!!node.ingestion_running}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_execution_date.width }}
              >
                {fldt(node.last_execution_date) || '-'}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.added_after_start.width }}
              >
                <ItemCopy content={node.added_after_start || '-'} variant="inLine" />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.current_state_cursor.width }}
              >
                <ItemCopy content={node.current_state_cursor || '-'} variant="inLine" />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <Security needs={[INGESTION_SETINGESTIONS]}>
            <IngestionTaxiiPopover
              ingestionTaxiiId={node.id}
              paginationOptions={paginationOptions}
              running={node.ingestion_running}
            />
          </Security>
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

IngestionTaxiiLineLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  fldt: PropTypes.func,
};

const IngestionTaxiiLineFragment = createFragmentContainer(
  IngestionTaxiiLineLineComponent,
  {
    node: graphql`
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
    `,
  },
);

export const IngestionTaxiiLine = compose(
  inject18n,
  withStyles(styles),
)(IngestionTaxiiLineFragment);

class IngestionTaxiiDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.uri.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.ingestion_running.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_execution_date.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.added_after_start.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={100}
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.current_state_cursor.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={100}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVert />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

IngestionTaxiiDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const IngestionTaxiiLineDummy = compose(
  inject18n,
  withStyles(styles),
)(IngestionTaxiiDummyComponent);
