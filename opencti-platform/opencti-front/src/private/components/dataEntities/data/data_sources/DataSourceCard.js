import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import {
  Card,
  Typography,
  Grid,
  Checkbox,
  Chip,
  Button,
  CardActions,
} from '@material-ui/core';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../../components/i18n';
import CyioCoreObjectLabels from '../../../common/stix_core_objects/CyioCoreObjectLabels';
import DataSourcesPopover from './DataSourcesPopover';
import resetIcon from '../../../../../resources/images/dataSources/resetIcon.svg';
import clearAllIcon from '../../../../../resources/images/dataSources/clearAllIcon.svg';
import startIcon from '../../../../../resources/images/dataSources/startIcon.svg';
import stopIcon from '../../../../../resources/images/dataSources/stopIcon.svg';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: '319px',
    borderRadius: 9,
  },
  cardDummy: {
    width: '100%',
    height: '319px',
    color: theme.palette.grey[700],
    borderRadius: 9,
  },
  avatar: {
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    backgroundColor: theme.palette.grey[600],
  },
  area: {
    width: '100%',
    height: '100%',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: '13px',
  },
  body: {
    marginBottom: '13px',
  },
  content: {
    width: '100%',
    padding: '24px',
  },
  description: {
    height: 170,
    overflow: 'hidden',
  },
  objectLabel: {
    height: 45,
    paddingTop: 7,
  },
  contentDummy: {
    width: '100%',
    height: 120,
    overflow: 'hidden',
    marginTop: 15,
  },
  placeholderHeader: {
    display: 'inline-block',
    height: '.8em',
    backgroundColor: theme.palette.grey[700],
  },
  placeholderHeaderDark: {
    display: 'inline-block',
    height: '.8em',
    backgroundColor: theme.palette.grey[800],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  buttonRipple: {
    opacity: 0,
  },
  headerDummy: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  chip: { borderRadius: '4px' },
  btnIcons: {
    minHeight: '2rem',
    minWidth: '2.5rem',
    margin: '0.8em 1em 1em 0',
  },
  iconContainer: {
    display: 'flex',
  },
});

class DataSourceCardComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      openMenu: false,
    };
  }

  handleOpenMenu(isOpen) {
    this.setState({ openMenu: isOpen });
  }

  render() {
    const {
      t,
      fsd,
      classes,
      node,
      selectAll,
      history,
      onToggleEntity,
      onLabelClick,
      selectedElements,
    } = this.props;
    return (
      <Card classes={{ root: classes.card }} raised={true} elevation={3}>
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          style={{ background: (selectAll || node.id in (selectedElements || {})) && '#075AD3' }}
          TouchRippleProps={this.state.openMenu && { classes: { root: classes.buttonRipple } }}
          to={`/data/data source/${node?.id}`}
        >
          <CardContent className={classes.content}>
            <Grid
              item={true}
              className={classes.header}
            >
              <Grid item xs={6}>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Name')}
                  </Typography>
                  <div className="clearfix" />
                  {node?.name && t(node?.name)}
                </div>
              </Grid>
              <Grid
                item={true}
                onClick={(event) => event.preventDefault()}
                style={{ display: 'flex' }}
              >
                <DataSourcesPopover
                  handleOpenMenu={this.handleOpenMenu.bind(this)}
                  history={history}
                  node={node}
                />
                <Checkbox
                  disableRipple={true}
                  onClick={onToggleEntity.bind(this, node)}
                  checked={selectAll || node.id in (selectedElements || {})}
                  color='primary'
                />
              </Grid>
            </Grid>
            <Grid container={true}>
              <Grid item={true} xs={6} className={classes.body}>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Type')}
                  </Typography>
                  {node.entity_type && t(node.entity_type)}
                </div>
              </Grid>
              <Grid item={true} xs={6} className={classes.body}>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom={true}
                  >
                    {t('Status')}
                  </Typography>
                  <Chip label="ACTIVE" style={{ backgroundColor: 'rgba(64, 204, 77, 0.2)' }} classes={{ root: classes.chip }}/>
                </div>
              </Grid>
            </Grid>
            <Grid container={true}>
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Count')}
                </Typography>
                <Typography>
                  10,000,000
                </Typography>
              </Grid>
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Trigger')}
                </Typography>
                <Chip variant="outlined" label="Automatic" style={{ backgroundColor: 'rgba(64, 204, 77, 0.2)' }} classes={{ root: classes.chip }}/>
              </Grid>
            </Grid>
            <div className={classes.iconContainer}>
              <Button color='primary' variant='contained' className={classes.btnIcons}>
                <img src={startIcon} />
              </Button>
              <Button color='primary' variant='contained' className={classes.btnIcons}>
                <img src={resetIcon} />
              </Button>
              <Button color='primary' variant='contained' className={classes.btnIcons}>
                <img src={clearAllIcon} />
              </Button>
            </div>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

DataSourceCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  classes: PropTypes.object,
  history: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  onLabelClick: PropTypes.func,
  onBookmarkClick: PropTypes.func,
};

const DataSourceCardFragment = createFragmentContainer(
  DataSourceCardComponent,
  {
    node: graphql`
      fragment DataSourceCard_node on DataSource {
        __typename
        id
        entity_type
        description
        name
        created
        modified
      }
    `,
  },
);

export const DataSourceCard = compose(
  inject18n,
  withStyles(styles),
)(DataSourceCardFragment);

class DataSourceCardDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <Card classes={{ root: classes.cardDummy }} raised={true} elevation={3}>
        <CardActionArea classes={{ root: classes.area }}>
          <CardHeader
            classes={{ root: classes.header }}
            title={
              <div className={classes.headerDummy}>
                <Skeleton
                  animation="wave"
                  variant="circle"
                  width={30}
                  height={30}
                />
                <div style={{ width: '100%', padding: '0px 20px' }}>
                  <Skeleton
                    animation="wave"
                    variant="rect"
                    width="100%"
                    style={{ marginBottom: 10 }}
                  />
                  <Skeleton
                    animation="wave"
                    variant="rect"
                    width="100%"
                  />
                </div>
                <Skeleton
                  animation="wave"
                  variant="circle"
                  width={30}
                  height={30}
                />
              </div>
            }
            titleTypographyProps={{ color: 'inherit' }}
          />
          <CardContent classes={{ root: classes.contentDummy }}>
            <Skeleton
              animation="wave"
              variant="rect"
              width="90%"
              style={{ marginBottom: 10 }}
            />
            <Skeleton
              animation="wave"
              variant="rect"
              width="95%"
              style={{ marginBottom: 10 }}
            />
            <Skeleton
              animation="wave"
              variant="rect"
              width="90%"
              style={{ marginBottom: 10 }}
            />
          </CardContent>
          <div style={{ width: '100%', padding: '0px 20px' }}>
            <Skeleton
              animation="wave"
              variant="rect"
              width="100%"
              style={{ marginBottom: 10 }}
            />
          </div>
        </CardActionArea>
      </Card>
    );
  }
}

DataSourceCardDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const DataSourceCardDummy = compose(
  inject18n,
  withStyles(styles),
)(DataSourceCardDummyComponent);
