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
} from '@material-ui/core';
import CardActionArea from '@material-ui/core/CardActionArea';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import Skeleton from '@material-ui/lab/Skeleton';
import inject18n from '../../../../../components/i18n';
import CyioCoreObjectLabels from '../../../common/stix_core_objects/CyioCoreObjectLabels';
import EntitiesPartiesPopover from './EntitiesPartiesPopover';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: '319px',
    borderRadius: 9,
    border: '1.5px solid #1F2842',
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
});

class EntityPartyCardComponent extends Component {
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
      <Card
        classes={{ root: classes.card }}
        raised={true}
        elevation={3}
        style={{
          background: (selectAll || node.id in (selectedElements || {})) && 'linear-gradient(0deg, rgba(0, 0, 0, 0.5), rgba(0, 0, 0, 0.5)), #075AD3',
          border: (selectAll || node.id in (selectedElements || {})) && '1.5px solid #075AD3',
        }}
      >
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          TouchRippleProps={this.state.openMenu && { classes: { root: classes.buttonRipple } }}
          to={`/data/entities/parties/${node?.id}`}
        >
          <CardContent className={classes.content}>
            <Grid
              item={true}
              className={classes.header}
            >
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Type')}
                </Typography>
                {node.party_type && t(node.party_type)}
              </div>
              <Grid
                item={true}
                onClick={(event) => event.preventDefault()}
                style={{ display: 'flex' }}
              >
                <EntitiesPartiesPopover
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
            <Grid container={true} >
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}>
                  {t('Name')}
                </Typography>
                <Typography>
                  {node?.name && node?.name}
                </Typography>
              </Grid>
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Creation Date')}
                </Typography>
                <Typography>
                  {node.created && fsd(node.created)}
                </Typography>
              </Grid>
            </Grid>
            <Grid container={true} >
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Marking')}
                </Typography>
                <Typography>
                  {/* {node?.parent_types
                    && (node?.parent_types)} */}
                </Typography>
              </Grid>
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Author')}
                </Typography>
                <Typography>
                  {t(node?.name)}
                </Typography>
              </Grid>
            </Grid>
            <Grid container={true} >
              <Grid item={true} xs={12} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Labels')}
                </Typography>
                <CyioCoreObjectLabels
                  labels={node.labels}
                  onClick={onLabelClick.bind(this)}
                />
              </Grid>
            </Grid>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

EntityPartyCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  fsd: PropTypes.func,
  onLabelClick: PropTypes.func,
  onBookmarkClick: PropTypes.func,
};

const EntityPartyCardFragment = createFragmentContainer(
  EntityPartyCardComponent,
  {
    node: graphql`
      fragment EntityPartyCard_node on OscalParty {
        __typename
        id
        name
        party_type
        created
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
        links {
          __typename
          id
          source_name
          description
          entity_type
          url
          hashes {
            value
          }
          external_id
        }
        remarks {
          __typename
          id
          entity_type
          abstract
          content
          authors
        }
      }
    `,
  },
);

export const EntityPartyCard = compose(
  inject18n,
  withStyles(styles),
)(EntityPartyCardFragment);

class EntityPartyCardDummyComponent extends Component {
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
        </CardActionArea>
      </Card>
    );
  }
}

EntityPartyCardDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const EntityPartyCardDummy = compose(
  inject18n,
  withStyles(styles),
)(EntityPartyCardDummyComponent);
