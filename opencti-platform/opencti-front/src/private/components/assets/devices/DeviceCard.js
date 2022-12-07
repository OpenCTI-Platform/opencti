/* eslint-disable */
/* refactor */
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
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import CyioCoreObjectLabels from '../../common/stix_core_objects/CyioCoreObjectLabels';

const styles = (theme) => ({
  card: {
    width: '100%',
    height: '319px',
    borderRadius: 9,
    border: `1.5px solid ${theme.palette.dataView.border}`,
  },
  selectedItem: {
    width: '100%',
    height: '319px',
    borderRadius: 9,
    border: `1.5px solid ${theme.palette.dataView.selectedBorder}`,
    background: theme.palette.dataView.selectedBackgroundColor,
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
});

class DeviceCardComponent extends Component {
  render() {
    const {
      t,
      classes,
      node,
      selectAll,
      onToggleEntity,
      onLabelClick,
      selectedElements,
    } = this.props;
    const operatingSystem = node.installed_operating_system?.vendor_name?.toLowerCase();
    return (
      <Card 
        classes={{
          root: (selectAll || node.id in (selectedElements || {}))
            ? classes.selectedItem : classes.card,
        }}
        raised={true}
        elevation={3}
      >
        <CardActionArea
          classes={{ root: classes.area }}
          component={Link}
          to={`/defender HQ/assets/devices/${node.id}`}
          data-cy='device card'
        >
          {/* <CardHeader
            classes={{ root: classes.header }}
            avatar={
              <Avatar className={classes.avatar}>{node.name.charAt(0)}</Avatar>
            }
            title={node.name}
            subheader={`${t('Updated the')} ${fsd(node.modified)}`}
            action={
              <IconButton
                size="small"
                onClick={
                  bookmarksIds.includes(node.id)
                    ? deleteBookMark.bind(this, node.id, 'Threat-Actor')
                    : addBookmark.bind(this, node.id, 'Threat-Actor')
                }
                color={bookmarksIds.includes(node.id) ? 'secondary' : 'primary'}
                style={{ marginTop: 10 }}
              >
                <StarBorderOutlined />
              </IconButton>
            }
          /> */}
          <CardContent className={classes.content}>
            {/* <div>
              <Typography
                variant="h3"
                gutterBottom={true}
              >
                {t('Type')}
              </Typography>
              <ComputerIcon />
            </div>
            <div className={classes.description}>
              <Markdown
                remarkPlugins={[remarkGfm, remarkParse]}
                parserOptions={{ commonmark: true }}
                disallowedTypes={['link', 'linkReference']}
                unwrapDisallowed={true}
              >
                {node.description}
              </Markdown>
            </div> */}
            <Grid item={true} className={classes.header}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Type')}
                </Typography>
                {node.asset_type
                  && <ItemIcon type={node.asset_type}/>}
              </div>
              <div style={{ marginRight: 'auto', marginLeft: '12px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Name')}
                </Typography>
                <Typography>
                  {/* {t('KK-HWELL-011')} */}
                  {node.name && t(node.name)}
                </Typography>
              </div>
              <div>
                <Checkbox
                  disableRipple={true}
                  onClick={onToggleEntity.bind(this, node)}
                  checked={selectAll || node.id in (selectedElements || {})}
                  color='primary'
                />
              </div>
            </Grid>
            <Grid xs={12} container={true} >
              <Grid item={true} xs={6} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom ={true}>
                  {t('Asset ID')}
                </Typography>
                <Typography>
                  {/* {t('KK-HWELL-011')} */}
                  {node.asset_id && truncate(t(node.asset_id), 25)}
                </Typography>
                <div className="clearfix" />
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('FQDN')}
                </Typography>
                <Typography>
                  {node.fqdn && truncate(t(node.fqdn), 25)}
                </Typography>
              </Grid>
              <Grid xs={6} item={true} className={classes.body}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom ={true}>
                  {t('IP Address')}
                </Typography>
                <Typography>
                  {node.ipv4_address
                    && node.ipv4_address.map((ipv4Address) => (
                      <>
                        <div className="clearfix" />
                        {ipv4Address.ip_address_value && t(ipv4Address.ip_address_value)}
                      </>
                    ))}
                </Typography>
                <div className="clearfix" />
                <Typography
                  variant="h3"
                  color="textSecondary"
                  style={{ marginTop: '13px' }}
                  gutterBottom={true}
                >
                  {t('Network ID')}
                </Typography>
                <Typography>
                  {node.network_id && t(node.network_id)}
                </Typography>
              </Grid>
              <Grid>
                <div>
                  <Typography
                    variant="h3"
                    color="textSecondary"
                    gutterBottom ={true}>
                    {t('Operating System')}
                  </Typography>
                  <div>
                    {node?.installed_operating_system?.name && node?.installed_operating_system?.vendor_name
                      && <div>
                        <Typography style={{ display: 'flex', alignItems: 'center' }}>
                        <ItemIcon variant='inline' type={operatingSystem === 'microsoft' || operatingSystem === 'apple' ||  operatingSystem === 'linux' ? operatingSystem : 'other'}/>&nbsp;&nbsp;
                          {t(node.installed_operating_system.name)}
                        </Typography>
                      </div>}
                  </div>
                </div>
              </Grid>
            </Grid>
            <div className={classes.objectLabel}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom ={true}>
                {t('Label')}
              </Typography>
              <CyioCoreObjectLabels
                labels={node.labels}
                onClick={onLabelClick.bind(this)}
              />
              {/* <StixCoreObjectLabels
                labels={node.labels}
                onClick={onLabelClick.bind(this)}
              /> */}
            </div>
          </CardContent>
        </CardActionArea>
      </Card>
    );
  }
}

DeviceCardComponent.propTypes = {
  node: PropTypes.object,
  bookmarksIds: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  onLabelClick: PropTypes.func,
  onBookmarkClick: PropTypes.func,
};

const DeviceCardFragment = createFragmentContainer(
  DeviceCardComponent,
  {
    node: graphql`
      fragment DeviceCard_node on HardwareAsset {
        id
        name
        asset_id
        ipv4_address{
          ip_address_value
        }
        installed_operating_system {
          name
          vendor_name
        }
        asset_type
        fqdn
        labels {
          __typename
          id
          name
          color
          entity_type
          description
        }
        external_references {
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
        notes {
          __typename
          id
          # created
          # modified
          entity_type
          abstract
          content
          authors
        }
        network_id
      }
    `,
  },
);

export const DeviceCard = compose(
  inject18n,
  withStyles(styles),
)(DeviceCardFragment);

class DeviceCardDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <Card classes={{ root: classes.cardDummy }} raised={true} elevation={3}>
        <CardActionArea classes={{ root: classes.area }}>
          <CardHeader
            classes={{ root: classes.header }}
            avatar={
              <Skeleton
                animation="wave"
                variant="circle"
                width={30}
                height={30}
              />
            }
            title={
              <Skeleton
                animation="wave"
                variant="rect"
                width="90%"
                style={{ marginBottom: 10 }}
              />
            }
            titleTypographyProps={{ color: 'inherit' }}
            subheader={
              <Skeleton
                animation="wave"
                variant="rect"
                width="90%"
                style={{ marginBottom: 10 }}
              />
            }
            action={
              <Skeleton
                animation="wave"
                variant="circle"
                width={30}
                height={30}
              />
            }
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

DeviceCardDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const DeviceCardDummy = compose(
  inject18n,
  withStyles(styles),
)(DeviceCardDummyComponent);
