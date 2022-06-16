/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { Grid, Switch, Chip } from '@material-ui/core';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { hexToRGB } from '../../../../../utils/Colors';
import { truncate } from '../../../../../utils/String';
import inject18n from '../../../../../components/i18n';
import CyioCoreObjectLabelsView from '../../../common/stix_core_objects/CyioCoreObjectLabelsView';
const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
  },
  link: {
    textAlign: 'left',
    fontSize: '16px',
    font: 'DIN Next LT Pro',
  },
  chip: {
    color: theme.palette.header.text,
    height: 25,
    fontSize: 12,
    padding: '14px 12px',
    margin: '0 7px 7px 0',
    backgroundColor: theme.palette.header.background,
  },
  scrollBg: {
    background: theme.palette.header.background,
    width: '100%',
    color: 'white',
    padding: '10px 5px 10px 15px',
    borderRadius: '5px',
    lineHeight: '20px',
  },
  scrollDiv: {
    width: '100%',
    background: theme.palette.header.background,
    height: '223px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
  markingText: {
    background: theme.palette.header.text,
    color: 'black',
    width: '100px',
    textAlign: 'center',
    padding: '3px 0',
  }
});

class EntityLabelDetailsComponent extends Component {
  render() {
    const {
      t,
      classes,
      refreshQuery,
      label,
      fldt,
      history,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Basic Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={3}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Name')}
                </Typography>
                <div className="clearfix" />
                {label.name && t(label.name)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Created')}
                </Typography>
                <div className="clearfix" />
                {label.created && fldt(label.created)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Color')}
                </Typography>
                <div className="clearfix" />
                <Chip
                  variant="outlined"
                  label={truncate(label.name, 10)}
                  style={{
                    color: label.color,
                    borderColor: label.color,
                    backgroundColor: hexToRGB(label.color),
                  }}
                />
              </div>
            </Grid>
            <Grid item={true} xs={4}>
              <div>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('ID')}
                </Typography>
                <div className="clearfix" />
                {label.id && t(label.id)}
              </div>
              <div style={{ marginTop: '20px' }}>
                <Typography
                  variant="h3"
                  color="textSecondary"
                  gutterBottom={true}
                >
                  {t('Last Modified')}
                </Typography>
                <div className="clearfix" />
                {label.modified && fldt(label.modified)}
              </div>
            </Grid>
            <Grid item={true} xs={4}>
              <Typography
                variant="h3"
                color="textSecondary"
                gutterBottom={true}
              >
                {t('Description')}
              </Typography>
              <div className="clearfix" />
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    <Markdown
                      remarkPlugins={[remarkGfm, remarkParse]}
                      parserOptions={{ commonmark: true }}
                      className="markdown"
                    >
                      {label.description && t(label.description)}
                    </Markdown>
                  </div>
                </div>
              </div>
            </Grid>
          </Grid>
        </Paper>
      </div>
    );
  }
}

EntityLabelDetailsComponent.propTypes = {
  label: PropTypes.object,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const EntityLabelDetails = createFragmentContainer(
  EntityLabelDetailsComponent,
  {
    label: graphql`
      fragment EntityLabelDetails_label on CyioLabel {
        __typename
        id
        name
        color
        created
        modified
        description
        standard_id
        entity_type
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(EntityLabelDetails);
