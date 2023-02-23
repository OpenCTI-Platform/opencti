/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
  map,
  pipe,
  pathOr,
  compose,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import { withStyles } from '@material-ui/core/styles/index';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import Typography from '@material-ui/core/Typography';
import { Information } from 'mdi-material-ui';
import DialogTitle from '@material-ui/core/DialogTitle';
import Tooltip from '@material-ui/core/Tooltip';
import Dialog from '@material-ui/core/Dialog';
import DialogActions from '@material-ui/core/DialogActions';
import DialogContent from '@material-ui/core/DialogContent';
import inject18n from '../../../../components/i18n';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';

const styles = (theme) => ({
  dialogTitle: {
    padding: '24px 0 16px 24px',
  },
  dialogContent: {
    padding: '0 24px',
    marginBottom: '24px',
    overflowY: 'auto',
    overflowX: 'hidden',
    minHeight: '550px',
  },
  dialogClosebutton: {
    float: 'left',
    marginLeft: '15px',
    marginBottom: '20px',
  },
  dialogActions: {
    justifyContent: 'flex-start',
    padding: '10px 0 20px 22px',
  },
  buttonPopover: {
    textTransform: 'capitalize',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
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
    height: '78px',
    overflow: 'hidden',
    overflowY: 'scroll',
  },
  scrollObj: {
    display: 'grid',
    gridTemplateColumns: '40% 1fr',
    color: theme.palette.header.text,
    fontFamily: 'sans-serif',
    padding: '0px',
    textAlign: 'left',
  },
});

class AuthorizationBoundaryComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      close: false,
    };
  }

  render() {
    const {
      t,
      classes,
      refreshQuery,
      informationSystem,
    } = this.props;
    const diagramData = pipe(
      pathOr([], ['authorization_boundary', 'diagrams']),
      map((n) => ({
        caption: n.caption,
        diagram_link: n.diagram_link,
      })),
    )(informationSystem);
    return (
      <Dialog
        open={this.props.openView}
        keepMounted={false}
      >
        <DialogTitle classes={{ root: classes.dialogTitle }}>
          {t('Authorization Boundary')}
        </DialogTitle>
        <DialogContent classes={{ root: classes.dialogContent }}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <Typography>
                {t("Identifies a description of this system's authorization boundary, optionally supplemented by diagrams that illustrate the authorization boundary.")}
              </Typography>
            </Grid>
            <Grid item={true} xs={12}>
              <div className={classes.textBase}>
                <Typography
                  variant='h3'
                  color='textSecondary'
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Description')}
                </Typography>
                <Tooltip title={t('Description')}>
                  <Information
                    style={{ marginLeft: '5px' }}
                    fontSize='inherit'
                    color='disabled'
                  />
                </Tooltip>
              </div>
              <div className='clearfix' />
              <Typography>
                {informationSystem.authorization_boundary && t(informationSystem.authorization_boundary.description)}
              </Typography>
            </Grid>
            <Grid item={true} xs={12}>
              <div className={classes.textBase}>
                <Typography
                  variant='h3'
                  color='textSecondary'
                  gutterBottom={true}
                  style={{ margin: 0 }}
                >
                  {t('Diagram(s)')}
                </Typography>
                <Tooltip title={t('Diagram(s)')}>
                  <Information
                    style={{ marginLeft: '5px' }}
                    fontSize='inherit'
                    color='disabled'
                  />
                </Tooltip>
              </div>
              <div className='clearfix' />
              <div style={{ display: 'grid', gridTemplateColumns: '40% 1fr', padding: '10px' }}>
                <Typography>
                  Caption
                </Typography>
                <Typography>
                  Diagram Link
                </Typography>
              </div>
              <div className={classes.scrollBg}>
                <div className={classes.scrollDiv}>
                  <div className={classes.scrollObj}>
                    {diagramData.length && diagramData.map((diagram) => (
                      <>
                        <Typography variant='h3' color='inherit'>
                          {diagram.caption && t(diagram.caption)}
                        </Typography>
                        <Typography variant='h3' color='inherit'>
                          {diagram.diagram_link && t(diagram.diagram_link)}
                        </Typography>
                      </>
                    ))}
                  </div>
                </div>
              </div>
            </Grid>
            <Grid item={true} xs={12}>
              <CyioCoreObjectExternalReferences
                externalReferences={informationSystem.links}
                cyioCoreObjectId={informationSystem.id}
                fieldName='links'
                refreshQuery={refreshQuery}
                typename={informationSystem.__typename}
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions classes={{ root: classes.dialogClosebutton }}>
          <Button
            variant='outlined'
            onClick={this.props.handleCloseView}
            classes={{ root: classes.buttonPopover }}
          >
            {t('Cancel')}
          </Button>
        </DialogActions>
      </Dialog>
    );
  }
}

AuthorizationBoundaryComponent.propTypes = {
  t: PropTypes.func,
  fldt: PropTypes.func,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  informationSystem: PropTypes.object,
};

const AuthorizationBoundaryPopover = createFragmentContainer(AuthorizationBoundaryComponent, {
  informationSystem: graphql`
    fragment AuthorizationBoundaryPopover_information on InformationSystem {
      __typename
      id
       authorization_boundary {
        id
        entity_type
        description
        diagrams {
          id
          entity_type
          created
          modified
          description
          caption
          diagram_link
        }
        links {
          id
          entity_type
          created
          modified
          source_name
          description
          url
          external_id
          reference_purpose
          media_type
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(AuthorizationBoundaryPopover);
