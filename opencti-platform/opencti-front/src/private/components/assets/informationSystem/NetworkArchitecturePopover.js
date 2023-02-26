/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import {
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
import SystemDocumentationDiagram from '../../common/form/SystemDocumentationDiagram';
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
  buttonPopover: {
    textTransform: 'capitalize',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
});

class NetworkArchitecturePopoverComponent extends Component {
  render() {
    const {
      t,
      classes,
      refreshQuery,
      informationSystem,
    } = this.props;
    const networkArchitecture = pathOr([], ['network_architecture'], informationSystem);
    return (
      <Dialog
        open={this.props.openView}
        keepMounted={false}
      >
        <DialogTitle classes={{ root: classes.dialogTitle }}>
          {t('Network Architecture')}
        </DialogTitle>
        <DialogContent classes={{ root: classes.dialogContent }}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={12}>
              <Typography>
                {t("Identifies a description of the system's network architecture, optionally supplemented by diagrams that illustrate the network architecture.")}
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
                {networkArchitecture.description && t(networkArchitecture.description)}
              </Typography>
            </Grid>
            <Grid item={true} xs={12}>
              <SystemDocumentationDiagram
                diagramType='network_architecture'
                title='Diagram(s)'
                id={informationSystem.id}
                name='diagram'
                disabled={true}
              />
            </Grid>
            <Grid item={true} xs={12}>
              <CyioCoreObjectExternalReferences
                externalReferences={networkArchitecture.links}
                cyioCoreObjectId={networkArchitecture.id}
                fieldName='links'
                refreshQuery={refreshQuery}
                typename={networkArchitecture.__typename}
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

NetworkArchitecturePopoverComponent.propTypes = {
  t: PropTypes.func,
  fldt: PropTypes.func,
  classes: PropTypes.object,
  refreshQuery: PropTypes.func,
  informationSystem: PropTypes.object,
};

const AuthorizationBoundaryPopover = createFragmentContainer(NetworkArchitecturePopoverComponent, {
  informationSystem: graphql`
    fragment NetworkArchitecturePopover_information on InformationSystem {
      __typename
      id
      network_architecture {
        id
        entity_type
        description
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
