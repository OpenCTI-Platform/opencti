import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { Formik, Form, Field } from 'formik';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import { toastGenericError } from '../../../../utils/bakedToast';
import SystemImplementationField from '../../common/form/SystemImplementationField';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '824px',
    margin: '10px 0 0 0',
    padding: '24px 24px 32px 24px',
    borderRadius: 6,
    maxHeight: '824px',
  },
  textBase: {
    display: 'flex',
    alignItems: 'center',
    marginBottom: 5,
  },
  impactContainer: {
    minWidth: '50px',
    display: 'flex',
    flexDirection: 'row',
  },
  impactTitle: {
    marginRight: '30px',
    minWidth: '30%',
  },
  impactContent: {
    minWidth: '10%',
  },
  impactText: {
    marginLeft: '10px',
  },
});

const systemImplementationAttachMutation = graphql`
  mutation SystemImplementationAttachMutation(
    $id: ID!,
    $entityId: ID!,
    $implementation_type: ImplementationType!,
    
  ) {
    addInformationSystemImplementationEntity(id: $id, entityId: $entityId, implementation_type: $implementation_type)
  }
`;

const systemImplementationRemoveMutation = graphql`
  mutation SystemImplementationRemoveMutation(
    $id: ID!,
    $entityId: ID!,
    $implementation_type: ImplementationType!,
    
  ) {
    removeInformationSystemImplementationEntity(id: $id, entityId: $entityId, implementation_type: $implementation_type)
  }
`;

class SystemImplementationComponent extends Component {
  onSubmit(name, output) {
    commitMutation({
      mutation: systemImplementationAttachMutation,
      variables: {
        id: this.props.informationSystem.id,
        entityId: output,
        implementation_type: name,
      },
      pathname: '/defender_hq/assets/information_systems',
      onCompleted: () => {
        this.props.refreshQuery();
      },
      onError: () => {
        toastGenericError(`Failed to add ${name}`);
      },
    });
  }

  onDelete(name, output) {
    commitMutation({
      mutation: systemImplementationRemoveMutation,
      variables: {
        id: this.props.informationSystem.id,
        entityId: output,
        implementation_type: name,
      },
      pathname: '/defender_hq/assets/information_systems',
      onCompleted: () => {
        this.props.refreshQuery();
      },
      onError: () => {
        toastGenericError(`Failed to delete ${name}`);
      },
    });
  }

  render() {
    const {
      t, classes, informationSystem,
    } = this.props;
    const systemImplementation = R.pathOr([], ['system_implementation'], informationSystem);
    return (
      <>
        <Grid item={true} xs={12}>
          <div className={classes.textBase}>
            <Typography
              variant='h3'
              color='textSecondary'
              gutterBottom={true}
              style={{ margin: 0 }}
            >
              {t('System Implementation')}
            </Typography>
            <Tooltip title={t('Identifies a description of the logical flow of information within the system and across its boundaries, optionally supplemented by diagrams that illustrate these flows.')}>
              <Information
                style={{ marginLeft: '5px' }}
                fontSize='inherit'
                color='disabled'
              />
            </Tooltip>
          </div>
        </Grid>
        <Grid item={true} xs={6}>
          <SystemImplementationField
            variant='outlined'
            title='Inventory Items'
            name='inventory_item'
            fullWidth={true}
            style={{ height: '38.09px' }}
            containerstyle={{ width: '100%' }}
            data={systemImplementation?.inventory_items || []}
            helperText={'Indicateds Inventory Items on this entity.'}
            onSubmit={this.onSubmit.bind(this)}
            onDelete={this.onDelete.bind(this)}

          />
        </Grid>
        <Grid item={true} xs={6}>
          <SystemImplementationField
            variant='outlined'
            title='Components'
            name='component'
            fullWidth={true}
            style={{ height: '38.09px' }}
            containerstyle={{ width: '100%' }}
            data={systemImplementation?.components || []}
            helperText={'Indicateds Components on this entity.'}
            onSubmit={this.onSubmit.bind(this)}
            onDelete={this.onDelete.bind(this)}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <SystemImplementationField
            variant='outlined'
            title='Leveraged Authorizations'
            name='leveraged_authorization'
            fullWidth={true}
            style={{ height: '38.09px' }}
            containerstyle={{ width: '100%' }}
            data={systemImplementation?.leveraged_authorizations || []}
            helperText={'Indicateds Leveraged Authorizations on this entity.'}
            onSubmit={this.onSubmit.bind(this)}
            onDelete={this.onDelete.bind(this)}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <SystemImplementationField
            variant='outlined'
            title='User Types'
            name='user_type'
            fullWidth={true}
            style={{ height: '38.09px' }}
            containerstyle={{ width: '100%' }}
            data={systemImplementation?.users || []}
            helperText={'Indicateds User Types on this entity.'}
            onSubmit={this.onSubmit.bind(this)}
            onDelete={this.onDelete.bind(this)}
          />
        </Grid>
      </>
    );
  }
}

SystemImplementationComponent.propTypes = {
  informationSystem: PropTypes.object,
  refreshQuery: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const SystemImplementation = createFragmentContainer(SystemImplementationComponent, {
  informationSystem: graphql`
    fragment SystemImplementation_information on InformationSystem {
      id
      system_implementation {
        components {
          id
          name
        }
        inventory_items {
          id
          name
        }
        leveraged_authorizations {
          id
          title
        }
        users {
          id
          name
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(SystemImplementation);
