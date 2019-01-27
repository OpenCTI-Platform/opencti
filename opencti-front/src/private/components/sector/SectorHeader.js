import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Formik, Field, Form } from 'formik';
import {
  compose, propOr, filter, append,
} from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import Typography from '@material-ui/core/Typography';
import IconButton from '@material-ui/core/IconButton';
import Slide from '@material-ui/core/Slide';
import { Add, Close } from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import TextField from '../../../components/TextField';
import SectorPopover from './SectorPopover';
import { commitMutation } from '../../../relay/environment';

const styles = () => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  aliases: {
    float: 'right',
    overflowX: 'hidden',
    marginTop: '-5px',
  },
  alias: {
    marginRight: 7,
  },
  aliasInput: {
    margin: '4px 0 0 10px',
    float: 'right',
  },
});

const sectorMutation = graphql`
    mutation SectorHeaderFieldMutation($id: ID!, $input: EditInput!) {
        sectorEdit(id: $id) {
            fieldPatch(input: $input) {
                ...SectorHeader_sector
            }
        }
    }
`;

class SectorHeaderComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { openAlias: false };
  }

  handleToggleCreateAlias() {
    this.setState({ openAlias: !this.state.openAlias });
  }

  onSubmitCreateAlias(data) {
    if (this.props.sector.stix_label === null
      || !this.props.sector.stix_label.includes(data.new_alias)) {
      commitMutation({
        mutation: sectorMutation,
        variables: {
          id: this.props.sector.id,
          input: { key: 'stix_label', value: append(data.new_alias, this.props.sector.stix_label) },
        },
      });
    }
    this.handleToggleCreateAlias();
  }

  deleteAlias(alias) {
    const aliases = filter(a => a !== alias, this.props.sector.stix_label);
    commitMutation({
      mutation: sectorMutation,
      variables: {
        id: this.props.sector.id,
        input: { key: 'stix_label', value: aliases },
      },
    });
  }

  render() {
    const {
      t, classes, variant, sector,
    } = this.props;
    return (
      <div>
        <Typography variant='h1' gutterBottom={true} classes={{ root: classes.title }}>
          {sector.name}
        </Typography>
        <div className={classes.popover}>
          <SectorPopover sectorId={sector.id}/>
        </div>
        {variant !== 'noalias'
          ? <div className={classes.aliases}>
            {propOr([], 'stix_label', sector).map(label => (label.length > 0 ? <Chip key={label} classes={{ root: classes.alias }} label={label} onDelete={this.deleteAlias.bind(this, label)}/> : ''))}
            <IconButton color='secondary' aria-label='Alias' onClick={this.handleToggleCreateAlias.bind(this)}>
              {this.state.openAlias ? <Close fontSize='small'/> : <Add fontSize='small'/>}
            </IconButton>
            <Slide direction='left' in={this.state.openAlias} mountOnEnter={true} unmountOnExit={true}>
              <Formik
                initialValues={{ new_alias: '' }}
                onSubmit={this.onSubmitCreateAlias.bind(this)}
                render={() => (
                  <Form style={{ float: 'right' }}>
                    <Field name='new_alias' component={TextField} placeholder={t('New alias')} className={classes.aliasInput}/>
                  </Form>
                )}
              />
            </Slide>
          </div> : ''
        }
        <div className='clearfix'/>
      </div>
    );
  }
}

SectorHeaderComponent.propTypes = {
  sector: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const SectorHeader = createFragmentContainer(SectorHeaderComponent, {
  sector: graphql`
      fragment SectorHeader_sector on Sector {
          id,
          name,
          stix_label,
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(SectorHeader);
