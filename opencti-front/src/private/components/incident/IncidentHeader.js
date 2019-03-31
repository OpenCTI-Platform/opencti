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
import IncidentPopover from './IncidentPopover';
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

const incidentMutation = graphql`
  mutation IncidentHeaderFieldMutation($id: ID!, $input: EditInput!) {
    incidentEdit(id: $id) {
      fieldPatch(input: $input) {
        ...IncidentHeader_incident
      }
    }
  }
`;

class IncidentHeaderComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { openAlias: false };
  }

  handleToggleCreateAlias() {
    this.setState({ openAlias: !this.state.openAlias });
  }

  onSubmitCreateAlias(data) {
    if (
      this.props.incident.alias === null
      || !this.props.incident.alias.includes(data.new_alias)
    ) {
      commitMutation({
        mutation: incidentMutation,
        variables: {
          id: this.props.incident.id,
          input: {
            key: 'alias',
            value: append(data.new_alias, this.props.incident.alias),
          },
        },
      });
    }
    this.handleToggleCreateAlias();
  }

  deleteAlias(alias) {
    const aliases = filter(a => a !== alias, this.props.incident.alias);
    commitMutation({
      mutation: incidentMutation,
      variables: {
        id: this.props.incident.id,
        input: { key: 'alias', value: aliases },
      },
    });
  }

  render() {
    const {
      t, classes, variant, incident,
    } = this.props;
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {incident.name}
        </Typography>
        <div className={classes.popover}>
          <IncidentPopover incidentId={incident.id} />
        </div>
        {variant !== 'noalias' ? (
          <div className={classes.aliases}>
            {propOr([], 'alias', incident).map(label => (label.length > 0 ? (
                <Chip
                  key={label}
                  classes={{ root: classes.alias }}
                  label={label}
                  onDelete={this.deleteAlias.bind(this, label)}
                />
            ) : (
              ''
            )))}
            <IconButton
              color="secondary"
              aria-label="Alias"
              onClick={this.handleToggleCreateAlias.bind(this)}
            >
              {this.state.openAlias ? (
                <Close fontSize="small" />
              ) : (
                <Add fontSize="small" />
              )}
            </IconButton>
            <Slide
              direction="left"
              in={this.state.openAlias}
              mountOnEnter={true}
              unmountOnExit={true}
            >
              <Formik
                initialValues={{ new_alias: '' }}
                onSubmit={this.onSubmitCreateAlias.bind(this)}
                render={() => (
                  <Form style={{ float: 'right' }}>
                    <Field
                      name="new_alias"
                      component={TextField}
                      autoFocus={true}
                      placeholder={t('New alias')}
                      className={classes.aliasInput}
                    />
                  </Form>
                )}
              />
            </Slide>
          </div>
        ) : (
          ''
        )}
        <div className="clearfix" />
      </div>
    );
  }
}

IncidentHeaderComponent.propTypes = {
  incident: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IncidentHeader = createFragmentContainer(IncidentHeaderComponent, {
  incident: graphql`
    fragment IncidentHeader_incident on Incident {
      id
      name
      alias
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(IncidentHeader);
