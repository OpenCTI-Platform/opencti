/* eslint-disable */
/* refactor */
import React, { Component, useState } from 'react';
import * as R from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import MenuItem from '@material-ui/core/MenuItem';
import graphql from 'babel-plugin-relay/macro';
import Typography from '@material-ui/core/Typography';
import CancelIcon from '@material-ui/icons/Cancel';
import IconButton from '@material-ui/core/IconButton';
import Chip from '@material-ui/core/Chip';
import AddIcon from '@material-ui/icons/Add';
import Tooltip from '@material-ui/core/Tooltip';
import { Information } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import SelectField from '../../../../components/SelectField';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';
import { SubscriptionFocus } from '../../../../components/Subscription';

const styles = (theme) => ({
  chip: {
    margin: '0 7px 7px 0',
    color: theme.palette.header.text,
    backgroundColor: theme.palette.header.background,
  },
  importButton: {
    position: 'absolute',
    top: 30,
    right: 30,
  },
  deleteIcon: {
    color: theme.palette.header.text,
  },
});

const SourceActorTypeQuery = graphql`
  query SourceActorTypeQuery {
    __type(name: "ActorType") {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;

const SourceOscalPartiesQuery = graphql`
  query SourceOscalPartiesQuery {
    oscalParties {
      edges {
        node {
          name
          description
        }
      }
    }
  }
`;

class Source extends Component {
  constructor(props) {
    super(props);
    this.state = {
      actorTypeList: [],
      oscalPartiesList: [],
    };
  }

  componentDidMount() {
    {
      this.props.type === 'actorTarget' &&
        fetchDarklightQuery(SourceActorTypeQuery)
          .toPromise()
          .then((data) => {
            const actorTypeEntities = R.pipe(
              R.pathOr([], ['__type', 'enumValues']),
              R.map((n) => ({
                label: n.description,
                value: n.name,
              }))
            )(data);
            this.setState({
              actorTypeList: {
                ...this.state.entities,
                actorTypeEntities,
              },
            });
          });
    }
    {
      this.props.type === 'oscalParties' &&
        fetchDarklightQuery(SourceOscalPartiesQuery)
          .toPromise()
          .then((data) => {
            const oscalPartiesEntities = R.pipe(
              R.pathOr([], ['oscalParties', 'edges']),
              R.map((n) => ({
                label: n.node.description,
                value: n.node.name,
              }))
            )(data);
            this.setState({
              oscalPartiesList: {
                ...this.state.entities,
                oscalPartiesEntities,
              },
            });
          });
    }
  }

  renderActorTarget() {
    const {
      t,
      name,
      size,
      label,
      style,
      variant,
      onChange,
      onFocus,
      containerstyle,
      editContext,
      disabled,
      helperText,
    } = this.props;
    const actorTypeList = R.pathOr(
      [],
      ['actorTypeEntities'],
      this.state.actorTypeList
    );
    return (
      <div>
        <div className='clearfix' />
        <Field
          component={SelectField}
          name={name}
          label={label}
          fullWidth={true}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          {actorTypeList.map(
            (et, key) =>
              et.label && (
                <Tooltip title={et.label} value={et.value} key={et.label}>
                  <MenuItem value={et.value}>{et.value}</MenuItem>
                </Tooltip>
              )
          )}
        </Field>
      </div>
    );
  }

  renderOscalParties() {
    const {
      t,
      name,
      size,
      label,
      style,
      variant,
      onChange,
      onFocus,
      containerstyle,
      editContext,
      disabled,
      helperText,
    } = this.props;

    const oscalPartiesList = R.pathOr(
      [],
      ['oscalPartiesEntities'],
      this.state.oscalPartiesList
    );
    return (
      <div>
        <div className='clearfix' />
        <Field
          component={SelectField}
          name={name}
          label={label}
          fullWidth={true}
          containerstyle={containerstyle}
          variant={variant}
          disabled={disabled || false}
          size={size}
          style={style}
          helperText={helperText}
        >
          {oscalPartiesList.map(
            (et, key) =>
              et.label && (
                <Tooltip title={et.label} value={et.value} key={et.label}>
                  <MenuItem value={et.value}>{et.value}</MenuItem>
                </Tooltip>
              )
          )}
        </Field>
      </div>
    );
  }

  render() {
    if (this.props.type === 'actorTarget') {
      return this.renderActorTarget();
    }
    if (this.props.type === 'oscalParties') {
      return this.renderOscalParties();
    }
    return <></>;
  }
}

// export default inject18n(Source);
export default R.compose(inject18n, withStyles(styles))(Source);
