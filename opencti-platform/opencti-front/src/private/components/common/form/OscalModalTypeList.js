/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import { Field } from 'formik';
import * as R from 'ramda';
import MenuItem from '@material-ui/core/MenuItem';
import IconButton from '@material-ui/core/IconButton';
import PublishIcon from '@material-ui/icons/Publish';
import { Information } from 'mdi-material-ui';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../../components/i18n';
import SelectField from '../../../../components/SelectField';
import { fetchDarklightQuery } from '../../../../relay/environmentDarkLight';

const OscalModalTypeListQuery = graphql`
  query OscalModalTypeListQuery {
    __type(name: "OscalModelType") {
      name
      description
      enumValues {
        name
        description
      }
    }
  }
`;

class OscalModalTypeList extends Component {
  constructor(props) {
    super(props);
    this.state = {
      OscalModalTypeList: [],
    };
  }

  componentDidMount() {
    fetchDarklightQuery(OscalModalTypeListQuery)
      .toPromise()
      .then((data) => {
        const OscalModalTypeEntities = R.pipe(
          R.pathOr([], ['__type', 'enumValues']),
          R.map((n) => ({
            label: n.description,
            value: n.name,
          }))
        )(data);
        this.setState({
          OscalModalTypeList: {
            ...this.state.entities,
            OscalModalTypeEntities,
          },
        });
      });
  }

  render() {
    const {
      t,
      handleOscalType,
    } = this.props;
    const OscalModalTypeList = R.pathOr(
      [],
      ['OscalModalTypeEntities'],
      this.state.OscalModalTypeList
    );
    return (
      <>
        {OscalModalTypeList.map(
          (et, key) =>
            et.value && (
              <MenuItem
                key={et.value}
                value={et.value}
                onClick={handleOscalType.bind(this, et.value)}
              >
                {et.label}
              </MenuItem>
            )
        )}
      </>
    );
  }
}

export default inject18n(OscalModalTypeList);
