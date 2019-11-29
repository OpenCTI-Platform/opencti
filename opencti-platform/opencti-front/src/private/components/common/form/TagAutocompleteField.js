import React, { Component } from 'react';
import { Field } from 'formik';
import {
  compose, pathOr, pipe, map, union,
} from 'ramda';
import { fetchQuery } from '../../../../relay/environment';
import Autocomplete from '../../../../components/Autocomplete';
import inject18n from '../../../../components/i18n';
import { tagsSearchQuery } from '../../settings/Tags';


class TagAutocompleteField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      tags: [],
    };
  }

  searchTags(event) {
    fetchQuery(tagsSearchQuery, {
      search: event.target.value,
    }).then((data) => {
      const tags = pipe(
        pathOr([], ['tags', 'edges']),
        map((n) => ({ label: `${n.node.tag_type}:${n.node.value}`, value: n.node.id })),
      )(data);
      this.setState({
        tags: union(
          this.state.tags,
          tags,
        ),
      });
    });
  }

  render() {
    const { t, name } = this.props;
    return (
      <Field
      name={name || 'tags'}
      component={Autocomplete}
      multiple={true}
      label={t('Tag')}
      options={this.state.tags}
      onInputChange={this.searchTags.bind(this)}
      />
    );
  }
}

export default compose(inject18n)(TagAutocompleteField);
