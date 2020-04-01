import React, { Component } from 'react';
import {
  compose, pathOr, pipe, map, union, append,
} from 'ramda';
import { Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import { Tag } from 'mdi-material-ui';
import { fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import { tagsSearchQuery } from '../../settings/Tags';
import TagCreation from '../../settings/tags/TagCreation';

const styles = () => ({
  icon: {
    paddingTop: 4,
    display: 'inline-block',
  },
  text: {
    display: 'inline-block',
    flexGrow: 1,
    marginLeft: 10,
  },
  autoCompleteIndicator: {
    display: 'none',
  },
});

class TagsField extends Component {
  constructor(props) {
    super(props);
    this.state = { tagCreation: false, tagInput: '', tags: [] };
  }

  handleOpenTagCreation() {
    this.setState({ tagCreation: true });
  }

  handleCloseTagCreation() {
    this.setState({ tagCreation: false });
  }

  searchTags(event) {
    this.setState({
      tagInput: event && event.target.value !== 0 ? event.target.value : '',
    });
    fetchQuery(tagsSearchQuery, {
      search: event && event.target.value !== 0 ? event.target.value : '',
    }).then((data) => {
      const tags = pipe(
        pathOr([], ['tags', 'edges']),
        map((n) => ({ label: n.node.value, value: n.node.id, color: n.node.color })),
      )(data);
      this.setState({
        tags: union(this.state.tags, tags),
      });
    });
  }

  render() {
    const {
      t,
      name,
      style,
      classes,
      setFieldValue,
      values,
      helpertext,
    } = this.props;
    return (
      <div>
        <Field
          component={AutocompleteField}
          style={style}
          name={name}
          multiple={true}
          textfieldprops={{
            label: t('Tags'),
            helperText: helpertext,
            onFocus: this.searchTags.bind(this),
          }}
          noOptionsText={t('No available options')}
          options={this.state.tags}
          onInputChange={this.searchTags.bind(this)}
          openCreate={this.handleOpenTagCreation.bind(this)}
          renderOption={(option) => (
            <React.Fragment>
              <div className={classes.icon} style={{ color: option.color }}>
                <Tag />
              </div>
              <div className={classes.text}>{option.label}</div>
            </React.Fragment>
          )}
          classes={{ clearIndicator: classes.autoCompleteIndicator }}
        />
        <TagCreation
          contextual={true}
          inputValue={this.state.tagInput}
          open={this.state.tagCreation}
          handleClose={this.handleCloseTagCreation.bind(this)}
          creationCallback={(data) => {
            setFieldValue(
              name,
              append(
                {
                  label: data.tagAdd.value,
                  value: data.tagAdd.id,
                },
                values,
              ),
            );
          }}
        />
      </div>
    );
  }
}

export default compose(inject18n, withStyles(styles))(TagsField);
