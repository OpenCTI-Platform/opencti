import React, { Component } from 'react';
import {
  compose,
  pathOr,
  pipe,
  map,
  sortWith,
  ascend,
  path,
  union,
  append,
} from 'ramda';
import { Field } from 'formik';
import withStyles from '@mui/styles/withStyles';
import { LanguageOutlined } from '@mui/icons-material';
import { ConnectionHandler } from 'relay-runtime';
import { commitMutation, fetchQuery } from '../../../../relay/environment';
import AutocompleteField from '../../../../components/AutocompleteField';
import inject18n from '../../../../components/i18n';
import { truncate } from '../../../../utils/String';
import { externalReferencesSearchQuery } from '../../analysis/ExternalReferences';
import ExternalReferenceCreation from '../../analysis/external_references/ExternalReferenceCreation';
import { externalReferenceLinesMutationRelationAdd } from '../../analysis/external_references/AddExternalReferencesLines';

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

const sharedUpdater = (store, stixCoreObjectId, newEdge) => {
  const entity = store.get(stixCoreObjectId);
  const conn = ConnectionHandler.getConnection(
    entity,
    'Pagination_externalReferences',
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class ExternalReferencesField extends Component {
  constructor(props) {
    super(props);
    this.state = {
      externalReferenceCreation: false,
      externalReferences: [],
    };
  }

  handleOpenExternalReferenceCreation() {
    this.setState({ externalReferenceCreation: true });
  }

  handleCloseExternalReferenceCreation() {
    this.setState({ externalReferenceCreation: false });
  }

  searchExternalReferences(event) {
    let filters = [];
    if (this.props.id) {
      filters = [{ key: 'usedBy', values: [this.props.id] }];
    }
    fetchQuery(externalReferencesSearchQuery, {
      search: event && event.target.value,
      filters,
    })
      .toPromise()
      .then((data) => {
        const externalReferences = pipe(
          pathOr([], ['externalReferences', 'edges']),
          sortWith([ascend(path(['node', 'source_name']))]),
          map((n) => ({
            label: `[${n.node.source_name}] ${truncate(
              n.node.description || n.node.url || n.node.external_id,
              150,
            )}`,
            value: n.node.id,
          })),
        )(data);
        this.setState({
          externalReferences: union(
            this.state.externalReferences,
            externalReferences,
          ),
        });
      });
  }

  render() {
    const {
      t,
      name,
      style,
      classes,
      onChange,
      setFieldValue,
      values,
      helpertext,
      noStoreUpdate,
      id,
    } = this.props;
    return (
      <div>
        <Field
          component={AutocompleteField}
          style={style}
          name={name}
          multiple={true}
          textfieldprops={{
            variant: 'standard',
            label: t('External references'),
            helperText: helpertext,
            onFocus: this.searchExternalReferences.bind(this),
          }}
          noOptionsText={t('No available options')}
          options={this.state.externalReferences}
          onInputChange={this.searchExternalReferences.bind(this)}
          openCreate={this.handleOpenExternalReferenceCreation.bind(this)}
          onChange={typeof onChange === 'function' ? onChange.bind(this) : null}
          renderOption={(props, option) => (
            <li {...props}>
              <div className={classes.icon} style={{ color: option.color }}>
                <LanguageOutlined />
              </div>
              <div className={classes.text}>{option.label}</div>
            </li>
          )}
          classes={{ clearIndicator: classes.autoCompleteIndicator }}
        />
        <ExternalReferenceCreation
          contextual={true}
          display={true}
          open={this.state.externalReferenceCreation}
          handleClose={this.handleCloseExternalReferenceCreation.bind(this)}
          creationCallback={(data) => {
            const newExternalReference = data.externalReferenceAdd;
            if (id) {
              const input = {
                fromId: id,
                relationship_type: 'external-reference',
              };
              commitMutation({
                mutation: externalReferenceLinesMutationRelationAdd,
                variables: {
                  id: newExternalReference.id,
                  input,
                },
                updater: (store) => {
                  if (noStoreUpdate !== true) {
                    const payload = store
                      .getRootField('externalReferenceEdit')
                      .getLinkedRecord('relationAdd', { input });
                    const relationId = payload.getValue('id');
                    const node = payload.getLinkedRecord('to');
                    const relation = store.get(relationId);
                    payload.setLinkedRecord(node, 'node');
                    payload.setLinkedRecord(relation, 'relation');
                    sharedUpdater(store, id, payload);
                  }
                },
              });
            }
            this.setState(
              {
                externalReferences: append(
                  {
                    label: `[${newExternalReference.source_name}] ${truncate(
                      newExternalReference.description
                        || newExternalReference.url
                        || newExternalReference.external_id,
                      150,
                    )}`,
                    value: newExternalReference.id,
                  },
                  this.state.externalReferences,
                ),
              },
              () => setFieldValue(
                name,
                append(
                  {
                    label: `[${newExternalReference.source_name}] ${truncate(
                      newExternalReference.description
                          || newExternalReference.url
                          || newExternalReference.external_id,
                      150,
                    )}`,
                    value: newExternalReference.id,
                  },
                  values || [],
                ),
              ),
            );
          }}
        />
      </div>
    );
  }
}

export default compose(inject18n, withStyles(styles))(ExternalReferencesField);
