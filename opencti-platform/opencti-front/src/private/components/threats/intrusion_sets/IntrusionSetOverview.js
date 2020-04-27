import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarking from '../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class IntrusionSetOverviewComponent extends Component {
  render() {
    const {
      t, fld, classes, intrusionSet,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {intrusionSet.markingDefinitions.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                />
              ),
              intrusionSet.markingDefinitions.edges,
            )
          ) : (
            <ItemMarking label="TLP:WHITE" />
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creation date')}
          </Typography>
          {fld(intrusionSet.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fld(intrusionSet.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor
            createdByRef={pathOr(null, ['createdByRef', 'node'], intrusionSet)}
          />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            className="markdown"
            source={intrusionSet.description}
            limit={250}
          />
        </Paper>
      </div>
    );
  }
}

IntrusionSetOverviewComponent.propTypes = {
  intrusionSet: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const IntrusionSetOverview = createFragmentContainer(
  IntrusionSetOverviewComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetOverview_intrusionSet on IntrusionSet {
        id
        name
        description
        created
        modified
        markingDefinitions {
          edges {
            node {
              id
              definition
            }
          }
        }
        createdByRef {
          node {
            id
            name
            entity_type
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(IntrusionSetOverview);
