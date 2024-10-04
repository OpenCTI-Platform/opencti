import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const styles = (theme) => ({
  paper: {
    marginTop: theme.spacing(1),
    padding: '15px',
    borderRadius: 4,
  },
});

class PositionOverviewComponent extends Component {
  render() {
    const { t, fldt, classes, position } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Typography variant="h3" gutterBottom={true}>
            {t('Original creation date')}
          </Typography>
          {fldt(position.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(position.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', position)} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown source={position.description} limit={400} />
        </Paper>
      </div>
    );
  }
}

PositionOverviewComponent.propTypes = {
  position: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const PositionOverview = createFragmentContainer(PositionOverviewComponent, {
  position: graphql`
    fragment PositionOverview_position on Position {
      id
      name
      description
      created
      modified
      createdBy {
        ... on Identity {
          id
          name
          entity_type
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(PositionOverview);
