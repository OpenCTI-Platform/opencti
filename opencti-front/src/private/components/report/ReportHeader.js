import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, propOr, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';
import ReportPopover from './ReportPopover';

const styles = () => ({
  title: {
    float: 'left',
    textTransform: 'uppercase',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  marking: {
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

class ReportHeaderComponent extends Component {
  render() {
    const { classes, report } = this.props;
    return (
      <div>
        <Typography variant='h1' gutterBottom={true} classes={{ root: classes.title }}>
          {propOr('-', 'name', report)}
        </Typography>
        <div className={classes.popover}>
          <ReportPopover reportId={propOr('-', 'id', report)}/>
        </div>
        <div className={classes.marking}>
          {pathOr([], ['markingDefinitions', 'edges'], report).map(markingDefinition => <ItemMarking key={markingDefinition.node.id} label={markingDefinition.node.definition}/>)}
        </div>
        <div className='clearfix'/>
      </div>
    );
  }
}

ReportHeaderComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ReportHeader = createFragmentContainer(ReportHeaderComponent, {
  report: graphql`
      fragment ReportHeader_report on Report {
          id,
          name,
          markingDefinitions {
              edges {
                  node {
                      id
                      definition
                  }
              }
          }
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(ReportHeader);
