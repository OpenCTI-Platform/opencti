import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import { truncate } from '../../../utils/String';
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
    const { classes, report, variant } = this.props;
    return (
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}>
          {truncate(report.name, 80)}
        </Typography>
        <div className={classes.popover}>
          <ReportPopover reportId={report.id} />
        </div>
        {variant !== 'noMarking' ? (
          <div className={classes.marking}>
            {pathOr([], ['markingDefinitions', 'edges'], report).map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                />
              ),
            )}
          </div>
        ) : (
          ''
        )}
        <div className="clearfix" />
      </div>
    );
  }
}

ReportHeaderComponent.propTypes = {
  report: PropTypes.object,
  variant: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const ReportHeader = createFragmentContainer(ReportHeaderComponent, {
  report: graphql`
    fragment ReportHeader_report on Report {
      id
      name
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
