import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ContainerHeader from '../../common/containers/ContainerHeader';
import ReportKnowledgeGraph, {
  reportKnowledgeGraphQuery,
} from './ReportKnowledgeGraph';
import Loader from '../../../../components/Loader';
import ReportPopover from './ReportPopover';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
  },
});

class ReportKnowledgeComponent extends Component {
  render() {
    const { classes, report } = this.props;
    return (
      <div className={classes.container}>
        <ContainerHeader
          container={report}
          PopoverComponent={<ReportPopover />}
        />
        <QueryRenderer
          query={reportKnowledgeGraphQuery}
          variables={{ id: report.id }}
          render={({ props }) => {
            if (props && props.report) {
              return <ReportKnowledgeGraph report={props.report} />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

ReportKnowledgeComponent.propTypes = {
  report: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const ReportKnowledge = createFragmentContainer(ReportKnowledgeComponent, {
  report: graphql`
    fragment ReportKnowledge_report on Report {
      id
      editContext {
        name
        focusOn
      }
      ...ContainerHeader_container
    }
  `,
});

export default compose(inject18n, withStyles(styles))(ReportKnowledge);
