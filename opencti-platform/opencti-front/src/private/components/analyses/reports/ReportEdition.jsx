import React from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import { commitMutation, QueryRenderer } from '../../../../relay/environment';
import ReportEditionContainer from './ReportEditionContainer';
import { reportEditionOverviewFocus } from './ReportEditionOverview';
import Loader from '../../../../components/Loader';

export const reportEditionQuery = graphql`
  query ReportEditionContainerQuery($id: String!) {
    report(id: $id) {
      ...ReportEditionContainer_report
    }
  }
`;

const ReportEdition = (props) => {
  const handleClose = () => {
    commitMutation({
      mutation: reportEditionOverviewFocus,
      variables: {
        id: props.reportId,
        input: { focusOn: '' },
      },
    });
  };

  const { reportId } = props;
  return (
    <QueryRenderer
      query={reportEditionQuery}
      variables={{ id: reportId }}
      render={({ props }) => {
        if (props) {
          return (
            <ReportEditionContainer
              report={props.report}
              handleClose={handleClose.bind(this)}
              controlledDial={EditEntityControlledDial}
            />
          );
        }
        return <Loader variant="inline" />;
      }}
    />
  );
};

ReportEdition.propTypes = {
  reportId: PropTypes.string,
  me: PropTypes.object,
  classes: PropTypes.object,
  theme: PropTypes.object,
};

export default ReportEdition;
