/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as R from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import * as Yup from 'yup';
import { Formik, Form, Field } from 'formik';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import RiskDetails from './RiskDetails';
import RiskEdition from './RiskEdition';
import RiskPopover from './RiskPopover';
import RiskDeletion from './RiskDeletion';
import CyioDomainObjectHeader from '../../common/stix_domain_objects/CyioDomainObjectHeader';
import CyioCoreObjectOrCyioCoreRelationshipNotes from '../../analysis/notes/CyioCoreObjectOrCyioCoreRelationshipNotes';
import RiskOverview from './RiskOverview';
import { commitMutation } from '../../../../relay/environment';
import CyioCoreObjectExternalReferences from '../../analysis/external_references/CyioCoreObjectExternalReferences';
import RiskObservation from './RiskObservation';
import { adaptFieldValue } from '../../../../utils/String';

const styles = () => ({
  container: {
    marginBottom: 50,
  },
  gridContainer: {
    marginBottom: 10,
    height: '70%',
  },
  bottomGrid: {
    height: '30%'
  }
});

export const riskEditMutation = graphql`
  mutation RiskEditMutation($id: ID!, $input: [EditInput]!) {
    editRisk(id: $id, input: $input) {
      id
      statement
      deadline
      risk_status
      accepted
      false_positive
      risk_adjusted
      vendor_dependency
      justification
    }
  }
`;

const RiskValidation = () => Yup.object().shape({
  statement: Yup.string().nullable(),
  risk_status: Yup.string().nullable(),
  deadline: Yup.string().nullable(),
  false_positive: Yup.string().nullable(),
  risk_adjusted: Yup.string().nullable(),
  vendor_dependency: Yup.string().nullable(),
  accepted: Yup.string().nullable(),
});

class RiskComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      displayEdit: false,
      open: false,
      modelName: '',
    };
  }

  handleDisplayEdit() {
    this.setState({ displayEdit: !this.state.displayEdit });
  }

  handleOpenNewCreation() {
    this.props.history.push({
      pathname: '/activities/risk_assessment/risks',
      openNewCreation: true,
    });
  }

  handleEditOpen(field) {
    this.setState({ open: !this.state.open, modelName: field });
  }

  handleSubmitField(name, value) {
    RiskValidation(this.props.t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          mutation: riskEditMutation,
          variables: { id: this.props.risk.id, input: { key: name, value } },
          onCompleted: () => {
            this.setState({ modelName: '', open: false });
          },
        });
      })
      .catch(() => false);
  }

  submitJustification(values, { setSubmitting }) {
    const adaptedValues = R.evolve(
      {
        justification: () => values.justification !== "" ? [values.justification] : [this.props.risk.justification],
      },
      values,
    );
    const finalValues = R.pipe(
      R.toPairs,
      R.map((n) => {

          if(n[0] === "justification" && values.justification === "") {
            return {
            'key': n[0],
            'value': [this.props.risk.justification],
            'operation': 'remove',
            }
          }
          return {
            'key': n[0],
            'value': adaptFieldValue(n[1]),
          }
        }
      ),
    )(adaptedValues)
    commitMutation({
      mutation: riskEditMutation,
      variables: { 
        id: this.props.risk.id, 
        input: finalValues,
         
      },
      onCompleted: () => {
        this.setState({ modelName: '', open: false });
      },
    });
  }

  render() {
    const {
      classes,
      risk,
      history,
      location,
      refreshQuery,
    } = this.props;
    const {
     open,
     modelName
    } = this.state;
    const initialValues = R.pipe(
      R.assoc('deadline', risk?.deadline || ''),
      R.assoc('statement', risk?.statement || ''),
      R.assoc('risk_status', risk?.risk_status || ''),
      R.assoc('vendor_dependency', risk?.vendor_dependency || false),
      R.assoc('risk_adjusted', risk?.risk_adjusted || false),
      R.assoc('false_positive', risk?.false_positive || false),
      R.assoc('accepted', risk?.accepted),
      R.pick([
        'deadline',
        'statement',
        'risk_status',
        'vendor_dependency',
        'false_positive',
        'risk_adjusted',
        'accepted',
      ]),
    )(risk);
    return (
      <>
        {!this.state.displayEdit && !location.openEdit ? (
          <Formik
            enableReinitialize={true}
            initialValues={initialValues}
          >
            <Form>
            <div className={classes.container}>
            <CyioDomainObjectHeader
              disabled={true}
              name={risk.name}
              history={history}
              cyioDomainObject={risk}
              PopoverComponent={<RiskPopover />}
              OperationsComponent={<RiskDeletion />}
              goBack='/activities/risk_assessment/risks'
              handleDisplayEdit={this.handleDisplayEdit.bind(this)}
              handleOpenNewCreation={this.handleOpenNewCreation.bind(this)}
            />
            <Grid
              container={true}
              spacing={3}
              classes={{ container: classes.gridContainer }}
            >
              <Grid item={true} xs={6}>
                <RiskOverview 
                  risk={risk} 
                  refreshQuery={refreshQuery}
                  handleSubmitField={this.handleSubmitField.bind(this)} 
                  handleEditOpen={this.handleEditOpen.bind(this)}
                  submitJustification={this.submitJustification.bind(this)}
                  open={open}
                  modelName={modelName}  
                 />
              </Grid>
              <Grid item={true} xs={6}>
                <RiskDetails 
                  risk={risk} 
                  history={history}
                  handleSubmitField={this.handleSubmitField.bind(this)} 
                  handleEditOpen={this.handleEditOpen.bind(this)}
                  open={open}
                  modelName={modelName}
                />
                <RiskObservation risk={risk} history={history}/>
              </Grid>
            </Grid>
            <Grid
              container={true}
              spacing={3}
              className={classes.bottomGrid}
            >
              <Grid item={true} xs={6}>
                <CyioCoreObjectExternalReferences
                  typename={risk.__typename}
                  fieldName='links'
                  externalReferences={risk.links}
                  cyioCoreObjectId={risk.id}
                  refreshQuery={refreshQuery}
                />
              </Grid>
              <Grid item={true} xs={6}>
                {/* <StixCoreObjectLatestHistory cyioCoreObjectId={risk.id} /> */}
                <CyioCoreObjectOrCyioCoreRelationshipNotes
                  typename={risk.__typename}
                  fieldName='remarks'
                  notes={risk.remarks}
                  cyioCoreObjectOrCyioCoreRelationshipId={risk.id}
                  marginTop='0px'
                  refreshQuery={refreshQuery}
                />
              </Grid>
            </Grid>
            {/* <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <RiskEdition riskId={risk.id} />
              </Security> */}
          </div>
            </Form>
          </Formik>
          
        ) : (
          // <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <RiskEdition
            open={this.state.openEdit}
            riskId={risk.id}
            history={history}
          />
          // </Security>
        )}
      </>
    );
  }
}

RiskComponent.propTypes = {
  risk: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  refreshQuery: PropTypes.func,
};

const Risk = createFragmentContainer(RiskComponent, {
  risk: graphql`
    fragment Risk_risk on Risk {
      __typename
      id
      name
      statement
      risk_status
      deadline
      false_positive
      risk_adjusted
      accepted
      vendor_dependency
      justification
      links {
        __typename
        id
        # created
        # modified
        external_id     # external id
        source_name     # Title
        description     # description
        url             # URL
        media_type      # Media Type
        entity_type
      }
      remarks {
        __typename
        id
        abstract
        content
        authors
        entity_type
      }
      ...RiskOverview_risk
      ...RiskDetails_risk
    }
  `,
});

export default R.compose(inject18n, withStyles(styles))(Risk);
