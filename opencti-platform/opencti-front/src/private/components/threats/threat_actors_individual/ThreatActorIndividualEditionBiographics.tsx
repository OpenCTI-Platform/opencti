import React from 'react';
import * as Yup from 'yup';
import { Form, Formik } from 'formik';
import { graphql, useFragment } from 'react-relay';
import {
  ThreatActorIndividualEditionOverviewFocus,
  ThreatActorIndividualMutationRelationDelete,
  threatActorIndividualRelationAddMutation,
} from '@components/threats/threat_actors_individual/ThreatActorIndividualEditionOverview';
import { GenericContext } from '../../common/model/GenericContextModel';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { HeightFieldEdit } from '../../common/form/HeightField';
import { WeightFieldEdit } from '../../common/form/WeightField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CommitMessage from '../../common/form/CommitMessage';
import { ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key } from './__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';
import OpenVocabField from '../../common/form/OpenVocabField';
import useUserMetric from '../../../../utils/hooks/useUserMetric';
import { useSchemaEditionValidation } from '../../../../utils/hooks/useEntitySettings';
import useFormEditor, { GenericData } from '../../../../utils/hooks/useFormEditor';
import AlertConfidenceForEntity from '../../../../components/AlertConfidenceForEntity';

const threatActorIndividualEditionBiographicsFocus = graphql`
  mutation ThreatActorIndividualEditionBiographicsFocusMutation(
    $id: ID!
    $input: EditContext!
  ) {
    threatActorIndividualContextPatch(id: $id, input: $input) {
      id
    }
  }
`;

const threatActorIndividualMutationFieldPatch = graphql`
  mutation ThreatActorIndividualEditionBiographicsFieldPatchMutation(
    $id: ID!
    $input: [EditInput]!
  ) {
    threatActorIndividualFieldPatch(id: $id, input: $input) {
      ...ThreatActorIndividualEditionBiographics_ThreatActorIndividual
      ...ThreatActorIndividual_ThreatActorIndividual
    }
  }
`;

const threatActorIndividualEditionBiographicsFragment = graphql`
  fragment ThreatActorIndividualEditionBiographics_ThreatActorIndividual on ThreatActorIndividual {
    id
    eye_color
    hair_color
    height {
      index
      date_seen
      measure
    }
    weight {
      index
      date_seen
      measure
    }
    confidence
    entity_type
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
  }
`;

interface ThreatActorIndividualEditionBiographicsComponentProps {
  threatActorIndividualRef: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key;
  enableReferences: boolean;
  context?: readonly (GenericContext | null)[] | null;
}

const ThreatActorIndividualEditionBiographicsComponent: React.FunctionComponent<
ThreatActorIndividualEditionBiographicsComponentProps
> = ({
  threatActorIndividualRef,
  enableReferences,
  context,
}: ThreatActorIndividualEditionBiographicsComponentProps) => {
  const { t_i18n } = useFormatter();
  const { heightsConverterLoad, weightsConverterLoad } = useUserMetric();
  const threatActorIndividual = useFragment(
    threatActorIndividualEditionBiographicsFragment,
    threatActorIndividualRef,
  );

  const basicShape = {
    eye_color: Yup.string()
      .nullable()
      .typeError(t_i18n('The value must be a string')),
    hair_color: Yup.string()
      .nullable()
      .typeError(t_i18n('The value must be a string')),
    weight: Yup.array().of(
      Yup.object().shape({
        measure: Yup.number().required(t_i18n('This field is required')),
        date_seen: Yup.date().required(t_i18n('This field is required'))
          .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
      }),
    ),
    height: Yup.array().of(
      Yup.object().shape({
        measure: Yup.number().required(t_i18n('This field is required')),
        date_seen: Yup.date().required(t_i18n('This field is required'))
          .typeError(t_i18n('The value must be a datetime (yyyy-MM-dd hh:mm (a|p)m)')),
      }),
    ),
  };
  const threatActorIndividualValidator = useSchemaEditionValidation(
    'Threat-Actor-Individual',
    basicShape,
  );

  const queries = {
    fieldPatch: threatActorIndividualMutationFieldPatch,
    relationAdd: threatActorIndividualRelationAddMutation,
    relationDelete: ThreatActorIndividualMutationRelationDelete,
    editionFocus: ThreatActorIndividualEditionOverviewFocus,
  };
  const editor = useFormEditor(
    threatActorIndividual as GenericData,
    enableReferences,
    queries,
    threatActorIndividualValidator,
  );

  const handleChangeFocus = (name: string) => commitMutation({
    ...defaultCommitMutation,
    mutation: threatActorIndividualEditionBiographicsFocus,
    variables: {
      id: threatActorIndividual.id,
      input: {
        focusOn: name,
      },
    },
  });
  const handleSubmitField = (name: string, value: string | string[]) => {
    threatActorIndividualValidator
      .validateAt(name, { [name]: value })
      .then(() => {
        editor.fieldPatch({
          variables: {
            id: threatActorIndividual.id,
            input: { key: name, value },
          },
        });
      })
      .catch(() => false);
  };

  const initialValues = {
    eye_color: threatActorIndividual.eye_color,
    hair_color: threatActorIndividual.hair_color,
    height: heightsConverterLoad(threatActorIndividual.height ?? []),
    weight: weightsConverterLoad(threatActorIndividual.weight ?? []),
  };

  return (
    <div>
      <Formik
        enableReinitialize={true}
        initialValues={initialValues}
        validationSchema={threatActorIndividualValidator}
        onSubmit={() => {}}
      >
        {({
          submitForm,
          isSubmitting,
          setFieldValue,
          values,
          isValid,
          dirty,
        }) => (
          <div>
            <Form style={{ margin: '20px 0 20px 0' }}>
              <AlertConfidenceForEntity entity={threatActorIndividual} />
              <OpenVocabField
                name="eye_color"
                label={t_i18n('Eye Color')}
                type="eye_color_ov"
                variant="edit"
                onChange={(name, value) => setFieldValue(name, value)}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={context}
              />
              <OpenVocabField
                name="hair_color"
                label={t_i18n('Hair Color')}
                type="hair_color_ov"
                variant="edit"
                onChange={(name, value) => setFieldValue(name, value)}
                onFocus={handleChangeFocus}
                onSubmit={handleSubmitField}
                containerStyle={fieldSpacingContainerStyle}
                multiple={false}
                editContext={context}
              />
              <HeightFieldEdit
                name="height"
                values={values.height}
                id={threatActorIndividual.id}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
              />
              <WeightFieldEdit
                name="weight"
                values={values.weight}
                id={threatActorIndividual.id}
                containerStyle={fieldSpacingContainerStyle}
                editContext={context}
              />
              {enableReferences && (
                <CommitMessage
                  submitForm={submitForm}
                  disabled={isSubmitting || !isValid || !dirty}
                  setFieldValue={setFieldValue}
                  open={false}
                  values={[]}
                  id={threatActorIndividual.id}
                />
              )}
            </Form>
          </div>
        )}
      </Formik>
    </div>
  );
};

export default ThreatActorIndividualEditionBiographicsComponent;
