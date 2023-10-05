import * as Yup from 'yup';
import { Form, Formik } from 'formik';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation, defaultCommitMutation } from '../../../../relay/environment';
import { HeightFieldEdit } from '../../common/form/HeightField';
import { WeightFieldEdit } from '../../common/form/WeightField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import CommitMessage from '../../common/form/CommitMessage';
import {
  ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividualEditionBiographics_ThreatActorIndividual.graphql';
import OpenVocabField from '../../common/form/OpenVocabField';
import useUserMetric from '../../../../utils/hooks/useUserMetric';

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
  }
`;

const threatActorIndividualValidation = (t: (s: string) => string) => Yup.object().shape({
  eye_color: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  hair_color: Yup.string()
    .nullable()
    .typeError(t('The value must be a string')),
  weight: Yup.array(),
  height: Yup.array(),
});

interface ThreatActorIndividualEditionBiographicsComponentProps {
  threatActorIndividualRef: ThreatActorIndividualEditionBiographics_ThreatActorIndividual$key,
  enableReferences: boolean,
  context: readonly {
    readonly focusOn: string | null;
    readonly name: string;
  }[] | null | undefined,
}

const ThreatActorIndividualEditionBiographicsComponent:
React.FunctionComponent<ThreatActorIndividualEditionBiographicsComponentProps> = ({
  threatActorIndividualRef,
  enableReferences,
  context,
}: ThreatActorIndividualEditionBiographicsComponentProps) => {
  const { t } = useFormatter();
  const { heightsConverterLoad, weightsConverterLoad } = useUserMetric();
  const threatActorIndividual = useFragment(threatActorIndividualEditionBiographicsFragment, threatActorIndividualRef);

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
    threatActorIndividualValidation(t)
      .validateAt(name, { [name]: value })
      .then(() => {
        commitMutation({
          ...defaultCommitMutation,
          mutation: threatActorIndividualMutationFieldPatch,
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
        validationSchema={threatActorIndividualValidation(t)}
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
              <OpenVocabField
                name="eye_color"
                label={t('Eye Color')}
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
                label={t('Hair Color')}
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
