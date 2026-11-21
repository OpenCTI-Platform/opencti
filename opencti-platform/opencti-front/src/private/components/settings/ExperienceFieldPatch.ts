import { graphql } from 'react-relay';

// Kept out of Experience.tsx so the AI terms-of-use dialog, and the markdown fields
// that open it, do not import the whole settings page (and the import cycle it closes)

export enum CGUStatus {
  pending = 'pending',
  disabled = 'disabled',
  enabled = 'enabled',
}

export const experienceFieldPatch = graphql`
  mutation ExperienceFieldPatchMutation($id: ID!, $input: [EditInput]!) {
    settingsEdit(id: $id) {
      fieldPatch(input: $input) {
        ...Experience
        platform_enterprise_edition {
          license_validated
        }
      }
    }
  }
`;
