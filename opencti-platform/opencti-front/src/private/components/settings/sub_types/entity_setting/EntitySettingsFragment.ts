import { graphql } from 'react-relay';

export const entitySettingsFragment = graphql`
  fragment EntitySettingsFragment_entitySetting on EntitySetting {
    id
    target_type
    platform_entity_files_ref
    platform_hidden_type
    enforce_reference
    sync_workflow_status_by_name
    availableSettings
    mandatoryAttributes
    scaleAttributes {
      name
      scale
    }
    defaultValuesAttributes {
      name
      type
      defaultValues {
        id
        name
      }
    }
    overview_layout_customization {
      key
      width
      label
    }
    requestAccessConfiguration {
      id
      approval_admin {
        id
        name
      }
      declined_status {
        id
        template {
          id
          name
          color
        }
      }
      approved_status {
        template {
          id
          name
          color
        }
      }
    }
  }
`;
