import { graphql } from 'react-relay';

// eslint-disable-next-line import/prefer-default-export
export const notificationLineFragment = graphql`
  fragment NotificationLine_node on Notification {
    id
    entity_type
    name
    created
    notification_type
    is_read
    notification_content {
      title
      events {
        message
        operation
        instance_id
      }
    }
  }
`;
