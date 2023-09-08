# Notifiers

## Sample notifiers

### Configure Teams webhook

You can check the [Microsoft website](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=dotnet)

### Default teams message for live trigger

The default configuration for a Teams message sent through webhook for a live notification is:
```
{
    "template": {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.thumbnail",
                "content": {
                    "subtitle": "Operation : <%=content[0].events[0].operation%>",
                    "text": "<%=(new Date(notification.created)).toLocaleString()%>",
                    "title": "<%=content[0].events[0].message%>",
                    "buttons": [
                        {
                            "type": "openUrl",
                            "title": "See in OpenCTI",
                            "value": "https://YOUR_OPENCTI_URL/dashboard/id/<%=content[0].events[0].instance_id%>"
                        }
                    ]
                }
            }
        ]
    }
    "url": "https://YOUR_DOMAIN.webhook.office.com/YOUR_ENDPOINT",
    "verb": "POST"
}
```

### Default teams message for digest

The default configuration for a Teams message sent through webhook for a digest notification is:
```
{
    "template": {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.0",
                    "body": [
                        {
                            "type": "Container",
                            "items": [
                                {
                                    "type": "TextBlock",
                                    "text": "<%=notification.name%>",
                                    "weight": "bolder",
                                    "size": "extraLarge"
                                }, {
                                    "type": "TextBlock",
                                    "text": "<%=(new Date(notification.created)).toLocaleString()%>",
                                    "size": "medium"
                                }
                            ]
                        },
                        <% for(var i=0; i<content.length; i++) { %>
                        {
                            "type": "Container",
                            "items": [<% for(var j=0; j<content[i].events.length; j++) { %>
                                {
                                    "type" : "TextBlock",
                                    "text" : "[<%=content[i].events[j].message%>](https://YOUR_OPENCTI_URL/dashboard/id/<%=content[i].events[j].instance_id%>)"
                                }<% if(j<(content[i].events.length - 1)) {%>,<% } %>
                            <% } %>]
                            }<% if(i<(content.length - 1)) {%>,<% } %>
                        <% } %>
                    ]
                }
            }
        ],
       "dataString": <%-JSON.stringify(notification)%>
    },
    "url": "https://YOUR_DOMAIN.webhook.office.com/YOUR_ENDPOINT",
    "verb": "POST"
}
```