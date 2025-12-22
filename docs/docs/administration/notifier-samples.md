# Notifier samples

## Configure Teams webhook

To configure a notifier for Teams, allowing to send notifications via Teams messages, we followed the guidelines outlined in the [Microsoft documentation](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook?tabs=dotnet).

![Teams notifier sample](assets/teams-notifier-sample.png)

## Template message for live trigger

The Teams template message sent through webhook for a live notification is:

```
{
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
```

## Template message for digest

The Teams template message sent through webhook for a digest notification is:

```
{
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
}
```