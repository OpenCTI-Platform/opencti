import { marked } from 'marked';

export default class NotificationTool {
  // eslint-disable-next-line class-methods-use-this
  m2h(markdownText: string) : string {
    return marked(markdownText) as string;
  }
}
