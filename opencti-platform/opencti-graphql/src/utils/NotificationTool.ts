import { marked } from 'marked';

export default class NotificationTool {
  // eslint-disable-next-line class-methods-use-this
  markdownToHtml(markdownText: string) : string {
    return marked(markdownText) as string;
  }
}
