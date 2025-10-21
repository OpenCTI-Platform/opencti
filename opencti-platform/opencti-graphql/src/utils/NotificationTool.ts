import { marked } from 'marked';

export default class NotificationTool {
  // eslint-disable-next-line class-methods-use-this
  markdownToHtml(markdownText?: string) : string | undefined {
    if (!markdownText) return undefined;
    return marked(markdownText) as string;
  }
}
