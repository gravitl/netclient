import { GoWriteToClipboard } from "../../wailsjs/go/main/App";

export async function writeTextToClipboard(text: string) {
  try {
    return await GoWriteToClipboard(text);
  } catch (err) {
    return Promise.reject(err);
  }
}
