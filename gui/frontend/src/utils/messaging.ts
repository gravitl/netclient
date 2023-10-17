import { GoOpenDialogue } from "../../wailsjs/go/main/App";

type DialogueBoxType = "info" | "warning" | "error" | "question";

export async function getUserConfirmation(msg: string, title: string) {
  const dialogueType: DialogueBoxType = "question";

  try {
    // "Yes" means user clicked "Yes/OK" button in dialogue box
    return (await GoOpenDialogue(dialogueType, msg, title)) === "Yes";
  } catch (err) {
    return Promise.reject(err);
  }
}

export async function notifyUser(
  msg: string,
  title: string = "An error occured",
  dialogueType: DialogueBoxType = "error",
) {
  try {
    return await GoOpenDialogue(dialogueType, msg, title);
  } catch (err) {
    return Promise.reject(err);
  }
}
