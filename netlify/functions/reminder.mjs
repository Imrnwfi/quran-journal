// Runs every day at 11:00 UTC = 7:00 pm Malaysia time.
// Sends a push notification if nothing has been logged today.
import { getStore } from "@netlify/blobs";
import * as webpush from "web-push";
import { runReminder } from "../lib/core.mjs";

export default async () => {
  const result = await runReminder(getStore({ name: "quran-journal", consistency: "strong" }), webpush);
  console.log("reminder", JSON.stringify(result));
};

export const config = { schedule: "0 11 * * *" };
