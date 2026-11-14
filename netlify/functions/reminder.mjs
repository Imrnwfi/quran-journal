// Runs every hour. Sends one push notification a day if nothing has been logged yet,
// at the owner's reminder hour (smart: an hour after their usual logging time; fixed: 7 pm), Malaysia time.
import { getStore } from "@netlify/blobs";
import * as webpush from "web-push";
import { runReminder } from "../lib/core.mjs";

export default async () => {
  const result = await runReminder(getStore({ name: "quran-journal", consistency: "strong" }), webpush);
  console.log("reminder", JSON.stringify(result));
};

export const config = { schedule: "0 * * * *" };
