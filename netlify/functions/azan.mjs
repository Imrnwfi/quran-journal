// Every 5 minutes: reminders before the adhan (only devices that turned them on are read).
import { getStore } from "@netlify/blobs";
import * as webpush from "web-push";
import { runAzanReminders } from "../lib/core.mjs";

export default async () => {
  const store = getStore({ name: "quran-journal", consistency: "strong" });
  console.log("azan", JSON.stringify(await runAzanReminders(store, webpush)));
};

export const config = { schedule: "*/5 * * * *" };
