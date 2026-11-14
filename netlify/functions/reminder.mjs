// Runs every hour (Malaysia time is used for the checks):
//  - daily reminder if nothing is logged yet (smart: an hour after the usual logging time; fixed: 7 pm)
//  - weekly report on Sunday from 9 pm
import { getStore } from "@netlify/blobs";
import * as webpush from "web-push";
import { runReminder, runWeekly } from "../lib/core.mjs";

export default async () => {
  const store = getStore({ name: "quran-journal", consistency: "strong" });
  console.log("reminder", JSON.stringify(await runReminder(store, webpush)));
  console.log("weekly", JSON.stringify(await runWeekly(store, webpush)));
};

export const config = { schedule: "0 * * * *" };
