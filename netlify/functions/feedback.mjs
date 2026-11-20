import { getStore } from "@netlify/blobs";
import { handleFeedback } from "../lib/core.mjs";

export default async (req) => handleFeedback(req, getStore({ name: "quran-journal", consistency: "strong" }));

export const config = { path: "/api/feedback" };
