import { getStore } from "@netlify/blobs";
import { handleTransfer } from "../lib/core.mjs";

export default async (req) => handleTransfer(req, getStore({ name: "quran-journal", consistency: "strong" }));

export const config = { path: "/api/transfer" };
