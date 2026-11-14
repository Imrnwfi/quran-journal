import { getStore } from "@netlify/blobs";
import { handleSolat } from "../lib/core.mjs";

export default async (req) => handleSolat(req, getStore({ name: "quran-journal", consistency: "strong" }));

export const config = { path: "/api/solat" };
