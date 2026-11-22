import { getStore } from "@netlify/blobs";
import * as webpush from "web-push";
import { handleRemind } from "../lib/core.mjs";

export default async (req) => handleRemind(req, getStore({ name: "quran-journal", consistency: "strong" }), webpush);

export const config = { path: "/api/remind" };
