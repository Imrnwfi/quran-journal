import { getStore } from "@netlify/blobs";
import * as webpush from "web-push";
import { handlePush } from "../lib/core.mjs";

export default async (req) => handlePush(req, getStore({ name: "quran-journal", consistency: "strong" }), webpush);

export const config = { path: "/api/push" };
