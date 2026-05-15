import { GoogleGenerativeAI } from "@google/generative-ai";
import { SafetyStatusValues, type SafetyStatus } from "../types";

const apiKey = import.meta.env.VITE_API_KEY;
if (!apiKey) {
  console.warn("VITE_API_KEY environment variable is not set.");
}

const ai = new GoogleGenerativeAI(apiKey || "");

export const analyzeLinkSafety = async (url: string): Promise<{
  status: SafetyStatus;
  reason: string;
  title: string;
  description: string;
}> => {
  if (!apiKey) {
    return {
      status: SafetyStatusValues.SUSPICIOUS,
      reason: "API key not configured. Please set VITE_API_KEY in your .env file.",
      title: "Configuration Required",
      description: "Gemini AI analysis is not available without an API key.",
    };
  }

  try {
    // gemini-pro is deprecated — use gemini-1.5-flash
    const model = ai.getGenerativeModel({ model: "gemini-1.5-flash" });

    const prompt = `You are a cybersecurity expert. Analyze this URL for safety threats such as phishing, malware, scams, or suspicious behavior: ${url}

Respond ONLY with a raw JSON object (no markdown, no code fences). Use this exact shape:
{
  "status": "SAFE" | "SUSPICIOUS" | "UNSAFE",
  "reason": "one or two sentence explanation",
  "title": "estimated or known page title",
  "description": "brief description of the site or threat"
}`;

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const raw = response.text();

    // Strip markdown code fences if Gemini wraps the JSON
    const cleaned = raw
      .replace(/```json\s*/gi, "")
      .replace(/```\s*/g, "")
      .trim();

    const data = JSON.parse(cleaned);

    // Validate status — default to SUSPICIOUS if model returns something unexpected
    const validStatuses = [
      SafetyStatusValues.SAFE,
      SafetyStatusValues.SUSPICIOUS,
      SafetyStatusValues.UNSAFE,
    ] as string[];
    const status = validStatuses.includes(data.status)
      ? (data.status as SafetyStatus)
      : SafetyStatusValues.SUSPICIOUS;

    return {
      status,
      reason: data.reason || "No reason provided.",
      title: data.title || "Unknown Page",
      description: data.description || "No description available.",
    };
  } catch (error) {
    console.error("Gemini Analysis Error:", error);
    return {
      status: SafetyStatusValues.SUSPICIOUS,
      reason: "Analysis failed. Please proceed with extreme caution.",
      title: "Error in analysis",
      description: "We couldn't verify this link safely.",
    };
  }
};