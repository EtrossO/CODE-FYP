
import { GoogleGenerativeAI } from "@google/generative-ai";
import { SafetyStatusValues, type SafetyStatus } from "../types";

// Initialize Gemini AI with API key from environment variables
// Make sure to create a .env file with VITE_API_KEY=your_api_key_here
const apiKey = import.meta.env.VITE_API_KEY;
if (!apiKey) {
  console.warn("VITE_API_KEY environment variable is not set. Gemini AI analysis will not work.");
}

const ai = new GoogleGenerativeAI(apiKey || "");

export const analyzeLinkSafety = async (url: string): Promise<{
  status: SafetyStatus;
  reason: string;
  title: string;
  description: string;
}> => {
  // Check if API key is available
  if (!apiKey) {
    return {
      status: SafetyStatusValues.SUSPICIOUS,
      reason: "API key not configured. Please set VITE_API_KEY in your .env file.",
      title: "Configuration Required",
      description: "Gemini AI analysis is not available without an API key."
    };
  }

  try {
    const model = ai.getGenerativeModel({ model: "gemini-pro" });
    
    const prompt = `Analyze the following URL for safety, phishing, malware, or scams: ${url}. 
    Respond with a JSON object containing: status (SAFE, SUSPICIOUS, or UNSAFE), reason (brief explanation), title (estimated webpage title), description (brief summary of the site).`;
    
    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    
    const data = JSON.parse(text || "{}");
    return {
      status: data.status as SafetyStatus,
      reason: data.reason,
      title: data.title || "Unknown Page",
      description: data.description || "No description available.",
    };
  } catch (error) {
    console.error("Gemini Analysis Error:", error);
    return {
      status: SafetyStatusValues.SUSPICIOUS,
      reason: "Analysis failed. Please proceed with extreme caution.",
      title: "Error in analysis",
      description: "We couldn't verify this link safely."
    };
  }
};
