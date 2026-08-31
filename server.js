const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "100kb" }));

// Serve the website
app.use(express.static(path.join(__dirname, "public")));

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    message: "English Word Lab server is running!"
  });
});

// Generate vocabulary with DeepSeek
app.post("/api/generate", async (req, res) => {
  try {
    const { words } = req.body;

    // Basic validation
    if (!Array.isArray(words)) {
      return res.status(400).json({
        error: "words must be an array"
      });
    }

    if (words.length === 0) {
      return res.status(400).json({
        error: "Please provide at least one word"
      });
    }

    if (words.length > 50) {
      return res.status(400).json({
        error: "Maximum 50 words per request"
      });
    }

    const cleanedWords = words
      .map(word => String(word).trim())
      .filter(Boolean);

    if (cleanedWords.length === 0) {
      return res.status(400).json({
        error: "No valid words provided"
      });
    }

    if (!process.env.DEEPSEEK_API_KEY) {
      return res.status(500).json({
        error: "DeepSeek API key is not configured"
      });
    }

const systemPrompt = `
You are an English vocabulary learning assistant.

The user will provide a list of English vocabulary words.

Generate a vocabulary library for these words.

IMPORTANT:
Each item in the user's list represents exactly ONE vocabulary word.
Treat each input item as a complete word.
NEVER split, segment, decompose, shorten, or reinterpret an input word.

For example:
- "banana" must produce exactly one entry with "word": "banana"
- "beautiful" must produce exactly one entry with "word": "beautiful"
- "reluctant" must produce exactly one entry with "word": "reluctant"

The number of vocabulary entries MUST match the number of valid input words.
Preserve the original word spelling exactly.

You MUST return valid JSON.

The JSON must have exactly this structure:

{
  "words": [
    {
      "word": "example",
      "definition": "a clear and concise English definition",
      "examples": [
        "A natural English example sentence.",
        "A second natural English example sentence.",
        "A third natural English example sentence."
      ],
      "synonyms": ["word1", "word2", "word3"],
      "antonyms": ["word1", "word2"],
      "root": "A concise explanation of the word origin or root.",
      "cognates": ["word1", "word2"]
    }
  ]
}

Rules:

1. Keep the original word spelling exactly as provided by the user.
2. Never split one input word into multiple words.
3. Create exactly one vocabulary entry for each input word.
4. The number of entries in "words" must match the number of valid input words.
5. Definitions must be clear, concise, and suitable for English learners.
6. Generate EXACTLY THREE example sentences for every word.
7. The three example sentences should be natural, grammatically correct, and useful for learning.
8. The three examples should use the target word naturally and demonstrate meaningful usage.
9. Avoid making the three example sentences repetitive.
10. Provide useful synonyms when possible.
11. Provide useful antonyms when possible.
12. Explain the word's root or etymology briefly and accurately when possible.
13. Provide useful English derivatives or cognates when possible.
14. If a field has no useful information, use an empty array or an empty string.
15. Do not add extra fields.
16. Return JSON only.
`;
    const userPrompt = `
Generate the vocabulary library for these words:

${cleanedWords.join("\n")}
`;

    const response = await fetch(
      "https://api.deepseek.com/chat/completions",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${process.env.DEEPSEEK_API_KEY}`
        },
        body: JSON.stringify({
  model: "deepseek-v4-flash",

  thinking: {
    type: "disabled"
  },

  messages: [
            {
              role: "system",
              content: systemPrompt
            },
            {
              role: "user",
              content: userPrompt
            }
          ],
          response_format: {
            type: "json_object"
          },
          max_tokens: 6000,
          stream: false
        })
      }
    );

    if (!response.ok) {
      const errorText = await response.text();

      console.error("DeepSeek API error:", errorText);

      return res.status(502).json({
        error: "DeepSeek API request failed"
      });
    }

    const data = await response.json();

    const content = data?.choices?.[0]?.message?.content;

    if (!content) {
      return res.status(502).json({
        error: "DeepSeek returned an empty response"
      });
    }

    let result;

    try {
      result = JSON.parse(content);
    } catch (error) {
      console.error("Invalid JSON from DeepSeek:", content);

      return res.status(502).json({
        error: "DeepSeek returned invalid JSON"
      });
    }

    if (!result.words || !Array.isArray(result.words)) {
      return res.status(502).json({
        error: "Invalid vocabulary data returned by DeepSeek"
      });
    }
   if (result.words.length !== cleanedWords.length) {
  return res.status(502).json({
    error: "DeepSeek returned an incorrect number of vocabulary entries"
  });
}

const expectedWords = cleanedWords.map(word => word.toLowerCase());
const returnedWords = result.words.map(item =>
  String(item.word || "").trim().toLowerCase()
);

if (expectedWords.some((word, index) => returnedWords[index] !== word)) {
  return res.status(502).json({
    error: "DeepSeek did not preserve the original vocabulary words"
  });
}
for (const item of result.words) {
  if (!Array.isArray(item.examples) || item.examples.length !== 3) {
    return res.status(502).json({
      error: `DeepSeek did not return exactly three examples for "${item.word}"`
    });
  }
}
    res.json(result);

  } catch (error) {
    console.error("Server error:", error);

    res.status(500).json({
      error: "Internal server error"
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
