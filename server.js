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

The user will provide a list of English words.

Generate a vocabulary library for these words.

You MUST return valid JSON.

The JSON must have exactly this structure:

{
  "words": [
    {
      "word": "example",
      "definition": "a clear English definition",
      "example": "A natural example sentence.",
      "synonyms": ["word1", "word2", "word3"],
      "antonyms": ["word1", "word2"],
      "root": "A concise explanation of the word origin or root.",
      "cognates": ["word1", "word2"]
    }
  ]
}

Rules:

1. Keep the original word spelling.
2. Definitions should be clear and suitable for English learners.
3. Example sentences should sound natural.
4. Provide useful synonyms and antonyms when possible.
5. Explain the word root or etymology briefly.
6. Provide useful English derivatives or cognates when possible.
7. If a field has no useful information, use an empty array or an empty string.
8. Return JSON only.
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
