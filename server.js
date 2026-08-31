const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use(express.static(path.join(__dirname, "public")));

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    message: "English Word Lab server is running!"
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});