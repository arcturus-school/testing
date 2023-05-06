import express from "express";

const app = express();

app.get("/", (_, res) => {
  res.send("Hello world");
});

app.get("/page1", (_, res) => {
  res.send("Page1");
});

app.listen(8083, () => {
  console.log("Server is running at http://localhost:8083");
});
