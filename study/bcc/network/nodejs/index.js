import express from "express";

const app = express();

app.get("/", (_, res) => {
  res.send("index");
});

app.get("/test", (_, res) => {
  res.send("test");
});

app.listen(8083, () => {
  console.log("Server is running at http://localhost:8083");
});
