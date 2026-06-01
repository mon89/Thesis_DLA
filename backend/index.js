const express = require("express");
const app = express();
app.get("/health", (req,res)=>res.json({ok:true}));
app.listen(3000, "127.0.0.1", () => console.log("API on 127.0.0.1:3000"));
