import express, { Request } from "express";

const app = express();

app.use(express.json());

const PORT = 3002;
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
