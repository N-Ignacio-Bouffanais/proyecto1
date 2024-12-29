import mysql from "mysql2/promise";
import axios from "axios";
import dotenv from "dotenv";

dotenv.config();

// Configuración de la conexión a la base de datos
const dbConfig = {
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || "3306"),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
};

// Lista de IPs a analizar
const ipList = [
  "8.8.8.8",
  "1.1.1.1",
  "203.0.113.5",
  "185.60.216.35",
  "52.32.123.45",
];

// ISP y países confiables
const trustedISPs = [
  "Google LLC",
  "Cloudflare",
  "Amazon.com",
  "Microsoft Corporation",
];
const trustedCountries = [
  "United States",
  "Canada",
  "Germany",
  "United Kingdom",
  "Australia",
];

async function populateDatabase() {
  // Conexión a la base de datos
  const db = await mysql.createPool(dbConfig);

  for (const ip of ipList) {
    try {
      // Consumir API de ipstack
      const apiKey = process.env.IPSTACK_API_KEY;
      const url = `http://api.ipstack.com/${ip}?access_key=${apiKey}`;
      const { data } = await axios.get(url);

      // Validar si el ISP y la ubicación son confiables
      const isTrustedISP = trustedISPs.includes(data.connection?.isp || "");
      const isValidLocation = trustedCountries.includes(
        data.country_name || ""
      );

      // Clasificar la IP usando datos reales
      let status: "Confiable" | "Sospechosa" | "Maliciosa";
      if (
        data.threat?.is_known_attacker ||
        data.threat?.is_tor ||
        data.threat?.is_crawler
      ) {
        status = "Maliciosa";
      } else if (data.threat?.is_proxy || !isTrustedISP || !isValidLocation) {
        status = "Sospechosa";
      } else {
        status = "Confiable";
      }

      // Guardar en la base de datos
      const query = `
        INSERT INTO ip_analysis (
          ip_address, type, country, city, isp, organization,
          is_trusted_isp, is_valid_location,
          is_known_attacker, is_proxy, is_tor, is_crawler,
          status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      const values = [
        ip,
        data.type || "Unknown",
        data.country_name || "Unknown",
        data.city || "Unknown",
        data.connection?.isp || "Unknown",
        data.connection?.organization || "Unknown",
        isTrustedISP,
        isValidLocation,
        data.threat?.is_known_attacker || false,
        data.threat?.is_proxy || false,
        data.threat?.is_tor || false,
        data.threat?.is_crawler || false,
        status,
      ];

      await db.execute(query, values);
      console.log(
        `IP ${ip} clasificada como ${status} y guardada en la base de datos.`
      );
    } catch (error:any) {
      console.error(`Error al procesar la IP ${ip}:`, error.message);
    }
  }

  // Cerrar conexión a la base de datos
  db.end();
}

populateDatabase()
  .then(() => console.log("Población de la base de datos completada."))
  .catch((err) =>
    console.error("Error al poblar la base de datos:", err.message)
  );
