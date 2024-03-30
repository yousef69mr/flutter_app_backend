const PrismaClient = require("@prisma/client");

const db = globalThis.prisma || new PrismaClient.PrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalThis.prisma = db;
}

module.exports = db;
