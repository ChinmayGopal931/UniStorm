const circomlibjs = require("circomlibjs");

const rounds = 220;
const seed = "mimcsponge";

process.stdout.write(circomlibjs.mimcSpongecontract.createCode(seed, rounds));
