const fs = require("fs");
const path = require("path");

const artifactPath = path.resolve(
  __dirname,
  "../artifacts/contracts/InheritanceGovernance.sol/InheritanceGovernance.json",
);
const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
const outputPath = path.resolve(__dirname, "../../backend/app/InheritanceGovernance.abi.json");
fs.writeFileSync(outputPath, `${JSON.stringify(artifact.abi, null, 2)}\n`);
console.log(`Exported contract ABI to ${outputPath}`);
