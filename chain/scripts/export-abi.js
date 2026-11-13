import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const artifactPath = path.resolve(
  scriptDir,
  "../artifacts/contracts/InheritanceGovernance.sol/InheritanceGovernance.json",
);
const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
process.stdout.write(`${JSON.stringify(artifact.abi, null, 2)}\n`);
