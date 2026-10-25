/* oxlint-disable -- fixture is CommonJS on purpose: it is packed as-is into app.asar */
// minimist 1.2.5: CVE-2021-44906 (prototype pollution)
const argv = require("minimist")(process.argv.slice(2));
const chalk = require("chalk");
console.log(chalk.green(JSON.stringify(argv)));
