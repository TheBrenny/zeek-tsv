#!/env/node

const scriptName = "zeek-tsv";

import {parse} from "./index.js";
import {readFileSync} from "fs";
import {resolve} from "path";

let ogConsoleError = console.error;
console.error = (...data) => {
    process.stderr.write("\x1b[31m");
    ogConsoleError(...data);
    process.stderr.write("\x1b[39m");
};

process.argv.splice(0, 2);

if(process.argv.length === 0 || process.argv.includes("-h") || process.argv.includes("--help")) {
    printHelp()
    exit();
}
let debug = process.argv.findIndex((a) => a === "--debug" || a === "-d")
if(debug >= 0) {
    process.argv.splice(debug, 1);
    debug = true;
} else debug = false;

for(let file of process.argv) {
    try {
        let log = parse(readFileSync(resolve(file)).toString());
        console.log(JSON.stringify(log.data));
    } catch(e) {
        console.error(e["message"] ?? "unknown error");
        console.error();
        if(debug) {
            console.error(e.stack ?? "no stack");
            console.error();
        }
        printHelp(console.error);
    }
}

function printHelp(log = console.log) {
    log(`Usage: ${scriptName} [-h|--help] | [-d|--debug] <...zeek.logs>`)
    log("")
    log("Options:")
    log("       -h | --help    [optional]   prints this help message")
    log("       -d | --debug   [optional]   prints verbose error stack traces")
    log("       ...zeek.log    <requried>   any number of zeek logs to parse")
    log("")
    log("Examples:")
    log(`       ${scriptName} ./conn.log`)
    log(`       ${scriptName} ./dns.log ./traceroute.log ./arp.log`)
}
function exit(code = 0) {
    process.exit(code);
}