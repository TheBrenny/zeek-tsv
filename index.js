import {Readable, Transform} from "stream";
import {ReadableStream} from "stream/web";

class ZeekLog {
    #separator;
    #setSeparator;
    #emptyField;
    #unsetField;
    #path;
    #fields;
    #types;
    #open;
    #close;

    #rest = {};

    #headersMem;
    #data;

    /**
     * @param {Object} param0 
     * @param {Readonly<Array<Object>>} parsed 
     */
    constructor({separator, setSeparator, emptyField, unsetField, path, fields, types, open, close, ...rest}, parsed) {
        this.#separator = separator;
        this.#setSeparator = setSeparator;
        this.#emptyField = emptyField;
        this.#unsetField = unsetField;
        this.#path = path;
        this.#fields = fields;
        this.#types = types;

        for(let r in rest) this.#rest[r] = rest[r];

        if(open === null || open === undefined) this.#open = null;
        else this.#open = fromDateString(open);
        if(close === null || close === undefined) this.#close = null;
        else this.#close = fromDateString(close);

        this.#data = parsed;
    }

    get separator() {return this.#separator;}
    get setSeparator() {return this.#setSeparator;}
    get emptyField() {return this.#emptyField;}
    get unsetField() {return this.#unsetField;}
    get path() {return this.#path;}
    get fields() {return [...this.#fields];}
    get open() {return this.#open;}
    get close() {return this.#close;}
    get allHeaders() {
        if(this.#headersMem) return this.#headersMem;
        this.#headersMem = [
            "separator",
            "setSeparator",
            "emptyField",
            "unsetField",
            "path",
            "fields",
            "open",
            "close",
            ...Object.keys(this.#rest)
        ];
        return this.#headersMem;
    }

    get data() {
        return [...this.#data];
    }

    stringify() {
        let data = this.#data.map((r) => Object.entries(r).map(([k, v], i) => transformToType(v, this.#types[i])).join(this.#separator));
        for(let r in this.#rest) {
            let v = this.#rest[r];
            if(Array.isArray(v)) v = v.join("\t");
            data.unshift(`#${r}\t${v}`);
        }
        data.unshift(
            `#separator\t\\x${this.#separator.charCodeAt(0).toString(16).padStart(2, "0")}`,
            `#setseparator\t${this.#setSeparator}`,
            `#emptyfield\t${this.#emptyField}`,
            `#unsetfield\t${this.#unsetField}`,
            `#path\t${this.#path}`,
            `#open\t${toDateString(this.#open)}`,
            `#fields\t${this.#fields.join("\t")}`,
            `#types\t${this.#types.join("\t")}`,
        );
        data.push(`#close\t${toDateString(this.#close)}`);
        return data.join("\n")
    }
}
class ZeekStreamer {
    #parts = {};
    #sep = " ";
    constructor() {
        this.#parts = {};
        this.#sep = " ";
    }

    transform(line) {
        if(line === "") return undefined;

        if(line.startsWith("#")) {
            let [key, ...values] = line.split(this.#sep);
            if(key === "separator") {
                this.#sep = values[0].substring(2);
                this.#sep = String.fromCharCode(parseInt(this.#sep, 16));
                values = [this.#sep];
            }
            this.#parts[key] = values.length === 1 ? values[0] : values;
        } else {
            let values = Object.fromEntries(line.split(this.#sep).map((v, i) => [this.#parts.fields[i], transformFromType(v, this.#parts.types[i])]));
            return values;
        }
        return undefined;
    }

    flush() {
        return this.#parts;
    }
}

/**
 * Parses the zeek log into a flat json object
 * @param {string} data
 * @returns {ZeekLog}
 */
export function parseZeek(data) {
    let lines = data.split("\n");

    let parts = {};
    let sep = " ";

    while(lines[0].startsWith("#") || lines[0] === "") {
        let comment = lines.splice(0, 1)[0];
        if(comment === "") continue;
        comment = comment.substring(1);

        let [key, ...values] = comment.split(sep);
        if(key === "separator") {
            sep = values[0].substring(2);
            sep = String.fromCharCode(parseInt(sep, 16));
            values = [sep];
        }
        parts[key] = values.length === 1 ? values[0] : values;
    }

    while(lines[lines.length - 1].startsWith("#") || lines[lines.length - 1] === "") {
        let comment = lines.splice(lines.length - 1, 1)[0];
        if(comment === "") continue;
        comment = comment.substring(1);

        let [key, ...values] = comment.split(sep);
        parts[key] = values.length === 1 ? values[0] : values;
    }

    let parsed = [];
    for(let row of lines) {
        // split on \t, then map to [k,v], all wrapped in a an Object maker, then freeze it so it can't change
        let values = Object.freeze(Object.fromEntries(row.split(parts.separator).map((v, i) => [parts.fields[i], transformFromType(v, parts.types[i])])));
        parsed.push(values);
    }

    return new ZeekLog(parts, Object.freeze(parsed));
}

/**
 * Transforms lines of TSV data into JSON lines
 * @returns {Transform}
 */
export const streamZeek = () => {
    /** @type {ZeekStreamer} */
    let zeekStreamer;
    return new Transform({
        construct(cb) {
            zeekStreamer = new ZeekStreamer();
            cb();
        },
        transform(line, encoding, cb) {
            let data = zeekStreamer.transform(line);
            if(data !== undefined) this.push(data);
            cb();
        },
        flush(cb) {
            let data = zeekStreamer.flush();
            if(data !== undefined) this.push(data);
            cb();
        }
    })
};

streamZeek.web = () => {
    /** @type {ZeekStreamer} */
    let zeekStreamer;
    return new TransformStream({
        start(controller) {
            zeekStreamer = new ZeekStreamer();
        },
        transform(chunk, controller) {
            let data = zeekStreamer.transform(chunk);
            if(data !== undefined) controller.enqueue(data);
        },
        flush(controller) {
            let data = zeekStreamer.flush();
            if(data !== undefined) controller.enqueue(data);
        }
    })
}

/**
 * Takes a stream (the output of `streamZeek`) and collates it into a ZeekLog.
 * @param {Readable|ReadableStream} stream
 * @returns {Promise<ZeekLog>}
 */
streamZeek.collect = (stream) => {
    return new Promise((resolve, reject) => {
        if(stream instanceof ReadableStream) stream = Readable.fromWeb(stream);
        if(stream instanceof Readable) {
            let arr = [];
            stream.on("data", (chunk) => {
                arr.push(Object.freeze(chunk));
            });
            stream.on("end", () => {
                let parts = arr.splice(arr.length - 1, 1)[0];
                resolve(new ZeekLog(parts, Object.freeze(arr)));
            });
            stream.on("error", (err) => {
                reject(err);
            })
        } else reject(new Error("incoming stream wasn't readable"));
    });
}

const dateRegex = /(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})-(?<hour>\d{2})-(?<minute>\d{2})-(?<second>\d{2})/
/** @type {(d: Date) => string} */
const toDateString = (d) => {
    let year = d.getFullYear() + "";
    let month = ((d.getMonth() + 1) + "").padStart(2, "0");
    let day = (d.getDate() + "").padStart(2, "0");
    let hour = (d.getHours() + "").padStart(2, "0");
    let minute = (d.getMinutes() + "").padStart(2, "0");
    let second = (d.getSeconds() + "").padStart(2, "0");
    return `${year}-${month}-${day}-${hour}-${minute}-${second}`
};
/** @type {(d: string) => Date} */
const fromDateString = (d) => {
    let reExec = dateRegex.exec(d);
    return new Date(parseInt(reExec.groups.year), parseInt(reExec.groups.month) - 1, parseInt(reExec.groups.day), parseInt(reExec.groups.hour), parseInt(reExec.groups.minute), parseInt(reExec.groups.second));
}

function transformFromType(data, type) {
    switch(type) {
        case "string": return data;
        case "date": return new Date(parseInt(data) * 1000);
        case "addr": return data;
        case "port": return parseInt(data);
        case "enum": return data;
        case "interval": return parseFloat(data);
        case "count": return parseInt(data);
        case "bool": return data === "T";
        case "int": return parseInt(data);
        default:
            return data;
    }
}
function transformToType(data, type) {
    switch(type) {
        case "string": return data;
        case "date": return data.getTime() / 1000;
        case "addr": return data;
        case "port": return data;
        case "enum": return data;
        case "interval": return data;
        case "count": return data.toFixed(0);
        case "bool": return data ? "T" : "F";
        case "int": return data.toFixed(0);
        default:
            return data;
    }
}
