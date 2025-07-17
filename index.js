import {Transform} from "stream";

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

/**
 * Parses the zeek log into a flat json object
 * @param {string} data 
 */
export function parseZeek(data) {
    data = data.split("\n");

    let parts = {};
    let sep = " ";

    while(data[0].startsWith("#") || data[0] === "") {
        let comment = data.splice(0, 1)[0];
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

    while(data[data.length - 1].startsWith("#") || data[data.length - 1] === "") {
        let comment = data.splice(data.length - 1, 1)[0];
        if(comment === "") continue;
        comment = comment.substring(1);

        let [key, ...values] = comment.split(sep);
        parts[key] = values.length === 1 ? values[0] : values;
    }

    let parsed = [];
    for(let row of data) {
        // split on \t, then map to [k,v], all wrapped in a an Object maker, then freeze it so it can't change
        let values = Object.freeze(Object.fromEntries(row.split(parts.separator).map((v, i) => [parts.fields[i], transformFromType(v, parts.types[i])])));
        parsed.push(values);
    }
    parsed = Object.freeze(parsed);

    return new ZeekLog(parts, parsed);
}

/**
 * Expects lines as chunks
 */
export const streamZeek = new Transform({
    construct() {
        this.#parts = {};
        this.#sep = " "
    },
    transform(line, encoding, cb) {
        if(line === "") return;

        if(line.startsWith("#")) {
            let [key, ...values] = comment.split(this.#sep);
            if(key === "separator") {
                this.#sep = values[0].substring(2);
                this.#sep = String.fromCharCode(parseInt(this.#sep, 16));
                values = [this.#sep];
            }
            this.#parts[key] = values.length === 1 ? values[0] : values;
        } else {
            let values = Object.fromEntries(line.split(this.#sep).map((v, i) => [this.#parts.fields[i], transformFromType(v, this.#parts.types[i])]));
            this.push(values);
        }
        cb();
    },
    flush(cb) {
        this.push(this.#parts);
        cb();
    }
});

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
    return new Date(reExec.groups.year, reExec.groups.month - 1, reExec.groups.day, reExec.groups.hour, reExec.groups.minute, reExec.groups.second);
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