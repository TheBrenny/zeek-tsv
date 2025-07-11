import TSV from "tsv";

const parser = new TSV.Parser("\t", {header: false});

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

class Parser {
    #separator;
    #setSeparator;
    #emptyField;
    #unsetField;
    #path;
    #fields;
    #types;
    #open;
    #close;

    #data;
    #parsedMemoize;

    constructor({separator, setSeparator, emptyField, unsetField, path, fields, types, open, close}, data) {
        this.#separator = separator;
        this.#setSeparator = setSeparator;
        this.#emptyField = emptyField;
        this.#unsetField = unsetField;
        this.#path = path;
        this.#fields = fields;
        this.#types = types;

        if(open === null) this.#open = null;
        else {
            let reExec = dateRegex.exec(open);
            this.#open = new Date(reExec.groups.year, reExec.groups.month - 1, reExec.groups.day, reExec.groups.hour, reExec.groups.minute, reExec.groups.second);
        }
        if(close === null) this.#close = null;
        else {
            let reExec = dateRegex.exec(close);
            this.#close = new Date(reExec.groups.year, reExec.groups.month - 1, reExec.groups.day, reExec.groups.hour, reExec.groups.minute, reExec.groups.second);
        }

        this.#data = data;
        this.#parsedMemoize = new Array(data.length).fill(null).map(() => new Array(this.#fields.length).fill(undefined));
    }

    get separator() {return this.#separator;}
    get setSeparator() {return this.#setSeparator;}
    get emptyField() {return this.#emptyField;}
    get unsetField() {return this.#unsetField;}
    get path() {return this.#path;}
    get fields() {return [...this.#fields];}
    get open() {return this.#open;}
    get close() {return this.#close;}

    all() {
        return this.row(0, this.#data.length);
    }

    row(start, stop) {
        let data = [];
        for(let r = start; r < stop; r++) {
            let row = {};
            for(let field of this.#fields) row[field] = this.get(r, field);
            data.push(row);
        }
        return data;
    }

    get(row, field) {
        let col = this.fields.indexOf(field);
        if(col === -1) throw new Error("Unknown field" + field);

        if(this.#parsedMemoize[row]?.[col] !== undefined) return this.#parsedMemoize[row][col];

        let dataPoint = this.#data[row][col];
        if(dataPoint === this.emptyField) return null;
        if(dataPoint === this.unsetField) return undefined;

        return transform(dataPoint, this.#types[col]);
    }

    stringify() {
        let data = [...this.#data];
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

function transform(data, type) {
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

/**
 * Parses the zeek log into a flat json object
 * @param {string} data 
 */
export function parse(data) {
    data = data.split("\n");

    let parts = {};

    while(data[0].startsWith("#") || data[0] === "") {
        let comment = data.splice(i, 1)[0];
        if(comment === "") continue;

        let [key, value] = comment.split("\t", 2);
        value = value.split("\t");
        parts[key] = value.length === 1 ? value[0] : value;
    }

    while(data[data.length - 1].startsWith("#") || data[data.length - 1] === "") {
        let comment = data.splice(i, 1)[0];
        if(comment === "") continue;

        let [key, value] = comment.split("\t", 2);
        value = value.split("\t");
        parts[key] = value.length === 1 ? value[0] : value;
    }

    let parsed = parser.parse(data);

    return new Parser(parts, parsed);
}