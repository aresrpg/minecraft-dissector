const dataPath = require("./minecraft-data/data/dataPaths.json")

const data = require(`./minecraft-data/data/${dataPath.pc["1.16"].protocol}/protocol.json`)
const assert = require("assert")

function indent(code, indent = "  ") {
  return code
    .split("\n")
    .map((line) => indent + line)
    .join("\n")
}

function unsnake(s) {
  return s
    .split("_")
    .map((e) => e[0].toUpperCase() + e.slice(1).toLowerCase())
    .join(" ")
}

function uncamel(s) {
  return s
    .replace(/_\w/g, (m) => m[1].toUpperCase())
    .split(/(?=[A-Z0-9])/)
    .map((e) => e[0].toUpperCase() + e.slice(1).toLowerCase())
    .join(" ")
}

const natives = {
  container(args, { path, read }) {
    return {
      code: args
        .filter(({ name }) => name)
        .map(({ type, name, anon }) => {
          const new_path = `${path}_${name}`
          const { code, hf_type } = read(type, undefined, {
            path: new_path,
            read,
          })
          hf.push({
            name,
            path: new_path,
            type: hf_type,
          })
          return `${code}(tree, hf_${new_path}, tvb, &offset);`
        })
        .join("\n"),
    }
  },
  varint() {
    return {
      code: "minecraft_add_varint",
      hf_type: "FT_UINT32",
    }
  },
  string() {
    return {
      code: "minecraft_add_string",
      hf_type: "FT_STRING",
    }
  },
  bool() {
    return {
      code: "minecraft_add_bool",
      hf_type: "FT_BOOLEAN",
    }
  },
  u8() {
    return {
      code: "minecraft_add_u8",
      hf_type: "FT_UINT8",
    }
  },
  i8() {
    return {
      code: "minecraft_add_i8",
      hf_type: "FT_INT8",
    }
  },
  u16() {
    return {
      code: "minecraft_add_u16",
      hf_type: "FT_UINT16",
    }
  },
  i16() {
    return {
      code: "minecraft_add_i16",
      hf_type: "FT_INT16",
    }
  },
  i64() {
    return {
      code: "minecraft_add_i64",
      hf_type: "FT_INT64",
    }
  },
  f32() {
    return {
      code: "minecraft_add_f32",
      hf_type: "FT_FLOAT",
    }
  },
  f64() {
    return {
      code: "minecraft_add_f64",
      hf_type: "FT_FLOAT",
    }
  },
  UUID() {
    return {
      code: "minecraft_add_UUID",
      hf_type: "FT_BYTES",
    }
  },
  bitfield() {
    return {
      code: "minecraft_add_bitfield",
      hf_type: "FT_UINT8",
    }
  },
  switch() {
    return {
      code: "minecraft_add_switch",
      hf_type: "FT_UINT8",
    }
  },
  restBuffer() {
    return {
      code: "minecraft_add_restbuffer",
      hf_type: "FT_UINT8",
    }
  },
}

const functions = []
const hf = []

function generate(namespace, remove = false) {
  const types = {}

  const res = namespace.reduce((c, v) => {
    if (c.types) {
      Object.assign(types, c.types)
    }
    return c[v]
  }, data)

  if (res.types) {
    Object.assign(types, res.types)
  }

  Object.assign(types, natives)

  function read(type, args, ctx = {}) {
    let fieldInfo
    if (typeof type === "string") {
      if (!(type in types)) throw new Error("unknown type " + type)

      fieldInfo = types[type]
    } else fieldInfo = type

    if (typeof fieldInfo === "function") {
      return fieldInfo(args, ctx)
    }
    if (typeof fieldInfo === "string") {
      if (fieldInfo === "native") {
        throw new Error("unknown native " + type)
      }
      return read(fieldInfo, args, ctx)
    } else if (Array.isArray(fieldInfo)) {
      return read(fieldInfo[0], fieldInfo[1], ctx)
    } else throw new Error("Invalid type " + type)
  }

  const { packet } = types

  assert(Array.isArray(packet) && packet.length == 2)
  assert(packet[0] === "container")
  assert(packet[1][0].name === "name" && packet[1][0].type[0] === "mapper")
  assert(packet[1][1].name === "params" && packet[1][1].type[0] === "switch")
  assert(packet[1][0].type[1].type === "varint")

  const names = packet[1][0].type[1].mappings
  const names_to_types = packet[1][1].type[1].fields

  const path = namespace.join("_")

  functions.push(
    `void ${path}(guint32 packet_id, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint32 len) {
  switch (packet_id) {
${indent(
    Object.entries(names)
      .map(([id, name]) => {
        if (remove) {
          return `case ${id}:
  col_set_str(pinfo->cinfo, COL_INFO, "${unsnake(name)} [${namespace[0]}] (${namespace[1]})");
  break;`
        }
        const { code } = read(names_to_types[name], undefined, {
          path: `${path}`,
          read,
        })
        return `case ${id}:
  col_set_str(pinfo->cinfo, COL_INFO, "${unsnake(name)} [${namespace[0]}] (${namespace[1]})");
${indent(code)}
  break;`
      }, "    ")
      .join("\n")
  )}
  }
}`
  )
}

generate(["handshaking", "toServer"])
generate(["handshaking", "toClient"])

generate(["status", "toServer"])
generate(["status", "toClient"])

generate(["login", "toServer"], true)
generate(["login", "toClient"], true)

generate(["play", "toServer"], true)
generate(["play", "toClient"], true)

console.log(hf.map(({ path }) => `static int hf_${path} = -1;`).join("\n"))

console.log("")

console.log(`static hf_register_info hf_generated[] = {`)

console.log(
  indent(
    hf
      .map(({ name, path, type }) => {
        return `{ &hf_${path},
    { "${uncamel(name)}", "minecraft.${path.replace(/_/g, ".")}", ${type}, ${
          type === "FT_STRING" ? "BASE_NONE" : "BASE_DEC"
        }, NULL,
      0x0, "${uncamel(name)}", HFILL }},`
      })
      .join("\n\n")
  )
)

console.log("};")

console.log("")

console.log(functions.join("\n\n"))
