const dataPath = require("./minecraft-data/data/dataPaths.json")

const data = require(`./minecraft-data/data/${dataPath.pc["1.16.3"].protocol}/protocol.json`)
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
        .map(({ type, name, anon }) => {
          if (name === 'item') console.error(type)
          const new_path = `${path}_${name}`
          const { code, hf_type } = read(type, undefined, {
            path: new_path,
            read,
            name
          })
          hf.push({
            name,
            path: new_path,
            type: hf_type,
          })
          return code
        })
        .join("\n"),
    }
  },
  varint(args, { path }) {
    return {
      code: `minecraft_add_varint(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_UINT32",
      return_type: "guint32"
    }
  },
  string(args, { path }) {
    return {
      code: `minecraft_add_string(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_STRING",
    }
  },
  bool(args, { path }) {
    return {
      code: `minecraft_add_bool(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_BOOLEAN",
    }
  },
  u8(args, { path }) {
    return {
      code: `minecraft_add_u8(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_UINT8",
    }
  },
  i8(args, { path }) {
    return {
      code: `minecraft_add_i8(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_INT8",
    }
  },
  u16(args, { path }) {
    return {
      code: `minecraft_add_u16(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_UINT16",
    }
  },
  i16(args, { path }) {
    return {
      code: `minecraft_add_i16(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_INT16",
    }
  },
  i32(args, { path }) {
    return {
      code: `minecraft_add_i32(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_INT32",
    }
  },
  i64(args, { path }) {
    return {
      code: `minecraft_add_i64(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_INT64",
    }
  },
  f32(args, { path }) {
    return {
      code: `minecraft_add_f32(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_FLOAT",
    }
  },
  f64(args, { path }) {
    return {
      code: `minecraft_add_f64(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_DOUBLE",
    }
  },
  UUID(args, { path }) {
    return {
      code: `minecraft_add_UUID(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_BYTES",
    }
  },
  restBuffer(args, { path }) {
    return {
      code: `minecraft_add_restbuffer(tree, hf_${path}, tvb, &offset);`,
      hf_type: "FT_BYTES",
    }
  },
  buffer({ countType }, { read, path, name }) {
    const count = read(countType, undefined, { read, path: `${path}_count`})

    hf.push({
      name: name ? `${name} Count` : 'Count',
      path: `${path}_count`,
      type: count.hf_type,
    })

    return {
      code:
`${count.return_type} ${path}_count = ${count.code}
minecraft_add_buffer(tree, hf_${path}, tvb, &offset, len);`,
      hf_type: "FT_BYTES",
    }
  },
  option(args, ctx) {
    const inner = ctx.read(args, undefined, ctx)
    return {
      code:
`if (tvb_get_guint8(tvb, offset) == 1) {
  offset += 1;
  ${inner.code}
}`,
      hf_type: inner.hf_type,
    }
  },
}

const functions = []
const hf = []

function generate(namespace, skip = []) {
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
        if (skip.includes(name)) {
          return `case ${id}:
  col_set_str(pinfo->cinfo, COL_INFO, "${unsnake(name)} [${namespace[0]}] (${namespace[1]})");
  break;`
        }
        const { code } = read(names_to_types[name], undefined, {
          path: `${path}_${name}`,
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

generate(["login", "toServer"])
generate(["login", "toClient"])

generate(["play", "toServer"], [
  // need to support bitfield and switch
  'query_block_nbt', 'use_entity', 'generate_structure', 'block_dig', 'advancement_tab', 'update_command_block',
  'update_jigsaw_block', 'update_structure_block', 'update_sign', 'block_place',
  'window_click', 'edit_book', 'set_creative_slot'
])

const use_array = [
  'statistics', 'multi_block_change', 'tab_complete', 'declare_commands', 'window_items',
  'explosion', 'login', 'map', 'trade_list', 'player_info', 'unlock_recipes', 'entity_destroy',
  'set_passengers', 'advancements', 'entity_update_attributes', 'declare_recipes', 'tags',
]
const use_optionalNbt = ['tile_entity_data']
const use_nbt = ['map_chunk', 'nbt_query_response', 'respawn']
const use_entityMetadataLoop = ['entity_metadata']
const use_topBitSetTerminatedArray = ['entity_equipment']
const use_bitfield = [
  'spawn_entity_painting', 'acknowledge_player_digging', 'block_break_animation', 'block_action', 'block_change',
  'world_event', 'open_sign_entity', 'spawn_position'
]
const use_switch = [
  'boss_bar', 'world_particles', 'combat_event', 'face_player', 'world_border', 'scoreboard_objective', 'teams',
  'scoreboard_score', 'title', 'stop_sound', 'set_slot'
]

generate(["play", "toClient"], [
  ...use_array,...use_optionalNbt, ...use_nbt, ...use_entityMetadataLoop,
  ...use_topBitSetTerminatedArray, ...use_bitfield, ...use_switch
])

console.log(hf.map(({ path }) => `static int hf_${path} = -1;`).join("\n"))

console.log("")

console.log(`static hf_register_info hf_generated[] = {`)


const NONE_TYPES = ["FT_STRING", "FT_BYTES", "FT_FLOAT", "FT_DOUBLE"]

console.log(
  indent(
    hf
      .map(({ name, path, type }) => {
        return `{ &hf_${path},
    { "${uncamel(name)}", "minecraft.${path.replace(/_/g, ".")}", ${type}, ${
        NONE_TYPES.includes(type)  ? "BASE_NONE" : "BASE_DEC"
        }, NULL,
      0x0, "${uncamel(name)}", HFILL }},`
      })
      .join("\n\n")
  )
)

console.log("};")

console.log("")

console.log(functions.join("\n\n"))
