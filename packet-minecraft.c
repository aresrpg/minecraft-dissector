#include <config.h>

#define WS_BUILD_DLL

#include <epan/packet.h>
#include <epan/proto.h>
#include <ws_attributes.h>
#include <ws_symbol_export.h>
#include <ws_version.h>
#include <stdbool.h>

#ifndef VERSION
#define VERSION "0.0.0"
#endif

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = WIRESHARK_VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = WIRESHARK_VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);


static int proto_minecraft = -1;
static int hf_length = -1;
static int hf_packet_id = -1;
static int hf_data = -1;

static hf_register_info hf[] = {

    { &hf_length,
        { "Length", "minecraft.length", FT_UINT32, BASE_DEC, NULL,
            0x00, "Packet Length", HFILL }},

    { &hf_packet_id,
        { "Packet Id", "minecraft.packet_id", FT_UINT32, BASE_HEX, NULL,
            0x0, "Packet Id", HFILL }},

    { &hf_data,
        { "Data", "minecraft.data", FT_BYTES, BASE_NONE, NULL,
            0x0, "Packet Data", HFILL }},
};

static int ett_minecraft = -1;
static int ett_data = -1;

static gint *ett[] = {
    &ett_minecraft,
    &ett_data,
};


static bool read_varint(guint32 *result, tvbuff_t *tvb, gint *offset)
{
    *result = 0;
    guint shift = 0;

    const guint length = tvb_reported_length(tvb);
    while (*offset < length && shift <= 35) {
        const guint8 b = tvb_get_guint8(tvb, *offset);
        *result |= ((b & 0x7f) << shift);
        *offset += 1;
        shift += 7;
        if ((b & 0x80) == 0) /* End of varint */
            return true;
    }
    return false;
}

static int dissect_minecraft_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint32 len)
{
    const guint offset_start = offset;
    guint32 packet_id = 0;
    read_varint(&packet_id, tvb, &offset);
    const guint packet_id_len = offset - offset_start;
    proto_tree_add_uint(tree, hf_packet_id, tvb, offset_start, packet_id_len, packet_id);

    const guint data_len = len - packet_id_len;
    proto_item *data_item = proto_tree_add_item(tree, hf_data, tvb, offset, data_len, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(data_item, ett_data);
}

static int dissect_minecraft(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    while (offset < tvb_reported_length(tvb)) {
        gint available = tvb_reported_length_remaining(tvb, offset);
        guint32 len = 0;
        const guint offset_start = offset;
        if (read_varint(&len, tvb, &offset) == false) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return (offset + available);
        }

        if (len > available) {
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = len - available;
            return (offset + available);
        }

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "minecraft");

        proto_item *item = proto_tree_add_item(tree, proto_minecraft, tvb, offset, len, ENC_NA);

        proto_tree *subtree = proto_item_add_subtree(item, ett_minecraft);

        proto_tree_add_uint(subtree, hf_length, tvb, offset_start, offset - offset_start, len);

        dissect_minecraft_packet(tvb, pinfo, subtree, offset, len);

        offset += (guint)len;
    }

    return tvb_captured_length(tvb);
}

static void proto_register_minecraft(void)
{
    proto_minecraft = proto_register_protocol("Minecraft Protocol", "Minecraft", "minecraft");

    proto_register_field_array(proto_minecraft, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static void proto_reg_handoff_minecraft(void)
{

    dissector_handle_t handle_minecraft = create_dissector_handle(dissect_minecraft, proto_minecraft);
    dissector_add_uint("tcp.port", 25565, handle_minecraft);
}

void plugin_register(void)
{
    static proto_plugin plug;

    plug.register_protoinfo = proto_register_minecraft;
    plug.register_handoff = proto_reg_handoff_minecraft;
    proto_register_plugin(&plug);
}
