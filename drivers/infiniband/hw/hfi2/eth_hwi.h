/* SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause */
/*
 * Copyright (c) 2026, Cornelis Networks
 *
 * Hardware interface
 */

#ifndef _HWI_H
#define _HWI_H

#include <linux/bitfield.h>
#include <linux/types.h>

#define CYR_EAL_CFG 0x0700000

#define CYR_SEND_CTXT_CHECK_L4_0X40_0X7F (CYR_TXE + 0x00000038A000)
#define CYR_SEND_CTXT_CHECK_L4_0X40_0X7F_RESETCSR 0x0000000000000000ull
#define CYR_SEND_CTXT_CHECK_L4_0X40_0X7F_ENABLE_SHIFT 0
#define CYR_SEND_CTXT_CHECK_L4_0X40_0X7F_ENABLE_MASK 0xFFFFFFFFFFFFFFFFull
#define CYR_SEND_CTXT_CHECK_L4_0X40_0X7F_ENABLE_SMASK 0xFFFFFFFFFFFFFFFFull

/* 14.13.3.26 SendLenCheck0 register */
/*
 * Bits [47:36]: LenVL3 field
 * Packets sent on VL3 with an LRH.PktLen that exceeds this value (in DWs)
 * will fail the integrity check if enabled. Maximum header size plus MTU
 * of payload (in DWs).
 */
#define SEND_LEN_CHECK0_LEN_VL3_MASK                    GENMASK_ULL(47, 36)
#define SEND_LEN_CHECK0_GET_LEN_VL3(r) FIELD_GET(SEND_LEN_CHECK0_LEN_VL3_MASK, (r))
#define SEND_LEN_CHECK0_SET_LEN_VL3(r, v) \
	{(r) = ((r) & ~SEND_LEN_CHECK0_LEN_VL3_MASK) | FIELD_PREP(SEND_LEN_CHECK0_LEN_VL3_MASK,\
	(v)); }

/*
 * Bits [35:24]: LenVL2 field
 * Packets sent on VL2 with an LRH.PktLen that exceeds this value (in DWs)
 * will fail the integrity check if enabled. Maximum header size plus MTU
 * of payload (in DWs).
 */
#define SEND_LEN_CHECK0_LEN_VL2_MASK                    GENMASK_ULL(35, 24)
#define SEND_LEN_CHECK0_GET_LEN_VL2(r) FIELD_GET(SEND_LEN_CHECK0_LEN_VL2_MASK, (r))
#define SEND_LEN_CHECK0_SET_LEN_VL2(r, v) \
	{(r) = ((r) & ~SEND_LEN_CHECK0_LEN_VL2_MASK) | FIELD_PREP(SEND_LEN_CHECK0_LEN_VL2_MASK,\
	(v)); }

/*
 * Bits [23:12]: LenVL1 field
 * Packets sent on VL1 with an LRH.PktLen that exceeds this value (in DWs)
 * will fail the integrity check if enabled. Maximum header size plus MTU
 * of payload (in DWs).
 */
#define SEND_LEN_CHECK0_LEN_VL1_MASK                    GENMASK_ULL(23, 12)
#define SEND_LEN_CHECK0_GET_LEN_VL1(r) FIELD_GET(SEND_LEN_CHECK0_LEN_VL1_MASK, (r))
#define SEND_LEN_CHECK0_SET_LEN_VL1(r, v)  \
	{(r) = ((r) & ~SEND_LEN_CHECK0_LEN_VL1_MASK) | FIELD_PREP(SEND_LEN_CHECK0_LEN_VL1_MASK,\
	(v)); }

/*
 * Bits [11:0]: LenVL0 field
 * Packets sent on VL0 with an LRH.PktLen that exceeds this value (in DWs)
 * will fail the integrity check if enabled. Maximum header size plus MTU
 * of payload (in DWs).
 */
#ifndef DEF_CHIP_REG  /* the following already defined in chip_registers.h */
#define SEND_LEN_CHECK0_LEN_VL0_MASK                    GENMASK_ULL(11, 0)
#endif
#define SEND_LEN_CHECK0_GET_LEN_VL0(r) FIELD_GET(SEND_LEN_CHECK0_LEN_VL0_MASK, (r))
#define SEND_LEN_CHECK0_SET_LEN_VL0(r, v)  \
	{(r) = ((r) & ~SEND_LEN_CHECK0_LEN_VL0_MASK) | FIELD_PREP(SEND_LEN_CHECK0_LEN_VL0_MASK,\
	(v)); }

/* 14.13.3.27 SendLenCheck1 register */
/*
 * Bits [59:48]: LenVL15 field
 * Packets sent on VL15 with an LRH.PktLen that exceeds this value (in DWs)
 * will fail the integrity check if enabled. Maximum header size plus MTU
 * of payload (in DWs).
 */
#ifndef DEF_CHIP_REG  /* the following already defined in chip_registers.h */
#define SEND_LEN_CHECK1_LEN_VL15_MASK                   GENMASK_ULL(59, 48)
#endif
#define SEND_LEN_CHECK1_GET_LEN_VL15(r) FIELD_GET(SEND_LEN_CHECK1_LEN_VL15_MASK, (r))
#define SEND_LEN_CHECK1_SET_LEN_VL15(r, v)  \
	{(r) = ((r) & ~SEND_LEN_CHECK1_LEN_VL15_MASK) | FIELD_PREP(SEND_LEN_CHECK1_LEN_VL15_MASK,\
	(v)); }

/*
 * Bits [47:36]: LenVL7 field
 * Packets sent on VL7 with an LRH.PktLen that exceeds this value (in DWs)
 * will fail the integrity check if enabled. Maximum header size plus MTU
 * of payload (in DWs).
 */
#define SEND_LEN_CHECK1_LEN_VL7_MASK                    GENMASK_ULL(47, 36)
#define SEND_LEN_CHECK1_GET_LEN_VL7(r) FIELD_GET(SEND_LEN_CHECK1_LEN_VL7_MASK, (r))
#define SEND_LEN_CHECK1_SET_LEN_VL7(r, v)  \
	{(r) = ((r) & ~SEND_LEN_CHECK1_LEN_VL7_MASK) |\
	FIELD_PREP(SEND_LEN_CHECK1_LEN_VL7_MASK, (v)); }

/*
 * Bits [35:24]: LenVL6 field
 * Packets sent on VL6 with an LRH.PktLen that exceeds this value (in DWs)
 * will fail the integrity check if enabled. Maximum header size plus MTU
 * of payload (in DWs).
 */
#define SEND_LEN_CHECK1_LEN_VL6_MASK                    GENMASK_ULL(35, 24)
#define SEND_LEN_CHECK1_GET_LEN_VL6(r) FIELD_GET(SEND_LEN_CHECK1_LEN_VL6_MASK, (r))
#define SEND_LEN_CHECK1_SET_LEN_VL6(r, v)  \
	{(r) = ((r) & ~SEND_LEN_CHECK1_LEN_VL6_MASK) |\
	FIELD_PREP(SEND_LEN_CHECK1_LEN_VL6_MASK, (v)); }

/*
 * Bits [23:12]: LenVL5 field
 * Packets sent on VL5 with an LRH.PktLen that exceeds this value (in DWs)
 * will fail the integrity check if enabled. Maximum header size plus MTU
 * of payload (in DWs).
 */
#define SEND_LEN_CHECK1_LEN_VL5_MASK                    GENMASK_ULL(23, 12)
#define SEND_LEN_CHECK1_GET_LEN_VL5(r) FIELD_GET(SEND_LEN_CHECK1_LEN_VL5_MASK, (r))
#define SEND_LEN_CHECK1_SET_LEN_VL5(r, v)  \
	{(r) = ((r) & ~SEND_LEN_CHECK1_LEN_VL5_MASK) |\
	FIELD_PREP(SEND_LEN_CHECK1_LEN_VL5_MASK, (v)); }

/*
 * Bits [11:0]: LenVL4 field
 * Packets sent on VL4 with an LRH.PktLen that exceeds this value (in DWs)
 * will fail the integrity check if enabled. Maximum header size plus MTU
 * of payload (in DWs).
 */
#ifndef DEF_CHIP_REG  /* the following already defined in chip_registers.h */
#define SEND_LEN_CHECK1_LEN_VL4_MASK                    GENMASK_ULL(11, 0)
#endif
#define SEND_LEN_CHECK1_GET_LEN_VL4(r) FIELD_GET(SEND_LEN_CHECK1_LEN_VL4_MASK, (r))
#define SEND_LEN_CHECK1_SET_LEN_VL4(r, v)  \
	{(r) = ((r) & ~SEND_LEN_CHECK1_LEN_VL4_MASK) |\
	FIELD_PREP(SEND_LEN_CHECK1_LEN_VL4_MASK, (v)); }


/* 14.14.3.19 RcvRsmCfg register */
/*
 * Bits [62:60]: PacketType field
 * Packet type for this RSM match:
 *   0x0 = expected receive packet
 *   0x1 = eager receive packet
 *   0x2 = verbs packet (i.e. 9B or 16B non-KDETH packet)
 *   0x3 = reserved (RSM of error packets is not supported)
 *   0x4 = bypass packet
 *   0x5 to 0x7 = reserved
 */
#define RCV_RSM_CFG_PACKET_TYPE_MASK                    GENMASK_ULL(62, 60)
#define RCV_RSM_CFG_PACKET_TYPE_EXPECTED	0
#define RCV_RSM_CFG_PACKET_TYPE_EAGER		1
#define RCV_RSM_CFG_PACKET_TYPE_VERBS		2
#define RCV_RSM_CFG_PACKET_TYPE_BYPASS		4
#define RCV_RSM_CFG_GET_PACKET_TYPE(r) FIELD_GET(RCV_RSM_CFG_PACKET_TYPE_MASK, (r))
#define RCV_RSM_CFG_SET_PACKET_TYPE(r, v)  \
	{(r) = ((r) & ~RCV_RSM_CFG_PACKET_TYPE_MASK) | \
	FIELD_PREP(RCV_RSM_CFG_PACKET_TYPE_MASK, (v)); }

/*
 * Bits [53:48]: BypassHdrSize field
 * Header size in DWs for bypass packets that match the RSM condition.
 * Minimum value is 0 DWs
 * Maximum value is 63 DWs
 * Note that all values are supported
 */
#define RCV_RSM_CFG_BYPASS_HDR_SIZE_MASK                GENMASK_ULL(53, 48)
#define RCV_RSM_CFG_GET_BYPASS_HDR_SIZE(r) FIELD_GET(RCV_RSM_CFG_BYPASS_HDR_SIZE_MASK, (r))
#define RCV_RSM_CFG_SET_BYPASS_HDR_SIZE(r, v)  \
	{(r) = ((r) & ~RCV_RSM_CFG_BYPASS_HDR_SIZE_MASK) | \
	FIELD_PREP(RCV_RSM_CFG_BYPASS_HDR_SIZE_MASK, (v)); }

/*
 * Bits [41:40]: PortEnableMask field
 * This bit field indicates the set of ingress ports that this RSM instance can possibly
 * match against. It is legal for multiple bits to be set. If this field is 0 or the packet
 * is from an ingress port whose corresponding PortEnableMask is off, then this RSM rule
 * is defined to not match. If the port is enabled in the PortEnableMask then the normal
 * packet matching rules are applied to determine a match.
 * Bits are defined as follows:
 *   Bit 0 - Fabric Port 1
 *   Bit 1 - Loopback Port 1
 */
#define RCV_RSM_CFG_PORT_ENABLE_MASK_MASK               GENMASK_ULL(41, 40)
#define RCV_RSM_CFG_GET_PORT_ENABLE_MASK(r) FIELD_GET(RCV_RSM_CFG_PORT_ENABLE_MASK_MASK, (r))
#define RCV_RSM_CFG_SET_PORT_ENABLE_MASK(r, v)  \
	{(r) = ((r) & ~RCV_RSM_CFG_PORT_ENABLE_MASK_MASK) | \
	FIELD_PREP(RCV_RSM_CFG_PORT_ENABLE_MASK_MASK, (v)); }

/*
 * Bits [24:16]: Offset field
 * The offset for the calculated 8-bit RSM index into the RcvRsmMapTable.
 * Range: 0-511 (9 bits)
 */
#define RCV_RSM_CFG_OFFSET_MASK                         GENMASK_ULL(24, 16)
#define RCV_RSM_CFG_GET_OFFSET(r) FIELD_GET(RCV_RSM_CFG_OFFSET_MASK, (r))
#define RCV_RSM_CFG_SET_OFFSET(r, v)  \
	{(r) = ((r) & ~RCV_RSM_CFG_OFFSET_MASK) | FIELD_PREP(RCV_RSM_CFG_OFFSET_MASK, (v)); }

/*
 * Bit [3]: EnableOrChainRsm3 field
 * If this CSR is for RSM instance 3, this is the enable bit for RSM instance 3.
 * Otherwise, this is a chain bit and indicates whether RSM3 is chained into this RSM instance.
 *   1 = Enable RSM3 (if instance 3) OR Chain RSM3 into this instance
 *   0 = Disable RSM3 (if instance 3) OR Do not chain RSM3
 */
#define RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM3_MASK           BIT_ULL(3)
#define RCV_RSM_CFG_GET_ENABLE_OR_CHAIN_RSM3(r) \
	FIELD_GET(RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM3_MASK, (r))
#define RCV_RSM_CFG_SET_ENABLE_OR_CHAIN_RSM3(r, v)  \
	{(r) = ((r) & ~RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM3_MASK) | \
	FIELD_PREP(RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM3_MASK, (v)); }

/*
 * Bit [2]: EnableOrChainRsm2 field
 * If this CSR is for RSM instance 2, this is the enable bit for RSM instance 2.
 * Otherwise, this is a chain bit and indicates whether RSM2 is chained into this RSM instance.
 *   1 = Enable RSM2 (if instance 2) OR Chain RSM2 into this instance
 *   0 = Disable RSM2 (if instance 2) OR Do not chain RSM2
 */
#define RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM2_MASK           BIT_ULL(2)
#define RCV_RSM_CFG_GET_ENABLE_OR_CHAIN_RSM2(r) \
	FIELD_GET(RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM2_MASK, (r))
#define RCV_RSM_CFG_SET_ENABLE_OR_CHAIN_RSM2(r, v)  \
	{(r) = ((r) & ~RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM2_MASK) | \
	FIELD_PREP(RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM2_MASK, (v)); }

/*
 * Bit [1]: EnableOrChainRsm1 field
 * If this CSR is for RSM instance 1, this is the enable bit for RSM instance 1.
 * Otherwise, this is a chain bit and indicates whether RSM1 is chained into this RSM instance.
 *   1 = Enable RSM1 (if instance 1) OR Chain RSM1 into this instance
 *   0 = Disable RSM1 (if instance 1) OR Do not chain RSM1
 */
#define RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM1_MASK           BIT_ULL(1)
#define RCV_RSM_CFG_GET_ENABLE_OR_CHAIN_RSM1(r) \
	FIELD_GET(RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM1_MASK, (r))
#define RCV_RSM_CFG_SET_ENABLE_OR_CHAIN_RSM1(r, v)  \
	{(r) = ((r) & ~RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM1_MASK) | \
	FIELD_PREP(RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM1_MASK, (v)); }

/*
 * Bit [0]: EnableOrChainRsm0 field
 * If this CSR is for RSM instance 0, this is the enable bit for RSM instance 0.
 * Otherwise, this is a chain bit and indicates whether RSM0 is chained into this RSM instance.
 *   1 = Enable RSM0 (if instance 0) OR Chain RSM0 into this instance
 *   0 = Disable RSM0 (if instance 0) OR Do not chain RSM0
 */
#ifndef DEF_CHIP_REG
#define RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM0_MASK           BIT_ULL(0)
#endif
#define RCV_RSM_CFG_GET_ENABLE_OR_CHAIN_RSM0(r) \
	FIELD_GET(RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM0_MASK, (r))
#define RCV_RSM_CFG_SET_ENABLE_OR_CHAIN_RSM0(r, v)  \
	{(r) = ((r) & ~RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM0_MASK) | \
	FIELD_PREP(RCV_RSM_CFG_ENABLE_OR_CHAIN_RSM0_MASK, (v)); }

/* 14.14.3.20 RcvRsmSelect register */
/*
 * Bits [63:60]: Index2Width field
 * Selects width of index 2 in range of 0 to 8 bits.
 * Valid values: 0 to 8 bits
 * Reserved values: 9 to 15
 * Index 2 is used as part of the RSM index calculation to map packets to receive contexts.
 */
#define RCV_RSM_SELECT_INDEX2_WIDTH_MASK                GENMASK_ULL(63, 60)
#define RCV_RSM_SELECT_GET_INDEX2_WIDTH(r) FIELD_GET(RCV_RSM_SELECT_INDEX2_WIDTH_MASK, (r))
#define RCV_RSM_SELECT_SET_INDEX2_WIDTH(r, v)  \
	{(r) = ((r) & ~RCV_RSM_SELECT_INDEX2_WIDTH_MASK) |\
	FIELD_PREP(RCV_RSM_SELECT_INDEX2_WIDTH_MASK, (v)); }

/*
 * Bits [57:48]: Index2Offset field
 * Selects start position (least significant bit) of index 2 in the range of 0 to 1023 bits
 * relative to the beginning of the packet.
 * The most significant bit of index 2 is at bit position (Index2Offset + Index2Width - 1).
 */
#define RCV_RSM_SELECT_INDEX2_OFFSET_MASK               GENMASK_ULL(57, 48)
#define RCV_RSM_SELECT_GET_INDEX2_OFFSET(r) FIELD_GET(RCV_RSM_SELECT_INDEX2_OFFSET_MASK, (r))
#define RCV_RSM_SELECT_SET_INDEX2_OFFSET(r, v)  \
	{(r) = ((r) & ~RCV_RSM_SELECT_INDEX2_OFFSET_MASK) | \
	FIELD_PREP(RCV_RSM_SELECT_INDEX2_OFFSET_MASK, (v)); }

/*
 * Bits [47:44]: Index1Width field
 * Selects width of index 1 in range of 0 to 8 bits.
 * Valid values: 0 to 8 bits
 * Reserved values: 9 to 15
 * Index 1 is used as part of the RSM index calculation to map packets to receive contexts.
 */
#define RCV_RSM_SELECT_INDEX1_WIDTH_MASK                GENMASK_ULL(47, 44)
#define RCV_RSM_SELECT_GET_INDEX1_WIDTH(r) FIELD_GET(RCV_RSM_SELECT_INDEX1_WIDTH_MASK, (r))
#define RCV_RSM_SELECT_SET_INDEX1_WIDTH(r, v)  \
	{(r) = ((r) & ~RCV_RSM_SELECT_INDEX1_WIDTH_MASK) | \
	FIELD_PREP(RCV_RSM_SELECT_INDEX1_WIDTH_MASK, (v)); }

/*
 * Bits [41:32]: Index1Offset field
 * Selects start position (least significant bit) of index 1 in the range of 0 to 1023 bits
 * relative to the beginning of the packet.
 * The most significant bit of index 1 is at bit position (Index1Offset + Index1Width - 1).
 */
#define RCV_RSM_SELECT_INDEX1_OFFSET_MASK               GENMASK_ULL(41, 32)
#define RCV_RSM_SELECT_GET_INDEX1_OFFSET(r) FIELD_GET(RCV_RSM_SELECT_INDEX1_OFFSET_MASK, (r))
#define RCV_RSM_SELECT_SET_INDEX1_OFFSET(r, v)  \
	{(r) = ((r) & ~RCV_RSM_SELECT_INDEX1_OFFSET_MASK) | \
	FIELD_PREP(RCV_RSM_SELECT_INDEX1_OFFSET_MASK, (v)); }

/*
 * Bits [25:16]: Field2Offset field
 * Selects start position (least significant bit) of field 2 in the range of 0 to 1023 bits
 * relative to the beginning of the packet.
 * Field 2 is used for packet header matching in RSM classification.
 * The field is always 8 bits wide. The most significant bit is at (Field2Offset + 7).
 */
#define RCV_RSM_SELECT_FIELD2_OFFSET_MASK               GENMASK_ULL(25, 16)
#define RCV_RSM_SELECT_GET_FIELD2_OFFSET(r) FIELD_GET(RCV_RSM_SELECT_FIELD2_OFFSET_MASK, (r))
#define RCV_RSM_SELECT_SET_FIELD2_OFFSET(r, v)  \
	{(r) = ((r) & ~RCV_RSM_SELECT_FIELD2_OFFSET_MASK) | \
	FIELD_PREP(RCV_RSM_SELECT_FIELD2_OFFSET_MASK, (v)); }

/*
 * Bits [9:0]: Field1Offset field
 * Selects start position (least significant bit) of field 1 in the range of 0 to 1023 bits
 * relative to the beginning of the packet.
 * Field 1 is used for packet header matching in RSM classification.
 * The field is always 8 bits wide. The most significant bit is at (Field1Offset + 7).
 */
#define RCV_RSM_SELECT_FIELD1_OFFSET_MASK               GENMASK_ULL(9, 0)
#define RCV_RSM_SELECT_GET_FIELD1_OFFSET(r) FIELD_GET(RCV_RSM_SELECT_FIELD1_OFFSET_MASK, (r))
#define RCV_RSM_SELECT_SET_FIELD1_OFFSET(r, v)  \
	{(r) = ((r) & ~RCV_RSM_SELECT_FIELD1_OFFSET_MASK) | \
	FIELD_PREP(RCV_RSM_SELECT_FIELD1_OFFSET_MASK, (v)); }

/* 14.14.3.21 RcvRsmMatch register is used for configuring the match criteria for RSM instance. */
/*
 * Bit 33: MatchInvertField2 field
 * The result of comparing field2 against the mask and match values should be
 * inverted when deciding if this RSM rule is a match.
 * 0 = Normal match (field2 must equal (packet_bits & Mask2) == Value2)
 * 1 = Inverted match (field2 must NOT equal, i.e., (packet_bits & Mask2) != Value2)
 */
#define RCV_RSM_MATCH_MATCH_INVERT_FIELD2_MASK          BIT_ULL(33)
#define RCV_RSM_MATCH_GET_MATCH_INVERT_FIELD2(r) \
	FIELD_GET(RCV_RSM_MATCH_MATCH_INVERT_FIELD2_MASK, (r))
#define RCV_RSM_MATCH_SET_MATCH_INVERT_FIELD2(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MATCH_MATCH_INVERT_FIELD2_MASK) | \
	FIELD_PREP(RCV_RSM_MATCH_MATCH_INVERT_FIELD2_MASK, (v)); }

/*
 * Bit 32: MatchInvertField1 field
 * The result of comparing field1 against the mask and match values should be
 * inverted when deciding if this RSM rule is a match.
 * 0 = Normal match (field1 must equal (packet_bits & Mask1) == Value1)
 * 1 = Inverted match (field1 must NOT equal, i.e., (packet_bits & Mask1) != Value1)
 */
#define RCV_RSM_MATCH_MATCH_INVERT_FIELD1_MASK          BIT_ULL(32)
#define RCV_RSM_MATCH_GET_MATCH_INVERT_FIELD1(r) \
	FIELD_GET(RCV_RSM_MATCH_MATCH_INVERT_FIELD1_MASK, (r))
#define RCV_RSM_MATCH_SET_MATCH_INVERT_FIELD1(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MATCH_MATCH_INVERT_FIELD1_MASK) | \
	FIELD_PREP(RCV_RSM_MATCH_MATCH_INVERT_FIELD1_MASK, (v)); }

/*
 * Bits [31:24]: Value2 field
 * 8-bit value for field 2 match.
 * Field 2 bits extracted from packet (at offset specified in RcvRsmSelect) are
 * ANDed with Mask2 and compared against Value2 to determine if this RSM rule matches.
 * Match condition: (packet_field2 & Mask2) == Value2 (or != if MatchInvertField2 is set)
 */
#define RCV_RSM_MATCH_VALUE2_MASK                       GENMASK_ULL(31, 24)
#define RCV_RSM_MATCH_GET_VALUE2(r) FIELD_GET(RCV_RSM_MATCH_VALUE2_MASK, (r))
#define RCV_RSM_MATCH_SET_VALUE2(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MATCH_VALUE2_MASK) | FIELD_PREP(RCV_RSM_MATCH_VALUE2_MASK, (v)); }

/*
 * Bits [23:16]: Mask2 field
 * 8-bit mask for field 2 match.
 * Specifies which bits of field 2 are significant for matching.
 * Bit = 1: This bit position must match
 * Bit = 0: This bit position is don't care (ignored)
 * Applied as: (packet_field2 & Mask2) == Value2
 */
#define RCV_RSM_MATCH_MASK2_MASK                        GENMASK_ULL(23, 16)
#define RCV_RSM_MATCH_GET_MASK2(r) FIELD_GET(RCV_RSM_MATCH_MASK2_MASK, (r))
#define RCV_RSM_MATCH_SET_MASK2(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MATCH_MASK2_MASK) | FIELD_PREP(RCV_RSM_MATCH_MASK2_MASK, (v)); }

/*
 * Bits [15:8]: Value1 field
 * 8-bit value for field 1 match.
 * Field 1 bits extracted from packet (at offset specified in RcvRsmSelect) are
 * ANDed with Mask1 and compared against Value1 to determine if this RSM rule matches.
 * Match condition: (packet_field1 & Mask1) == Value1 (or != if MatchInvertField1 is set)
 */
#define RCV_RSM_MATCH_VALUE1_MASK                       GENMASK_ULL(15, 8)
#define RCV_RSM_MATCH_GET_VALUE1(r) FIELD_GET(RCV_RSM_MATCH_VALUE1_MASK, (r))
#define RCV_RSM_MATCH_SET_VALUE1(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MATCH_VALUE1_MASK) | FIELD_PREP(RCV_RSM_MATCH_VALUE1_MASK, (v)); }

/*
 * Bits [7:0]: Mask1 field
 * 8-bit mask for field 1 match.
 * Specifies which bits of field 1 are significant for matching.
 * Bit = 1: This bit position must match
 * Bit = 0: This bit position is don't care (ignored)
 * Applied as: (packet_field1 & Mask1) == Value1
 */
#define RCV_RSM_MATCH_MASK1_MASK                        GENMASK_ULL(7, 0)
#define RCV_RSM_MATCH_GET_MASK1(r) FIELD_GET(RCV_RSM_MATCH_MASK1_MASK, (r))
#define RCV_RSM_MATCH_SET_MASK1(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MATCH_MASK1_MASK) | FIELD_PREP(RCV_RSM_MATCH_MASK1_MASK, (v)); }

/* 14.14.3.22 RcvRsmMapTable register */
/*
 * Bits [56:48]: RcvContextD field
 * Receive context used when the RSM index is equal to (i * 4) + 3,
 * where i is the index of this CSR in the RcvRsmMapTable array (0-127).
 * Valid values: 0 to RXE_MAX_CONTEXTS (typically 255)
 * Invalid values (> RXE_MAX_CONTEXTS): cause packets to be dropped
 */
#define RCV_RSM_MAP_TABLE_RCV_CONTEXT_D_MASK            GENMASK_ULL(56, 48)
#define RCV_RSM_MAP_TABLE_GET_RCV_CONTEXT_D(r) \
	FIELD_GET(RCV_RSM_MAP_TABLE_RCV_CONTEXT_D_MASK, (r))
#define RCV_RSM_MAP_TABLE_SET_RCV_CONTEXT_D(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MAP_TABLE_RCV_CONTEXT_D_MASK) | \
	FIELD_PREP(RCV_RSM_MAP_TABLE_RCV_CONTEXT_D_MASK, (v)); }

/*
 * Bits [40:32]: RcvContextC field
 * Receive context used when the RSM index is equal to (i * 4) + 2,
 * where i is the index of this CSR in the RcvRsmMapTable array (0-127).
 * Valid values: 0 to RXE_MAX_CONTEXTS (typically 255)
 * Invalid values (> RXE_MAX_CONTEXTS): cause packets to be dropped
 */
#define RCV_RSM_MAP_TABLE_RCV_CONTEXT_C_MASK            GENMASK_ULL(40, 32)
#define RCV_RSM_MAP_TABLE_GET_RCV_CONTEXT_C(r) \
	FIELD_GET(RCV_RSM_MAP_TABLE_RCV_CONTEXT_C_MASK, (r))
#define RCV_RSM_MAP_TABLE_SET_RCV_CONTEXT_C(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MAP_TABLE_RCV_CONTEXT_C_MASK) | \
	FIELD_PREP(RCV_RSM_MAP_TABLE_RCV_CONTEXT_C_MASK, (v)); }

/*
 * Bits [24:16]: RcvContextB field
 * Receive context used when the RSM index is equal to (i * 4) + 1,
 * where i is the index of this CSR in the RcvRsmMapTable array (0-127).
 * Valid values: 0 to RXE_MAX_CONTEXTS (typically 255)
 * Invalid values (> RXE_MAX_CONTEXTS): cause packets to be dropped
 */
#define RCV_RSM_MAP_TABLE_RCV_CONTEXT_B_MASK            GENMASK_ULL(24, 16)
#define RCV_RSM_MAP_TABLE_GET_RCV_CONTEXT_B(r) FIELD_GET(RCV_RSM_MAP_TABLE_RCV_CONTEXT_B_MASK, (r))
#define RCV_RSM_MAP_TABLE_SET_RCV_CONTEXT_B(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MAP_TABLE_RCV_CONTEXT_B_MASK) | \
	FIELD_PREP(RCV_RSM_MAP_TABLE_RCV_CONTEXT_B_MASK, (v)); }

/*
 * Bits [8:0]: RcvContextA field
 * Receive context used when the RSM index is equal to (i * 4) + 0,
 * where i is the index of this CSR in the RcvRsmMapTable array (0-127).
 * Valid values: 0 to RXE_MAX_CONTEXTS (typically 255)
 * Invalid values (> RXE_MAX_CONTEXTS): cause packets to be dropped
 */
#define RCV_RSM_MAP_TABLE_RCV_CONTEXT_A_MASK            GENMASK_ULL(8, 0)
#define RCV_RSM_MAP_TABLE_GET_RCV_CONTEXT_A(r) FIELD_GET(RCV_RSM_MAP_TABLE_RCV_CONTEXT_A_MASK, (r))
#define RCV_RSM_MAP_TABLE_SET_RCV_CONTEXT_A(r, v)  \
	{(r) = ((r) & ~RCV_RSM_MAP_TABLE_RCV_CONTEXT_A_MASK) | \
	FIELD_PREP(RCV_RSM_MAP_TABLE_RCV_CONTEXT_A_MASK, (v)); }

/* TOD_CTRL register */
#define TOD_CONTROL_OFFSET (CYR_EAL_CFG) /* 0x700000 */

/*
 * Bit [31]: SOC_RESET field
 * NOTE: This bit only affects the datapath and alarm/defect/counters logic.
 * This does not affect the regmap control RW registers.
 *   0 = SoC datapath logic active
 *   1 = SoC datapath logic in reset
 */
#define CONTROL_SOC_RESET_MASK                          BIT(31)
#define CONTROL_GET_SOC_RESET(r) FIELD_GET(CONTROL_SOC_RESET_MASK, (r))
#define CONTROL_SET_SOC_RESET(r, v)  \
	{(r) = ((r) & ~CONTROL_SOC_RESET_MASK) | FIELD_PREP(CONTROL_SOC_RESET_MASK, (v)); }

/*
 * Bit [30]: USE_LOCAL_TOD_MASTER_CLK field
 * Enable Update of TOD from a local crystal/TOD master.
 * This bit has precedence over AUTO_TOD_UP_ENABLE.
 *   1 = enable
 *   0 = disable
 */
#define CONTROL_USE_LOCAL_TOD_MASTER_CLK_MASK           BIT(30)
#define CONTROL_GET_USE_LOCAL_TOD_MASTER_CLK(r) \
	FIELD_GET(CONTROL_USE_LOCAL_TOD_MASTER_CLK_MASK, (r))
#define CONTROL_SET_USE_LOCAL_TOD_MASTER_CLK(r, v)  \
	{(r) = ((r) & ~CONTROL_USE_LOCAL_TOD_MASTER_CLK_MASK) | \
	FIELD_PREP(CONTROL_USE_LOCAL_TOD_MASTER_CLK_MASK, (v)); }

/*
 * Bit [6]: USE_PTP_EVENT_MSG_TYPE_FILTER field
 * Enable PTP Event Message Filter for the PTP event message capture.
 * When enabled, only the PTP event message type matches the EXP_EVENT_MSG_TYPE
 * value will be used by the PTP packet parser.
 *   1 = enable MSG_EVENT filter
 *   0 = disable
 */
#define CONTROL_USE_PTP_EVENT_MSG_TYPE_FILTER_MASK      BIT(6)
#define CONTROL_GET_USE_PTP_EVENT_MSG_TYPE_FILTER(r) \
	FIELD_GET(CONTROL_USE_PTP_EVENT_MSG_TYPE_FILTER_MASK, (r))
#define CONTROL_SET_USE_PTP_EVENT_MSG_TYPE_FILTER(r, v)  \
	{(r) = ((r) & ~CONTROL_USE_PTP_EVENT_MSG_TYPE_FILTER_MASK) | \
	FIELD_PREP(CONTROL_USE_PTP_EVENT_MSG_TYPE_FILTER_MASK, (v)); }

/*
 * Bit [5]: USE_DA_FILTER field
 * Enable Destination Address (DA) Filter for the PTP event message capture.
 * When enabled, only the DA matches the EXP_DA value will be used by the
 * PTP packet parser.
 *   1 = enable DA filter
 *   0 = disable
 */
#define CONTROL_USE_DA_FILTER_MASK                      BIT(5)
#define CONTROL_GET_USE_DA_FILTER(r) FIELD_GET(CONTROL_USE_DA_FILTER_MASK, (r))
#define CONTROL_SET_USE_DA_FILTER(r, v)  \
	{(r) = ((r) & ~CONTROL_USE_DA_FILTER_MASK) | \
	FIELD_PREP(CONTROL_USE_DA_FILTER_MASK, (v)); }

/*
 * Bit [4]: USE_SA_FILTER field
 * Enable Source Address (SA) Filter for the PTP event message capture.
 * When enabled, only the SA matches the EXP_SA value will be used by the
 * PTP packet parser.
 *   1 = enable SA filter
 *   0 = disable
 */
#define CONTROL_USE_SA_FILTER_MASK                      BIT(4)
#define CONTROL_GET_USE_SA_FILTER(r) FIELD_GET(CONTROL_USE_SA_FILTER_MASK, (r))
#define CONTROL_SET_USE_SA_FILTER(r, v)  \
	{(r) = ((r) & ~CONTROL_USE_SA_FILTER_MASK) | \
	FIELD_PREP(CONTROL_USE_SA_FILTER_MASK, (v)); }

/*
 * Bit [3]: FORCE_SW_TOD_ADJ_PARA_UPDATE field
 * The rising edge (0 to 1 transition) to replace the internal TIME/PERIOD_ADJ
 * values with the Software programmed TIME/PERIOD_ADJ value
 */
#define CONTROL_FORCE_SW_TOD_ADJ_PARA_UPDATE_MASK       BIT(3)
#define CONTROL_FORCE_SW_TOD_ADJ_PARA_UPDATE(r) \
	FIELD_GET(CONTROL_FORCE_SW_TOD_ADJ_PARA_UPDATE_MASK, (r))
#define CONTROL_SET_FORCE_SW_TOD_ADJ_PARA_UPDATE(r, v)  \
	{(r) = ((r) & ~CONTROL_FORCE_SW_TOD_ADJ_PARA_UPDATE_MASK) | \
	FIELD_PREP(CONTROL_FORCE_SW_TOD_ADJ_PARA_UPDATE_MASK, (v)); }

/*
 * Bit [2]: FORCE_SW_TOD_UPDATE field
 * The rising edge (0 to 1 transition) to replace the internal TOD with the
 * Software programmed TOD value (SW_FRC_TOD_*)
 */
#define CONTROL_FORCE_SW_TOD_UPDATE_MASK                BIT(2)
#define CONTROL_GET_FORCE_SW_TOD_UPDATE(r) FIELD_GET(CONTROL_FORCE_SW_TOD_UPDATE_MASK, (r))
#define CONTROL_SET_FORCE_SW_TOD_UPDATE(r, v)  \
	{(r) = ((r) & ~CONTROL_FORCE_SW_TOD_UPDATE_MASK) | \
	FIELD_PREP(CONTROL_FORCE_SW_TOD_UPDATE_MASK, (v)); }

/*
 * Bit [1]: AUTO_TOD_UP_MODE field
 * Auto_sync TOD update PTP mode
 *   1 = 1 step timestamp update (i.e. use time info from Sync Event Message only)
 *   0 = 2 step timestamp update (i.e. use time info from Followup Event Message only)
 */
#define CONTROL_AUTO_TOD_UP_MODE_MASK                   BIT(1)
#define CONTROL_GET_AUTO_TOD_UP_MODE(r) FIELD_GET(CONTROL_AUTO_TOD_UP_MODE_MASK, (r))
#define CONTROL_SET_AUTO_TOD_UP_MODE(r, v)  \
	{(r) = ((r) & ~CONTROL_AUTO_TOD_UP_MODE_MASK) | \
	FIELD_PREP(CONTROL_AUTO_TOD_UP_MODE_MASK, (v)); }

/*
 * Bit [0]: AUTO_TOD_UP_ENABLE field
 * Enable control of Auto_sync TOD update.
 * This control bit is lower in priority than USE_LOCAL_TOD_MASTER_CLK.
 *   1 = enable
 *   0 = disable
 */
#define CONTROL_AUTO_TOD_UP_ENABLE_MASK                 BIT(0)
#define CONTROL_GET_AUTO_TOD_UP_ENABLE(r) FIELD_GET(CONTROL_AUTO_TOD_UP_ENABLE_MASK, (r))
#define CONTROL_SET_AUTO_TOD_UP_ENABLE(r, v)  \
	{(r) = ((r) & ~CONTROL_AUTO_TOD_UP_ENABLE_MASK) | \
	FIELD_PREP(CONTROL_AUTO_TOD_UP_ENABLE_MASK, (v)); }

#define TOD_SOC_INT_STATUS_OFFSET (CYR_EAL_CFG + 0x4 * 2)

#define TOD_CLK_PERIOD_OFFSET (CYR_EAL_CFG + 0x2c * 2)

#define TOD_SW_FRC_TOD0_OFFSET (CYR_EAL_CFG + 0x40 * 2)
#define TOD_SW_FRC_TOD1_OFFSET (CYR_EAL_CFG + 0x44 * 2)
#define TOD_SW_FRC_TOD2_OFFSET (CYR_EAL_CFG + 0x48 * 2)

#define TOD_ACC_PERIOD_ADJ (CYR_EAL_CFG + 0x50 * 2)

/* ACC_TIME_ADJ register */
#define TOD_ACC_TIME_ADJ (CYR_EAL_CFG + 0x54 * 2)

/*
 * Bit [31]: SIGN field
 * Sign bit for time adjustment value
 *   0 = ACC_TIME_ADJ value is positive (add to TOD)
 *   1 = ACC_TIME_ADJ value is negative (subtract from TOD)
 */
#define ACC_TIME_ADJ_SIGN_MASK          BIT(31)
#define ACC_TIME_ADJ_GET_SIGN(r) FIELD_GET(ACC_TIME_ADJ_SIGN_MASK, (r))
#define ACC_TIME_ADJ_SET_SIGN(r, v)  \
	{(r) = ((r) & ~ACC_TIME_ADJ_SIGN_MASK) | FIELD_PREP(ACC_TIME_ADJ_SIGN_MASK, (v)); }

/*
 * Bits [30:0]: Value field
 * Absolute magnitude of time adjustment value
 *   Bits [30:24] = nanoseconds (7 bits)
 *   Bits [23:0]  = fraction of nanoseconds (24 bits)
 * This is the absolute value; sign is indicated by SIGN field
 */
#define ACC_TIME_ADJ_NS_MASK            GENMASK(30, 24)  /* Nanosecond portion */
#define ACC_TIME_ADJ_GET_NS(r) FIELD_GET(ACC_TIME_ADJ_NS_MASK, (r))
#define ACC_TIME_ADJ_SET_NS(r, v)  \
	{(r) = ((r) & ~ACC_TIME_ADJ_NS_MASK) | FIELD_PREP(ACC_TIME_ADJ_NS_MASK, (v)); }

#define ACC_TIME_ADJ_FRAC_MASK          GENMASK(23, 0)   /* Fractional ns portion */
#define ACC_TIME_ADJ_GET_FRAC(r) FIELD_GET(ACC_TIME_ADJ_FRAC_MASK, (r))
#define ACC_TIME_ADJ_SET_FRAC(r, v)  \
	{(r) = ((r) & ~ACC_TIME_ADJ_FRAC_MASK) | FIELD_PREP(ACC_TIME_ADJ_FRAC_MASK, (v)); }

/* TOD register access functions.  Use for CUR_TODx and SW_FRC_TODx registers.
 * TOD0/1/2: TOD (Time of Day) value registers
 * The TOD value is split across three 32-bit registers forming a 96-bit timestamp:
 *   - *_TOD0: Fractional nanoseconds [15:0] and LSB of nanoseconds [31:16]
 *   - *_TOD1: MSB of nanoseconds [15:0] and LSB of seconds [31:16]
 *   - *_TOD2: MSB of seconds [31:0]
 */

/*
 * Bits [31:16]: NS_LSB field
 * Lower 16 bits of the nanosecond counter
 */
#define TOD0_NS_LSB_MASK            GENMASK(31, 16)
#define TOD0_GET_NS_LSB(r) FIELD_GET(TOD0_NS_LSB_MASK, (r))
#define TOD0_SET_NS_LSB(r, v)  \
	{(r) = ((r) & ~TOD0_NS_LSB_MASK) | FIELD_PREP(TOD0_NS_LSB_MASK, (v)); }

/*
 * Bits [15:0]: FRAC_NS field
 * Fractional nanoseconds (sub-nanosecond precision)
 */
#define TOD0_FRAC_NS_MASK           GENMASK(15, 0)
#define TOD0_GET_FRAC_NS(r) FIELD_GET(TOD0_FRAC_NS_MASK, (r))
#define TOD0_SET_FRAC_NS(r, v)  \
	{(r) = ((r) & ~TOD0_FRAC_NS_MASK) | FIELD_PREP(TOD0_FRAC_NS_MASK, (v)); }

/*
 * Bits [31:16]: SEC_LSB field
 * Lower 16 bits of the seconds counter
 */
#define TOD1_SEC_LSB_MASK           GENMASK(31, 16)
#define TOD1_GET_SEC_LSB(r) FIELD_GET(TOD1_SEC_LSB_MASK, (r))
#define TOD1_SET_SEC_LSB(r, v)  \
	{(r) = ((r) & ~TOD1_SEC_LSB_MASK) | FIELD_PREP(TOD1_SEC_LSB_MASK, (v)); }

/*
 * Bits [15:0]: NS_MSB field
 * Upper 16 bits of the nanosecond counter
 * Combined with CUR_TOD0.NS_LSB forms a 32-bit nanosecond value
 */
#define TOD1_NS_MSB_MASK            GENMASK(15, 0)
#define TOD1_GET_NS_MSB(r) FIELD_GET(TOD1_NS_MSB_MASK, (r))
#define TOD1_SET_NS_MSB(r, v)  \
	{(r) = ((r) & ~TOD1_NS_MSB_MASK) | FIELD_PREP(TOD1_NS_MSB_MASK, (v)); }

/*
 * Bits [31:0]: SEC_MSB field
 * Upper 32 bits of the seconds counter
 * Combined with CUR_TOD1.SEC_LSB forms a 48-bit seconds value
 */
#define TOD2_SEC_MSB_MASK           GENMASK(31, 0)
#define TOD2_GET_SEC_MSB(r) FIELD_GET(TOD2_SEC_MSB_MASK, (r))
#define TOD2_SET_SEC_MSB(r, v)  \
	{(r) = ((r) & ~TOD2_SEC_MSB_MASK) | FIELD_PREP(TOD2_SEC_MSB_MASK, (v)); }

/* CUR_TOD0 register */
#define TOD_CUR_TOD0_OFFSET (CYR_EAL_CFG + 0xc0 * 2)

/* CUR_TOD1 register */
#define TOD_CUR_TOD1_OFFSET (CYR_EAL_CFG + 0xc4 * 2)

/* CUR_TOD2 register */
#define TOD_CUR_TOD2_OFFSET (CYR_EAL_CFG + 0xc8 * 2)

/* D.4.3 EAL_RKEY_ALLOCATION register */
#define CYR_EAL_RKEY_ALLOCATION (CYR_EAL_CFG + 0xc0000 + 0x0 * 8)

/* D.4.4 EAL_BCAST_CFG register */
#define CYR_EAL_BCAST_CFG (CYR_EAL_CFG + 0xc0000 + 0x1 * 8)

/* D.4.5 EAL_LEN_LIMIT0 register */
#define CYR_EAL_LEN_LIMIT0 (CYR_EAL_CFG + 0xc0000 + 0x2 * 8)

/*
 * Bits [63:48]: MAX_LEN_VL3 field
 * Maximum frame length in bytes for Virtual Lane 3
 */
#define EAL_LEN_LIMIT0_MAX_LEN_VL3_MASK                 GENMASK_ULL(63, 48)
#define EAL_LEN_LIMIT0_GET_MAX_LEN_VL3(r) FIELD_GET(EAL_LEN_LIMIT0_MAX_LEN_VL3_MASK, (r))
#define EAL_LEN_LIMIT0_SET_MAX_LEN_VL3(r, v)  \
	{(r) = ((r) & ~EAL_LEN_LIMIT0_MAX_LEN_VL3_MASK) | \
	FIELD_PREP(EAL_LEN_LIMIT0_MAX_LEN_VL3_MASK, (v)); }

/*
 * Bits [47:32]: MAX_LEN_VL2 field
 * Maximum frame length in bytes for Virtual Lane 2
 */
#define EAL_LEN_LIMIT0_MAX_LEN_VL2_MASK                 GENMASK_ULL(47, 32)
#define EAL_LEN_LIMIT0_GET_MAX_LEN_VL2(r) FIELD_GET(EAL_LEN_LIMIT0_MAX_LEN_VL2_MASK, (r))
#define EAL_LEN_LIMIT0_SET_MAX_LEN_VL2(r, v)  \
	{(r) = ((r) & ~EAL_LEN_LIMIT0_MAX_LEN_VL2_MASK) | \
	FIELD_PREP(EAL_LEN_LIMIT0_MAX_LEN_VL2_MASK, (v)); }

/*
 * Bits [31:16]: MAX_LEN_VL1 field
 * Maximum frame length in bytes for Virtual Lane 1
 */
#define EAL_LEN_LIMIT0_MAX_LEN_VL1_MASK                 GENMASK_ULL(31, 16)
#define EAL_LEN_LIMIT0_GET_MAX_LEN_VL1(r) FIELD_GET(EAL_LEN_LIMIT0_MAX_LEN_VL1_MASK, (r))
#define EAL_LEN_LIMIT0_SET_MAX_LEN_VL1(r, v)  \
	{(r) = ((r) & ~EAL_LEN_LIMIT0_MAX_LEN_VL1_MASK) | \
	FIELD_PREP(EAL_LEN_LIMIT0_MAX_LEN_VL1_MASK, (v)); }

/*
 * Bits [15:0]: MAX_LEN_VL0 field
 * Maximum frame length in bytes for Virtual Lane 0
 */
#define EAL_LEN_LIMIT0_MAX_LEN_VL0_MASK                 GENMASK_ULL(15, 0)
#define EAL_LEN_LIMIT0_GET_MAX_LEN_VL0(r) FIELD_GET(EAL_LEN_LIMIT0_MAX_LEN_VL0_MASK, (r))
#define EAL_LEN_LIMIT0_SET_MAX_LEN_VL0(r, v)  \
	{(r) = ((r) & ~EAL_LEN_LIMIT0_MAX_LEN_VL0_MASK) | \
	FIELD_PREP(EAL_LEN_LIMIT0_MAX_LEN_VL0_MASK, (v)); }

/* D.4.6 EAL_LEN_LIMIT1 */
#define CYR_EAL_LEN_LIMIT1 (CYR_EAL_CFG + 0xc0000 + 0x3 * 8)

/*
 * Bits [63:48]: MAX_LEN_VL7 field
 * Maximum frame length in bytes for Virtual Lane 7
 */
#define EAL_LEN_LIMIT1_MAX_LEN_VL7_MASK                 GENMASK_ULL(63, 48)
#define EAL_LEN_LIMIT1_GET_MAX_LEN_VL7(r) FIELD_GET(EAL_LEN_LIMIT1_MAX_LEN_VL7_MASK, (r))
#define EAL_LEN_LIMIT1_SET_MAX_LEN_VL7(r, v)  \
	{(r) = ((r) & ~EAL_LEN_LIMIT1_MAX_LEN_VL7_MASK) | \
	FIELD_PREP(EAL_LEN_LIMIT1_MAX_LEN_VL7_MASK, (v)); }

/*
 * Bits [47:32]: MAX_LEN_VL6 field
 * Maximum frame length in bytes for Virtual Lane 6
 */
#define EAL_LEN_LIMIT1_MAX_LEN_VL6_MASK                 GENMASK_ULL(47, 32)
#define EAL_LEN_LIMIT1_GET_MAX_LEN_VL6(r) FIELD_GET(EAL_LEN_LIMIT1_MAX_LEN_VL6_MASK, (r))
#define EAL_LEN_LIMIT1_SET_MAX_LEN_VL6(r, v)  \
	{(r) = ((r) & ~EAL_LEN_LIMIT1_MAX_LEN_VL6_MASK) | \
	FIELD_PREP(EAL_LEN_LIMIT1_MAX_LEN_VL6_MASK, (v)); }

/*
 * Bits [31:16]: MAX_LEN_VL5 field
 * Maximum frame length in bytes for Virtual Lane 5
 */
#define EAL_LEN_LIMIT1_MAX_LEN_VL5_MASK                 GENMASK_ULL(31, 16)
#define EAL_LEN_LIMIT1_GET_MAX_LEN_VL5(r) FIELD_GET(EAL_LEN_LIMIT1_MAX_LEN_VL5_MASK, (r))
#define EAL_LEN_LIMIT1_SET_MAX_LEN_VL5(r, v)  \
	{(r) = ((r) & ~EAL_LEN_LIMIT1_MAX_LEN_VL5_MASK) | \
	FIELD_PREP(EAL_LEN_LIMIT1_MAX_LEN_VL5_MASK, (v)); }

/*
 * Bits [15:0]: MAX_LEN_VL4 field
 * Maximum frame length in bytes for Virtual Lane 4
 */
#define EAL_LEN_LIMIT1_MAX_LEN_VL4_MASK                 GENMASK_ULL(15, 0)
#define EAL_LEN_LIMIT1_GET_MAX_LEN_VL4(r) FIELD_GET(EAL_LEN_LIMIT1_MAX_LEN_VL4_MASK, (r))
#define EAL_LEN_LIMIT1_SET_MAX_LEN_VL4(r, v)  \
	{(r) = ((r) & ~EAL_LEN_LIMIT1_MAX_LEN_VL4_MASK) | \
	FIELD_PREP(EAL_LEN_LIMIT1_MAX_LEN_VL4_MASK, (v)); }

/* D.4.9 EAL_FIRST_INT register */
#define CYR_EAL_FIRST_INT (CYR_EAL_CFG + 0xc0000 + 0x6 * 8)

/* D.4.10 EAL_DMAC_ADDRESS register */
#define CYR_EAL_DMAC_ADDRESS (CYR_EAL_CFG + 0xc0000 + 0xa * 8)

/* D.4.11 EAL_SMAC_FILTER register */
#define CYR_EAL_SMAC_FILTER (CYR_EAL_CFG + 0xc0000 + 0xb * 8)

/*
 * D.4.12 EAL_PAUSE_PKT_COUNT register
 *
 * Unlike the other EAL_* counters in this section, this register is
 * PER-PORT and SHARED across all VFs rather than per-VF.
 */
#define CYR_EAL_PAUSE_PKT_COUNT (CYR_EAL_CFG + 0xC0000 + 0xC * 8)

/*
 * Bits [63:32]: pause_pkt_tx_count field
 * Number of 802.3x PAUSE frames transmitted on this port.
 * Free-running, rolls over. Access: RO/V (Read-only/Volatile)
 */
#define EAL_PAUSE_PKT_COUNT_TX_MASK              GENMASK_ULL(63, 32)
#define EAL_PAUSE_PKT_COUNT_GET_TX(r) FIELD_GET(EAL_PAUSE_PKT_COUNT_TX_MASK, (r))

/*
 * Bits [31:0]: pause_pkt_rx_count field
 * Number of 802.3x PAUSE frames received on this port.
 * Free-running, rolls over. Access: RO/V (Read-only/Volatile)
 */
#define EAL_PAUSE_PKT_COUNT_RX_MASK               GENMASK_ULL(31, 0)
#define EAL_PAUSE_PKT_COUNT_GET_RX(r) FIELD_GET(EAL_PAUSE_PKT_COUNT_RX_MASK, (r))

/*
 * D.4.13 EAL_RX_PKT_COUNT register - per-VF/PF frames received.
 *
 * Free-running 64-bit counter. Access: RO/V (Read-only/Volatile)
 */
#define CYR_EAL_RX_PKT_COUNT (CYR_EAL_CFG + 0xC0000 + 0xD * 8)

/*
 * D.4.14 EAL_RX_PKT_BYTE_COUNT register - per-VF/PF bytes received.
 *
 * Free-running 64-bit counter. Access: RO/V (Read-only/Volatile)
 */
#define CYR_EAL_RX_PKT_BYTE_COUNT (CYR_EAL_CFG + 0xC0000 + 0xE * 8)

/*
 * D.4.15 EAL_TX_PKT_COUNT register - per-VF/PF frames transmitted.
 *
 * Free-running 64-bit counter. Access: RO/V (Read-only/Volatile)
 */
#define CYR_EAL_TX_PKT_COUNT (CYR_EAL_CFG + 0xC0000 + 0xF * 8)

/*
 * D.4.16 EAL_TX_PKT_BYTE_COUNT register - per-VF/PF bytes transmitted.
 *
 * Free-running 64-bit counter. Access: RO/V (Read-only/Volatile)
 */
#define CYR_EAL_TX_PKT_BYTE_COUNT (CYR_EAL_CFG + 0xC0000 + 0x10 * 8)

/* D.4.17 EAL_RX_PKT_DROP_COUNT register */
#define CYR_EAL_RX_PKT_DROP_COUNT (CYR_EAL_CFG + 0xC0000 + 0x11 * 8)

/*
 * Bits [63:48]: rx_drop_reasons field
 * Each bit represents a different drop reason after parsing packet header
 * Access: RW/V (Read-Write/Volatile)
 */
#define EAL_RX_PKT_DROP_COUNT_RX_DROP_REASONS_MASK      GENMASK_ULL(63, 48)
#define EAL_RX_PKT_DROP_COUNT_GET_RX_DROP_REASONS(r) \
	FIELD_GET(EAL_RX_PKT_DROP_COUNT_RX_DROP_REASONS_MASK, (r))

/* Drop reason bit definitions */
#define EAL_RX_DROP_REASON_MAC_FRAME_ERROR              BIT_ULL(48)   /* Bit 0: MAC frame error */
#define EAL_RX_DROP_REASON_FRAME_SIZE_ERROR             BIT_ULL(49)   /* Bit 1: Frame size error */
#define EAL_RX_DROP_REASON_FILTER_ALL_RX                BIT_ULL(50)   /* Bit 2: Filter all RX */
#define EAL_RX_DROP_REASON_VLAN_TAG_FILTER              BIT_ULL(51)   /* Bit 3: VLAN tag filter */
#define EAL_RX_DROP_REASON_BROADCAST_FILTER             BIT_ULL(52)   /* Bit 4: Broadcast filter */
#define EAL_RX_DROP_REASON_MULTICAST_FILTER             BIT_ULL(53)   /* Bit 5: Multicast filter */
#define EAL_RX_DROP_REASON_UNICAST_FILTER               BIT_ULL(54)   /* Bit 6: Unicast filtering */
#define EAL_RX_DROP_REASON_SRC_MAC_ADDR                 BIT_ULL(55)   /* Bit 7: Source MAC addr */
#define EAL_RX_DROP_REASON_DST_MAC_ADDR                 BIT_ULL(56)   /* Bit 8: Dest MAC address */
#define EAL_RX_DROP_REASON_L2_ETHTYPE                   BIT_ULL(57)   /* Bit 9: L2 EthType field */
#define EAL_RX_DROP_REASON_IPV4_IPV6_SRC_ADDR           BIT_ULL(58)   /* Bit 10: IPv4/6 src addr */
#define EAL_RX_DROP_REASON_IPV4_IPV6_DST_ADDR           BIT_ULL(59)   /* Bit 11: IPv4/6 dst addr */
#define EAL_RX_DROP_REASON_IPV4_IPV6_PROTOCOL           BIT_ULL(60)   /* Bit 12: IPv4/6 protocol */
#define EAL_RX_DROP_REASON_TCP_UDP_PORT                 BIT_ULL(61)   /* Bit 13: TCP/UDP port val */

/*
 * Bits [47:0]: rx_drop_count field
 * Number of frames received and dropped for this VF
 * Access: RO/V (Read-only/Volatile)
 */
#define EAL_RX_PKT_DROP_COUNT_RX_DROP_COUNT_MASK        GENMASK_ULL(47, 0)
#define EAL_RX_PKT_DROP_COUNT_GET_RX_DROP_COUNT(r) \
	FIELD_GET(EAL_RX_PKT_DROP_COUNT_RX_DROP_COUNT_MASK, (r))

#define EAL_RX_PKT_DROP_COUNT_HAS_DROP_REASON(r, reason_bit) (((r) & (reason_bit)) != 0)

/* D.4.18 EAL_TX_PKT_DROP_COUNT register */
#define CYR_EAL_TX_PKT_DROP_COUNT (CYR_EAL_CFG + 0xC0000 + 0x12 * 8)

/*
 * Bits [63:48]: tx_drop_reasons field
 * Access: RW/V (Read-Write/Volatile)
 */
#define EAL_TX_PKT_DROP_COUNT_TX_DROP_REASONS_MASK      GENMASK_ULL(63, 48)
#define EAL_TX_PKT_DROP_COUNT_GET_TX_DROP_REASONS(r) \
	FIELD_GET(EAL_TX_PKT_DROP_COUNT_TX_DROP_REASONS_MASK, (r))

/* Drop reason bit definitions */
#define EAL_TX_DROP_REASON_MBE_DECAP            BIT_ULL(48)   /* Bit 0: MBE packet decapsulation */
#define EAL_TX_DROP_REASON_PKT_MAX_LEN          BIT_ULL(49)   /* Bit 1: Packet max length error */
#define EAL_TX_DROP_REASON_FILTER_ALL_TX        BIT_ULL(50)   /* Bit 2: Filter all TX */
#define EAL_TX_DROP_REASON_DLID_ZERO            BIT_ULL(51)   /* Bit 3: DLID value of zero */
#define EAL_TX_DROP_REASON_BAD_PKT              BIT_ULL(52)   /* Bit 4: Bad packet (EBP) */
#define EAL_TX_DROP_REASON_SRC_MAC_ADDR         BIT_ULL(53)   /* Bit 5: Source MAC addr */
#define EAL_TX_DROP_REASON_MBE_DATA             BIT_ULL(54)   /* Bit 6: MBE pkt data or tag bufs */
#define EAL_TX_DROP_REASON_FILTER_ALL_TX_BUF    BIT_ULL(55)   /* Bit 7: Filter all pkts in TX buf */

/*
 * Bits [47:0]: tx_drop_count field
 * Number of frames dropped on transmit for this VF/PF.
 * Access: RO/V (Read-only/Volatile)
 */
#define EAL_TX_PKT_DROP_COUNT_TX_DROP_COUNT_MASK        GENMASK_ULL(47, 0)
#define EAL_TX_PKT_DROP_COUNT_GET_TX_DROP_COUNT(r) \
	FIELD_GET(EAL_TX_PKT_DROP_COUNT_TX_DROP_COUNT_MASK, (r))

#define EAL_TX_PKT_DROP_COUNT_HAS_DROP_REASON(r, reason_bit) (((r) & (reason_bit)) != 0)

/* D.4.19 EAL_RIFT_ALLOCATION register */
#define CYR_EAL_RIFT_ALLOCATION (CYR_EAL_CFG + 0xc0000 + 0x13 * 8)

/* D.4.20 EAL_1588_PTP_CFG register */
#define CYR_EAL_1588_PTP_CFG (CYR_EAL_CFG + 0xc0000 + 0x14 * 8)
#define EAL_1588_PTP_CFG_PTP_RX_TS_ENABLE BIT_ULL(0)

/* D.4.21 EAL_1588_PTP_TX_CFG register */
#define CYR_EAL_1588_PTP_TX_CFG (CYR_EAL_CFG + 0xc0000 + 0x15 * 8)

/* D.4.25 EAL_VF_DROP_ALL register */
#define CYR_EAL_VF_DROP_ALL (CYR_EAL_CFG + 0xc0000 + 0x19 * 8)

/* D.4.34 EAL_RBUF_CREDITS_AVAIL0 register */
#define CYR_EAL_RBUF_CREDITS_AVAIL0 (CYR_EAL_CFG + 0xc0000 + 0x22 * 8)
/*
 * Bits [61:48]: vl3_rbuf_credits_avail field
 * Rbuf credits available (not used) for VL3
 * Read-only/Volatile
 */
#define EAL_RBUF_CREDITS_AVAIL0_VL3_RBUF_CREDITS_AVAIL_MASK     GENMASK_ULL(61, 48)
#define EAL_RBUF_CREDITS_AVAIL0_GET_VL3_RBUF_CREDITS_AVAIL(r) \
	FIELD_GET(EAL_RBUF_CREDITS_AVAIL0_VL3_RBUF_CREDITS_AVAIL_MASK, (r))

/*
 * Bits [45:32]: vl2_rbuf_credits_avail field
 * Rbuf credits available (not used) for VL2
 * Read-only/Volatile
 */
#define EAL_RBUF_CREDITS_AVAIL0_VL2_RBUF_CREDITS_AVAIL_MASK     GENMASK_ULL(45, 32)
#define EAL_RBUF_CREDITS_AVAIL0_GET_VL2_RBUF_CREDITS_AVAIL(r) \
	FIELD_GET(EAL_RBUF_CREDITS_AVAIL0_VL2_RBUF_CREDITS_AVAIL_MASK, (r))

/*
 * Bits [29:16]: vl1_rbuf_credits_avail field
 * Rbuf credits available (not used) for VL1
 * Read-only/Volatile
 */
#define EAL_RBUF_CREDITS_AVAIL0_VL1_RBUF_CREDITS_AVAIL_MASK     GENMASK_ULL(29, 16)
#define EAL_RBUF_CREDITS_AVAIL0_GET_VL1_RBUF_CREDITS_AVAIL(r) \
	FIELD_GET(EAL_RBUF_CREDITS_AVAIL0_VL1_RBUF_CREDITS_AVAIL_MASK, (r))

/*
 * Bits [13:0]: vl0_rbuf_credits_avail field
 * Rbuf credits available (not used) for VL0
 * Read-only/Volatile
 */
#define EAL_RBUF_CREDITS_AVAIL0_VL0_RBUF_CREDITS_AVAIL_MASK     GENMASK_ULL(13, 0)
#define EAL_RBUF_CREDITS_AVAIL0_GET_VL0_RBUF_CREDITS_AVAIL(r) \
	FIELD_GET(EAL_RBUF_CREDITS_AVAIL0_VL0_RBUF_CREDITS_AVAIL_MASK, (r))

/* D.4.36 EAL_TBUF_CREDITS_AVAIL0 register */
#define CYR_EAL_TBUF_CREDITS_AVAIL0 (CYR_EAL_CFG + 0xc0000 + 0x24 * 8)

/* D.4.38 EAL_MAC_PFC_PAUSED register */
#define CYR_EAL_MAC_PFC_PAUSED (CYR_EAL_CFG + 0xc0000 + 0x26 * 8)
/*
 * Bits [7:0]: mac_pfc_paused field
 * 1 = Associated PFC-priority is currently flow-controlled/paused
 * 0 = PFC-priority not paused
 * Read-only/Volatile
 *
 * Bit 0 = PFC priority 0 pause state
 * Bit 1 = PFC priority 1 pause state
 * Bit 2 = PFC priority 2 pause state
 * Bit 3 = PFC priority 3 pause state
 * Bit 4 = PFC priority 4 pause state
 * Bit 5 = PFC priority 5 pause state
 * Bit 6 = PFC priority 6 pause state
 * Bit 7 = PFC priority 7 pause state
 */
#define EAL_MAC_PFC_PAUSED_MAC_PFC_PAUSED_MASK          GENMASK_ULL(7, 0)
#define EAL_MAC_PFC_PAUSED_GET_MAC_PFC_PAUSED(r) \
	FIELD_GET(EAL_MAC_PFC_PAUSED_MAC_PFC_PAUSED_MASK, (r))
#define EAL_MAC_PFC_PAUSED_IS_PFC_PAUSED(r, pfc) (((r) & BIT_ULL(pfc)) != 0)

/* D.4.39 EAL_INT_STATUS register */
#define CYR_EAL_INT_STATUS (CYR_EAL_CFG + 0xc0000 + 0x27 * 8)

/* D.4.40 EAL_INT_MASK register */
#define CYR_EAL_INT_MASK (CYR_EAL_CFG + 0xc0000 + 0x28 * 8)

/* D.4.43 TX_CAPTURE_TOD register */
#define CYR_TX_CAPTURE_TOD (CYR_EAL_CFG + 0xC0000 + 0x2B * 8)

/* D.4.45 EAL_VF_PRF_CREDIT_DROP_CNTR register */
#define CYR_EAL_VF_PRF_CREDIT_DROP_CNTR (CYR_EAL_CFG + 0xC0000 + 0x150 * 8)
/*
 * Counts frames dropped during ingress due to insufficient RBUF credit
 * availability, i.e. receive-buffer-exhaustion (congestion) drops. This
 * is the only register that counts these drops.
 *
 * NOTE: This counter is port-global and not per VF.
 *
 * Register Layout (64 bits):
 * [63:48] - Unused (RO, no defined reset - mask before use)
 * [47:0]  - credit_drop_count: number of dropped frames (RO/V, reset 0x0).
 *           Non-saturating: the 48-bit field wraps.
 */
#define EAL_VF_PRF_CREDIT_DROP_CNTR_COUNT_MASK  GENMASK_ULL(47, 0)
#define EAL_VF_PRF_CREDIT_DROP_CNTR_GET_COUNT(r) \
	FIELD_GET(EAL_VF_PRF_CREDIT_DROP_CNTR_COUNT_MASK, (r))

/* D.4.45 EAL_VF_PRF_RBUF_PAUSE_TIME_SHR register */
#define CYR_EAL_VF_PRF_RBUF_PAUSE_TIME_SHR (CYR_EAL_CFG + 0xc0000 + 0x151 * 8)

/* D.4.46 EAL_VF_PRF_RBUF_PAUSE_CNTR_SHR  register */
#define CYR_EAL_VF_PRF_RBUF_PAUSE_CNTR_SHR (CYR_EAL_CFG + 0xc0000 + 0x152 * 8)
/*
 * Register Layout (64 bits):
 * [63:48] - reserved
 * [47:0]  - pause_event_count: Number of pause events triggered
 */

/*
 * Bits [47:0]: pause_event_count field
 * Number of pause threshold events triggered by shared RBUF credit allocation
 * Access: RO/V (Read-only/Volatile)
 */
#define EAL_VF_PRF_RBUF_PAUSE_CNTR_SHR_PAUSE_EVENT_COUNT_MASK   GENMASK_ULL(47, 0)
#define EAL_VF_PRF_RBUF_PAUSE_CNTR_SHR_GET_PAUSE_EVENT_COUNT(r) \
	FIELD_GET(EAL_VF_PRF_RBUF_PAUSE_CNTR_SHR_PAUSE_EVENT_COUNT_MASK, (r))

/* D.4.47 EAL_VF_PRF_RBUF_PAUSE_RESEND_SHR register */
#define CYR_EAL_VF_PRF_RBUF_PAUSE_RESEND_SHR (CYR_EAL_CFG + 0xc0000 + 0x153 * 8)

/* D.4.48 EAL_VF_PRF_RX_MINIPAUSE_CNTR register */
#define CYR_EAL_VF_PRF_RX_MINIPAUSE_CNTR (CYR_EAL_CFG + 0xc0000 + 0x154 * 8)

/* D.4.49 EAL_VF_PRF_RBUF_PAUSE_TIME_VL0 register */
#define CYR_EAL_VF_PRF_RBUF_PAUSE_TIME_VL0 (CYR_EAL_CFG + 0xc0000 + 0x160 * 8)

/* Pause time/resend/mini-pause: 48-bit width assumed like other VF_PRF */
#define EAL_VF_PRF_CNTR_COUNT_MASK	GENMASK_ULL(47, 0)
#define EAL_VF_PRF_CNTR_GET_COUNT(r) \
	FIELD_GET(EAL_VF_PRF_CNTR_COUNT_MASK, (r))

/* D.4.57 EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0 register */
#define CYR_EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0 (CYR_EAL_CFG + 0xC0000 + (0x168 * 8))
/*
 * Bits [47:0]: pause_event_count field
 * Number of pause threshold events triggered by VL0
 * Access: RO/V (Read-only/Volatile)
 */
#define EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0_PAUSE_EVENT_COUNT_MASK   GENMASK_ULL(47, 0)
#define EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0_GET_PAUSE_EVENT_COUNT(r) \
	FIELD_GET(EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0_PAUSE_EVENT_COUNT_MASK, (r))

/* D.4.65 EAL_VF_PRF_RBUF_PAUSE_RESEND_VL0 register */
#define CYR_EAL_VF_PRF_RBUF_PAUSE_RESEND_VL0 (CYR_EAL_CFG + 0xc0000 + 0x170 * 8)

/*
 * D.5.34 EAL_DESTINATION_PORT_TABLE - 16-entry PF-only UDP/TCP dst-port CAM.
 * A match feeds the entry index into the ingress context_info field (bit 13 =
 * match, bits [12:9] = index), enabling RSM steering.  Program one entry for
 * RoCEv2 (dst port 4791, tcp=0) to steer RoCE traffic to the bulksvc context.
 */
#define CYR_EAL_DESTINATION_PORT_TABLE (CYR_EAL_CFG + 0xd0000 + 0x70 * 8)
#define CYR_EAL_DESTINATION_PORT_TABLE_ENTRIES 16

#define EAL_DSTPORT_VALID_MASK		BIT_ULL(0)
#define EAL_DSTPORT_SET_VALID(r, v) \
	{(r) = ((r) & ~EAL_DSTPORT_VALID_MASK) | FIELD_PREP(EAL_DSTPORT_VALID_MASK, (v)); }
#define EAL_DSTPORT_FILTER_MASK		BIT_ULL(1)
#define EAL_DSTPORT_SET_FILTER(r, v) \
	{(r) = ((r) & ~EAL_DSTPORT_FILTER_MASK) | FIELD_PREP(EAL_DSTPORT_FILTER_MASK, (v)); }
#define EAL_DSTPORT_FWD_EXCEPTION_MASK	BIT_ULL(2)
#define EAL_DSTPORT_SET_FWD_EXCEPTION(r, v) \
	{(r) = ((r) & ~EAL_DSTPORT_FWD_EXCEPTION_MASK) | \
		FIELD_PREP(EAL_DSTPORT_FWD_EXCEPTION_MASK, (v)); }
#define EAL_DSTPORT_TCP_MASK		BIT_ULL(3)
#define EAL_DSTPORT_SET_TCP(r, v) \
	{(r) = ((r) & ~EAL_DSTPORT_TCP_MASK) | FIELD_PREP(EAL_DSTPORT_TCP_MASK, (v)); }
#define EAL_DSTPORT_PORT_MASK		GENMASK_ULL(23, 8)
#define EAL_DSTPORT_SET_PORT(r, v) \
	{(r) = ((r) & ~EAL_DSTPORT_PORT_MASK) | FIELD_PREP(EAL_DSTPORT_PORT_MASK, (v)); }
#define EAL_DSTPORT_VF_MASK		GENMASK_ULL(31, 24)
#define EAL_DSTPORT_SET_VF_MASK(r, v) \
	{(r) = ((r) & ~EAL_DSTPORT_VF_MASK) | FIELD_PREP(EAL_DSTPORT_VF_MASK, (v)); }

/*
 * D.4.8 EAL_ROCEV2_CFG - per-VF RoCEv2 hardware-offload control.
 * roce_by_software=1 sends all RoCE packets to software (Stage 1: skip HW
 * RKEY/RIF placement).  VF window base + index 0x5, resolving to 0x7C0028.
 *
 * Field layout transcribed from A00502-0.6.1 D.4.8 via design Appendix C.5.
 * All fields reset to zero, which is a usable bring-up state here (unlike the
 * VF column-ownership registers in C.4): suppression off, every header
 * written.
 */
#define CYR_EAL_ROCEV2_CFG (CYR_EAL_CFG + 0xc0000 + 0x5 * 8)
#define EAL_ROCEV2_CFG_ROCE_BY_SOFTWARE_MASK	BIT_ULL(0)
#define EAL_ROCEV2_CFG_SET_ROCE_BY_SOFTWARE(r, v) \
	{(r) = ((r) & ~EAL_ROCEV2_CFG_ROCE_BY_SOFTWARE_MASK) | \
		FIELD_PREP(EAL_ROCEV2_CFG_ROCE_BY_SOFTWARE_MASK, (v)); }
#define EAL_ROCEV2_CFG_GET_ROCE_BY_SOFTWARE(r) \
	FIELD_GET(EAL_ROCEV2_CFG_ROCE_BY_SOFTWARE_MASK, (r))
/* Clear bit 1 to let hardware FIRST create a RIF entry. */
#define EAL_ROCEV2_CFG_ROCE_FIRST_BY_SOFTWARE_MASK	BIT_ULL(1)
#define EAL_ROCEV2_CFG_SET_ROCE_FIRST_BY_SOFTWARE(r, v) \
	{(r) = ((r) & ~EAL_ROCEV2_CFG_ROCE_FIRST_BY_SOFTWARE_MASK) | \
		FIELD_PREP(EAL_ROCEV2_CFG_ROCE_FIRST_BY_SOFTWARE_MASK, (v)); }
#define EAL_ROCEV2_CFG_GET_ROCE_FIRST_BY_SOFTWARE(r) \
	FIELD_GET(EAL_ROCEV2_CFG_ROCE_FIRST_BY_SOFTWARE_MASK, (r))
#define EAL_ROCEV2_CFG_ROCE_LAST_BY_SOFTWARE_MASK	BIT_ULL(2)
#define EAL_ROCEV2_CFG_SET_ROCE_LAST_BY_SOFTWARE(r, v) \
	{(r) = ((r) & ~EAL_ROCEV2_CFG_ROCE_LAST_BY_SOFTWARE_MASK) | \
		FIELD_PREP(EAL_ROCEV2_CFG_ROCE_LAST_BY_SOFTWARE_MASK, (v)); }
#define EAL_ROCEV2_CFG_GET_ROCE_LAST_BY_SOFTWARE(r) \
	FIELD_GET(EAL_ROCEV2_CFG_ROCE_LAST_BY_SOFTWARE_MASK, (r))
#define EAL_ROCEV2_CFG_PSN_HDR_SUPPRESS_ENB_MASK	BIT_ULL(3)
#define EAL_ROCEV2_CFG_SET_PSN_HDR_SUPPRESS_ENB(r, v) \
	{(r) = ((r) & ~EAL_ROCEV2_CFG_PSN_HDR_SUPPRESS_ENB_MASK) | \
		FIELD_PREP(EAL_ROCEV2_CFG_PSN_HDR_SUPPRESS_ENB_MASK, (v)); }
/* 0x0 writes every header, 0x1 every other, ... 0xFF every 255. */
#define EAL_ROCEV2_CFG_PSN_WR_HDR_COUNT_MASK	GENMASK_ULL(11, 4)
#define EAL_ROCEV2_CFG_SET_PSN_WR_HDR_COUNT(r, v) \
	{(r) = ((r) & ~EAL_ROCEV2_CFG_PSN_WR_HDR_COUNT_MASK) | \
		FIELD_PREP(EAL_ROCEV2_CFG_PSN_WR_HDR_COUNT_MASK, (v)); }
/*
 * rocev2_mtu is the stride hardware uses to place a MIDDLE:
 *	start_vaddr + stride * (BTH.PSN - start_psn)
 * The RIF entry carries no MTU field, so this register is hardware's only
 * source for it.  A wrong stride does not fail - it places correct bytes at
 * an incorrect address at line rate.
 */
#define EAL_ROCEV2_CFG_ROCEV2_MTU_MASK		GENMASK_ULL(18, 16)
#define EAL_ROCEV2_CFG_SET_ROCEV2_MTU(r, v) \
	{(r) = ((r) & ~EAL_ROCEV2_CFG_ROCEV2_MTU_MASK) | \
		FIELD_PREP(EAL_ROCEV2_CFG_ROCEV2_MTU_MASK, (v)); }
#define EAL_ROCEV2_CFG_GET_ROCEV2_MTU(r) \
	FIELD_GET(EAL_ROCEV2_CFG_ROCEV2_MTU_MASK, (r))

/*
 * rocev2_mtu encodings (A00502-0.6.1 D.4.8, design C.5).
 *
 * This is NOT an OPA/IB MTU enum and must not be mapped as one.  4096 appears
 * at both encoding 0 and encoding 6, and encoding 0 is documented as "target
 * defaults to zeros" - a reset artifact rather than a deliberate setting.
 * Always program 4096 as encoding 6 so that a programmed 4096 is
 * distinguishable from an unprogrammed register.  Note the encoding is
 * otherwise ascending from 128 at 1, which makes 0 the odd value.
 */
enum eal_rocev2_mtu {
	EAL_ROCEV2_MTU_DEFAULT_ZEROS	= 0,	/* 4096, reset artifact - do not program */
	EAL_ROCEV2_MTU_128		= 1,
	EAL_ROCEV2_MTU_256		= 2,
	EAL_ROCEV2_MTU_512		= 3,
	EAL_ROCEV2_MTU_1024		= 4,
	EAL_ROCEV2_MTU_2048		= 5,
	EAL_ROCEV2_MTU_4096		= 6,	/* program 4096 here, never 0 */
	EAL_ROCEV2_MTU_8192		= 7,
};

/*
 * RIF and R_Key table apertures (A00502-0.6.1 D.1/D.1.1/D.1.2 Tables D-1/D-2,
 * design Appendix C.1).
 *
 * These are NOT reachable from the CYR_EAL_CFG + 0xc0000 / + 0xd0000 pattern
 * the per-VF and PF register windows use.  The R_Key table sits below the
 * per-VF window and the RIF table sits outside the 0x700000 region entirely,
 * so the bases are spelled out here rather than derived.
 *
 * The PIO and Configuration buses share one address space for both tables and
 * the EAL block arbitrates between them.  WDATA0/1/2 sit at byte offsets 0, 8
 * and 16 from the table base on BOTH buses, which is what makes writing
 * entries through PIO an aperture substitution rather than a re-layout.
 *
 * Entry writes go through PIO (gate H21, design 5.1.5): PIO carries the whole
 * 192-bit entry in one cycle, so the arming write is atomic in hardware and
 * needs none of the cross-function serialization with the Ethernet driver,
 * VFs and Cport that the RTL owner requires on the Configuration bus.
 * Configuration remains the read path - PIO is write-only.
 */
#define CYR_EAL_PIO_RIF_TABLE		0x600000
#define CYR_EAL_PIO_RKEY_TABLE		0x680000
#define CYR_EAL_CFG_RKEY_TABLE		0x780000
#define CYR_EAL_CFG_RIF_TABLE		0x800000

#define EAL_TABLE_WDATA0		(0x0 * 8)
#define EAL_TABLE_WDATA1		(0x1 * 8)
#define EAL_TABLE_WDATA2		(0x2 * 8)

/*
 * Reads are addressed differently from writes, and the difference is easy to
 * miss because both use the same table.  A write goes to the fixed WDATA0/1/2
 * offsets above and hardware takes the destination row and bucket from the
 * PAYLOAD - rif_qp's low bits and rif_bucket_numb.  A Configuration-bus read
 * is flat: the row, bucket and qword are encoded in the ADDRESS, per Tables
 * 4-12 and 4-13.
 *
 * RIF qword 3 is not a fourth entry qword - it returns psn_count[7:0], a
 * hardware counter, and is debug-only.  R_Key qword 3 aliases qword 2.
 */
#define EAL_TABLE_READ_QWORD_MASK	GENMASK(4, 3)
#define EAL_TABLE_READ_ENTRY_MASK	GENMASK(8, 5)
#define EAL_RIF_READ_ROW_MASK		GENMASK(19, 9)
#define EAL_RKEY_READ_ROW_MASK		GENMASK(17, 9)

#define EAL_RIF_READ_ADDR(row, entry, qword) \
	(CYR_EAL_CFG_RIF_TABLE | \
	 FIELD_PREP(EAL_RIF_READ_ROW_MASK, (row)) | \
	 FIELD_PREP(EAL_TABLE_READ_ENTRY_MASK, (entry)) | \
	 FIELD_PREP(EAL_TABLE_READ_QWORD_MASK, (qword)))
#define EAL_RKEY_READ_ADDR(row, entry, qword) \
	(CYR_EAL_CFG_RKEY_TABLE | \
	 FIELD_PREP(EAL_RKEY_READ_ROW_MASK, (row)) | \
	 FIELD_PREP(EAL_TABLE_READ_ENTRY_MASK, (entry)) | \
	 FIELD_PREP(EAL_TABLE_READ_QWORD_MASK, (qword)))

/* The RIF row is selected by the low bits of the QP number. */
#define EAL_RIF_ROW_FROM_QP(qpn)	((qpn) & (EAL_RIF_TABLE_ROWS - 1))

/*
 * The R_Key row is R_Key[8:0] (A00502 4.5.2.5.13.9), with the residual
 * R_Key[31:9] held as the comparand.  Software supplies the whole key to
 * EAL_RKEY_TABLE_WDATA2 and hardware splits it; this macro exists only for the
 * occupancy map, which is indexed the same way hardware indexes the table.
 */
#define EAL_RKEY_ROW_FROM_KEY(rkey)	((rkey) & (EAL_RKEY_TABLE_ROWS - 1))

/*
 * Table geometry (design C.6 discrepancy 1 and 2).  Both WDATA2 registers
 * describe the bucket selector as choosing "one of the eight row table
 * entries" while the adjacent bucket field is documented as a 4-bit
 * one-of-sixteen selector: the eight is a stale copy of the VF count and
 * sixteen is correct.  EAL_RKEY_VF_MAPPING_CFG0 separately states the R_Key
 * table is 1024 deep; every other source gives 512.
 */
#define EAL_RKEY_TABLE_ROWS		512
#define EAL_RIF_TABLE_ROWS		2048
#define EAL_TABLE_ENTRIES_PER_ROW	16

/*
 * D.3.3-D.3.5 EAL_RKEY_TABLE_WDATA0/1/2 (design C.2).
 */
#define EAL_RKEY_WDATA0_VIRTUAL_ADDRESS_MASK	GENMASK_ULL(63, 0)
#define EAL_RKEY_WDATA1_PASID_MASK		GENMASK_ULL(51, 32)
#define EAL_RKEY_WDATA1_PERMISSIONS_MASK	GENMASK_ULL(31, 28)
#define EAL_RKEY_PERMISSION_WRITE		BIT(0)
#define EAL_RKEY_PERMISSION_READ		BIT(1)
/* Byte count, not 16-byte units (gate H15).  Max 2^24 - 1 = 16777215. */
#define EAL_RKEY_WDATA1_LENGTH_MASK		GENMASK_ULL(27, 4)
#define EAL_RKEY_LENGTH_MAX			(BIT(24) - 1)
#define EAL_RKEY_WDATA2_BUCKET_NUMB_MASK	GENMASK_ULL(36, 33)
/*
 * The full 32-bit key goes here.  4.5.2.5.13.9 describes an entry as holding
 * the "upper 23 bits of the R_Key", but that is what hardware stores and
 * compares after deriving the row from R_Key[8:0] - it is not what software
 * supplies.  Masking to 23 bits before the write corrupts row selection.
 */
#define EAL_RKEY_WDATA2_RKEY_MASK		GENMASK_ULL(32, 1)
#define EAL_RKEY_WDATA2_ENTRY_VALID_MASK	BIT_ULL(0)

/*
 * D.2.3-D.2.5 EAL_RIF_TABLE_WDATA0/1/2 (design C.3).
 */
#define EAL_RIF_WDATA0_START_VIRTUAL_ADDRESS_MASK	GENMASK_ULL(63, 0)
#define EAL_RIF_WDATA1_END_PSN_MASK		GENMASK_ULL(63, 40)
#define EAL_RIF_WDATA1_START_PSN_MASK		GENMASK_ULL(39, 16)
/*
 * rif_next_psn is the only split field in either table: bits [23:8] land in
 * WDATA1[15:0] and bits [7:0] land in WDATA2[63:56], and both halves carry
 * the same field name.  A transposition is a factor-of-256 error that appears
 * only on bursts long enough to cross an 8-bit boundary, so callers must use
 * the EAL_RIF_NEXT_PSN_{HI,LO} helpers below and never build the halves by
 * hand.
 */
#define EAL_RIF_WDATA1_NEXT_PSN_HI_MASK		GENMASK_ULL(15, 0)
#define EAL_RIF_WDATA2_NEXT_PSN_LO_MASK		GENMASK_ULL(63, 56)
#define EAL_RIF_NEXT_PSN_HI(psn)		(((psn) >> 8) & 0xffff)
#define EAL_RIF_NEXT_PSN_LO(psn)		((psn) & 0xff)
#define EAL_RIF_NEXT_PSN_FROM_HALVES(hi, lo)	((((u32)(hi) & 0xffff) << 8) | \
						 ((u32)(lo) & 0xff))
#define EAL_RIF_WDATA2_NEXT_PSN_STATE_MASK	GENMASK_ULL(53, 52)
#define EAL_RIF_WDATA2_PASID_MASK		GENMASK_ULL(51, 32)
#define EAL_RIF_WDATA2_BUCKET_NUMB_MASK		GENMASK_ULL(28, 25)
/* Low 11 bits select the row. */
#define EAL_RIF_WDATA2_QP_MASK			GENMASK_ULL(24, 1)
#define EAL_RIF_WDATA2_ENTRY_VALID_MASK		BIT_ULL(0)

/*
 * next_psn_state.  Software arms with INITIALIZING; hardware latches the
 * first arriving MIDDLE's own BTH.PSN + 1 and advances to RUNNING.  The latch
 * is state-01 only (gate H24) - RUNNING is a diagnostic setting, never a
 * configuration to adopt.
 */
enum eal_rif_next_psn_state {
	EAL_RIF_NEXT_PSN_STATE_IDLE		= 0,
	EAL_RIF_NEXT_PSN_STATE_INITIALIZING	= 1,
	EAL_RIF_NEXT_PSN_STATE_RUNNING		= 2,
	EAL_RIF_NEXT_PSN_STATE_RECOVERING	= 3,
};

/*
 * D.4.3, D.4.19, D.5.6-D.5.9 allocation and VF column mapping (design C.4).
 *
 * The two *_ALLOCATION registers are read-only reports of what the PF has
 * granted; there is nothing for the driver to program in them.  The writable
 * mapping registers are PF-only and each carries a 16-bit column bitmap per
 * VF: bits 15:0 first VF, 31:16 second, 47:32 third, 63:48 fourth.
 *
 * These must be programmed before any entry write can land.  Reset is zero
 * columns owned, and a write to a bucket the function does not own is
 * SILENTLY IGNORED - so at reset every arm disappears without error, which is
 * indistinguishable from an arm never attempted.  Columns owned by one VF
 * must be consecutive, assignments must not overlap, and hardware does not
 * prevent a wrong configuration.
 */
#define CYR_EAL_RKEY_VF_MAPPING_CFG0	(CYR_EAL_CFG + 0xd0000 + 0x12 * 8)
#define CYR_EAL_RIFT_VF_MAPPING_CFG0	(CYR_EAL_CFG + 0xd0000 + 0x14 * 8)

#define EAL_VF_MAPPING_COLUMNS_MASK(vf)	GENMASK_ULL(((vf) & 0x3) * 16 + 15, \
						    ((vf) & 0x3) * 16)
/* Single tenant (design 5.1.1, gate H8): all sixteen columns to the PF. */
#define EAL_VF_MAPPING_ALL_COLUMNS	0xFFFF

/*
 * D.4.26 EAL_IPV4_DA_TABLE - per-VF command portal for the eight-entry
 * IPv4 destination-address CAM.  A keyed write with valid=1 installs an
 * address; the same key with valid=0 removes it.
 */
#define CYR_EAL_VF_IP_DA_TABLE (CYR_EAL_CFG + 0xc0000 + 0x1a * 8)
#define EAL_VF_IP_DA_VALID_MASK		BIT_ULL(0)
#define EAL_VF_IP_DA_ADDR_MASK		GENMASK_ULL(63, 32)

/* D.5.3 EAL_L2_PROTOCOL_TABLE register */
#define CYR_EAL_L2_PROTOCOL_TABLE (CYR_EAL_CFG + 0xd0000 + 0x0 * 8)
#define CYR_EAL_L2_PROTOCOL_TABLE_ENTRIES 16

/* D.5.4 EAL_PF_DROP_ALL register */
#define CYR_EAL_PF_DROP_ALL (CYR_EAL_CFG + 0xd0000 + 0x10 * 8)

/* D.5.5 EAL_16B_HEADER_DEFAULTS register */
#define CYR_EAL_16B_HEADER_DEFAULTS (CYR_EAL_CFG + 0xd0000 + 0x11 * 8)

/* D.5.6 EAL_RKEY_VF_MAPPING_CFG0 register */
#define CYR_EAL_RKEY_VF_MAPPING_CFG0 (CYR_EAL_CFG + 0xd0000 + 0x12 * 8)

/* D.5.8 EAL_RIFT_VF_MAPPING_CFG0 register */
#define CYR_EAL_RIFT_VF_MAPPING_CFG0 (CYR_EAL_CFG + 0xd0000 + 0x14 * 8)

/* D.5.10 EAL_DMAC_SMAC_CFG register */
#define CYR_EAL_DMAC_SMAC_CFG (CYR_EAL_CFG + 0xd0000 + 0x16 * 8)

/* D.5.11 EAL_PF_SMAC_FILTER register */
#define CYR_EAL_PF_SMAC_FILTER (CYR_EAL_CFG + 0xd0000 + 0x18 * 8)
/*
 * Bits [63:49]: reserved
 */
#define EAL_PF_SMAC_RESERVED_MASK		GENMASK_ULL(63, 49)

/*
 * Bit [48]: smac_valid field
 * SMAC Entry Valid Flag
 * 1 = Associated entry is valid
 * 0 = Associated entry is invalid and frames should be dropped if pf_egress_smac_chk is set
 *
 * Note: Read value reflects what hardware is using (may be VF or PF value
 *       depending on pf_enb_vfs configuration)
 */
#define EAL_PF_SMAC_VALID_MASK                  BIT_ULL(48)
#define EAL_PF_SMAC_GET_VALID(r) FIELD_GET(EAL_PF_SMAC_VALID_MASK, (r))
#define EAL_PF_SMAC_SET_VALID(r, valid)  \
	{(r) = ((r) & ~EAL_PF_SMAC_VALID_MASK) | FIELD_PREP(EAL_PF_SMAC_VALID_MASK, (valid)); }

/*
 * Bits [47:0]: pf_smac field
 * L2/Ethernet Source MAC Address (SMAC)
 * 48-bit MAC address for this VF/PF
 *
 * Format: Standard IEEE 802 MAC address
 * This is the expected source MAC for egress frames from this VF/PF.
 * When pf_smac_filter is set, frames with non-matching SMAC are dropped.
 *
 * Note: Read value reflects what hardware is using (may be VF or PF value
 *       depending on pf_enb_vfs configuration)
 */
#define EAL_PF_SMAC_ADDR_MASK                   GENMASK_ULL(47, 0)
#define EAL_PF_SMAC_GET_ADDR(r) FIELD_GET(EAL_PF_SMAC_ADDR_MASK, (r))
#define EAL_PF_SMAC_SET_ADDR(r, addr)  \
	{(r) = ((r) & ~EAL_PF_SMAC_ADDR_MASK) | FIELD_PREP(EAL_PF_SMAC_ADDR_MASK, (addr)); }

/* D.5.12 EAL_PF_DMAC_ADDRESS register */
#define CYR_EAL_PF_DMAC_ADDRESS (CYR_EAL_CFG + 0xd0000 + 0x20 * 8)
/*
 * Bits [63:56]: pf_dmac_mask field
 * DMAC Mask - Applied to the lower 8 bits [7:0] of the DMAC
 * A mask bit "set" makes the associated bit a "don't care"
 *
 * Note: Read value reflects what hardware is using (may be VF or PF value
 *       depending on pf_enb_vfs configuration)
 */
#define EAL_PF_DMAC_MASK_MASK                   GENMASK_ULL(63, 56)
#define EAL_PF_DMAC_GET_MASK(r) FIELD_GET(EAL_PF_DMAC_MASK_MASK, (r))
#define EAL_PF_DMAC_SET_MASK(r, mask)  \
	{(r) = ((r) & ~EAL_PF_DMAC_MASK_MASK) | FIELD_PREP(EAL_PF_DMAC_MASK_MASK, (mask)); }

/*
 * Bit [50]: dmac_valid field
 * DMAC Entry Valid Flag
 * 1 = Associated entry is valid
 * 0 = Associated entry is invalid and frames should be dropped if pf_egress_smac_chk is set
 *
 * Note: Read value reflects what hardware is using (may be VF or PF value
 *       depending on pf_enb_vfs configuration)
 */
#define EAL_PF_DMAC_VALID_MASK                  BIT_ULL(50)
#define EAL_PF_DMAC_GET_VALID(r) FIELD_GET(EAL_PF_DMAC_VALID_MASK, (r))
#define EAL_PF_DMAC_SET_VALID(r, valid)  \
	{(r) = ((r) & ~EAL_PF_DMAC_VALID_MASK) | FIELD_PREP(EAL_PF_DMAC_VALID_MASK, (valid)); }

/*
 * Bit [48]: pf_dmac_filter field
 * Filter frames with this DMAC
 * 1 = Filter/drop frames with matching DMAC
 * 0 = Accept frames with matching DMAC
 *
 * Possible use case: VM goes away, set this bit to filter frames destined
 * to that VM until a new VM is spun up.
 *
 * Note: Read value reflects what hardware is using (may be VF or PF value
 *       depending on pf_enb_vfs configuration)
 */
#define EAL_PF_DMAC_FILTER_MASK                 BIT_ULL(48)
#define EAL_PF_DMAC_GET_FILTER(r) FIELD_GET(EAL_PF_DMAC_FILTER_MASK, (r))
#define EAL_PF_DMAC_SET_FILTER(r, filter)  \
	{(r) = ((r) & ~EAL_PF_DMAC_FILTER_MASK) | FIELD_PREP(EAL_PF_DMAC_FILTER_MASK, (filter)); }

/*
 * Bits [47:0]: pf_dmac field
 * L2/Ethernet Destination MAC Address (DMAC)
 * 48-bit MAC address for this VF/PF
 *
 * Format: Standard IEEE 802 MAC address
 * Note: Read value reflects what hardware is using (may be VF or PF value
 *       depending on pf_enb_vfs configuration)
 */
#define EAL_PF_DMAC_ADDR_MASK                   GENMASK_ULL(47, 0)
#define EAL_PF_DMAC_GET_ADDR(r) FIELD_GET(EAL_PF_DMAC_ADDR_MASK, (r))
#define EAL_PF_DMAC_SET_ADDR(r, addr)  \
	{(r) = ((r) & ~EAL_PF_DMAC_ADDR_MASK) | FIELD_PREP(EAL_PF_DMAC_ADDR_MASK, (addr)); }

/* D.5.13 EAL_MCAST_ADDRESS register */
#define CYR_EAL_MCAST_ADDRESS (CYR_EAL_CFG + 0xd0000 + 0x30 * 8)
#define CYR_EAL_MCAST_ADDRESS_ENTRIES 32

/* D.5.14 EAL_RX_PAUSE_CONFIG_VL0 register */
#define CYR_EAL_RX_PAUSE_CONFIG_VL0 (CYR_EAL_CFG + 0xd0000 + 0x50 * 8)
/*
 * Bits [63:58]: vl0_pause_resend field
 * When pause counter < threshold and credits still low, resend pause frame
 * 0x00 = no resend, 0x01 = 64 quanta (4KiB), 0x3F = 4Ki quanta (256KiB)
 */
#define EAL_RX_PAUSE_CFG_VL0_RESEND_MASK        GENMASK_ULL(63, 58)
#define EAL_RX_PAUSE_CFG_VL0_GET_RESEND(r) \
	FIELD_GET(EAL_RX_PAUSE_CFG_VL0_RESEND_MASK, (r))
#define EAL_RX_PAUSE_CFG_VL0_SET_RESEND(r, resend)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_VL0_RESEND_MASK) | \
	      FIELD_PREP(EAL_RX_PAUSE_CFG_VL0_RESEND_MASK, (resend)); }

/*
 * Bits [57:42]: vl0_pause_quanta field
 */
#define EAL_RX_PAUSE_CFG_VL0_QUANTA_MASK        GENMASK_ULL(57, 42)
#define EAL_RX_PAUSE_CFG_VL0_GET_QUANTA(r) FIELD_GET(EAL_RX_PAUSE_CFG_VL0_QUANTA_MASK, (r))
#define EAL_RX_PAUSE_CFG_VL0_SET_QUANTA(r, quanta)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_VL0_QUANTA_MASK) | \
	      FIELD_PREP(EAL_RX_PAUSE_CFG_VL0_QUANTA_MASK, (quanta)); }

/*
 * Bits [41:28]: vl0_restart_threshold field
 * When credits >= threshold, send pause frame with quanta=0
 */
#define EAL_RX_PAUSE_CFG_VL0_RESTART_MASK       GENMASK_ULL(41, 28)
#define EAL_RX_PAUSE_CFG_VL0_GET_RESTART(r) FIELD_GET(EAL_RX_PAUSE_CFG_VL0_RESTART_MASK, (r))
#define EAL_RX_PAUSE_CFG_VL0_SET_RESTART(r, threshold)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_VL0_RESTART_MASK) | \
	      FIELD_PREP(EAL_RX_PAUSE_CFG_VL0_RESTART_MASK, (threshold)); }

/*
 * Bits [27:14]: vl0_low_water_theshold field
 * When credits < threshold, generate pause frame
 */
#define EAL_RX_PAUSE_CFG_VL0_LOW_WATER_MASK     GENMASK_ULL(27, 14)
#define EAL_RX_PAUSE_CFG_VL0_GET_LOW_WATER(r) FIELD_GET(EAL_RX_PAUSE_CFG_VL0_LOW_WATER_MASK, (r))
#define EAL_RX_PAUSE_CFG_VL0_SET_LOW_WATER(r, threshold)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_VL0_LOW_WATER_MASK) | \
	      FIELD_PREP(EAL_RX_PAUSE_CFG_VL0_LOW_WATER_MASK, (threshold)); }

/*
 * Bits [13:0]: vl0_rbuf_credits field
 */
#define EAL_RX_PAUSE_CFG_VL0_CREDITS_MASK       GENMASK_ULL(13, 0)
#define EAL_RX_PAUSE_CFG_VL0_GET_CREDITS(r) FIELD_GET(EAL_RX_PAUSE_CFG_VL0_CREDITS_MASK, (r))
#define EAL_RX_PAUSE_CFG_VL0_SET_CREDITS(r, credits)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_VL0_CREDITS_MASK) | \
	      FIELD_PREP(EAL_RX_PAUSE_CFG_VL0_CREDITS_MASK, (credits)); }

/* D.5.22 EAL_RX_PAUSE_CONFIG register */
#define CYR_EAL_RX_PAUSE_CONFIG (CYR_EAL_CFG + 0xd0000 + 0x58 * 8)
/*
 * Bit [1]: rx_mac_pfc_enable field
 * 1 = Enable RX PFC processing in MAC IP
 * 0 = Disable RX PFC processing in MAC IP
 */
#define EAL_RX_PAUSE_CFG_RX_MAC_PFC_EN_MASK     BIT_ULL(1)
#define EAL_RX_PAUSE_CFG_GET_RX_MAC_PFC_EN(r) FIELD_GET(EAL_RX_PAUSE_CFG_RX_MAC_PFC_EN_MASK, (r))
#define EAL_RX_PAUSE_CFG_SET_RX_MAC_PFC_EN(r, enable)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_RX_MAC_PFC_EN_MASK) | \
	      FIELD_PREP(EAL_RX_PAUSE_CFG_RX_MAC_PFC_EN_MASK, (enable)); }

/*
 * Bit [0]: pfc_pause_enabled field
 * 1 = PFC mode (priority-based, 802.1Qbb)
 * 0 = Classic Pause mode (non-priority, 802.3x)
 */
#define EAL_RX_PAUSE_CFG_PFC_ENABLED_MASK       BIT_ULL(0)
#define EAL_RX_PAUSE_CFG_GET_PFC_ENABLED(r) FIELD_GET(EAL_RX_PAUSE_CFG_PFC_ENABLED_MASK, (r))
#define EAL_RX_PAUSE_CFG_SET_PFC_ENABLED(r, enable)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_PFC_ENABLED_MASK) | \
	      FIELD_PREP(EAL_RX_PAUSE_CFG_PFC_ENABLED_MASK, (enable)); }

/* D.5.23 EAL_PF_FORCE_PAUSE_DISABLE register */
#define CYR_EAL_PF_FORCE_PAUSE_DISABLE (CYR_EAL_CFG + 0xd0000 + 0x59 * 8)
/*
 * Bit n = 1 stops VL/priority n generating pause/PFC frames (HAS 0.6.1).
 * Reset: 0xFE (VL0 only); HAS 0.6.1 clean copy lists 0x00.
 */
#define EAL_PF_FORCE_PAUSE_DISABLE_MASK      GENMASK_ULL(7, 0)
#define EAL_PF_FORCE_PAUSE_DISABLE_GET_MASK(r) FIELD_GET(EAL_PF_FORCE_PAUSE_DISABLE_MASK, (r))
#define EAL_PF_FORCE_PAUSE_DISABLE_SET_MASK(r, mask)  \
	{(r) = ((r) & ~EAL_PF_FORCE_PAUSE_DISABLE_MASK) | \
	      FIELD_PREP(EAL_PF_FORCE_PAUSE_DISABLE_MASK, (mask)); }

/* D.5.24 EAL_PF_VLAN_CFG register */
#define CYR_EAL_PF_VLAN_CFG (CYR_EAL_CFG + 0xd0000 + 0x5a * 8)

/* D.5.25 EAL_VL_PFC_MAPPING_TABLE register */
#define CYR_EAL_VL_PFC_MAPPING_TABLE (CYR_EAL_CFG + 0xd0000 + 0x5b * 8)

/* D.5.26 EAL_PORT_RX_PKT_COUNT register */
#define CYR_EAL_PORT_RX_PKT_COUNT (CYR_EAL_CFG + 0xd0000 + 0x5c * 8)

/* D.5.27 EAL_PORT_RX_PKT_BYTE_COUNT register */
#define CYR_EAL_PORT_RX_PKT_BYTE_COUNT (CYR_EAL_CFG + 0xd0000 + 0x5d * 8)

/* D.5.28 EAL_PORT_TX_PKT_COUNT register */
#define CYR_EAL_PORT_TX_PKT_COUNT (CYR_EAL_CFG + 0xd0000 + 0x5e * 8)

/* D.5.29 EAL_PORT_TX_PKT_BYTE_COUNT register */
#define CYR_EAL_PORT_TX_PKT_BYTE_COUNT (CYR_EAL_CFG + 0xd0000 + 0x5f * 8)

/* D.5.30 EAL_PORT_RX_PKT_DROP_COUNT register */
#define CYR_EAL_PORT_RX_PKT_DROP_COUNT (CYR_EAL_CFG + 0xd0000 + 0x60 * 8)
/*
 * Bits [47:0]: pause_event_count field
 * Number of pause threshold events triggered by VL0
 * Access: RO/V (Read-only/Volatile)
 */
#define EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0_PAUSE_EVENT_COUNT_MASK   GENMASK_ULL(47, 0)
#define EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0_GET_PAUSE_EVENT_COUNT(r) \
	FIELD_GET(EAL_VF_PRF_RBUF_PAUSE_CNTR_VL0_PAUSE_EVENT_COUNT_MASK, (r))

/* D.5.31 EAL_PORT_TX_PKT_DROP_COUNT register */
#define CYR_EAL_PORT_TX_PKT_DROP_COUNT (CYR_EAL_CFG + 0xd0000 + 0x61 * 8)

/* D.5.32 EAL_PF_BCAST_CFG register */
#define CYR_EAL_PF_BCAST_CFG (CYR_EAL_CFG + 0xd0000 + 0x62 * 8)

/* D.5.33 EAL_IP_PROTOCOL_TABLE register */
#define CYR_EAL_IP_PROTOCOL_TABLE (CYR_EAL_CFG + 0xd0000 + 0x68 * 8)
#define CYR_EAL_IP_PROTOCOL_TABLE_ENTRIES 8

/* D.5.35 EAL_CFG register */
#define CYR_EAL_FILTER_CFG (CYR_EAL_CFG + 0xd0000 + 0x81 * 8)
/*
 * Bit [2]: filter_unknown_ip_da field
 * Filter Unknown IP Destination Address
 * 1 = Filter (drop) frames with a Destination IP address that doesn't match
 *     an entry in the IP DA table
 * 0 = Forward frames with unknown IP destination addresses
 *
 * This applies to IP packets whose destination IP address is not found in the
 * EAL IP Destination Address lookup table.
 */
#define EAL_CFG_FILTER_UNKNOWN_IP_DA_MASK       BIT_ULL(2)
#define EAL_CFG_GET_FILTER_UNKNOWN_IP_DA(r) FIELD_GET(EAL_CFG_FILTER_UNKNOWN_IP_DA_MASK, (r))
#define EAL_CFG_SET_FILTER_UNKNOWN_IP_DA(r, filter)  \
	{(r) = ((r) & ~EAL_CFG_FILTER_UNKNOWN_IP_DA_MASK) | \
	      FIELD_PREP(EAL_CFG_FILTER_UNKNOWN_IP_DA_MASK, (filter)); }

/*
 * Bit [1]: filter_unknown_mcast field
 * Filter Unknown L2 Multicast
 * 1 = Filter (drop) L2 multicast frames that don't have an entry in the MCAST table
 * 0 = Forward L2 multicast frames even if not in the MCAST table
 *
 * This applies to L2 multicast frames (non-IP multicast). If there is no entry in
 * the MCAST table for this L2 multicast address and this bit is set, the frame
 * will be filtered.
 */
#define EAL_CFG_FILTER_UNKNOWN_MCAST_MASK       BIT_ULL(1)
#define EAL_CFG_GET_FILTER_UNKNOWN_MCAST(r) FIELD_GET(EAL_CFG_FILTER_UNKNOWN_MCAST_MASK, (r))
#define EAL_CFG_SET_FILTER_UNKNOWN_MCAST(r, filter)  \
	{(r) = ((r) & ~EAL_CFG_FILTER_UNKNOWN_MCAST_MASK) | \
	      FIELD_PREP(EAL_CFG_FILTER_UNKNOWN_MCAST_MASK, (filter)); }

/*
 * Bit [0]: filter_unknown_dmac field
 * Filter Unknown Destination MAC Address
 * 1 = Filter (drop) frames with a DMAC that doesn't match an entry in the DMAC table
 * 0 = Forward frames with unknown DMAC addresses
 *
 * This applies to unicast frames whose destination MAC address is not found in
 * the EAL DMAC lookup table (EAL_PF_DMAC_ADDRESS).
 */
#define EAL_CFG_FILTER_UNKNOWN_DMAC_MASK        BIT_ULL(0)
#define EAL_CFG_GET_FILTER_UNKNOWN_DMAC(r) FIELD_GET(EAL_CFG_FILTER_UNKNOWN_DMAC_MASK, (r))
#define EAL_CFG_SET_FILTER_UNKNOWN_DMAC(r, filter)  \
	{(r) = ((r) & ~EAL_CFG_FILTER_UNKNOWN_DMAC_MASK) | \
	      FIELD_PREP(EAL_CFG_FILTER_UNKNOWN_DMAC_MASK, (filter)); }

/* D.5.36 EAL_TX_AU_TABLE_0TO3 register */
#define CYR_EAL_TX_AU_TABLE_0TO3 (CYR_EAL_CFG + 0xd0000 + 0x82 * 8)

/* D.5.38 EAL_RX_AU_TABLE_0TO3 register */
#define CYR_EAL_RX_AU_TABLE_0TO3 (CYR_EAL_CFG + 0xd0000 + 0x85 * 8)

/* D.5.40 EAL_1588_PTP_PF_CFG0 register */
#define CYR_EAL_1588_PTP_PF_CFG0 (CYR_EAL_CFG + 0xd0000 + 0x87 * 8)

/*
 * Bit [20]: ptp_master field
 * Indicates whether this Port/PF is acting as the PTP Master or Slave
 *   1 = PTP Master
 *   0 = PTP Slave
 */
#define EAL_1588_PTP_PF_CFG0_PTP_MASTER_MASK            BIT_ULL(20)
#define EAL_1588_PTP_PF_CFG0_GET_PTP_MASTER(r) FIELD_GET(EAL_1588_PTP_PF_CFG0_PTP_MASTER_MASK, (r))
#define EAL_1588_PTP_PF_CFG0_SET_PTP_MASTER(r, v)  \
	{(r) = ((r) & ~EAL_1588_PTP_PF_CFG0_PTP_MASTER_MASK) | \
	FIELD_PREP(EAL_1588_PTP_PF_CFG0_PTP_MASTER_MASK, (v)); }

/*
 * Bits [17:16]: ptp_rx_ts_size field
 * Size of the timestamp added on Ingress in bytes:
 *   00 = 12-bytes (6-byte "seconds", 4-byte "nanoseconds", 2-byte "fraction of nanoseconds")
 *   01 = 10-bytes (6-byte "seconds", 4-byte "nanoseconds")
 *   10,11 = 8-bytes (4-byte "seconds", 4-byte "nanoseconds")
 */
#define EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_MASK        GENMASK_ULL(17, 16)
#define EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_8B		2
#define EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_10B		1
#define EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_12B		0
#define EAL_1588_PTP_PF_CFG0_GET_PTP_RX_TS_SIZE(r) \
	FIELD_GET(EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_MASK, (r))
#define EAL_1588_PTP_PF_CFG0_SET_PTP_RX_TS_SIZE(r, v)  \
	{(r) = ((r) & ~EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_MASK) | \
	FIELD_PREP(EAL_1588_PTP_PF_CFG0_PTP_RX_TS_SIZE_MASK, (v)); }

#define CNE_RX_TS_SIZE 12

/*
 * Bits [7:0]: ptp_rx_ts_enb_mask field
 * Enable timestamping to be managed by a VF/PF for ingress.
 * Each bit corresponds to a VF (bit 0 = VF0, bit 1 = VF1, etc.)
 *   1 = enable timestamping for this VF/PF
 *   0 = disable (also clears corresponding VF's EAL_1588_PTP_CFG.ptp_rx_ts_enable)
 * Individual control is performed through EAL_1588_PTP_CFG.ptp_rx_ts_enable.
 */
#define EAL_1588_PTP_PF_CFG0_PTP_RX_TS_ENB_MASK_MASK    GENMASK_ULL(7, 0)
#define EAL_1588_PTP_PF_CFG0_GET_PTP_RX_TS_ENB_MASK(r) \
	FIELD_GET(EAL_1588_PTP_PF_CFG0_PTP_RX_TS_ENB_MASK_MASK, (r))
#define EAL_1588_PTP_PF_CFG0_SET_PTP_RX_TS_ENB_MASK(r, v)  \
	{(r) = ((r) & ~EAL_1588_PTP_PF_CFG0_PTP_RX_TS_ENB_MASK_MASK) | \
	FIELD_PREP(EAL_1588_PTP_PF_CFG0_PTP_RX_TS_ENB_MASK_MASK, (v)); }

/* D.5.41 EAL_1588_PTP_TX_CFG register */
#define CYR_EAL_PF_1588_PTP_TX_CFG (CYR_EAL_CFG + 0xd0000 + 0x88 * 8)

/* D.5.45 EAL_PF_1588_PTP_EVENTS register */
#define CYR_EAL_PF_1588_PTP_EVENTS (CYR_EAL_CFG + 0xd0000 + 0x8c * 8)
/*
 * Sticky PTP event message detected flags.
 * Access: RW/1C/V (Read/Write-1-to-Clear/Volatile)
 */

/* D.5.46 EAL_TBUF_AVAIL_THRESHOLD register */
#define CYR_EAL_TBUF_AVAIL_THRESHOLD (CYR_EAL_CFG + 0xd0000 + 0x8d * 8)

/* D.5.47 EAL_TBUF_AVAIL_SPACE register */
#define CYR_EAL_TBUF_AVAIL_SPACE (CYR_EAL_CFG + 0xd0000 + 0x8e * 8)

/* D.5.48 EAL_RBUF_CREDIT_RET_ERR register */
#define CYR_EAL_RBUF_CREDIT_RET_ERR (CYR_EAL_CFG + 0xd0000 + 0x8f * 8)
/*
 * Sticky per-VL and shared RBUF credit return error flags.
 * Access: RW/1C/V (Read/Write-1-to-Clear/Volatile)
 */

/* D.5.49 EAL_TODGEN_CORE_CLK_PERIOD register */
#define CYR_EAL_TODGEN_CORE_CLK_PERIOD (CYR_EAL_CFG + 0xd0000 + 0xa0 * 8)
/*
 * Bits [31:0]: core_clk_period field
 * Core clock period in ns * 2^32. Reset: 0x9A1CAC08 (0.602 ns)
 */

/* D.5.50 EAL_MINI_PAUSE_CFG register */
#define CYR_EAL_MINI_PAUSE_CFG (CYR_EAL_CFG + 0xd0000 + 0xa1 * 8)

/* D.5.51 EAL_TAG_TIME_WINDOW_THRESHOLD register */
#define CYR_EAL_TAG_TIME_WINDOW_THRESHOLD (CYR_EAL_CFG + 0xd0000 + 0xa2 * 8)

/* D.5.52 EAL_TID_RDMA_CFG register */
#define CYR_EAL_TID_RDMA_CFG (CYR_EAL_CFG + 0xd0000 + 0xa3 * 8)

/* D.5.53 EAL_RX_PAUSE_CONFIG_SHR register */
#define CYR_EAL_RX_PAUSE_CFG_SHR (CYR_EAL_CFG + 0xD0000 + 0xA4 * 8)
/*
 * Bits [63:58]: shr_pause_resend field
 * This value multiplied by 64 quanta to create the Pause frame resend threshold.
 * When the pause counter goes below this value and credit thresholds indicate
 * that pausing is desired, a Pause frame will be resent and the pause counter
 * reset to shr_pause_quanta.
 *   0x00 = no resend
 *   0x01 = 64 quanta (4 KiB)
 *   0x3F = 4Ki quanta (256 KiB)
 */
#define EAL_RX_PAUSE_CFG_SHR_PAUSE_RESEND_MASK       GENMASK_ULL(63, 58)
#define EAL_RX_PAUSE_CFG_SHR_GET_PAUSE_RESEND(r) \
	FIELD_GET(EAL_RX_PAUSE_CFG_SHR_PAUSE_RESEND_MASK, (r))
#define EAL_RX_PAUSE_CFG_SHR_SET_PAUSE_RESEND(r, v)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_SHR_PAUSE_RESEND_MASK) | \
	FIELD_PREP(EAL_RX_PAUSE_CFG_SHR_PAUSE_RESEND_MASK, (v)); }

/*
 * Bits [57:42]: shr_pause_quanta field
 * Pause quanta value sent in the Pause frame when a Pause frame is generated.
 * Each quanta represents a 512-bit time (64 bytes at minimum frame rate).
 */
#define EAL_RX_PAUSE_CFG_SHR_PAUSE_QUANTA_MASK       GENMASK_ULL(57, 42)
#define EAL_RX_PAUSE_CFG_SHR_GET_PAUSE_QUANTA(r) \
	FIELD_GET(EAL_RX_PAUSE_CFG_SHR_PAUSE_QUANTA_MASK, (r))
#define EAL_RX_PAUSE_CFG_SHR_SET_PAUSE_QUANTA(r, v)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_SHR_PAUSE_QUANTA_MASK) | \
	FIELD_PREP(EAL_RX_PAUSE_CFG_SHR_PAUSE_QUANTA_MASK, (v)); }

/*
 * Bits [41:28]: shr_restart_threshold field
 * When the transmission of frames has been paused and the Rbuf credits go
 * above or equal to this value, a Pause frame with 0s in the pause quanta
 * will be generated, allowing the remote transmitter to send packets again.
 * Units: Credits (1 credit = 64 bytes)
 */
#define EAL_RX_PAUSE_CFG_SHR_RESTART_THRESHOLD_MASK  GENMASK_ULL(41, 28)
#define EAL_RX_PAUSE_CFG_SHR_GET_RESTART_THRESHOLD(r) \
	FIELD_GET(EAL_RX_PAUSE_CFG_SHR_RESTART_THRESHOLD_MASK, (r))
#define EAL_RX_PAUSE_CFG_SHR_SET_RESTART_THRESHOLD(r, v)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_SHR_RESTART_THRESHOLD_MASK) | \
	FIELD_PREP(EAL_RX_PAUSE_CFG_SHR_RESTART_THRESHOLD_MASK, (v)); }

/*
 * Bits [27:14]: shr_low_water_theshold field
 * When the number of credits available in the Rbuf goes below this threshold,
 * a Pause frame is generated.
 * Units: Credits (1 credit = 64 bytes)
 */
#define EAL_RX_PAUSE_CFG_SHR_LOW_WATER_THRESHOLD_MASK GENMASK_ULL(27, 14)
#define EAL_RX_PAUSE_CFG_SHR_GET_LOW_WATER_THRESHOLD(r) \
	FIELD_GET(EAL_RX_PAUSE_CFG_SHR_LOW_WATER_THRESHOLD_MASK, (r))
#define EAL_RX_PAUSE_CFG_SHR_SET_LOW_WATER_THRESHOLD(r, v)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_SHR_LOW_WATER_THRESHOLD_MASK) | \
	 FIELD_PREP(EAL_RX_PAUSE_CFG_SHR_LOW_WATER_THRESHOLD_MASK, (v)); }

/*
 * Bits [13:0]: shr_rbuf_credits field
 * Rbuf credits allocated to the shared pool.
 * Units: Credits (1 credit = 64 bytes)
 */
#define EAL_RX_PAUSE_CFG_SHR_RBUF_CREDITS_MASK       GENMASK_ULL(13, 0)
#define EAL_RX_PAUSE_CFG_SHR_GET_RBUF_CREDITS(r) \
	FIELD_GET(EAL_RX_PAUSE_CFG_SHR_RBUF_CREDITS_MASK, (r))
#define EAL_RX_PAUSE_CFG_SHR_SET_RBUF_CREDITS(r, v)  \
	{(r) = ((r) & ~EAL_RX_PAUSE_CFG_SHR_RBUF_CREDITS_MASK) | \
	FIELD_PREP(EAL_RX_PAUSE_CFG_SHR_RBUF_CREDITS_MASK, (v)); }

#define CYR_RX_MAC_MAX_PKT_THRES (CYR_EAL_CFG + 0xf1038)
#define CYR_TX_MAC_MAX_PKT_THRES (CYR_EAL_CFG + 0xf0038)

/* D.4.24 EAL_VLAN_CFG register */
#define CYR_EAL_VLAN_CFG (CYR_EAL_CFG + 0xc0000 + 0x18 * 8)

/*
 * Bit [33]: strip_outer_tag field
 * Strip Outer VLAN Tag
 * 1 = If there are two tags present, strip the outer tag
 * 0 = Do not strip outer tag
 *
 * This applies when a frame has two VLAN tags (Q-in-Q).
 */
#define EAL_VLAN_CFG_STRIP_OUTER_TAG_MASK       BIT_ULL(33)
#define EAL_VLAN_CFG_GET_STRIP_OUTER_TAG(r) FIELD_GET(EAL_VLAN_CFG_STRIP_OUTER_TAG_MASK, (r))
#define EAL_VLAN_CFG_SET_STRIP_OUTER_TAG(r, strip)  \
	{(r) = ((r) & ~EAL_VLAN_CFG_STRIP_OUTER_TAG_MASK) | \
	      FIELD_PREP(EAL_VLAN_CFG_STRIP_OUTER_TAG_MASK, (strip)); }

/*
 * Bit [32]: strip_inner_tag field
 * Strip Inner (or Only) VLAN Tag
 * 1 = Remove inner or only tag
 * 0 = Do not strip inner tag
 *
 * Note: There is no reason to remove an inner tag without having removed
 * an outer tag as well. Therefore, if this bit is set, the strip_outer_tag
 * is also considered set.
 */
#define EAL_VLAN_CFG_STRIP_INNER_TAG_MASK       BIT_ULL(32)
#define EAL_VLAN_CFG_GET_STRIP_INNER_TAG(r) FIELD_GET(EAL_VLAN_CFG_STRIP_INNER_TAG_MASK, (r))
#define EAL_VLAN_CFG_SET_STRIP_INNER_TAG(r, strip)  \
	{(r) = ((r) & ~EAL_VLAN_CFG_STRIP_INNER_TAG_MASK) | \
	      FIELD_PREP(EAL_VLAN_CFG_STRIP_INNER_TAG_MASK, (strip)); }

/*
 * Bits [31:20]: vlan_vid_2 field
 * Second VLAN ID/VID
 * 12-bit VLAN ID this VF may also be a member of
 *
 * Range: 0x000 - 0xFFF (0-4095)
 * Valid only when vid2_valid is set
 */
#define EAL_VLAN_CFG_VID2_MASK                  GENMASK_ULL(31, 20)
#define EAL_VLAN_CFG_GET_VID2(r) FIELD_GET(EAL_VLAN_CFG_VID2_MASK, (r))
#define EAL_VLAN_CFG_SET_VID2(r, vid)  \
	{(r) = ((r) & ~EAL_VLAN_CFG_VID2_MASK) | FIELD_PREP(EAL_VLAN_CFG_VID2_MASK, (vid)); }

/*
 * Bits [19:8]: vlan_vid field
 * Primary VLAN ID/VID
 * 12-bit VLAN ID this VF is a member of
 *
 * Range: 0x000 - 0xFFF (0-4095)
 * Valid only when vid_valid is set
 */
#define EAL_VLAN_CFG_VID_MASK                   GENMASK_ULL(19, 8)
#define EAL_VLAN_CFG_GET_VID(r) FIELD_GET(EAL_VLAN_CFG_VID_MASK, (r))
#define EAL_VLAN_CFG_SET_VID(r, vid)  \
	{(r) = ((r) & ~EAL_VLAN_CFG_VID_MASK) | FIELD_PREP(EAL_VLAN_CFG_VID_MASK, (vid)); }

/*
 * Bit [4]: vid2_valid field
 * VID 2 Entry Valid
 * 1 = VID 2 entry (vlan_vid_2) is valid and should be used
 * 0 = VID 2 entry is not valid
 *
 * Must be set for the second VLAN ID to be used.
 */
#define EAL_VLAN_CFG_VID2_VALID_MASK            BIT_ULL(4)
#define EAL_VLAN_CFG_GET_VID2_VALID(r) FIELD_GET(EAL_VLAN_CFG_VID2_VALID_MASK, (r))
#define EAL_VLAN_CFG_SET_VID2_VALID(r, valid)  \
	{(r) = ((r) & ~EAL_VLAN_CFG_VID2_VALID_MASK) | \
	      FIELD_PREP(EAL_VLAN_CFG_VID2_VALID_MASK, (valid)); }

/*
 * Bit [3]: vid_valid field
 * VID Entry Valid
 * 1 = VID entry (vlan_vid) is valid and should be used
 * 0 = VID entry is not valid
 *
 * Must be set for the primary VLAN ID to be used.
 */
#define EAL_VLAN_CFG_VID_VALID_MASK             BIT_ULL(3)
#define EAL_VLAN_CFG_GET_VID_VALID(r) FIELD_GET(EAL_VLAN_CFG_VID_VALID_MASK, (r))
#define EAL_VLAN_CFG_SET_VID_VALID(r, valid)  \
	{(r) = ((r) & ~EAL_VLAN_CFG_VID_VALID_MASK) | \
	      FIELD_PREP(EAL_VLAN_CFG_VID_VALID_MASK, (valid)); }

/*
 * Bit [2]: filter_non_vlan_tagged_mcast field
 * Filter Non-VLAN-Tagged Multicast Frames
 * 1 = Filter (drop) received multicast frames that do not include a VLAN tag
 * 0 = Accept multicast frames without VLAN tags
 *
 * This applies specifically to multicast frames.
 */
#define EAL_VLAN_CFG_FILTER_NON_VLAN_TAGGED_MCAST_MASK  BIT_ULL(2)
#define EAL_VLAN_CFG_GET_FILTER_NON_VLAN_TAGGED_MCAST(r) \
	FIELD_GET(EAL_VLAN_CFG_FILTER_NON_VLAN_TAGGED_MCAST_MASK, (r))
#define EAL_VLAN_CFG_SET_FILTER_NON_VLAN_TAGGED_MCAST(r, filter)  \
	{(r) = ((r) & ~EAL_VLAN_CFG_FILTER_NON_VLAN_TAGGED_MCAST_MASK) | \
	      FIELD_PREP(EAL_VLAN_CFG_FILTER_NON_VLAN_TAGGED_MCAST_MASK, (filter)); }

/*
 * Bit [1]: filter_all_vlan_tagged field
 * Filter All VLAN-Tagged Frames
 * 1 = Filter (drop) received frames that have a VLAN tag targeting this VF
 * 0 = Accept frames with VLAN tags
 */
#define EAL_VLAN_CFG_FILTER_ALL_VLAN_TAGGED_MASK        BIT_ULL(1)
#define EAL_VLAN_CFG_GET_FILTER_ALL_VLAN_TAGGED(r) \
	FIELD_GET(EAL_VLAN_CFG_FILTER_ALL_VLAN_TAGGED_MASK, (r))
#define EAL_VLAN_CFG_SET_FILTER_ALL_VLAN_TAGGED(r, filter)  \
	{(r) = ((r) & ~EAL_VLAN_CFG_FILTER_ALL_VLAN_TAGGED_MASK) | \
	      FIELD_PREP(EAL_VLAN_CFG_FILTER_ALL_VLAN_TAGGED_MASK, (filter)); }

/*
 * Bit [0]: filter_non_vlan_tagged field
 * Filter Non-VLAN-Tagged Unicast Frames
 * 1 = Filter (drop) received unicast frames that do not include a VLAN tag
 * 0 = Accept unicast frames without VLAN tags
 *
 * This flag is NOT applicable to multicast and broadcast frames.
 */
#define EAL_VLAN_CFG_FILTER_NON_VLAN_TAGGED_MASK        BIT_ULL(0)
#define EAL_VLAN_CFG_GET_FILTER_NON_VLAN_TAGGED(r) \
	FIELD_GET(EAL_VLAN_CFG_FILTER_NON_VLAN_TAGGED_MASK, (r))
#define EAL_VLAN_CFG_SET_FILTER_NON_VLAN_TAGGED(r, filter)  \
	{(r) = ((r) & ~EAL_VLAN_CFG_FILTER_NON_VLAN_TAGGED_MASK) | \
	      FIELD_PREP(EAL_VLAN_CFG_FILTER_NON_VLAN_TAGGED_MASK, (filter)); }

/* Omega Core RX_MAIN_CTL1_MAIN_CTL1 register */
#define CYR_OCORE_RX_MAIN_CTL1 (CYR_EAL_CFG + 0xF1000)
/*
 * Bits [31:24]: max_ptp_block_windows field
 * Time windows for the core to consider each 40/20 words windows
 *
 * 8-bit value for PTP block window timing configuration.
 * Range: 0x00 - 0xFF
 */
#define OCORE_RX_MAIN_CTL1_MAX_PTP_BLOCK_WINDOWS_MASK       GENMASK(31, 24)
#define OCORE_RX_MAIN_CTL1_GET_MAX_PTP_BLOCK_WINDOWS(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_MAX_PTP_BLOCK_WINDOWS_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_MAX_PTP_BLOCK_WINDOWS(r, windows)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_MAX_PTP_BLOCK_WINDOWS_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_MAX_PTP_BLOCK_WINDOWS_MASK, (windows)); }

/*
 * Bit [22]: ptp_ts_mode field
 * 0 = (default) PMA MODE
 * 1 = 66B/MII CBR MODE
 */
#define OCORE_RX_MAIN_CTL1_PTP_TS_MODE_MASK                 BIT(22)
#define OCORE_RX_MAIN_CTL1_PTP_TS_MODE_PMA                  0
#define OCORE_RX_MAIN_CTL1_PTP_TS_MODE_66B_MII_CBR          1
#define OCORE_RX_MAIN_CTL1_GET_PTP_TS_MODE(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_PTP_TS_MODE_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_PTP_TS_MODE(r, mode)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_PTP_TS_MODE_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_PTP_TS_MODE_MASK, (mode)); }

/*
 * Bit [21]: block_adj_format field
 * 0 = (default) BLOCK_ADJ format is {4-bit ns, 12-bit fraction of ns}
 * 1 = BLOCK_ADJ format is {16-bit fraction of ns}
 */
#define OCORE_RX_MAIN_CTL1_BLOCK_ADJ_FORMAT_MASK            BIT(21)
#define OCORE_RX_MAIN_CTL1_BLOCK_ADJ_FORMAT_4_12            0       /* 4-bit ns, 12-bit frac */
#define OCORE_RX_MAIN_CTL1_BLOCK_ADJ_FORMAT_16              1       /* 16-bit frac only */
#define OCORE_RX_MAIN_CTL1_GET_BLOCK_ADJ_FORMAT(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_BLOCK_ADJ_FORMAT_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_BLOCK_ADJ_FORMAT(r, format)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_BLOCK_ADJ_FORMAT_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_BLOCK_ADJ_FORMAT_MASK, (format)); }

/*
 * Bit [20]: enable_len_chk field
 * 0 = Turns off checking, no length error will flag
 * 1 = (default) Check the type/length content and evaluate as type or size
 *
 * All frames type/length field is checked for sizing:
 * - Regular: >=46 & <=1500
 * - VLAN1:   >=42 & <=1500
 * - VLAN2:   >=38 & <=1500
 */
#define OCORE_RX_MAIN_CTL1_ENABLE_LEN_CHK_MASK              BIT(20)
#define OCORE_RX_MAIN_CTL1_GET_ENABLE_LEN_CHK(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_ENABLE_LEN_CHK_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_ENABLE_LEN_CHK(r, enable)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_ENABLE_LEN_CHK_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_ENABLE_LEN_CHK_MASK, (enable)); }

/*
 * Bit [17]: stats_en field
 * 0 = Clock gate to Statistics monitor.  All Statistic Registers will return 0.
 * 1 = Enable statistics monitoring
 */
#define OCORE_RX_MAIN_CTL1_STATS_EN_MASK                    BIT(17)
#define OCORE_RX_MAIN_CTL1_GET_STATS_EN(r) FIELD_GET(OCORE_RX_MAIN_CTL1_STATS_EN_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_STATS_EN(r, enable)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_STATS_EN_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_STATS_EN_MASK, (enable)); }

/*
 * Bit [16]: force_ovsz_pkt_terminate field
 * 0 = (default) Oversize packets transmitted to client at full length
 * 1 = Any packet (with FCS) that violates MAX_PKT_SIZE will be terminated.
 *     Binning and CRC check continue internally. Client sees packet with error indication.
 */
#define OCORE_RX_MAIN_CTL1_FORCE_OVSZ_PKT_TERMINATE_MASK    BIT(16)
#define OCORE_RX_MAIN_CTL1_GET_FORCE_OVSZ_PKT_TERMINATE(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_FORCE_OVSZ_PKT_TERMINATE_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_FORCE_OVSZ_PKT_TERMINATE(r, terminate)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_FORCE_OVSZ_PKT_TERMINATE_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_FORCE_OVSZ_PKT_TERMINATE_MASK, (terminate)); }

/*
 * Bit [15]: drop_sub_64b_packets field
 * 0 = (default) Undersize packets transmitted to the client
 * 1 = Any packet less than 64 bytes will be dropped
 */
#define OCORE_RX_MAIN_CTL1_DROP_SUB_64B_PACKETS_MASK        BIT(15)
#define OCORE_RX_MAIN_CTL1_GET_DROP_SUB_64B_PACKETS(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_DROP_SUB_64B_PACKETS_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_DROP_SUB_64B_PACKETS(r, drop)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_DROP_SUB_64B_PACKETS_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_DROP_SUB_64B_PACKETS_MASK, (drop)); }

/*
 * Bit [14]: preamble_remove_en field
 * 0 = Disable preamble removal (pass preamble to client)
 * 1 = (default) Enable preamble removal
 */
#define OCORE_RX_MAIN_CTL1_PREAMBLE_REMOVE_EN_MASK          BIT(14)
#define OCORE_RX_MAIN_CTL1_GET_PREAMBLE_REMOVE_EN(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_PREAMBLE_REMOVE_EN_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_PREAMBLE_REMOVE_EN(r, enable)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_PREAMBLE_REMOVE_EN_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_PREAMBLE_REMOVE_EN_MASK, (enable)); }

/*
 * Bits [13:6]: tod_sync_samp_margin field
 * 8-bit value for Time-of-Day synchronization sampling margin (default: 0x10)
 */
#define OCORE_RX_MAIN_CTL1_TOD_SYNC_SAMP_MARGIN_MASK        GENMASK(13, 6)
#define OCORE_RX_MAIN_CTL1_TOD_SYNC_SAMP_MARGIN_DEFAULT     16
#define OCORE_RX_MAIN_CTL1_GET_TOD_SYNC_SAMP_MARGIN(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_TOD_SYNC_SAMP_MARGIN_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_TOD_SYNC_SAMP_MARGIN(r, margin)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_TOD_SYNC_SAMP_MARGIN_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_TOD_SYNC_SAMP_MARGIN_MASK, (margin)); }

/*
 * Bit [5]: fault_pattern_type field
 * 0 = (default) Clause 84 (40G+)
 * 1 = Clause 49 (25G and below)
 */
#define OCORE_RX_MAIN_CTL1_FAULT_PATTERN_TYPE_MASK          BIT(5)
#define OCORE_RX_MAIN_CTL1_FAULT_PATTERN_CLAUSE_84          0       /* 40G+ */
#define OCORE_RX_MAIN_CTL1_FAULT_PATTERN_CLAUSE_49          1       /* 25G and below */
#define OCORE_RX_MAIN_CTL1_GET_FAULT_PATTERN_TYPE(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_FAULT_PATTERN_TYPE_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_FAULT_PATTERN_TYPE(r, type)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_FAULT_PATTERN_TYPE_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_FAULT_PATTERN_TYPE_MASK, (type)); }

/*
 * Bit [3]: client_out_rate field
 * 0 = (default) Use the provided i__rx_fifo_req line to pull data from the FIFO
 * 1 = Use the PCS data rate to pull data out of the FIFO
 */
#define OCORE_RX_MAIN_CTL1_CLIENT_OUT_RATE_MASK             BIT(3)
#define OCORE_RX_MAIN_CTL1_CLIENT_OUT_RATE_REQ_LINE         0       /* Use req line */
#define OCORE_RX_MAIN_CTL1_CLIENT_OUT_RATE_PCS              1       /* Use PCS rate */
#define OCORE_RX_MAIN_CTL1_GET_CLIENT_OUT_RATE(r) \
	FIELD_GET(OCORE_RX_MAIN_CTL1_CLIENT_OUT_RATE_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_CLIENT_OUT_RATE(r, rate)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_CLIENT_OUT_RATE_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_CLIENT_OUT_RATE_MASK, (rate)); }

/*
 * Bit [2]: pause_fwd field
 * 0 = (default) Pause drop enabled - Pause frames not forwarded to receiving client
 * 1 = Pause forward enabled - Client receives all pause/PFC frames
 */
#define OCORE_RX_MAIN_CTL1_PAUSE_FWD_MASK                   BIT(2)
#define OCORE_RX_MAIN_CTL1_GET_PAUSE_FWD(r) FIELD_GET(OCORE_RX_MAIN_CTL1_PAUSE_FWD_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_PAUSE_FWD(r, forward)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_PAUSE_FWD_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_PAUSE_FWD_MASK, (forward)); }

/*
 * Bit [1]: pause_en field
 * 0 = Disable 802.3 PAUSE frame handling
 * 1 = (default) Enable 802.3 PAUSE frame handling. TX MAC responds to PAUSE requests.
 */
#define OCORE_RX_MAIN_CTL1_PAUSE_EN_MASK                    BIT(1)
#define OCORE_RX_MAIN_CTL1_GET_PAUSE_EN(r) FIELD_GET(OCORE_RX_MAIN_CTL1_PAUSE_EN_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_PAUSE_EN(r, enable)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_PAUSE_EN_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_PAUSE_EN_MASK, (enable)); }

/*
 * Bit [0]: pm_tick_en field
 * 0 = (default) Disable external performance monitoring (PM) tick
 * 1 = Enable external PM tick to latch current counter values
 */
#define OCORE_RX_MAIN_CTL1_PM_TICK_EN_MASK                  BIT(0)
#define OCORE_RX_MAIN_CTL1_GET_PM_TICK_EN(r) FIELD_GET(OCORE_RX_MAIN_CTL1_PM_TICK_EN_MASK, (r))
#define OCORE_RX_MAIN_CTL1_SET_PM_TICK_EN(r, enable)  \
	{(r) = ((r) & ~OCORE_RX_MAIN_CTL1_PM_TICK_EN_MASK) | \
	      FIELD_PREP(OCORE_RX_MAIN_CTL1_PM_TICK_EN_MASK, (enable)); }

#define TX_MAC_PAUSE_FRM_CNT_MSB  0x7F0060
#define TX_MAC_PAUSE_FRM_CNT_LSB 0x7F0068
#define TX_MAC_PFC_FRM_CNT_MSB 0x7F0200
#define TX_MAC_PFC_FRM_CNT_LSB 0x7F0208

#define RX_MAC_PAUSE_FRM_CNT_MSB 0x7F1060
#define RX_MAC_PAUSE_FRM_CNT_LSB 0x7F1068
#define RX_MAC_PFC_FRM_CNT_MSB 0x7F1260
#define RX_MAC_PFC_FRM_CNT_LSB 0x7F1268

/* Omega Core TX_MAIN_CTL1_MAIN_CTL1 register */
#define CYR_OCORE_TX_MAIN_CTL1 (CYR_EAL_CFG + 0xF0000)

/* driver_addr = <block base> + (vendor_offset * 2), per EAL MAS S2.11.2 */
#define OCORE_MAC_OFF(vendor_off) ((vendor_off) * 2)

/*
 * MAIN_CTL1.STATS_EN gates the whole statistics/RMON monitor for a
 * direction; MAIN_CTL1.PM_TICK_EN gates the periodic hardware latch
 * that updates all RMON/MIB counters once per SOC_CMN PM_TICK_PERIOD.
 *
 * NOTE: unlike most fields in this file, STATS_EN sits at a *different*
 * bit position for TX (bit 16) than for RX (bit 17).
 */
#define OCORE_TX_MAIN_CTL1_STATS_EN_MASK BIT(16)
#define OCORE_TX_MAIN_CTL1_GET_STATS_EN(r) FIELD_GET(OCORE_TX_MAIN_CTL1_STATS_EN_MASK, (r))
/* Returns @r with the stats_en field replaced by @enable (assign the result). */
#define OCORE_TX_MAIN_CTL1_SET_STATS_EN(r, enable) \
	(((r) & ~OCORE_TX_MAIN_CTL1_STATS_EN_MASK) | \
	 FIELD_PREP(OCORE_TX_MAIN_CTL1_STATS_EN_MASK, (enable)))

#define OCORE_TX_MAIN_CTL1_PM_TICK_EN_MASK BIT(0)
#define OCORE_TX_MAIN_CTL1_GET_PM_TICK_EN(r) FIELD_GET(OCORE_TX_MAIN_CTL1_PM_TICK_EN_MASK, (r))
/* Returns @r with the pm_tick_en field replaced by @enable (assign the result). */
#define OCORE_TX_MAIN_CTL1_SET_PM_TICK_EN(r, enable) \
	(((r) & ~OCORE_TX_MAIN_CTL1_PM_TICK_EN_MASK) | \
	 FIELD_PREP(OCORE_TX_MAIN_CTL1_PM_TICK_EN_MASK, (enable)))

/*
 * OmegaCORE MAC MIB RMON (RFC 2819) counters. All are type ROP
 * (Read-only, PM-controlled).
 *
 * Each counter is 48-bit at CYR's 400G line rate ("200G & above (48
 * bits)" per the vendor datasheet): MSB register only implements bits
 * [15:0] (bits [31:16] are unused/RO-0).
 *
 */
#define OCORE_MAC_BYTE_CNT_MSB_OFF          0x020 /* bits 47:32 of rx/tx byte count */
#define OCORE_MAC_BYTE_CNT_LSB_OFF          0x024
#define OCORE_MAC_TOTAL_FRM_CNT_MSB_OFF     0x028 /* frames without error, bits 47:32 */
#define OCORE_MAC_TOTAL_FRM_CNT_LSB_OFF     0x02C

/*
 * LATCHED_INT: bit 15 PM_TICK is a sticky RW1C
 * status bit that latches high each time the periodic PM_TICK event
 * fires (i.e. each time the ROP counters below are re-latched with a
 * fresh PM_TICK_PERIOD window). It can be polled with hardware IRQ
 * delivery fully disabled. Write 1 to bit 15 to clear only that bit (RW1C),
 * preserving other latched fault bits.
 */
#define OCORE_MAC_LATCHED_INT_OFF              0x008
#define OCORE_MAC_LATCHED_INT_PM_TICK_MASK     BIT(15)
#define OCORE_MAC_LATCHED_INT_GET_PM_TICK(r) \
	FIELD_GET(OCORE_MAC_LATCHED_INT_PM_TICK_MASK, (r))

#define OCORE_MAC_UNDERSIZE_FRM_CNT_MSB_OFF 0x0E0 /* good CRC, < min_pkt_len */
#define OCORE_MAC_UNDERSIZE_FRM_CNT_LSB_OFF 0x0E4
#define OCORE_MAC_OVERSIZE_FRM_CNT_MSB_OFF  0x0E8 /* good CRC, > max_pkt_len */
#define OCORE_MAC_OVERSIZE_FRM_CNT_LSB_OFF  0x0EC
#define OCORE_MAC_RUNT_FRM_CNT_MSB_OFF      0x0F0 /* bad CRC, < min_pkt_len: RMON "fragments" */
#define OCORE_MAC_RUNT_FRM_CNT_LSB_OFF      0x0F4
#define OCORE_MAC_JABBER_FRM_CNT_MSB_OFF    0x0F8 /* bad CRC, > max_pkt_len: RMON "jabbers" */
#define OCORE_MAC_JABBER_FRM_CNT_LSB_OFF    0x0FC

/*
 * OmegaCORE MAC MIB byte-size histogram: 13 native HW bins (RFC 2819
 * "pktsXtoYOctets" analog). MSB offset for each bin is listed; the LSB
 * register is always MSB_OFF + 4. Same 13-bin layout applies to both
 * RX_MAC and TX_MAC blocks.
 */
#define OCORE_MAC_HIST_NUM_BINS 13
#define OCORE_MAC_HIST_64B_MSB_OFF          0x050
#define OCORE_MAC_HIST_65_127B_MSB_OFF      0x058
#define OCORE_MAC_HIST_128_255B_MSB_OFF     0x060
#define OCORE_MAC_HIST_256_511B_MSB_OFF     0x068
#define OCORE_MAC_HIST_512_1023B_MSB_OFF    0x070
#define OCORE_MAC_HIST_1024_1518B_MSB_OFF   0x078
#define OCORE_MAC_HIST_1519_1522B_MSB_OFF   0x080
#define OCORE_MAC_HIST_1523_1548B_MSB_OFF   0x088
#define OCORE_MAC_HIST_1549_2047B_MSB_OFF   0x090
#define OCORE_MAC_HIST_2048_4095B_MSB_OFF   0x098
#define OCORE_MAC_HIST_4096_8191B_MSB_OFF   0x0A0
#define OCORE_MAC_HIST_8192_9600B_MSB_OFF   0x0A8
#define OCORE_MAC_HIST_9601B_UP_MSB_OFF     0x0B0

/*
 * OmegaCORE MAC MIB counters backing the RFC 3635 dot3StatsTable
 * (ethtool "eth-mac" group). Same ROP / 48-bit / MSB[15:0]<<32|LSB
 * / PM_TICK-snapshot semantics as the RMON counters above.
 *
 * GOOD_FRM_CNT / GOOD_BYTE_CNT are direction-symmetric. (identical
 * offset in the RX_MAC and TX_MAC blocks).
 */
#define OCORE_MAC_GOOD_FRM_CNT_MSB_OFF      0x0B8
#define OCORE_MAC_GOOD_FRM_CNT_LSB_OFF      0x0BC
#define OCORE_MAC_GOOD_BYTE_CNT_MSB_OFF     0x0D0
#define OCORE_MAC_GOOD_BYTE_CNT_LSB_OFF     0x0D4

/*
 * RX-only error counters (no TX analog in dot3StatsTable):
 *   CRC_ERR_FRM_CNT     -> FrameCheckSequenceErrors (bad FCS)
 *   MISALIGNMENT_FRM_CNT-> AlignmentErrors. SEMANTIC CAVEAT: on this
 *     400G MAC this counts a preamble/SFD alignment fault (MAL_ERR,
 *     "received frame has preamble error"), NOT the 802.3 dribble-nibble
 *     alignment error of the original RFC 3635 definition (unreachable
 *     at 400G). It is the closest available analog; documented here so
 *     the mapping is not mistaken for an exact RFC match.
 */
#define OCORE_MAC_CRC_ERR_FRM_CNT_MSB_OFF   0x0C8
#define OCORE_MAC_CRC_ERR_FRM_CNT_LSB_OFF   0x0CC
#define OCORE_MAC_MISALIGNMENT_FRM_CNT_MSB_OFF 0x100
#define OCORE_MAC_MISALIGNMENT_FRM_CNT_LSB_OFF 0x104

/*
 * Multicast / broadcast frame counters.
 * NOTE: the RX_MAC and TX_MAC blocks place these at DIFFERENT offsets -
 * the TX layout is effectively reversed relative to RX.
 */
#define OCORE_RX_MAC_MULTICAST_FRM_CNT_MSB_OFF 0x038
#define OCORE_RX_MAC_MULTICAST_FRM_CNT_LSB_OFF 0x03C
#define OCORE_RX_MAC_BROADCAST_FRM_CNT_MSB_OFF 0x048
#define OCORE_RX_MAC_BROADCAST_FRM_CNT_LSB_OFF 0x04C
#define OCORE_TX_MAC_MULTICAST_FRM_CNT_MSB_OFF 0x040
#define OCORE_TX_MAC_MULTICAST_FRM_CNT_LSB_OFF 0x044
#define OCORE_TX_MAC_BROADCAST_FRM_CNT_MSB_OFF 0x038
#define OCORE_TX_MAC_BROADCAST_FRM_CNT_LSB_OFF 0x03C

/*
 * Remaining MAC MIB counters (same ROP / 48-bit semantics). Offsets are
 * shared by the RX_MAC and TX_MAC blocks unless prefixed RX_/TX_. The
 * TX_MAC block also implements CRC_ERR, UNDERSIZE, OVERSIZE, RUNT and
 * JABBER at the offsets above.
 */
#define OCORE_MAC_PAUSE_FRM_CNT_MSB_OFF           0x030
#define OCORE_MAC_PAUSE_FRM_CNT_LSB_OFF           0x034
#define OCORE_MAC_ERROR_FRM_CNT_MSB_OFF           0x0C0
#define OCORE_MAC_ERROR_FRM_CNT_LSB_OFF           0x0C4
#define OCORE_MAC_ERROR_BYTE_CNT_MSB_OFF          0x0D8
#define OCORE_MAC_ERROR_BYTE_CNT_LSB_OFF          0x0DC
#define OCORE_MAC_PAUSE_XON_FRM_CNT_MSB_OFF       0x1E8
#define OCORE_MAC_PAUSE_XON_FRM_CNT_LSB_OFF       0x1EC
#define OCORE_MAC_PAUSE_XOFF_FRM_CNT_MSB_OFF      0x1F0
#define OCORE_MAC_PAUSE_XOFF_FRM_CNT_LSB_OFF      0x1F4
#define OCORE_MAC_CRC_ALIGN_FRM_CNT_MSB_OFF       0x1F8
#define OCORE_MAC_CRC_ALIGN_FRM_CNT_LSB_OFF       0x1FC
#define OCORE_RX_MAC_UNICAST_FRM_CNT_MSB_OFF      0x040
#define OCORE_RX_MAC_UNICAST_FRM_CNT_LSB_OFF      0x044
#define OCORE_TX_MAC_UNICAST_FRM_CNT_MSB_OFF      0x048
#define OCORE_TX_MAC_UNICAST_FRM_CNT_LSB_OFF      0x04C
#define OCORE_RX_MAC_BAD_PREAMBLE_FRM_CNT_MSB_OFF 0x108
#define OCORE_RX_MAC_BAD_PREAMBLE_FRM_CNT_LSB_OFF 0x10C
#define OCORE_RX_MAC_PFC_FRM_CNT_MSB_OFF          0x130
#define OCORE_RX_MAC_PFC_FRM_CNT_LSB_OFF          0x134
#define OCORE_TX_MAC_PFC_FRM_CNT_MSB_OFF          0x100
#define OCORE_TX_MAC_PFC_FRM_CNT_LSB_OFF          0x104

/*
 * MAC control/configuration registers. _OFF is the first of _NUM
 * consecutive 32-bit vendor registers. LOCAL_INT_CNT_CTL (0x014; a 0->1
 * write to bit 0 clears every counter in the block) and TX_MAC
 * FLOW_CTL_STAT (0x134, ROC) are deliberately not covered.
 */
#define OCORE_MAC_MAIN_CTL2_OFF             0x004
#define OCORE_MAC_INT_MASK_OFF              0x00C
#define OCORE_MAC_MIN_PKT_THRES_OFF         0x018

/* LOCAL_INT_CNT_CTL: a 0->1 write to CNT_CLEAR latches and clears counters */
#define OCORE_MAC_LOCAL_INT_CNT_CTL_OFF            0x014
#define OCORE_MAC_LOCAL_INT_CNT_CTL_CNT_CLEAR_MASK BIT_ULL(0)

#define OCORE_RX_MAC_FRM_CTL_OFF            0x110 /* FCS_FRM_CTL .. FCS_CTL */
#define OCORE_RX_MAC_FRM_CTL_NUM            8
#define OCORE_RX_MAC_PTP_VLAN_OFF           0x180 /* 1588_ADJ .. CVLAN_TPID */
#define OCORE_RX_MAC_PTP_VLAN_NUM           21
#define OCORE_TX_MAC_FIFO_OFF               0x108 /* FIFO_BP, FIFO_READ_THRESH */
#define OCORE_TX_MAC_FIFO_NUM               2
#define OCORE_TX_MAC_FLOW_OFF               0x12C /* FCS_CTL, FLOW_CTL */
#define OCORE_TX_MAC_FLOW_NUM               2
#define OCORE_TX_MAC_PAUSE_OFF              0x138 /* PAUSE_SRC_ADDR .. PFC_XOFF_WINDOW */
#define OCORE_TX_MAC_PAUSE_NUM              11
#define OCORE_TX_MAC_PTP_VLAN_OFF           0x170 /* DIC_AM_ADJ .. CVLAN_TPID */
#define OCORE_TX_MAC_PTP_VLAN_NUM           25
#define OCORE_TX_MAC_PPM_OFF                0x1E0 /* PPM_ADJ, AM_TOD_ADJ */
#define OCORE_TX_MAC_PPM_NUM                2

/* OmegaCORE SOC_CMN block */
#define CYR_OCORE_SOC_CONTROL (CYR_EAL_CFG + 0xE0400)
#define CYR_OCORE_PM_TICK_PERIOD (CYR_OCORE_SOC_CONTROL + OCORE_MAC_OFF(0x0C))
#define OCORE_SOC_CONTROL_TX_SYS_RESET_MASK BIT(31)
#define OCORE_SOC_CONTROL_RX_SYS_RESET_MASK BIT(30)
#define OCORE_SOC_CONTROL_GET_TX_SYS_RESET(r) FIELD_GET(OCORE_SOC_CONTROL_TX_SYS_RESET_MASK, (r))
#define OCORE_SOC_CONTROL_GET_RX_SYS_RESET(r) FIELD_GET(OCORE_SOC_CONTROL_RX_SYS_RESET_MASK, (r))
/*
 * PM_TICK_PERIOD (RW, reset 1,000,000,000) is the period of the PM tick
 * shared by the MAC and RS-FEC statistics latches, in OmegaCORE core
 * clock cycles. The regmap's "~1 sec" only holds for a 1 GHz core clock;
 * a 0.602 s latch window was measured on a 400G CYR link.
 */
#define OCORE_PM_TICK_PERIOD_POR_VALUE 0x3B9ACA00

/*
 * SOC_CMN control/status registers (_OFF is the first of _NUM
 * consecutive vendor registers). SOC_CONTROL bits 5/4 are
 * GLOBAL_CNT_CLEAR/GLOBAL_INT_CLEAR and must never be written from a
 * dump path; RX_66B_ERR_CNT (0x288) is ROC and is deliberately skipped.
 */
#define OCORE_SOC_CTL_OFF                   0x000 /* SOC_CONTROL .. INT_STATUS */
#define OCORE_SOC_CTL_NUM                   3
#define OCORE_SOC_CFG_OFF                   0x010 /* AM_FACTOR_SIM .. DP_MODE1 */
#define OCORE_SOC_CFG_NUM                   7
#define OCORE_SOC_LINK_INT_OFF              0x030 /* LINK/RXLOS/L2 mask + latched */
#define OCORE_SOC_LINK_INT_NUM              6
#define OCORE_SOC_PCS_CFG_OFF               0x100 /* FECPCS_CONFIG_0 .. RESET_CONFIG */
#define OCORE_SOC_PCS_CFG_NUM               11
#define OCORE_SOC_CLK_RST_OFF               0x130 /* SW_CLK_GATE .. MAC_RESET_CONFIG */
#define OCORE_SOC_CLK_RST_NUM               4
#define OCORE_SOC_66B_ERR_INT_OFF           0x280 /* PCS_66B_ERR latched + mask */
#define OCORE_SOC_66B_ERR_INT_NUM           2
#define OCORE_SOC_ECC_INT_OFF               0x28C /* PCS_ECC_ERR latched/mask 0..2 */
#define OCORE_SOC_ECC_INT_NUM               5
#define OCORE_SOC_FLEXO_OTU_AM_CNTRL_OFF    0x140
#define OCORE_SOC_CLIENT_OFF                0x148 /* TX_MAC_CLIENT_LF .. FEC_FOUR_LANE_PMD */
#define OCORE_SOC_CLIENT_NUM                3
#define OCORE_SOC_AM_LANE_OFF               0x160 /* AM_LOCK_CFG_0 .. LANE_SKEW_LIMIT_7 */
#define OCORE_SOC_AM_LANE_NUM               16
#define OCORE_SOC_RX_ALIGN_CONFIG_OFF       0x240
#define OCORE_SOC_SW_TOD_ADJUST_OFF         0x250
#define OCORE_SOC_ECC_INT_MASK2_OFF         0x300

/*
 * OmegaCORE RX RS-FEC statistics block (ethtool "fec" group).
 *
 * The vendor addressBlock rx_pcs_rsfec_400g_200g_ch_0 sits at vendor base
 * 0x2400 in the same OmegaCORE APB aperture as the MAC blocks (TC HAS
 * A00502 Appendix D Table D-2: 0x7E0000-0x7FFFFF, PF-only), so the same
 * driver_addr = CYR_EAL_CFG + 0xE0000 + (vendor_offset * 2) rule applies
 * and OCORE_MAC_OFF() is reused for block-relative offsets. Single-channel
 * Caiman variant: only _ch_0 exists.
 *
 * FEC_BASE = CYR_EAL_CFG + 0xE0000 + (0x2400 * 2) = CYR_EAL_CFG + 0xE4800.
 */
#define CYR_OCORE_RX_FEC (CYR_EAL_CFG + 0xE4800)

/*
 * FEC MAIN_CTL1 (block offset 0x0000). Both bits reset to 0 and BOTH must
 * be set: STATS_EN (bit 12) enables the RS decoder statistics counters
 * ("All Statistic Registers will return 0" otherwise); FEC_PM_TICK_EN
 * (bit 5) promotes the ROCP (read-to-clear) counters to PM-latched
 * non-destructive reads, latched on the shared SOC_CMN PM_TICK.
 */
#define OCORE_FEC_MAIN_CTL1_STATS_EN_MASK BIT(12)
#define OCORE_FEC_MAIN_CTL1_GET_STATS_EN(r) FIELD_GET(OCORE_FEC_MAIN_CTL1_STATS_EN_MASK, (r))
#define OCORE_FEC_MAIN_CTL1_SET_STATS_EN(r, enable) \
	(((r) & ~OCORE_FEC_MAIN_CTL1_STATS_EN_MASK) | \
	 FIELD_PREP(OCORE_FEC_MAIN_CTL1_STATS_EN_MASK, (enable)))

#define OCORE_FEC_MAIN_CTL1_PM_TICK_EN_MASK BIT(5)
#define OCORE_FEC_MAIN_CTL1_GET_PM_TICK_EN(r) FIELD_GET(OCORE_FEC_MAIN_CTL1_PM_TICK_EN_MASK, (r))
#define OCORE_FEC_MAIN_CTL1_SET_PM_TICK_EN(r, enable) \
	(((r) & ~OCORE_FEC_MAIN_CTL1_PM_TICK_EN_MASK) | \
	 FIELD_PREP(OCORE_FEC_MAIN_CTL1_PM_TICK_EN_MASK, (enable)))

/*
 * FEC MAIN_CTL1 bit 4 FEC_DECODER_BYPASS_EN (RW, reset 0): inverted-logic RS
 * decoder enable:
 *
 * 0 = RS-FEC decoder active (normal)
 * 1 = decoder bypassed (no FEC correction)
 */
#define OCORE_FEC_MAIN_CTL1_DEC_BYPASS_EN_MASK BIT(4)
#define OCORE_FEC_MAIN_CTL1_GET_DEC_BYPASS_EN(r) \
	FIELD_GET(OCORE_FEC_MAIN_CTL1_DEC_BYPASS_EN_MASK, (r))

/*
 * FEC codeword / symbol-error counters. All are 40-bit ROCP:
 * MSB register implements bits [7:0] (= counter bits [39:32]); LSB
 * register holds bits [31:0]. Block-relative vendor offsets (driver
 * addr = CYR_OCORE_RX_FEC + OCORE_MAC_OFF(off)).
 *
 * With FEC_PM_TICK_EN=0, reading an MSB register clears both MSB and
 * LSB, so the LSB must be read first. With FEC_PM_TICK_EN=1 both halves
 * are PM-latched and reads are non-destructive.
 *
 * Never touch these from a dump or debug path:
 * - RX_257_ERR_CNT (0x090)
 * - RX_66B_ERR_CNT (0x094)
 * - IN_LCK_AM_ERR_CNT (0x098)
 * - OUT_OF_AM_LOCK_CNT (0x09C)
 * - TEST_PATTERN_ERROR_CNT (0x0A0)
 * These registers are ROC regardless of FEC_PM_TICK_EN. The RX_PCS_HI_BER
 * registers (0x260-0x268) include a ROC BER count, and a 0->1 write to
 * LOCAL_INT_CNT_CTL (0x014) bit 0 clears every counter in the block.
 *
 * WARNING: FEC_CORRECTED_ZEROS has its LSB at 0x1D0, NOT MSB+4 (0x1C0);
 * the usual MSB/MSB+4 pairing does not hold there.
 *
 */
#define OCORE_FEC_COR_CW_CNT_MSB_OFF        0x19C
#define OCORE_FEC_COR_CW_CNT_LSB_OFF        0x1A0
#define OCORE_FEC_UNCOR_CW_CNT_MSB_OFF      0x1A4
#define OCORE_FEC_UNCOR_CW_CNT_LSB_OFF      0x1A8
#define OCORE_FEC_ACCUM_SYM_ERR_CNT_MSB_OFF 0x1AC /* all lanes */
#define OCORE_FEC_ACCUM_SYM_ERR_CNT_LSB_OFF 0x1B0
#define OCORE_FEC_CODEWRD_CNT_MSB_OFF       0x1B4 /* codewords received */
#define OCORE_FEC_CODEWRD_CNT_LSB_OFF       0x1B8
#define OCORE_FEC_CORRECTED_ZEROS_MSB_OFF   0x1BC
#define OCORE_FEC_CORRECTED_ZEROS_LSB_OFF   0x1D0 /* NOT 0x1C0 - see warning above */
#define OCORE_FEC_CORRECTED_ONES_MSB_OFF    0x1D4
#define OCORE_FEC_CORRECTED_ONES_LSB_OFF    0x1D8

/* MSB/LSB pairs in the per-lane and histogram arrays are 8 bytes apart. */
#define OCORE_FEC_CNT_STRIDE                8

/* FEC_SYM_ERR_CNT_LN<n>: symbol errors on FEC lane @n (0..15). */
#define OCORE_FEC_NUM_LANES                 16
#define OCORE_FEC_SYM_ERR_CNT_LN_MSB_OFF(n) (0x11C + (n) * OCORE_FEC_CNT_STRIDE)
#define OCORE_FEC_SYM_ERR_CNT_LN_LSB_OFF(n) (0x120 + (n) * OCORE_FEC_CNT_STRIDE)

/* RX_FEC_HISTO_SYMB_ERR<k>: codewords with exactly @k symbol errors (0..15). */
#define OCORE_FEC_HISTO_NUM_BINS            16
#define OCORE_FEC_HISTO_SYMB_ERR_MSB_OFF(k) (0x1DC + (k) * OCORE_FEC_CNT_STRIDE)
#define OCORE_FEC_HISTO_SYMB_ERR_LSB_OFF(k) (0x1E0 + (k) * OCORE_FEC_CNT_STRIDE)

/*
 * RS-FEC control/status registers that are safe to read (RO, RW, or
 * RW1C). _OFF is the first of _NUM consecutive vendor registers; the
 * runs skip LOCAL_INT_CNT_CTL and the ROC registers listed above.
 */
#define OCORE_FEC_CTL_STAT_OFF              0x004 /* MAIN_CTL2 .. STATUS */
#define OCORE_FEC_CTL_STAT_NUM              4
#define OCORE_FEC_LANE_STAT_OFF             0x018 /* LATCHED_INT2 .. WS_LN15 */
#define OCORE_FEC_LANE_STAT_NUM             30
#define OCORE_FEC_DATAPATH_OFF              0x0A4 /* DATAPATH_MAX_ENTRY .. PTP_FIFO_STATUS */
#define OCORE_FEC_DATAPATH_NUM              4
#define OCORE_FEC_THRES_OFF                 0x100 /* BAD_CODEWORD_THRES .. DEGRADED_SER_INTERVAL */
#define OCORE_FEC_THRES_NUM                 7
#define OCORE_FEC_HI_SER_PERIOD_OFF         0x25C
#define OCORE_FEC_AM_PERIOD_OFF             0x26C /* CUR_AM_PERIOD_FNS .. AUTO_PTP_PPM_ADJ_CTL */
#define OCORE_FEC_AM_PERIOD_NUM             7

/*
 * OmegaCORE TX RS-FEC block. The runs skip LOCAL_INT_CNT_CTL (0x014)
 * and the ROC error counters at 0x020-0x028.
 */
#define CYR_OCORE_TX_FEC (CYR_EAL_CFG + 0xE4000)
#define OCORE_TX_FEC_CTL_OFF                0x000 /* MAIN_CTL1 .. SPARE */
#define OCORE_TX_FEC_CTL_NUM                5
#define OCORE_TX_FEC_AM_SF_CTL_OFF          0x018
#define OCORE_TX_FEC_DATAPATH_OFF           0x030 /* DATAPATH_MAX_ENTRY, DATAPATH_CTRL */
#define OCORE_TX_FEC_DATAPATH_NUM           2
#define OCORE_TX_FEC_AM_PERIOD_OFF          0x040 /* CUR_AM_PERIOD_FNS .. AUTO_PTP_PPM_ADJ_CTL */
#define OCORE_TX_FEC_AM_PERIOD_NUM          7

/*
 * OmegaCORE SERDES handler block: lane crossbars, gearbox, loopback, and
 * CDC FIFO configuration. All registers are RO, RW, or RW1C.
 */
#define CYR_OCORE_SERDES (CYR_EAL_CFG + 0xE1E00)
#define OCORE_SERDES_XBAR_OFF               0x000 /* SERDES_HANDLER_CONTROL .. EXTERNAL_XBAR_CFG */
#define OCORE_SERDES_XBAR_NUM               11
#define OCORE_SERDES_CDC_OFF                0x030 /* CDC_FIFO_CFG .. LINE_RX2TX_LOOPBACK_C_CFG */
#define OCORE_SERDES_CDC_NUM                23

/* Egress Ethernet Packet Encapsulation Header */
struct eal_egress_header {
	u64 q0;
	u64 q1;
} __packed;

#define EAL_EGRESS_LT_MASK		GENMASK_ULL(63, 63)
#define EAL_EGRESS_SET_LT(h, v) \
	{(h)->q0 = ((h)->q0 & ~EAL_EGRESS_LT_MASK) | \
		FIELD_PREP(EAL_EGRESS_LT_MASK, (v)); }

#define EAL_EGRESS_L2_MASK		GENMASK_ULL(62, 61)
#define EAL_EGRESS_SET_L2(h, v) \
	{(h)->q0 = ((h)->q0 & ~EAL_EGRESS_L2_MASK) | \
		FIELD_PREP(EAL_EGRESS_L2_MASK, (v)); }

#define EAL_EGRESS_F_MASK		GENMASK_ULL(60, 60)

#define EAL_EGRESS_TYPE_MASK		GENMASK_ULL(59, 57)
#define EAL_EGRESS_TYPE_ETH		0
#define EAL_EGRESS_TYPE_ROCEV2		1
#define EAL_EGRESS_TYPE_EXCPTN		2
#define EAL_EGRESS_TYPE_PTP		3
#define EAL_EGRESS_SET_TYPE(h, v) \
	{(h)->q0 = ((h)->q0 & ~EAL_EGRESS_TYPE_MASK) | \
		FIELD_PREP(EAL_EGRESS_TYPE_MASK, (v)); }

#define EAL_EGRESS_RSVD_SC_MASK		GENMASK_ULL(56, 52) /* Reserved (SC) */
#define EAL_EGRESS_RESTRICTED		GENMASK_ULL(51, 32) /* Required for CYR, not used by EAL */
#define EAL_EGRESS_B_MASK		GENMASK_ULL(31, 31)

#define EAL_EGRESS_LENGTH_MASK		GENMASK_ULL(30, 20) /* Number of flits to decapsulate */
#define EAL_EGRESS_SET_LENGTH(h, v) \
	{(h)->q0 = ((h)->q0 & ~EAL_EGRESS_LENGTH_MASK) | \
		FIELD_PREP(EAL_EGRESS_LENGTH_MASK, (v)); }

#define EAL_EGRESS_E_MASK		GENMASK_ULL(19, 17) /* Ethernet packet padding bytes */
#define EAL_EGRESS_SET_E(h, v) \
	{(h)->q0 = ((h)->q0 & ~EAL_EGRESS_E_MASK) | \
		FIELD_PREP(EAL_EGRESS_E_MASK, (v)); }

#define EAL_EGRESS_TS_CAPTURE_MASK	GENMASK_ULL(16, 16) /* Capture timestamps for PTP/non-PTP */
#define EAL_EGRESS_SET_TS_CAPTURE(h, v) \
	{(h)->q0 = ((h)->q0 & ~EAL_EGRESS_TS_CAPTURE_MASK) | \
		FIELD_PREP(EAL_EGRESS_TS_CAPTURE_MASK, (v)); }

#define EAL_EGRESS_TS_MODE_MASK		GENMASK_ULL(15, 14) /* Timestamp mode */
#define EAL_EGRESS_TS_MODE_0B		0
#define EAL_EGRESS_TS_MODE_8B		1
#define EAL_EGRESS_TS_MODE_10B		2
#define EAL_EGRESS_TS_MODE_12B		3
#define EAL_EGRESS_SET_TS_MODE(h, v) \
	{(h)->q0 = ((h)->q0 & ~EAL_EGRESS_TS_MODE_MASK) | \
		FIELD_PREP(EAL_EGRESS_TS_MODE_MASK, (v)); }

#define EAL_EGRESS_TS_OFFSET_MASK	GENMASK_ULL(13, 0)  /* Byte offset for inserted timestamp */
#define EAL_EGRESS_SET_TS_OFFSET(h, v) \
	{(h)->q0 = ((h)->q0 & ~EAL_EGRESS_TS_OFFSET_MASK) | \
		FIELD_PREP(EAL_EGRESS_TS_OFFSET_MASK, (v)); }

#define EAL_EGRESS_R_MASK		GENMASK_ULL(63, 56) /* Multicast match index / etc */
#define EAL_EGRESS_AGE_MASK		GENMASK_ULL(55, 52) /* Packet age bits [7:4] */

#define EAL_EGRESS_SI_NUMBER_MASK	GENMASK_ULL(51, 48) /* System Image (VF) number */
#define EAL_EGRESS_SET_SI_NUMBER(h, v) \
	{(h)->q1 = ((h)->q1 & ~EAL_EGRESS_SI_NUMBER_MASK) | \
		FIELD_PREP(EAL_EGRESS_SI_NUMBER_MASK, (v)); }

#define EAL_EGRESS_RSVD_ENTROPY_MASK	GENMASK_ULL(47, 44) /* Reserved (Entropy bits [15:12]) */

#define EAL_EGRESS_IP_VER_MASK		GENMASK_ULL(43, 43) /* 0: IPv4, 1: IPv6 */
#define EAL_EGRESS_IP_VER_4		0
#define EAL_EGRESS_IP_VER_6		1
#define EAL_EGRESS_SET_IP_VER(h, v) \
	{(h)->q1 = ((h)->q1 & ~EAL_EGRESS_IP_VER_MASK) | \
		FIELD_PREP(EAL_EGRESS_IP_VER_MASK, (v)); }

#define EAL_EGRESS_VLAN_TAGS_MASK	GENMASK_ULL(42, 41) /* 0: None, 1: One, 10/11: Two */
#define EAL_EGRESS_VLAN_TAGS_0		0
#define EAL_EGRESS_VLAN_TAGS_1		1
#define EAL_EGRESS_VLAN_TAGS_2		2
#define EAL_EGRESS_SET_VLAN_TAGS(h, v) \
	{(h)->q1 = ((h)->q1 & ~EAL_EGRESS_VLAN_TAGS_MASK) | \
		FIELD_PREP(EAL_EGRESS_VLAN_TAGS_MASK, (v)); }

#define EAL_EGRESS_ADD_ICRC_MASK	GENMASK_ULL(40, 40) /* 1: Calculate and append ICRC */
#define EAL_EGRESS_SET_ADD_ICRC(h, v) \
	{(h)->q1 = ((h)->q1 & ~EAL_EGRESS_ADD_ICRC_MASK) | \
		FIELD_PREP(EAL_EGRESS_ADD_ICRC_MASK, (v)); }

#define EAL_EGRESS_BTH_OFFSET_MASK	GENMASK_ULL(39, 32) /* BTH Offset (not used by EAL) */
#define EAL_EGRESS_SET_BTH_OFFSET(h, v) \
	{(h)->q1 = ((h)->q1 & ~EAL_EGRESS_BTH_OFFSET_MASK) | \
		FIELD_PREP(EAL_EGRESS_BTH_OFFSET_MASK, (v)); }

#define EAL_EGRESS_PKEY_MASK		GENMASK_ULL(31, 16) /* Partition Key */
#define EAL_EGRESS_SET_PKEY(h, v) \
	{(h)->q1 = ((h)->q1 & ~EAL_EGRESS_PKEY_MASK) | \
		FIELD_PREP(EAL_EGRESS_PKEY_MASK, (v)); }

#define EAL_EGRESS_DLID_23_20_MASK	GENMASK_ULL(15, 12) /* Required for CYR, not used by EAL */
#define EAL_EGRESS_SET_DLID_23_20(h, v) \
	{(h)->q1 = ((h)->q1 & ~EAL_EGRESS_DLID_23_20_MASK) | \
		FIELD_PREP(EAL_EGRESS_DLID_23_20_MASK, (v)); }

#define EAL_EGRESS_SLID_23_20_MASK	GENMASK_ULL(11, 8)  /* Source MAC mapping bits */
#define EAL_EGRESS_SET_SLID_23_20(h, v) \
	{(h)->q1 = ((h)->q1 & ~EAL_EGRESS_SLID_23_20_MASK) | \
		FIELD_PREP(EAL_EGRESS_SLID_23_20_MASK, (v)); }

#define EAL_EGRESS_L4_MASK		GENMASK_ULL(7, 0)   /* Layer 4 field type */
#define EAL_EGRESS_L4_ETH		0x78
#define EAL_EGRESS_L4_EXCPTN		0x79
#define EAL_EGRESS_L4_VRMA		0x7A
#define EAL_EGRESS_L4_TID		0x7C
#define EAL_EGRESS_SET_L4(h, v) \
	{(h)->q1 = ((h)->q1 & ~EAL_EGRESS_L4_MASK) | \
		FIELD_PREP(EAL_EGRESS_L4_MASK, (v)); }

/* Standard Ethernet Packet Encapsulation Header */
struct eal_ingress_header {
	u64 q0;
	u64 q1;
} __packed;

#define EAL_INGRESS_LT_MASK		GENMASK_ULL(63, 63) /* fixed 1 */
#define EAL_INGRESS_L2_MASK		GENMASK_ULL(62, 61) /* fixed 2 */
#define EAL_INGRESS_F_MASK		GENMASK_ULL(60, 60) /* fixed 0 */
#define EAL_INGRESS_TYPE_MASK		GENMASK_ULL(59, 57)
#define EAL_INGRESS_TYPE_Q0_BIT		57
/*
 * The CN6000 TC HAS defines Type 0 as Ethernet and Type 1 as RoCEv2.  Other
 * values are not expected on the EAL control-RCD path and are dropped by its
 * header check.  The eal_test steering rule matches Type 0 explicitly, so a
 * Type 1 RoCEv2 frame cannot match that rule.
 */
#define EAL_INGRESS_TYPE_ETHERNET		0
#define EAL_INGRESS_TYPE_ROCEV2		1
#define EAL_INGRESS_GET_TYPE(h) FIELD_GET(EAL_INGRESS_TYPE_MASK, (h)->q0)

#define EAL_INGRESS_TS_PRESENT_MASK	GENMASK_ULL(56, 56)
#define EAL_INGRESS_GET_TS_PRESENT(h) FIELD_GET(EAL_INGRESS_TS_PRESENT_MASK, (h)->q0)

#define EAL_INGRESS_VF_MASK		GENMASK_ULL(54, 52)
#define EAL_INGRESS_GET_VF(h) FIELD_GET(EAL_INGRESS_VF_MASK, (h)->q0)

#define EAL_INGRESS_CTXT_INFO_MASK	GENMASK_ULL(51, 32)
#define EAL_INGRESS_GET_CTXT_INFO(h) FIELD_GET(EAL_INGRESS_CTXT_INFO_MASK, (h)->q0)

/*
 * For Type 0 packets, context_info bit 13 flags an L4 UDP/TCP destination-port
 * table match and bits [12:9] carry the matching entry index.  Type 1 reuses
 * the entire field for the lower 20 bits of the BTH destination QP.
 */
#define EAL_INGRESS_CTXT_INFO_L4_DSTPORT_MATCH_BIT	13
#define EAL_INGRESS_CTXT_INFO_L4_DSTPORT_ENTRY_MASK	GENMASK_ULL(12, 9)
#define EAL_INGRESS_CTXT_INFO_L4_DSTPORT_ENTRY_BIT	9
#define EAL_INGRESS_L4_DSTPORT_MATCH_Q0_BIT \
	(32 + EAL_INGRESS_CTXT_INFO_L4_DSTPORT_MATCH_BIT)
#define EAL_INGRESS_L4_DSTPORT_ENTRY_Q0_BIT \
	(32 + EAL_INGRESS_CTXT_INFO_L4_DSTPORT_ENTRY_BIT)
#define EAL_INGRESS_L4_DSTPORT_MATCH(h) \
	(EAL_INGRESS_GET_CTXT_INFO(h) & \
	 BIT_ULL(EAL_INGRESS_CTXT_INFO_L4_DSTPORT_MATCH_BIT))
#define EAL_INGRESS_GET_L4_DSTPORT_ENTRY(h) \
	FIELD_GET(EAL_INGRESS_CTXT_INFO_L4_DSTPORT_ENTRY_MASK, \
		  EAL_INGRESS_GET_CTXT_INFO(h))

#define EAL_INGRESS_B_MASK		GENMASK_ULL(31, 31)
#define EAL_INGRESS_LENGTH_MASK		GENMASK_ULL(30, 20)
#define EAL_INGRESS_GET_LENGTH(h) FIELD_GET(EAL_INGRESS_LENGTH_MASK, (h)->q0)

#define EAL_INGRESS_SADDR_19_0_MASK	GENMASK_ULL(19, 0)
#define EAL_INGRESS_GET_SADDR_19_0(h) FIELD_GET(EAL_INGRESS_SADDR_19_0_MASK, (h)->q0)

#define EAL_INGRESS_MCAST_INDEX_MASK	GENMASK_ULL(63, 59)
#define EAL_INGRESS_GET_MCAST_INDEX(h) FIELD_GET(EAL_INGRESS_MCAST_INDEX_MASK, (h)->q1)

#define EAL_INGRESS_E_MASK		GENMASK_ULL(58, 56)
#define EAL_INGRESS_GET_E(h) FIELD_GET(EAL_INGRESS_E_MASK, (h)->q1)

#define EAL_INGRESS_MCAST_MBRS_MASK	GENMASK_ULL(55, 48)
#define EAL_INGRESS_GET_MCAST_MBRS(h) FIELD_GET(EAL_INGRESS_MCAST_MBRS_MASK, (h)->q1)

#define EAL_INGRESS_ENTROPY_MASK	GENMASK_ULL(47, 32)
#define EAL_INGRESS_GET_ENTROPY(h) FIELD_GET(EAL_INGRESS_ENTROPY_MASK, (h)->q1)

#define EAL_INGRESS_PKEY_MASK		GENMASK_ULL(31, 16)
#define EAL_INGRESS_GET_PKEY(h) FIELD_GET(EAL_INGRESS_PKEY_MASK, (h)->q1)

#define EAL_INGRESS_DLID_23_20_MASK	GENMASK_ULL(15, 12)
#define EAL_INGRESS_GET_DLID_23_20(h) FIELD_GET(EAL_INGRESS_DLID_23_20_MASK, (h)->q1)

#define EAL_INGRESS_SADDR_23_20_MASK	GENMASK_ULL(11, 8)
#define EAL_INGRESS_GET_SADDR_23_20(h) FIELD_GET(EAL_INGRESS_SADDR_23_20_MASK, (h)->q1)

#define EAL_INGRESS_L4_MASK		GENMASK_ULL(7, 0)
#define EAL_INGRESS_L4_ETHERNET		0x78
#define EAL_INGRESS_GET_L4(h) FIELD_GET(EAL_INGRESS_L4_MASK, (h)->q1)

/*
 * Type 1 (RoCEv2) ingress overlay, A00502-0.6.1 Table 4-19.
 *
 * Every field aligns with the Type 0 overlay above; only the meanings differ,
 * so the two must not be mixed.  Read EAL_INGRESS_GET_TYPE() first and use
 * these accessors only when it returns EAL_INGRESS_TYPE_ROCEV2.  In
 * particular q1 63:59 is the multicast index under Type 0 and End_state here,
 * and the adjacent E[2:0] at 58:56 is Ethernet padding in both overlays -
 * never a truncated End_state, which is five bits wide.
 */
#define EAL_INGRESS_ROCE_QP_19_0_MASK	GENMASK_ULL(51, 32)
#define EAL_INGRESS_ROCE_GET_QP_19_0(h) \
	FIELD_GET(EAL_INGRESS_ROCE_QP_19_0_MASK, (h)->q0)

#define EAL_INGRESS_ROCE_QP_23_20_MASK	GENMASK_ULL(15, 12)
#define EAL_INGRESS_ROCE_GET_QP_23_20(h) \
	FIELD_GET(EAL_INGRESS_ROCE_QP_23_20_MASK, (h)->q1)

/* BTH destination QP, reassembled from its two ingress-header fields. */
#define EAL_INGRESS_ROCE_GET_QP(h) \
	(((u32)EAL_INGRESS_ROCE_GET_QP_23_20(h) << 20) | \
	 (u32)EAL_INGRESS_ROCE_GET_QP_19_0(h))

#define EAL_INGRESS_ROCE_END_STATE_MASK	GENMASK_ULL(63, 59)
#define EAL_INGRESS_ROCE_GET_END_STATE(h) \
	FIELD_GET(EAL_INGRESS_ROCE_END_STATE_MASK, (h)->q1)

/* End_state enumeration, not a bitmask: all other values are reserved. */
#define EAL_INGRESS_ROCE_END_STATE_OK		0x00
#define EAL_INGRESS_ROCE_END_STATE_FIRST_ERR	0x01
#define EAL_INGRESS_ROCE_END_STATE_MIDDLE_OO	0x02
#define EAL_INGRESS_ROCE_END_STATE_MIDDLE_NO_QP	0x04
#define EAL_INGRESS_ROCE_END_STATE_LAST_ERR	0x08

#define EAL_INGRESS_ROCE_OPCODE_MASK	GENMASK_ULL(55, 48)
#define EAL_INGRESS_ROCE_GET_OPCODE(h) \
	FIELD_GET(EAL_INGRESS_ROCE_OPCODE_MASK, (h)->q1)

/*
 * VRMA ingress header, A00502-0.6.1 Table 4-20.  Present only when
 * EAL_INGRESS_GET_L4() returns EAL_EGRESS_L4_VRMA; q2 and q3 do not exist on
 * an on-load header, so the two-qword struct above stays the Type 0 shape.
 */
struct eal_ingress_vrma_header {
	u64 q0;
	u64 q1;
	u64 q2;
	u64 q3;
} __packed;

/*
 * q2 carries the placement virtual address when the packet is in sequence.
 * Out of sequence - End_state 0x02, WR_PAYLOAD clear - it carries the
 * packet's PSN and the PSN hardware expected instead, so software can
 * compare hardware's cursor against its own rather than infer loss.
 */
#define EAL_INGRESS_VRMA_GET_VA(h) ((h)->q2)

#define EAL_INGRESS_VRMA_PKT_PSN_MASK	GENMASK_ULL(55, 32)
#define EAL_INGRESS_VRMA_GET_PKT_PSN(h) \
	FIELD_GET(EAL_INGRESS_VRMA_PKT_PSN_MASK, (h)->q2)

#define EAL_INGRESS_VRMA_NEXT_PSN_MASK	GENMASK_ULL(23, 0)
#define EAL_INGRESS_VRMA_GET_NEXT_PSN(h) \
	FIELD_GET(EAL_INGRESS_VRMA_NEXT_PSN_MASK, (h)->q2)

/* Dwords written to the header queue, including the standard 16B header. */
#define EAL_INGRESS_VRMA_HDR_DWORDS_MASK	GENMASK_ULL(61, 56)
#define EAL_INGRESS_VRMA_GET_HDR_DWORDS(h) \
	FIELD_GET(EAL_INGRESS_VRMA_HDR_DWORDS_MASK, (h)->q3)

/* Clear means the payload was trimmed and never reached host memory. */
#define EAL_INGRESS_VRMA_WR_PAYLOAD_MASK	GENMASK_ULL(55, 55)
#define EAL_INGRESS_VRMA_GET_WR_PAYLOAD(h) \
	FIELD_GET(EAL_INGRESS_VRMA_WR_PAYLOAD_MASK, (h)->q3)

#define EAL_INGRESS_VRMA_PAYLOAD_OFFSET_MASK	GENMASK_ULL(53, 48)
#define EAL_INGRESS_VRMA_GET_PAYLOAD_OFFSET(h) \
	FIELD_GET(EAL_INGRESS_VRMA_PAYLOAD_OFFSET_MASK, (h)->q3)

#define EAL_INGRESS_VRMA_PASID_MASK	GENMASK_ULL(35, 16)
#define EAL_INGRESS_VRMA_GET_PASID(h) \
	FIELD_GET(EAL_INGRESS_VRMA_PASID_MASK, (h)->q3)

#define EAL_INGRESS_VRMA_LENGTH_ADJ_MASK	GENMASK_ULL(14, 2)
#define EAL_INGRESS_VRMA_GET_LENGTH_ADJ(h) \
	FIELD_GET(EAL_INGRESS_VRMA_LENGTH_ADJ_MASK, (h)->q3)

#define EAL_INGRESS_VRMA_LENGTH_ADJ_PAD_MASK	GENMASK_ULL(1, 0)
#define EAL_INGRESS_VRMA_GET_LENGTH_ADJ_PAD(h) \
	FIELD_GET(EAL_INGRESS_VRMA_LENGTH_ADJ_PAD_MASK, (h)->q3)

/*
 * Bytes hardware placed, stated per packet rather than inferred from PMTU.
 * This is what lets a burst served jointly by hardware and software be
 * reconciled exactly.  HDR_DWORDS and PAYLOAD_OFFSET use the same dword unit.
 */
#define EAL_INGRESS_VRMA_PLACED_BYTES(h) \
	((u32)EAL_INGRESS_VRMA_GET_LENGTH_ADJ(h) * 4 - \
	 (u32)EAL_INGRESS_VRMA_GET_LENGTH_ADJ_PAD(h))

/* Link status */
#define LINK_UP_MASK	BIT_ULL(0)
#define LINK_UP(v) ((bool)FIELD_GET(LINK_UP_MASK, (v)))

#define LINK_SPEED_MASK	GENMASK_ULL(8,  1)
#define LINK_SPEED(v) ((u8)FIELD_GET(LINK_SPEED_MASK, (v)))
#define LINK_SPEED_10	1 /* 10Gbps */
#define LINK_SPEED_25	2 /* 25Gbps */
#define LINK_SPEED_40	3 /* 40Gbps */
#define LINK_SPEED_50	4 /* 50Gbps */
#define LINK_SPEED_100	5 /* 100Gbps */
#define LINK_SPEED_200	6 /* 200Gbps */
#define LINK_SPEED_400	7 /* 400Gbps */
#define LINK_SPEED_800	8 /* 800Gbps */

#define LINK_LANE_WIDTH_MASK	GENMASK_ULL(12, 9)
#define LINK_LANE_WIDTH(v) ((u8)FIELD_GET(LINK_LANE_WIDTH_MASK, (v)))

#define LINK_RSVD0_MASK		GENMASK_ULL(15, 13)
#define LINK_CABLE_TYPE_MASK	GENMASK_ULL(19, 16)
#define LINK_CABLE_TYPE(v) ((u8)FIELD_GET(LINK_CABLE_TYPE_MASK, (v)))
#define LINK_CABLE_TYPE_CR	1 /* CR (passive copper DAC) */
#define LINK_CABLE_TYPE_SR	2 /* SR (optical) */

#define LINK_CABLE_LENGTH_MASK	GENMASK_ULL(31, 20)
#define LINK_CABLE_LENGTH(v) ((u16)FIELD_GET(LINK_CABLE_LENGTH_MASK, (v)))

#define LINK_RSVD1_MASK		GENMASK_ULL(63, 32)

#endif /* _HWI_H */
